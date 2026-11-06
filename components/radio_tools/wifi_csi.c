#include "wifi_csi.h"
#include "wifi_manager.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>
#include <string.h>

#define CSI_NUM_SUB 64
#define CSI_SELECTED_COUNT 12
#define CSI_CAL_FRAMES 200
#define CSI_HAMPEL_WIN 7
#define CSI_MV_WIN 50

static const int s_selected[CSI_SELECTED_COUNT] = {12,14,16,18,20,24,28,36,40,44,48,52};
static float s_amplitudes[CSI_NUM_SUB];
static bool s_data_ready;
static volatile bool s_running;
static uint32_t s_frames;
static portMUX_TYPE s_csi_mux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t s_filter_mac[6];
static bool s_filter;
static TaskHandle_t s_task;
static float s_cal[CSI_CAL_FRAMES];
static float s_hampel[CSI_HAMPEL_WIN];
static float s_mv[CSI_MV_WIN];
static int s_cal_count;
static int s_hampel_count;
static int s_hampel_idx;
static int s_mv_count;
static int s_mv_idx;
static float s_lp_b0, s_lp_a1, s_lp_x, s_lp_y;
static float s_threshold;
static float s_turbulence;
static float s_variance;
static uint8_t s_state;
static uint8_t s_calibration;
static uint8_t s_source_mac[6];

static float turbulence(const float amplitudes[CSI_NUM_SUB])
{
    float sum = 0, sq = 0;
    for (int i = 0; i < CSI_SELECTED_COUNT; i++) {
        float v = amplitudes[s_selected[i]];
        sum += v;
        sq += v * v;
    }
    float mean = sum / CSI_SELECTED_COUNT;
    float var = sq / CSI_SELECTED_COUNT - mean * mean;
    float std = var > 0 ? sqrtf(var) : 0;
    return mean > 0.1f ? std / mean : std;
}

static float hampel(float value)
{
    s_hampel[s_hampel_idx] = value;
    s_hampel_idx = (s_hampel_idx + 1) % CSI_HAMPEL_WIN;
    if (s_hampel_count < CSI_HAMPEL_WIN) s_hampel_count++;
    float sorted[CSI_HAMPEL_WIN], diffs[CSI_HAMPEL_WIN];
    memcpy(sorted, s_hampel, sizeof(sorted));
    for (int i = 1; i < s_hampel_count; i++) {
        float key = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j] > key) { sorted[j + 1] = sorted[j]; j--; }
        sorted[j + 1] = key;
    }
    float median = sorted[s_hampel_count / 2];
    for (int i = 0; i < s_hampel_count; i++) diffs[i] = fabsf(s_hampel[i] - median);
    for (int i = 1; i < s_hampel_count; i++) {
        float key = diffs[i];
        int j = i - 1;
        while (j >= 0 && diffs[j] > key) { diffs[j + 1] = diffs[j]; j--; }
        diffs[j + 1] = key;
    }
    float mad = diffs[s_hampel_count / 2] * 1.4826f;
    return mad > 0 && fabsf(value - median) > 5.0f * mad ? median : value;
}

static float lowpass(float value)
{
    float y = s_lp_b0 * value + s_lp_b0 * s_lp_x - s_lp_a1 * s_lp_y;
    s_lp_x = value;
    s_lp_y = y;
    return y;
}

static float moving_variance(float value)
{
    s_mv[s_mv_idx] = value;
    s_mv_idx = (s_mv_idx + 1) % CSI_MV_WIN;
    if (s_mv_count < CSI_MV_WIN) s_mv_count++;
    float sum = 0, sq = 0;
    for (int i = 0; i < s_mv_count; i++) { sum += s_mv[i]; sq += s_mv[i] * s_mv[i]; }
    float mean = sum / s_mv_count;
    return sq / s_mv_count - mean * mean;
}

static float percentile95(void)
{
    float sorted[CSI_CAL_FRAMES];
    memcpy(sorted, s_cal, sizeof(sorted));
    for (int i = 1; i < CSI_CAL_FRAMES; i++) {
        float key = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j] > key) { sorted[j + 1] = sorted[j]; j--; }
        sorted[j + 1] = key;
    }
    return sorted[(CSI_CAL_FRAMES * 95) / 100];
}

static void csi_rx(void *ctx, wifi_csi_info_t *info)
{
    (void)ctx;
    if (!s_running || !info || !info->buf || info->len < 2) return;
    if (s_filter && memcmp(info->mac, s_filter_mac, 6) != 0) return;
    int pairs = info->len / 2;
    if (pairs > CSI_NUM_SUB) pairs = CSI_NUM_SUB;
    float amplitudes[CSI_NUM_SUB] = {0};
    const int8_t *buf = (const int8_t *)info->buf;
    for (int i = 0; i < pairs; i++) {
        float q = buf[i * 2], in = buf[i * 2 + 1];
        amplitudes[i] = sqrtf(q * q + in * in);
    }
    portENTER_CRITICAL(&s_csi_mux);
    memcpy(s_amplitudes, amplitudes, sizeof(s_amplitudes));
    memcpy(s_source_mac, info->mac, 6);
    s_frames++;
    s_data_ready = true;
    portEXIT_CRITICAL(&s_csi_mux);
}

static void process_sample(const float amplitudes[CSI_NUM_SUB])
{
    float raw = turbulence(amplitudes);
    float filtered = hampel(raw);
    s_turbulence = lowpass(filtered);
    s_variance = moving_variance(s_turbulence);
    if (s_cal_count < CSI_CAL_FRAMES) {
        s_cal[s_cal_count++] = s_variance;
        s_calibration = (uint8_t)(s_cal_count * 100 / CSI_CAL_FRAMES);
        s_state = 1;
        if (s_cal_count == CSI_CAL_FRAMES) {
            s_threshold = percentile95() * 1.1f;
            if (s_threshold < 1e-6f) s_threshold = 1e-6f;
            s_calibration = 100;
        }
        return;
    }
    if (s_variance > s_threshold * 3.0f) s_state = 4;
    else if (s_variance > s_threshold) s_state = 3;
    else s_state = 2;
}

static void process_task(void *arg)
{
    int sock = -1;
    struct sockaddr_in gateway = {0};
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if (sta && esp_netif_get_ip_info(sta, &info) == ESP_OK && info.gw.addr) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        gateway.sin_family = AF_INET;
        gateway.sin_port = htons(55555);
        gateway.sin_addr.s_addr = info.gw.addr;
    }
    uint32_t last_ping = 0;
    while (s_running) {
        float amplitudes[CSI_NUM_SUB];
        bool ready = false;
        portENTER_CRITICAL(&s_csi_mux);
        if (s_data_ready) {
            memcpy(amplitudes, s_amplitudes, sizeof(amplitudes));
            s_data_ready = false;
            ready = true;
        }
        portEXIT_CRITICAL(&s_csi_mux);
        if (ready)
            process_sample(amplitudes);
        if (sock >= 0 && xTaskGetTickCount() - last_ping >= pdMS_TO_TICKS(80)) {
            uint8_t byte = 0x42;
            sendto(sock, &byte, 1, 0, (struct sockaddr *)&gateway, sizeof(gateway));
            last_ping = xTaskGetTickCount();
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    if (sock >= 0) close(sock);
    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_csi_start(uint8_t mode, uint8_t channel, const uint8_t source_mac[6])
{
    if (mode > 1 || s_running) return ESP_ERR_INVALID_ARG;
    if (mode == 0 && !wifi_mgr_is_connected()) return ESP_ERR_INVALID_STATE;
    memset(s_cal, 0, sizeof(s_cal));
    memset(s_hampel, 0, sizeof(s_hampel));
    memset(s_mv, 0, sizeof(s_mv));
    s_cal_count = s_hampel_count = s_hampel_idx = s_mv_count = s_mv_idx = 0;
    s_threshold = s_turbulence = s_variance = 0;
    s_state = 0;
    s_calibration = 0;
    s_frames = 0;
    s_data_ready = false;
    float wc = tanf((float)M_PI * 11.0f / 100.0f);
    float k = 1.0f + wc;
    s_lp_b0 = wc / k;
    s_lp_a1 = (wc - 1.0f) / k;
    s_lp_x = s_lp_y = 0;
    s_filter = source_mac != NULL;
    if (s_filter) memcpy(s_filter_mac, source_mac, 6);
    esp_err_t err = ESP_OK;
    if (channel) {
        err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if (err != ESP_OK)
            ESP_LOGE("wifi_csi", "set_channel(%u) failed: %s", channel, esp_err_to_name(err));
    }
    if (mode == 1) {
        err = esp_wifi_set_promiscuous(true);
        if (err != ESP_OK)
            ESP_LOGE("wifi_csi", "set_promiscuous failed: %s", esp_err_to_name(err));
    }

    wifi_csi_config_t cfg = {0};
#if CONFIG_SOC_WIFI_HE_SUPPORT
    cfg.enable = true;
    cfg.acquire_csi_legacy = true;
#if CONFIG_SOC_WIFI_MAC_VERSION_NUM == 3
    cfg.acquire_csi_force_lltf = true;
    cfg.acquire_csi_vht = true;
    cfg.acquire_csi_he_stbc_mode = 2;
#else
    cfg.acquire_csi_he_stbc = 2;
#endif
    cfg.acquire_csi_ht20 = true;
    cfg.acquire_csi_ht40 = true;
    cfg.acquire_csi_su = true;
    cfg.acquire_csi_mu = true;
    cfg.acquire_csi_dcm = true;
    cfg.acquire_csi_beamformed = true;
#else
    cfg.lltf_en = true;
    cfg.htltf_en = true;
    cfg.stbc_htltf2_en = true;
    cfg.ltf_merge_en = true;
    cfg.channel_filter_en = mode == 1;
    cfg.manu_scale = false;
    cfg.shift = false;
#endif
    err = esp_wifi_set_csi_config(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_csi", "set_csi_config failed: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_wifi_set_csi_rx_cb(csi_rx, NULL);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_csi", "set_csi_rx_cb failed: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_wifi_set_csi(true);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_csi", "set_csi failed: %s", esp_err_to_name(err));
        return err;
    }
    s_running = true;
    if (xTaskCreate(process_task, "csi_process", 6144, NULL, 5, &s_task) != pdPASS) {
        s_running = false;
        esp_wifi_set_csi(false);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

int wifi_csi_status(uint8_t *out, uint16_t cap)
{
    if (!out || cap < 24) return 0;
    out[0] = s_state;
    out[1] = s_calibration;
    portENTER_CRITICAL(&s_csi_mux);
    memcpy(&out[2], &s_frames, 4);
    memcpy(&out[18], s_source_mac, 6);
    portEXIT_CRITICAL(&s_csi_mux);
    memcpy(&out[6], &s_turbulence, 4);
    memcpy(&out[10], &s_variance, 4);
    memcpy(&out[14], &s_threshold, 4);
    return 24;
}

void wifi_csi_stop(void)
{
    s_running = false;
    esp_wifi_set_csi(false);
    esp_wifi_set_csi_rx_cb(NULL, NULL);
    esp_wifi_set_promiscuous(false);
    for (int i = 0; i < 50 && s_task; i++) vTaskDelay(pdMS_TO_TICKS(2));
}
