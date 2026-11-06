#include "wifi_wps.h"
#include "wifi_manager.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

#define WPS_MAX 48

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    bool wps1only;
    uint32_t last_seen;
} wps_ap_t;

static wps_ap_t s_aps[WPS_MAX];
static volatile uint8_t s_count;
static volatile uint8_t s_channel;
static volatile bool s_running;
static uint8_t s_cursor;
static TaskHandle_t s_hop_task;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

static int find_ap(const uint8_t *bssid)
{
    for (uint8_t i = 0; i < s_count; i++)
        if (!memcmp(s_aps[i].bssid, bssid, 6)) return i;
    return -1;
}

static void parse_wps(const wifi_promiscuous_pkt_t *pkt)
{
    const uint8_t *f = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 38) return;
    uint8_t subtype = (f[0] & 0xF0) >> 4;
    if (subtype != 8 && subtype != 5) return;

    char ssid[33] = {0};
    bool wps = false, locked = false, pin = false, known = false, version2 = false;
    for (int i = 36; i + 2 <= len;) {
        uint8_t id = f[i], elen = f[i + 1];
        if (i + 2 + elen > len) break;
        const uint8_t *d = f + i + 2;
        if (id == 0 && elen <= 32) {
            memcpy(ssid, d, elen);
            ssid[elen] = 0;
        } else if (id == 221 && elen >= 4 &&
                   d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x04) {
            wps = true;
            for (int j = 4; j + 4 <= elen;) {
                uint16_t aid = ((uint16_t)d[j] << 8) | d[j + 1];
                uint16_t alen = ((uint16_t)d[j + 2] << 8) | d[j + 3];
                if (j + 4 + alen > elen) break;
                const uint8_t *av = d + j + 4;
                if (aid == 0x1057 && alen >= 1) {
                    locked = av[0] == 1;
                } else if ((aid == 0x1008 || aid == 0x1053) && alen >= 2) {
                    uint16_t methods = ((uint16_t)av[0] << 8) | av[1];
                    known = true;
                    pin = (methods & (0x0004 | 0x0008 | 0x0100)) != 0;
                } else if (aid == 0x1049 && alen >= 4 &&
                           av[0] == 0x00 && av[1] == 0x37 && av[2] == 0x2A) {
                    for (uint16_t k = 3; k + 2 <= alen;) {
                        uint8_t sid = av[k], slen = av[k + 1];
                        if (k + 2 + slen > alen) break;
                        if (sid == 0) version2 = true;
                        k = (uint16_t)(k + 2 + slen);
                    }
                }
                j += 4 + alen;
            }
        }
        i += 2 + elen;
    }
    if (!wps || !known || !pin || locked) return;

    portENTER_CRITICAL(&s_mux);
    int idx = find_ap(f + 16);
    if (idx < 0 && s_count < WPS_MAX) {
        idx = s_count++;
        memcpy(s_aps[idx].bssid, f + 16, 6);
    }
    if (idx >= 0) {
        if (ssid[0]) memcpy(s_aps[idx].ssid, ssid, sizeof(s_aps[idx].ssid));
        s_aps[idx].rssi = pkt->rx_ctrl.rssi;
        s_aps[idx].channel = pkt->rx_ctrl.channel;
        s_aps[idx].wps1only = !version2;
        s_aps[idx].last_seen = (uint32_t)(esp_timer_get_time() / 1000);
    }
    portEXIT_CRITICAL(&s_mux);
}

static void rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || type != WIFI_PKT_MGMT) return;
    parse_wps((const wifi_promiscuous_pkt_t *)buf);
}

static void hop_task(void *arg)
{
    uint8_t channel = 1;
    uint32_t dwell = (uint32_t)arg;
    while (s_running) {
        s_channel = channel;
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        channel = channel >= 13 ? 1 : channel + 1;
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(dwell));
    }
    s_hop_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_wps_start(uint16_t hop_dwell_ms)
{
    if (s_running) return ESP_ERR_INVALID_STATE;
    s_count = 0;
    s_cursor = 0;
    memset(s_aps, 0, sizeof(s_aps));
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_mgr_disconnect();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(rx_cb);
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) return err;
    if (!hop_dwell_ms) hop_dwell_ms = 320;
    s_running = true;
    if (xTaskCreate(hop_task, "wps_hop", 2560, (void *)(uintptr_t)hop_dwell_ms,
                    5, &s_hop_task) != pdPASS) {
        s_running = false;
        esp_wifi_set_promiscuous(false);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

int wifi_wps_next(uint8_t *out, uint16_t cap)
{
    if (!out || cap < 2) return 0;
    portENTER_CRITICAL(&s_mux);
    if (s_cursor >= s_count) {
        out[0] = 1;
        out[1] = s_channel;
        portEXIT_CRITICAL(&s_mux);
        return 2;
    }
    wps_ap_t ap = s_aps[s_cursor++];
    portEXIT_CRITICAL(&s_mux);

    uint8_t ssid_len = (uint8_t)strnlen(ap.ssid, 32);
    uint16_t need = 2 + 6 + 1 + ssid_len + 3;
    if (cap < need) return 0;
    out[0] = 0;
    out[1] = s_channel;
    memcpy(&out[2], ap.bssid, 6);
    out[8] = ssid_len;
    memcpy(&out[9], ap.ssid, ssid_len);
    uint16_t pos = 9 + ssid_len;
    out[pos++] = (uint8_t)ap.rssi;
    out[pos++] = ap.channel;
    out[pos++] = ap.wps1only ? 1 : 0;
    return (int)pos;
}

void wifi_wps_stop(void)
{
    s_running = false;
    if (s_hop_task) xTaskNotifyGive(s_hop_task);
    for (int i = 0; i < 50 && s_hop_task; i++) vTaskDelay(pdMS_TO_TICKS(10));
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
}
