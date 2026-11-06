#include "wifi_channel_monitor.h"
#include "wifi_manager.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

#define CHANNEL_COUNT 13

typedef struct {
    uint32_t packets;
    uint32_t metric;
    int8_t rssi;
    uint8_t load;
} channel_stat_t;

static channel_stat_t s_stats[CHANNEL_COUNT + 1];
static volatile uint32_t s_packets;
static volatile uint32_t s_bytes;
static volatile uint32_t s_deauth;
static volatile int8_t s_peak = -128;
static volatile uint8_t s_channel;
static volatile bool s_running;
static uint8_t s_mode;
static uint16_t s_dwell;
static TaskHandle_t s_task;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

static void rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    if (!s_running || !buf) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    portENTER_CRITICAL(&s_mux);
    s_packets++;
    s_bytes += pkt->rx_ctrl.sig_len;
    if (pkt->rx_ctrl.rssi > s_peak) s_peak = pkt->rx_ctrl.rssi;
    if (s_mode == 1 && type == WIFI_PKT_MGMT && pkt->rx_ctrl.sig_len >= 2) {
        uint8_t ftype = (pkt->payload[0] & 0x0C) >> 2;
        uint8_t subtype = (pkt->payload[0] & 0xF0) >> 4;
        if (ftype == 0 && (subtype == 12 || subtype == 10)) s_deauth++;
    }
    portEXIT_CRITICAL(&s_mux);
}

static void sample_task(void *arg)
{
    uint8_t channel = 1;
    while (s_running) {
        portENTER_CRITICAL(&s_mux);
        s_packets = 0;
        s_bytes = 0;
        s_deauth = 0;
        s_peak = -128;
        portEXIT_CRITICAL(&s_mux);
        s_channel = channel;
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(s_dwell));

        portENTER_CRITICAL(&s_mux);
        uint32_t packets = s_packets;
        uint32_t bytes = s_bytes;
        uint32_t deauth = s_deauth;
        int8_t peak = s_peak;
        portEXIT_CRITICAL(&s_mux);

        channel_stat_t *st = &s_stats[channel];
        uint8_t load;
        if (s_mode == 0) {
            uint32_t airtime_us = (bytes * 8U) / 6U + packets * 60U;
            uint32_t dwell_us = (uint32_t)s_dwell * 1000U;
            uint32_t pct = dwell_us ? airtime_us * 100U / dwell_us : 0;
            load = pct > 100 ? 100 : (uint8_t)pct;
        } else {
            uint32_t rate = s_dwell ? deauth * 1000U / s_dwell : 0;
            load = rate > 255 ? 255 : (uint8_t)rate;
        }
        portENTER_CRITICAL(&s_mux);
        st->packets = packets;
        st->metric = s_mode == 0 ? bytes : deauth;
        st->rssi = peak;
        st->load = load;
        portEXIT_CRITICAL(&s_mux);
        channel = channel >= CHANNEL_COUNT ? 1 : channel + 1;
    }
    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_channel_monitor_start(uint8_t mode, uint16_t dwell_ms)
{
    if (mode > 1 || s_running) return ESP_ERR_INVALID_ARG;
    memset(s_stats, 0, sizeof(s_stats));
    s_mode = mode;
    s_dwell = dwell_ms < 50 ? 250 : dwell_ms;
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_mgr_disconnect();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(rx_cb);
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) return err;
    s_running = true;
    if (xTaskCreate(sample_task, "channel_mon", 3072, NULL, 5, &s_task) != pdPASS) {
        s_running = false;
        esp_wifi_set_promiscuous(false);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

int wifi_channel_monitor_stats(uint8_t *out, uint16_t cap)
{
    if (!out || cap < 1 + CHANNEL_COUNT * 10) return 0;
    out[0] = s_channel;
    uint16_t pos = 1;
    portENTER_CRITICAL(&s_mux);
    for (uint8_t ch = 1; ch <= CHANNEL_COUNT; ch++) {
        uint32_t packets = s_stats[ch].packets;
        uint32_t metric = s_stats[ch].metric;
        memcpy(&out[pos], &packets, 4);
        memcpy(&out[pos + 4], &metric, 4);
        out[pos + 8] = (uint8_t)s_stats[ch].rssi;
        out[pos + 9] = s_stats[ch].load;
        pos += 10;
    }
    portEXIT_CRITICAL(&s_mux);
    return (int)pos;
}

void wifi_channel_monitor_stop(void)
{
    s_running = false;
    if (s_task) xTaskNotifyGive(s_task);
    for (int i = 0; i < 50 && s_task; i++) vTaskDelay(pdMS_TO_TICKS(10));
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
}
