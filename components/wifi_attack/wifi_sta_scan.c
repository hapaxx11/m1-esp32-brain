/*
 * WiFi Station (Client) Discovery — promiscuous-mode implementation
 *
 * Sniffs 802.11 frames on the target AP's channel and extracts the MAC
 * addresses of associated/communicating stations by inspecting the
 * ToDS/FromDS bits and the three address fields of each frame header.
 */

#include "wifi_sta_scan.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "wifi_sta_scan";

#define STA_SCAN_MAX_DEVS 32

/* 802.11 MAC header (first 24 bytes of the payload for 3-address frames). */
typedef struct {
    uint8_t  frame_ctrl[2];   /* byte0: proto/type/subtype, byte1: flags (ToDS/FromDS ...) */
    uint8_t  duration[2];
    uint8_t  addr1[6];        /* RA / DA */
    uint8_t  addr2[6];        /* TA / SA */
    uint8_t  addr3[6];        /* BSSID / DA / SA depending on ToDS/FromDS */
    uint8_t  seq_ctrl[2];
} __attribute__((packed)) ieee80211_hdr_t;

/* Frame Control byte 1 flag bits. */
#define FCTL_TODS   (1 << 0)
#define FCTL_FROMDS (1 << 1)

static uint8_t          s_target_bssid[6];
static bool             s_running;
static wifi_sta_dev_t   s_devs[STA_SCAN_MAX_DEVS];
static int              s_dev_count;
static SemaphoreHandle_t s_lock;
static TaskHandle_t     s_timer_task;

static inline bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

/* Broadcast (FF:FF:...) or group/multicast (LSB of first octet set). */
static inline bool mac_is_group(const uint8_t *a)
{
    return (a[0] & 0x01) != 0;
}

static inline bool mac_is_zero(const uint8_t *a)
{
    static const uint8_t z[6] = {0};
    return memcmp(a, z, 6) == 0;
}

/* Insert / update a station MAC in the results table. cb context. */
static void add_station(const uint8_t *mac, int8_t rssi)
{
    if (mac_is_group(mac) || mac_is_zero(mac)) return;
    if (mac_eq(mac, s_target_bssid)) return;

    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return; /* never block WiFi task */

    for (int i = 0; i < s_dev_count; i++) {
        if (mac_eq(s_devs[i].mac, mac)) {
            s_devs[i].rssi = rssi;      /* refresh RSSI */
            xSemaphoreGive(s_lock);
            return;
        }
    }
    if (s_dev_count < STA_SCAN_MAX_DEVS) {
        memcpy(s_devs[s_dev_count].mac, mac, 6);
        s_devs[s_dev_count].rssi = rssi;
        s_dev_count++;
        ESP_LOGI(TAG, "STA " MACSTR " rssi=%d (total %d)",
                 MAC2STR(mac), rssi, s_dev_count);
    }
    xSemaphoreGive(s_lock);
}

/* Promiscuous RX callback — runs in the WiFi task context. */
static void promisc_rx(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    if (pkt->rx_ctrl.sig_len < sizeof(ieee80211_hdr_t)) return;

    const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)pkt->payload;
    const int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;

    const uint8_t flags = hdr->frame_ctrl[1];
    const bool to_ds   = (flags & FCTL_TODS)   != 0;
    const bool from_ds = (flags & FCTL_FROMDS) != 0;

    const uint8_t *bssid;   /* which address holds the BSSID */
    const uint8_t *sta;     /* which address holds the station */

    if (!to_ds && !from_ds) {
        /* IBSS / mgmt frames: addr3 = BSSID, addr1 = DA, addr2 = SA.
         * The station is whichever of DA/SA is not the AP BSSID. */
        bssid = hdr->addr3;
        if (!mac_eq(bssid, s_target_bssid)) return;
        /* addr2 (SA) is the transmitter; prefer it, else addr1 (DA). */
        if (!mac_eq(hdr->addr2, s_target_bssid)) sta = hdr->addr2;
        else                                     sta = hdr->addr1;
    } else if (to_ds && !from_ds) {
        /* STA -> AP: addr1 = BSSID, addr2 = STA(SA), addr3 = DA. */
        bssid = hdr->addr1;
        if (!mac_eq(bssid, s_target_bssid)) return;
        sta = hdr->addr2;
    } else if (!to_ds && from_ds) {
        /* AP -> STA: addr1 = STA(DA), addr2 = BSSID, addr3 = SA. */
        bssid = hdr->addr2;
        if (!mac_eq(bssid, s_target_bssid)) return;
        sta = hdr->addr1;
    } else {
        /* WDS (4-address) frame — no single STA/BSSID mapping; skip. */
        return;
    }

    add_station(sta, rssi);
}

/* Auto-stop task: waits duration_sec then stops the scan. */
static void duration_task(void *arg)
{
    uint32_t secs = (uint32_t)(uintptr_t)arg;
    vTaskDelay(pdMS_TO_TICKS(secs * 1000));
    s_timer_task = NULL;   /* clear before stop so stop() doesn't self-delete us */
    wifi_sta_scan_stop();
    vTaskDelete(NULL);
}

esp_err_t wifi_sta_scan_start(const uint8_t bssid[6], uint8_t channel, uint16_t duration_sec)
{
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (!bssid) return ESP_ERR_INVALID_ARG;

    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        if (!s_lock) return ESP_ERR_NO_MEM;
    }

    /* Clear results table. */
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(s_target_bssid, bssid, 6);
    s_dev_count = 0;
    memset(s_devs, 0, sizeof(s_devs));
    xSemaphoreGive(s_lock);

    esp_err_t err;

    err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) { ESP_LOGE(TAG, "set_promiscuous: %s", esp_err_to_name(err)); return err; }

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    err = esp_wifi_set_promiscuous_filter(&filter);
    if (err != ESP_OK) { ESP_LOGE(TAG, "set_filter: %s", esp_err_to_name(err)); goto fail; }

    err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) { ESP_LOGE(TAG, "set_channel: %s", esp_err_to_name(err)); goto fail; }

    err = esp_wifi_set_promiscuous_rx_cb(promisc_rx);
    if (err != ESP_OK) { ESP_LOGE(TAG, "set_rx_cb: %s", esp_err_to_name(err)); goto fail; }

    s_running = true;
    ESP_LOGI(TAG, "STA scan start: bssid=" MACSTR " ch=%d dur=%us",
             MAC2STR(bssid), channel, duration_sec);

    if (duration_sec > 0) {
        xTaskCreate(duration_task, "sta_scan_to", 2048,
                    (void *)(uintptr_t)duration_sec, 5, &s_timer_task);
    }
    return ESP_OK;

fail:
    esp_wifi_set_promiscuous(false);
    return err;
}

void wifi_sta_scan_stop(void)
{
    if (!s_running) return;
    s_running = false;

    /* If an auto-stop task is pending, cancel it. */
    if (s_timer_task) {
        TaskHandle_t t = s_timer_task;
        s_timer_task = NULL;
        vTaskDelete(t);
    }

    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);

    /* Restore normal STA mode so the WiFi link works afterward. */
    esp_wifi_set_mode(WIFI_MODE_STA);

    ESP_LOGI(TAG, "STA scan stopped (%d stations)", s_dev_count);
}

int wifi_sta_scan_get_results(wifi_sta_dev_t *out, int max)
{
    if (!out || max <= 0 || !s_lock) return 0;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    int n = s_dev_count < max ? s_dev_count : max;
    memcpy(out, s_devs, (size_t)n * sizeof(wifi_sta_dev_t));
    xSemaphoreGive(s_lock);
    return n;
}
