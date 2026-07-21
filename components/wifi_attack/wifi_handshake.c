/*
 * WPA 4-way handshake (EAPOL) capture — promiscuous-mode implementation.
 *
 * Sniffs 802.11 frames on the target AP's channel. Captures the AP beacon
 * once (crackers need the SSID) and every EAPOL-Key frame belonging to the
 * target BSSID, appending each raw 802.11 frame to a static PCAP buffer
 * (global header + per-frame records, LINKTYPE_IEEE802_11 = 105).
 *
 * EAPOL detection: a data frame whose payload after the 802.11 MAC header
 * (24B, +2B QoS if the subtype carries QoS) and LLC/SNAP (AA AA 03 00 00 00)
 * begins with ethertype 0x888E. The EAPOL-Key Information field is parsed to
 * classify messages M1..M4; capture is marked complete once M1+M2 (minimum)
 * up through M4 have been observed.
 */

#include "wifi_handshake.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "wifi_hs";

/* ---- Capture buffer (static, mutex-guarded, cb runs in WiFi task) ---- */
#define HS_BUF_SIZE 4096

/* ---- 802.11 frame parsing ---- */
#define FC0_TYPE_MASK      0x0C   /* frame_ctrl[0] bits 2-3: type   */
#define FC0_SUBTYPE_MASK   0xF0   /* frame_ctrl[0] bits 4-7: subtype */
#define FC0_TYPE_MGMT      0x00
#define FC0_TYPE_DATA      0x08
#define FC0_SUBTYPE_BEACON 0x80   /* mgmt subtype 8 << 4            */
#define FC0_QOS_BIT        0x80   /* data subtype bit that flags QoS */

#define FCTL_TODS   (1 << 0)
#define FCTL_FROMDS (1 << 1)

#define IEEE80211_HDR_LEN 24      /* 3-address MAC header            */
#define QOS_CTRL_LEN      2
#define LLC_SNAP_LEN      8       /* AA AA 03 00 00 00 <ethertype>  */
#define ETHERTYPE_EAPOL   0x888E

/* 802.11 MAC header (3-address). */
typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
} __attribute__((packed)) ieee80211_hdr_t;

/* PCAP global header (24 bytes). */
typedef struct {
    uint32_t magic;         /* 0xA1B2C3D4                */
    uint16_t version_major; /* 2                         */
    uint16_t version_minor; /* 4                         */
    int32_t  thiszone;      /* 0                         */
    uint32_t sigfigs;       /* 0                         */
    uint32_t snaplen;       /* 65535                     */
    uint32_t network;       /* 105 = LINKTYPE_IEEE802_11 */
} __attribute__((packed)) pcap_hdr_t;

/* PCAP per-packet record header (16 bytes). */
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed)) pcap_rec_t;

static uint8_t           s_target_bssid[6];
static bool              s_running;
static hs_state_t        s_state;
static SemaphoreHandle_t s_lock;

static uint8_t           s_buf[HS_BUF_SIZE];
static uint32_t          s_len;          /* bytes used in s_buf */
static bool              s_beacon_saved;
static uint8_t           s_msg_mask;     /* bit0=M1 bit1=M2 bit2=M3 bit3=M4 */

static inline bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

/* Append raw bytes to the buffer as a PCAP record. cb context; caller must
 * not hold blocking locks — takes the mutex non-blocking and drops on miss. */
static void pcap_append(const uint8_t *frame, uint16_t frame_len,
                        const wifi_pkt_rx_ctrl_t *rx)
{
    if (frame_len == 0) return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return; /* never block WiFi task */

    uint32_t need = sizeof(pcap_rec_t) + frame_len;
    if (s_len + need > HS_BUF_SIZE) {
        xSemaphoreGive(s_lock);
        return;                                       /* buffer full — drop */
    }

    pcap_rec_t rec = {
        .ts_sec   = (uint32_t)(rx->timestamp / 1000000U),
        .ts_usec  = (uint32_t)(rx->timestamp % 1000000U),
        .incl_len = frame_len,
        .orig_len = frame_len,
    };
    memcpy(&s_buf[s_len], &rec, sizeof(rec));
    s_len += sizeof(rec);
    memcpy(&s_buf[s_len], frame, frame_len);
    s_len += frame_len;

    xSemaphoreGive(s_lock);
}

/* Classify an EAPOL-Key message from its 2-byte Key Information field
 * (big-endian). Returns 1..4 for M1..M4, or 0 if not a pairwise key msg.
 *
 * Key Info bits: 0x0008 = Key Type (1=pairwise), 0x0080 = Key ACK,
 *                0x0100 = Key MIC,  0x0040 = Secure, 0x2000 = Key Data present.
 *   M1: pairwise, ACK=1, MIC=0, Secure=0
 *   M2: pairwise, ACK=0, MIC=1, Secure=0, has key data (RSN IE)
 *   M3: pairwise, ACK=1, MIC=1, Secure=1
 *   M4: pairwise, ACK=0, MIC=1, Secure=1, no key data
 */
static int eapol_classify(uint16_t key_info, uint16_t key_data_len)
{
    const bool pairwise = (key_info & 0x0008) != 0;
    if (!pairwise) return 0;
    const bool ack    = (key_info & 0x0080) != 0;
    const bool mic    = (key_info & 0x0100) != 0;
    const bool secure = (key_info & 0x0040) != 0;

    if (ack && !mic)            return 1;                 /* M1 */
    if (!ack && mic && !secure) return 2;                 /* M2 */
    if (ack && mic && secure)   return 3;                 /* M3 */
    if (!ack && mic && secure)  return (key_data_len == 0) ? 4 : 3;
    return 0;
}

/* Promiscuous RX callback — runs in the WiFi task context. No blocking. */
static void promisc_rx(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    if (!s_running) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < IEEE80211_HDR_LEN) return;

    const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)pkt->payload;
    const uint8_t fc0   = hdr->frame_ctrl[0];
    const uint8_t flags = hdr->frame_ctrl[1];

    /* Frame must involve the target BSSID (any of the 3 addresses). */
    const bool bssid_match = mac_eq(hdr->addr1, s_target_bssid) ||
                             mac_eq(hdr->addr2, s_target_bssid) ||
                             mac_eq(hdr->addr3, s_target_bssid);
    if (!bssid_match) return;

    const uint8_t ftype = fc0 & FC0_TYPE_MASK;

    /* Beacon: capture once for the SSID. */
    if (ftype == FC0_TYPE_MGMT) {
        if (!s_beacon_saved && (fc0 & FC0_SUBTYPE_MASK) == FC0_SUBTYPE_BEACON) {
            pcap_append(pkt->payload, len, &pkt->rx_ctrl);
            s_beacon_saved = true;
        }
        return;
    }

    if (ftype != FC0_TYPE_DATA) return;

    /* Compute 802.11 header length (QoS data carries a 2-byte QoS field). */
    uint16_t hdrlen = IEEE80211_HDR_LEN;
    if (fc0 & FC0_QOS_BIT) hdrlen += QOS_CTRL_LEN;   /* QoS-data subtypes */

    /* Need LLC/SNAP + at least the EAPOL header for classification. */
    if (len < hdrlen + LLC_SNAP_LEN) return;

    const uint8_t *llc = pkt->payload + hdrlen;
    static const uint8_t snap[6] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00 };
    if (memcmp(llc, snap, 6) != 0) return;

    const uint16_t ethertype = ((uint16_t)llc[6] << 8) | llc[7];
    if (ethertype != ETHERTYPE_EAPOL) return;

    /* EAPOL frame — capture it. */
    pcap_append(pkt->payload, len, &pkt->rx_ctrl);

    /* Parse the EAPOL-Key body to classify M1..M4.
     * EAPOL header (4B): version, type, length(2B). type 3 = EAPOL-Key.
     * EAPOL-Key body: descriptor(1B), key_info(2B, BE), key_len(2B) ...
     * key_data_len is the last 2 bytes of the 95-byte key descriptor. */
    const uint8_t *eapol = llc + LLC_SNAP_LEN;
    const uint16_t eapol_avail = len - (hdrlen + LLC_SNAP_LEN);
    if (eapol_avail < 4 + 3) return;
    const uint8_t eapol_type = eapol[1];             /* 3 = Key */
    if (eapol_type != 3) return;

    const uint16_t key_info = ((uint16_t)eapol[5] << 8) | eapol[6];
    uint16_t key_data_len = 0;
    /* Key Data Length lives at offset 4(EAPOL hdr)+93..94 within the frame. */
    if (eapol_avail >= 4 + 95) {
        key_data_len = ((uint16_t)eapol[4 + 93] << 8) | eapol[4 + 94];
    }

    const int msg = eapol_classify(key_info, key_data_len);
    if (msg >= 1 && msg <= 4) {
        s_msg_mask |= (uint8_t)(1u << (msg - 1));
        ESP_LOGI(TAG, "EAPOL M%d captured (mask=0x%X, len=%u)",
                 msg, s_msg_mask, (unsigned)s_len);
    }

    /* Complete when the full handshake (M1..M4) is seen, or at minimum the
     * PTK-deriving pair M1+M2 has been captured. */
    if ((s_msg_mask & 0x0F) == 0x0F) {
        s_state = HS_COMPLETE;
    } else if ((s_msg_mask & 0x03) == 0x03 && s_state == HS_CAPTURING) {
        s_state = HS_COMPLETE;   /* M1+M2 sufficient for a crack attempt */
    }
}

esp_err_t wifi_handshake_start(const uint8_t bssid[6], uint8_t channel)
{
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (!bssid) return ESP_ERR_INVALID_ARG;

    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        if (!s_lock) return ESP_ERR_NO_MEM;
    }

    /* Reset capture state and write the PCAP global header. */
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(s_target_bssid, bssid, 6);
    s_beacon_saved = false;
    s_msg_mask     = 0;
    s_len          = 0;

    pcap_hdr_t gh = {
        .magic         = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = 65535,
        .network       = 105,   /* LINKTYPE_IEEE802_11 */
    };
    memcpy(&s_buf[0], &gh, sizeof(gh));
    s_len = sizeof(gh);
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

    s_state   = HS_CAPTURING;
    s_running = true;
    ESP_LOGI(TAG, "Handshake capture start: bssid=" MACSTR " ch=%d",
             MAC2STR(bssid), channel);
    return ESP_OK;

fail:
    esp_wifi_set_promiscuous(false);
    return err;
}

void wifi_handshake_stop(void)
{
    if (!s_running) return;
    s_running = false;

    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);

    /* Restore normal STA mode so the WiFi link works afterward. */
    esp_wifi_set_mode(WIFI_MODE_STA);

    if (s_state == HS_CAPTURING) s_state = HS_IDLE;
    ESP_LOGI(TAG, "Handshake capture stopped (mask=0x%X, %u bytes)",
             s_msg_mask, (unsigned)s_len);
}

hs_state_t wifi_handshake_state(void)
{
    return s_state;
}

uint32_t wifi_handshake_len(void)
{
    if (!s_lock) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t n = s_len;
    xSemaphoreGive(s_lock);
    return n;
}

int wifi_handshake_read(uint32_t offset, uint8_t *out, uint16_t max)
{
    if (!out || max == 0 || !s_lock) return 0;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    int n = 0;
    if (offset < s_len) {
        uint32_t avail = s_len - offset;
        n = (avail < max) ? (int)avail : (int)max;
        memcpy(out, &s_buf[offset], (size_t)n);
    }
    xSemaphoreGive(s_lock);
    return n;
}
