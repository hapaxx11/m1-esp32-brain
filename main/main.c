/*
 * M1 ESP32-C6 Network Coprocessor — main entry point
 *
 * Architecture:
 *   M1 (STM32H573) = SPI MASTER, device controller
 *   ESP32-C6       = SPI SLAVE  (spi_slave_hd), network coprocessor
 *
 * M1 sends binary m1_rpc REQ frames over SPI. ESP32 executes WiFi/BLE/Zigbee
 * operations natively and returns RESP/NAK, or pushes EVENT frames for async
 * data (scan done, captured packets). Complex operations (Bad-BT scripts,
 * deauth loops, captive portals) run autonomously on the ESP32.
 *
 * Also runs a TCP RPC server for qMonstatek — screen frames pushed by the M1
 * are cached and forwarded, no AT+CIPSEND bottleneck.
 *
 * Wire protocol: components/m1_rpc/include/m1_rpc.h (0x4D31 binary frames).
 */

#include "m1_link.h"
#include "wifi_manager.h"
#include "wifi_attack.h"
#include "wifi_sta_scan.h"
#include "wifi_handshake.h"
#include "rpc_server.h"
#include "ble_hid.h"
#include "ble_scan.h"
#include "ble_conn.h"
#include "ble_spam.h"
#include "ble_nus.h"
#include "ieee802154_sniff.h"
#include "esp_now_link.h"
#include "m1_rpc.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_system.h"
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "main";

/* This firmware's identity + honest capability set (only features actually wired).
 * Every bit below has a working handler in dispatch_request(); do not advertise a
 * capability whose handler still returns NAK (PMKID/OTA/SET_MAC/SET_CHAN/NETSCAN
 * /BLE_GATT are intentionally omitted until implemented). */
#define M1_FW_NAME  "m1-native"
#define M1_FW_CAPS  (M1_CAP_WIFI_SCAN | M1_CAP_WIFI_JOIN | M1_CAP_DEAUTH   | \
                     M1_CAP_PKTMON    | M1_CAP_STA_SCAN  | M1_CAP_BEACON   | \
                     M1_CAP_PORTAL    | M1_CAP_HANDSHAKE | M1_CAP_802154   | \
                     M1_CAP_BLE_SCAN  | M1_CAP_BLE_ADV   | M1_CAP_BLE_HID  | \
                     M1_CAP_BLE_SPAM  | M1_CAP_802154_TX | M1_CAP_PROBE_FLOOD | \
                     M1_CAP_KARMA     | M1_CAP_SOFTAP)

/* Max scan-response payload; fragmented across frames, fits the M1's 2KB
 * reassembly buffer. (Handshake uses chunked reads, not this.) */
#define M1_SCAN_RESP_MAX  1800

static void dispatch_request(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t payload_len);

/* 802.15.4 sniff handlers are defined below dispatch_request (which calls them) */
static void handle_zb_sniff_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len);
static void handle_zb_sniff_stop(const m1_rpc_header_t *hdr);
static void handle_zb_sniff_get(const m1_rpc_header_t *hdr);
static void handle_zb_flood_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len);
static void handle_zb_inject(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t len);

/* ESP-NOW peer-link handlers (defined below dispatch_request) */
static void handle_now_start(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t len);
static void handle_now_peers_get(const m1_rpc_header_t *hdr);
static void handle_now_send(const m1_rpc_header_t *hdr,
                            const uint8_t *payload, uint16_t len);
static void handle_now_recv_get(const m1_rpc_header_t *hdr);

static uint8_t s_rx_buf[M1_RPC_DMA_MAX_LEN];

/* NimBLE has one legacy advertising procedure. Bluetooth Direct (NUS) and
 * Bad-BT (HID) therefore cannot both own it. Keep the user's Direct setting
 * as intent so it resumes after Bad-BT stops instead of competing every few
 * seconds in GAP ADV_COMPLETE callbacks. */
static bool s_ble_direct_enabled = false;
static bool s_ble_direct_restore_after_hid = false;

/* ---------- Frame send helpers (ESP32 -> M1) ---------- */

static void send_frame(m1_rpc_msgtype_t type, uint16_t msg_id,
                       const uint8_t *payload, uint16_t payload_len)
{
    /* Fragments automatically if payload exceeds one transaction. */
    m1_link_send_msg((uint8_t)type, msg_id, payload, payload_len, 1000);
}

/* Success response — payload is the data; msg_id echoes the request. */
static inline void send_resp(uint16_t msg_id, const uint8_t *payload, uint16_t len)
{
    send_frame(M1_RPC_RESP, msg_id, payload, len);
}

/* Error response — payload is a single status byte; msg_id echoes the request. */
static inline void send_nak(uint16_t msg_id, m1_rpc_status_t status)
{
    uint8_t s = (uint8_t)status;
    send_frame(M1_RPC_NAK, msg_id, &s, 1);
}

/* Async notification (ESP32 -> M1). */
static inline void send_event(uint16_t evt_id, const uint8_t *payload, uint16_t len)
{
    send_frame(M1_RPC_EVENT, evt_id, payload, len);
}

/* ---------- Command dispatch task ---------- */

static void cmd_dispatch_task(void *arg)
{
    ESP_LOGI(TAG, "Command dispatch task started");

    while (1) {
        int n = m1_link_receive(s_rx_buf, sizeof(s_rx_buf), 100);
        if (n <= 0) continue;

        m1_rpc_header_t hdr;
        const uint8_t *payload;
        uint16_t payload_len;

        if (m1_rpc_parse(s_rx_buf, n, &hdr, &payload, &payload_len) != 0) {
            continue;  /* bad magic/crc/length — skip */
        }
        /* We only act on requests; ignore anything the M1 echoes back. */
        if (hdr.msg_type != M1_RPC_REQ) continue;

        dispatch_request(&hdr, payload, payload_len);
    }
}

/* ---------- System handlers ---------- */

static void handle_get_status(const m1_rpc_header_t *hdr)
{
    m1_rpc_devstatus_t st = {0};
    st.proto_ver = M1_RPC_VERSION;
    m1_rpc_caps_set(st.cap_bitmap, M1_FW_CAPS);
    strncpy(st.fw_name, M1_FW_NAME, sizeof(st.fw_name) - 1);
    send_resp(hdr->msg_id, (const uint8_t *)&st, sizeof(st));
}

static void handle_fw_version(const m1_rpc_header_t *hdr)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    m1_rpc_fw_version_t v = {0};
    v.major = 1; v.minor = 3; v.patch = 0;
    /* Expose PROJECT_VER via the git_hash slot only when it's a distinct build
     * tag — if it equals the semver, leave it blank so the device info shows
     * "m1_link 1.0.0" instead of a redundant "1.0.0 1.0.0". */
    char sem[16];
    snprintf(sem, sizeof(sem), "%d.%d.%d", v.major, v.minor, v.patch);
    if (strcmp(desc->version, sem) != 0)
        strncpy(v.git_hash, desc->version, sizeof(v.git_hash) - 1);
    send_resp(hdr->msg_id, (const uint8_t *)&v, sizeof(v));
}

/* NTP time sync — WiFi must be connected. Blocks up to 5s for the first sync,
 * returns UTC time. Replaces the legacy AT+CIPSNTP path on the M1. */
static void handle_sntp_sync(const m1_rpc_header_t *hdr)
{
    if (!wifi_mgr_is_connected()) {
        send_nak(hdr->msg_id, M1_RPC_ERR_NOT_RUNNING);
        return;
    }

    esp_netif_sntp_deinit();   /* clear any prior instance (safe if none) */
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    if (esp_netif_sntp_init(&cfg) != ESP_OK) {
        send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
        return;
    }

    esp_err_t err = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(5000));
    if (err != ESP_OK) {
        esp_netif_sntp_deinit();
        send_nak(hdr->msg_id, M1_RPC_ERR_TIMEOUT);
        return;
    }

    time_t now = 0;
    struct tm tmv = {0};
    time(&now);
    gmtime_r(&now, &tmv);
    esp_netif_sntp_deinit();

    m1_rpc_time_t t = {
        .year    = (uint16_t)(tmv.tm_year + 1900),
        .month   = (uint8_t)(tmv.tm_mon + 1),
        .day     = (uint8_t)tmv.tm_mday,
        .hour    = (uint8_t)tmv.tm_hour,
        .minute  = (uint8_t)tmv.tm_min,
        .second  = (uint8_t)tmv.tm_sec,
        .weekday = (uint8_t)tmv.tm_wday,
    };
    send_resp(hdr->msg_id, (const uint8_t *)&t, sizeof(t));
}

/* ---------- WiFi handlers ---------- */

static void handle_wifi_scan(const m1_rpc_header_t *hdr)
{
    wifi_scan_config_t scan_cfg = { .show_hidden = true };
    if (esp_wifi_scan_start(&scan_cfg, true) != ESP_OK) {
        send_nak(hdr->msg_id, M1_RPC_ERR_BUSY);
        return;
    }

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    wifi_ap_record_t *records = NULL;
    if (count > 0) {
        records = malloc(count * sizeof(wifi_ap_record_t));
        if (records) esp_wifi_scan_get_ap_records(&count, records);
        /* On malloc failure the driver's internal AP list is still held; free it
         * explicitly (esp_wifi_scan_get_ap_records would have) so it doesn't leak
         * every scan under memory pressure. */
        else { esp_wifi_clear_ap_list(); count = 0; }
    }

    /* Payload: [count:2 LE] then per AP: m1_rpc_scan_entry_t + ssid bytes */
    uint8_t *resp = malloc(M1_RPC_MAX_PAYLOAD);
    if (!resp) { free(records); send_nak(hdr->msg_id, M1_RPC_ERR_NO_MEM); return; }

    uint16_t off = 0;
    resp[off++] = (uint8_t)(count & 0xFF);
    resp[off++] = (uint8_t)(count >> 8);

    /* Capped to M1_SCAN_RESP_MAX; fragmented across frames by m1_link. */
    for (int i = 0; i < count; i++) {
        uint8_t ssid_len = (uint8_t)strnlen((char *)records[i].ssid, 32);
        if (off + sizeof(m1_rpc_scan_entry_t) + ssid_len > M1_SCAN_RESP_MAX) break;
        m1_rpc_scan_entry_t e;
        memcpy(e.bssid, records[i].bssid, 6);
        e.rssi     = records[i].rssi;
        e.channel  = records[i].primary;
        e.authmode = (uint8_t)records[i].authmode;
        e.ssid_len = ssid_len;
        memcpy(&resp[off], &e, sizeof(e)); off += sizeof(e);
        memcpy(&resp[off], records[i].ssid, ssid_len); off += ssid_len;
    }

    free(records);
    send_resp(hdr->msg_id, resp, off);
    free(resp);
}

static void handle_wifi_connect(const m1_rpc_header_t *hdr,
                                const uint8_t *payload, uint16_t len)
{
    /* connect_req: [ssid_len:1][ssid][pwd_len:1][pwd] (bssid/chan/auth optional) */
    if (len < 2) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    uint8_t ssid_len = payload[0];
    if ((size_t)1 + ssid_len + 1 > len) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    uint8_t pwd_len = payload[1 + ssid_len];
    if ((size_t)2 + ssid_len + pwd_len > len) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }

    /* Requested SSID as a C string for the idempotency check below. */
    char ssid_str[33] = {0};
    memcpy(ssid_str, &payload[1], ssid_len < 32 ? ssid_len : 32);

    /* Idempotent connect: if we're already associated to the requested SSID,
     * return the current IP without tearing the link down. If associated to a
     * DIFFERENT SSID, disconnect + settle first so the new association is clean. */
    if (wifi_mgr_is_connected()) {
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK &&
            strncmp((char *)ap.ssid, ssid_str, 32) == 0) {
            uint8_t resp[5] = {0};
            resp[0] = M1_RPC_OK;
            esp_netif_ip_info_t info;
            esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            if (sta && esp_netif_get_ip_info(sta, &info) == ESP_OK) {
                memcpy(&resp[1], &info.ip.addr, 4);
            }
            send_resp(hdr->msg_id, resp, sizeof(resp));
            return;
        }
        /* Different SSID — drop the current link before re-associating. */
        wifi_mgr_disconnect();
        vTaskDelay(pdMS_TO_TICKS(300));
    }

    wifi_config_t cfg = {0};
    memcpy(cfg.sta.ssid, &payload[1], ssid_len);
    memcpy(cfg.sta.password, &payload[2 + ssid_len], pwd_len);
    /* channel 0 = don't pin; scan EVERY channel and, for a mesh SSID that lives
     * on multiple channels (e.g. 6 and 11), connect to the strongest AP. This
     * also undoes any channel pin left by ESP-NOW/peer-link or the monitor-mode
     * attack features — without it, connect stays stuck on their channel and
     * times out whenever the AP is elsewhere. */
    cfg.sta.channel     = 0;
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    cfg.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

    /* Put the radio back in a clean STA state before associating, so a prior
     * feature that pinned the channel / enabled monitor mode can't block us.
     * PRESERVE a running SoftAP: if the WiFi Hotspot is up (AP/APSTA), use APSTA
     * so joining a network doesn't tear the hotspot down — and so NAT can bridge
     * hotspot clients out to this upstream link. */
    esp_wifi_set_promiscuous(false);
    wifi_mode_t cur_mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&cur_mode);
    esp_wifi_set_mode((cur_mode == WIFI_MODE_AP || cur_mode == WIFI_MODE_APSTA)
                      ? WIFI_MODE_APSTA : WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &cfg);

    /* Kick off the association ASYNCHRONOUSLY and answer immediately. Blocking
     * here (as wifi_mgr_connect() did) froze this single cmd_dispatch task for the
     * whole ~12-15s association: no screen frames, no qMonstatek relay poll got
     * serviced, and the M1 held the shared SPI link mutex the entire time — which
     * wedged screen-sharing. resp[0]=OK now means "connect started"; the M1 polls
     * WIFI_GET_STATUS for the actual result (that response carries the IP). */
    esp_err_t err = wifi_mgr_connect_async();
    uint8_t resp[5] = {0};
    resp[0] = (err == ESP_OK) ? M1_RPC_OK : M1_RPC_ERR_TIMEOUT;
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

static void handle_wifi_status(const m1_rpc_header_t *hdr)
{
    uint8_t resp[5] = {0};
    resp[0] = wifi_mgr_is_connected() ? 1 : 0;
    if (resp[0]) {
        esp_netif_ip_info_t info;
        esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta && esp_netif_get_ip_info(sta, &info) == ESP_OK) {
            memcpy(&resp[1], &info.ip.addr, 4);
        }
    }
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

/* ---------- Offensive WiFi ---------- */

static void handle_deauth_start(const m1_rpc_header_t *hdr,
                                const uint8_t *payload, uint16_t len)
{
    /* m1_rpc_deauth_req_t: bssid[6], channel, station[6], count:2, interval_ms:2 */
    if (len < sizeof(m1_rpc_deauth_req_t)) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    const m1_rpc_deauth_req_t *req = (const m1_rpc_deauth_req_t *)payload;

    wifi_attack_deauth_config_t cfg;
    memcpy(cfg.ap_mac, req->bssid, 6);
    memcpy(cfg.target_mac, req->station, 6);
    cfg.channel     = req->channel;
    cfg.count       = req->count;
    cfg.interval_ms = req->interval_ms ? req->interval_ms : 10;

    wifi_attack_deauth_start(&cfg);
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

static void handle_deauth_stop(const m1_rpc_header_t *hdr)
{
    wifi_attack_deauth_stop();
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

/* Beacon spam: payload [count:1] then per SSID [len:1][ssid] */
static void handle_beacon_start(const m1_rpc_header_t *hdr,
                                const uint8_t *payload, uint16_t len)
{
    if (len < 1) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    wifi_attack_beacon_config_t cfg = {0};
    uint8_t count = payload[0];
    uint16_t off = 1;
    int j = 0;
    for (int i = 0; i < count && j < 32; i++) {
        if (off >= len) break;
        uint8_t l = payload[off++];
        if ((uint16_t)(off + l) > len) break;
        uint8_t cl = l < 32 ? l : 32;
        memcpy(cfg.ssids[j], &payload[off], cl);
        cfg.ssids[j][cl] = 0;
        off += l;
        j++;
    }
    cfg.ssid_count = (uint8_t)j;
    cfg.channel = 1;
    cfg.interval_ms = 0;
    if (j == 0) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t err = wifi_attack_beacon_start(&cfg);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Probe-request flood. Payload: [channel:1][count:1] then [len:1][ssid] x count
 * (count 0 = wildcard broadcast probes). */
static void handle_probe_start(const m1_rpc_header_t *hdr,
                               const uint8_t *payload, uint16_t len)
{
    uint8_t channel = (len >= 1) ? payload[0] : 1;
    uint8_t count   = (len >= 2) ? payload[1] : 0;
    static char ssids[16][33];
    uint16_t off = 2;
    int j = 0;
    for (int i = 0; i < count && j < 16; i++) {
        if (off >= len) break;
        uint8_t l = payload[off++];
        if ((uint16_t)(off + l) > len) break;
        uint8_t cl = l < 32 ? l : 32;
        memcpy(ssids[j], &payload[off], cl);
        ssids[j][cl] = 0;
        off += l;
        j++;
    }
    esp_err_t err = wifi_attack_probe_start((const char (*)[33])ssids, (uint8_t)j, channel);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Karma auto-responder. Payload: [channel:1]. */
static void handle_karma_start(const m1_rpc_header_t *hdr,
                               const uint8_t *payload, uint16_t len)
{
    uint8_t channel = (len >= 1) ? payload[0] : 1;
    esp_err_t err = wifi_attack_karma_start(channel);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Raw 802.11 injection. Payload: [channel:1][raw 802.11 frame...]. */
static void handle_raw_tx(const m1_rpc_header_t *hdr,
                          const uint8_t *payload, uint16_t len)
{
    if (len < 11) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t err = wifi_attack_raw_tx(payload[0], &payload[1], (size_t)(len - 1));
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Station (client) scan for a target AP */
static void handle_sta_scan_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len)
{
    /* payload: [bssid:6][channel:1][dur:1] */
    if (len < 8) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t err = wifi_sta_scan_start(payload, payload[6], payload[7]);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Handshake (EAPOL) capture */
static void handle_hs_start(const m1_rpc_header_t *hdr,
                            const uint8_t *payload, uint16_t len)
{
    /* payload: [bssid:6][channel:1][deauth_count:2] */
    if (len < 9) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t err = wifi_handshake_start(payload, payload[6]);
    if (err != ESP_OK) { send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE); return; }

    uint16_t deauth_count = payload[7] | (payload[8] << 8);
    if (deauth_count) {
        /* Force clients to reconnect so we catch the handshake. */
        wifi_attack_deauth_config_t cfg;
        memcpy(cfg.ap_mac, payload, 6);
        memset(cfg.target_mac, 0xFF, 6);   /* broadcast */
        cfg.channel = payload[6];
        cfg.count = deauth_count;
        cfg.interval_ms = 100;
        wifi_attack_deauth_start(&cfg);
    }
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

static void handle_hs_status(const m1_rpc_header_t *hdr)
{
    uint8_t resp[5];
    resp[0] = (uint8_t)wifi_handshake_state();
    uint32_t total = wifi_handshake_len();
    memcpy(&resp[1], &total, 4);
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

static void handle_hs_get(const m1_rpc_header_t *hdr,
                          const uint8_t *payload, uint16_t len)
{
    if (len < 6) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    uint32_t offset = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);
    uint16_t want = payload[4] | (payload[5] << 8);
    if (want > M1L_PAYLOAD_MAX) want = M1L_PAYLOAD_MAX;
    static uint8_t chunk[M1L_PAYLOAD_MAX];
    int n = wifi_handshake_read(offset, chunk, want);
    send_resp(hdr->msg_id, chunk, n > 0 ? (uint16_t)n : 0);
}

static void handle_sta_scan_results(const m1_rpc_header_t *hdr)
{
    static wifi_sta_dev_t stas[32];
    int cnt = wifi_sta_scan_get_results(stas, 32);
    uint8_t resp[2 + 32 * 7];
    uint16_t off = 2, filled = 0;
    for (int i = 0; i < cnt && off + 7 <= (int)sizeof(resp); i++) {
        memcpy(&resp[off], stas[i].mac, 6); off += 6;
        resp[off++] = (uint8_t)stas[i].rssi;
        filled++;
    }
    resp[0] = (uint8_t)(filled & 0xFF);
    resp[1] = (uint8_t)(filled >> 8);
    send_resp(hdr->msg_id, resp, off);
}

/* ---------- Packet Monitor ---------- */

static void handle_monitor_start(const m1_rpc_header_t *hdr,
                                 const uint8_t *payload, uint16_t len)
{
    /* payload: [channel:1][band:1]. channel 0 => hop 1-13. RPC path pulls
     * frames via MONITOR_READ, so no push callback is registered. */
    uint8_t channel = len >= 1 ? payload[0] : 0;
    esp_err_t err = channel == 0
                        ? wifi_attack_monitor_hop_start(250, NULL)
                        : wifi_attack_monitor_start(channel, NULL);
    /* Always RESP with the raw esp_err (LE int32, 0 = OK) so the M1 can report
     * the precise failure reason instead of a generic NAK. */
    uint8_t resp[4];
    memcpy(resp, &err, 4);
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

static void handle_monitor_stop(const m1_rpc_header_t *hdr)
{
    wifi_attack_monitor_stop();
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

static void handle_monitor_stats(const m1_rpc_header_t *hdr)
{
    uint32_t total = 0, dropped = 0; uint8_t buffered = 0;
    wifi_attack_monitor_stats(&total, &dropped, &buffered);
    uint8_t resp[9];
    memcpy(&resp[0], &total, 4);
    memcpy(&resp[4], &dropped, 4);
    resp[8] = buffered;
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

static void handle_monitor_read(const m1_rpc_header_t *hdr)
{
    /* RESP [ch:1][rssi:i8][len:2][frame], or empty when nothing is buffered. */
    uint8_t resp[4 + 256];
    int8_t rssi = 0; uint8_t ch = 0;
    uint16_t n = wifi_attack_monitor_read(&resp[4], 256, &rssi, &ch);
    if (n == 0) { send_resp(hdr->msg_id, NULL, 0); return; }
    resp[0] = ch;
    resp[1] = (uint8_t)rssi;
    resp[2] = (uint8_t)(n & 0xFF);
    resp[3] = (uint8_t)(n >> 8);
    send_resp(hdr->msg_id, resp, (uint16_t)(4 + n));
}

/* ---------- Captive Portal ---------- */

static void handle_captive_start(const m1_rpc_header_t *hdr,
                                 const uint8_t *payload, uint16_t len)
{
    /* payload: [channel:1][ssid_len:1][ssid][title(rest, optional)] */
    if (len < 2) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    wifi_attack_captive_config_t cfg = {0};
    cfg.channel = payload[0];
    uint8_t slen = payload[1];
    if ((uint16_t)(2 + slen) > len || slen == 0 || slen > 32) {
        send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return;
    }
    memcpy(cfg.ssid, &payload[2], slen);
    cfg.ssid[slen] = 0;
    uint16_t toff = 2 + slen;
    if (toff < len) {
        uint16_t tlen = len - toff;
        if (tlen > sizeof(cfg.portal_title) - 1) tlen = sizeof(cfg.portal_title) - 1;
        memcpy(cfg.portal_title, &payload[toff], tlen);
        cfg.portal_title[tlen] = 0;
    }
    esp_err_t err = wifi_attack_captive_start(&cfg);
    /* Always RESP with the raw esp_err (LE int32, 0 = OK). */
    uint8_t resp[4];
    memcpy(resp, &err, 4);
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

static void handle_captive_stop(const m1_rpc_header_t *hdr)
{
    wifi_attack_captive_stop();
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

static void handle_captive_diag(const m1_rpc_header_t *hdr)
{
    uint32_t dns_q = 0, http_hits = 0; uint8_t clients = 0;
    char lastpost[96] = {0};
    wifi_attack_captive_diag(&dns_q, &http_hits, &clients, lastpost, sizeof(lastpost));
    uint8_t resp[9 + 96];
    memcpy(&resp[0], &dns_q, 4);
    memcpy(&resp[4], &http_hits, 4);
    resp[8] = clients;
    int pl = (int)strnlen(lastpost, sizeof(lastpost));
    memcpy(&resp[9], lastpost, pl);
    send_resp(hdr->msg_id, resp, (uint16_t)(9 + pl));
}

static void handle_captive_creds(const m1_rpc_header_t *hdr)
{
    /* RESP [count:1] then per cred [ts:4][ulen:1][user][plen:1][pass] */
    static wifi_attack_credential_t creds[32];
    int cnt = wifi_attack_captive_get_creds(creds, 32);
    uint8_t resp[M1L_PAYLOAD_MAX];
    uint16_t off = 1;
    uint8_t emitted = 0;
    for (int i = 0; i < cnt; i++) {
        uint8_t ul = (uint8_t)strnlen(creds[i].username, sizeof(creds[i].username));
        uint8_t pl = (uint8_t)strnlen(creds[i].password, sizeof(creds[i].password));
        if (off + 4 + 1 + ul + 1 + pl > sizeof(resp)) break;
        memcpy(&resp[off], &creds[i].timestamp, 4); off += 4;
        resp[off++] = ul; memcpy(&resp[off], creds[i].username, ul); off += ul;
        resp[off++] = pl; memcpy(&resp[off], creds[i].password, pl); off += pl;
        emitted++;
    }
    resp[0] = emitted;
    send_resp(hdr->msg_id, resp, off);
}

/* ---------- BLE HID (native NimBLE — BadBT) ---------- */

static void handle_ble_hid_init(const m1_rpc_header_t *hdr,
                                const uint8_t *payload, uint16_t len)
{
    char name[32] = "M1-BadBT";
    if (len > 0) {
        uint16_t n = len < sizeof(name) - 1 ? len : sizeof(name) - 1;
        memcpy(name, payload, n);
        name[n] = 0;
    }

    /* NimBLE provides one legacy advertising slot.  Every other advertiser
     * keeps its own restart callback, so merely stopping the currently visible
     * packet is insufficient: its callback can claim the slot again a moment
     * later.  Disable every competing owner's intent before Bad-BT starts. */
    s_ble_direct_restore_after_hid = s_ble_direct_enabled;
    if (s_ble_direct_enabled)
        ble_nus_adv_stop();
    ble_adv_stop();
    ble_spam_stop();
    esp_err_t err = ble_hid_start(name);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

static void handle_ble_hid_key(const m1_rpc_header_t *hdr,
                               const uint8_t *payload, uint16_t len)
{
    /* m1_rpc_hid_key_t: [modifier:1][key_count:1][keys...] */
    if (len < 2) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    uint8_t modifier = payload[0];
    uint8_t count = payload[1];
    if ((uint16_t)(2 + count) > len) count = (uint8_t)(len - 2);
    esp_err_t err = ble_hid_send_key(modifier, &payload[2], count);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_NOT_RUNNING);
}

static void handle_ble_hid_status(const m1_rpc_header_t *hdr)
{
    /* bit 0 = link established; bit 1 = encrypted HID input is subscribed. */
    uint8_t status = (ble_hid_is_connected() ? 0x01 : 0x00) |
                     (ble_hid_is_ready()     ? 0x02 : 0x00);
    send_resp(hdr->msg_id, &status, 1);
}

/* ---------- BLE scan (native NimBLE central) ---------- */

static void handle_ble_scan_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len)
{
    uint16_t dur = 3;                       /* seconds; default 3 */
    if (len >= 1) dur = payload[0];
    if (len >= 2) dur = payload[0] | (payload[1] << 8);
    esp_err_t err = ble_scan_start(dur);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

static void handle_ble_scan_results(const m1_rpc_header_t *hdr)
{
    static ble_scan_dev_t devs[32];
    int cnt = ble_scan_get_results(devs, 32);

    /* Payload: [count:2 LE] then per dev: addr[6], addr_type, rssi(i8),
     * name_len, name[name_len]. Cap to one m1_link frame (no frag yet). */
    /* Allocate the full RPC payload (fragmented across frames by m1_link), matching
     * the M1_SCAN_RESP_MAX cap used below. The previous M1L_PAYLOAD_MAX (502) alloc
     * was smaller than the 1800-byte cap, so many/long-named BLE advertisers (names
     * are attacker-controlled) overflowed the heap. Mirrors handle_wifi_scan. */
    uint8_t *resp = malloc(M1_RPC_MAX_PAYLOAD);
    if (!resp) { send_nak(hdr->msg_id, M1_RPC_ERR_NO_MEM); return; }
    uint16_t off = 2, filled = 0;
    for (int i = 0; i < cnt; i++) {
        uint8_t nl = (uint8_t)strnlen(devs[i].name, sizeof(devs[i].name));
        if (off + 6 + 1 + 1 + 1 + nl > M1_SCAN_RESP_MAX) break;
        memcpy(&resp[off], devs[i].addr, 6); off += 6;
        resp[off++] = devs[i].addr_type;
        resp[off++] = (uint8_t)devs[i].rssi;
        resp[off++] = nl;
        memcpy(&resp[off], devs[i].name, nl); off += nl;
        filled++;
    }
    resp[0] = (uint8_t)(filled & 0xFF);
    resp[1] = (uint8_t)(filled >> 8);
    send_resp(hdr->msg_id, resp, off);
    free(resp);
}

/* ---------- BLE connect / advertise (native NimBLE) ---------- */

static void handle_ble_connect(const m1_rpc_header_t *hdr,
                               const uint8_t *payload, uint16_t len)
{
    /* payload: [addr:6][addr_type:1] */
    if (len < 7) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t err = ble_conn_connect(payload, payload[6], 8000);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_TIMEOUT);
}

static void handle_ble_advertise(const m1_rpc_header_t *hdr,
                                 const uint8_t *payload, uint16_t len)
{
    char name[32] = "M1-BLE";
    if (len > 0) {
        uint16_t n = len < sizeof(name) - 1 ? len : sizeof(name) - 1;
        memcpy(name, payload, n);
        name[n] = 0;
    }
    esp_err_t err = ble_adv_start(name);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* ---------- BLE spam (proximity-pair popup flooder) ---------- */

static void handle_ble_spam_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len)
{
    uint8_t mode = (len >= 1) ? payload[0] : BLE_SPAM_MODE_ALL;
    esp_err_t err = ble_spam_start(mode);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Bluetooth Direct: start/stop advertising the NUS RPC service (M1 toggle). */
static void handle_ble_rpc_adv(const m1_rpc_header_t *hdr,
                               const uint8_t *payload, uint16_t len)
{
    uint8_t enable = (len >= 1) ? payload[0] : 0;
    esp_err_t err;
    if (enable) {
        /* Optional name follows the enable byte: [enable:1][name bytes].
         * len==1 keeps the current name; a name here is the Direct identity,
         * kept fully separate from the Bad-BT HID name. */
        if (len > 1) {
            char name[32];
            uint16_t n = (uint16_t)(len - 1);
            if (n > sizeof(name) - 1) n = sizeof(name) - 1;
            memcpy(name, &payload[1], n);
            name[n] = '\0';
            ble_nus_set_name(name);
        }
        s_ble_direct_enabled = true;
        s_ble_direct_restore_after_hid = false;
        ble_hid_stop();
        err = ble_nus_adv_start();
    } else {
        s_ble_direct_enabled = false;
        s_ble_direct_restore_after_hid = false;
        ble_nus_adv_stop();
        err = ESP_OK;
    }
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* Report which BLE role(s) are currently active, for the host "BT Info" screen.
 * One byte of flags — Direct (NUS) and Bad-BT (HID) are independent identities. */
static void handle_ble_state(const m1_rpc_header_t *hdr)
{
    uint8_t flags = (ble_nus_is_advertising() ? 0x01 : 0x00) |
                    (ble_nus_connected()      ? 0x02 : 0x00) |
                    (ble_hid_is_advertising() ? 0x04 : 0x00) |
                    (ble_hid_is_connected()   ? 0x08 : 0x00);
    send_resp(hdr->msg_id, &flags, 1);
}

/* ---------- SoftAP ("WiFi Hotspot") ---------- */

/* payload: [channel:1][ssid\0][pass\0] — bring up a real WiFi AP the phone can
 * join (no router needed) and reach the RPC server over. */
static void handle_softap_start(const m1_rpc_header_t *hdr,
                                const uint8_t *payload, uint16_t len)
{
    if (len < 3) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    uint8_t channel = payload[0];
    const char *ssid = (const char *)&payload[1];
    size_t maxs = (size_t)len - 1;
    size_t ssid_len = strnlen(ssid, maxs);
    if (ssid_len == 0 || ssid_len + 1 >= maxs) {
        send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS);
        return;
    }
    const char *pass = ssid + ssid_len + 1;   /* null-terminated within payload */
    esp_err_t err = wifi_mgr_softap_start(ssid, pass, channel);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

static void handle_softap_stop(const m1_rpc_header_t *hdr)
{
    esp_err_t err = wifi_mgr_softap_stop();
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

static void handle_softap_sta_list(const m1_rpc_header_t *hdr)
{
    /* Self-heal NAT: (re)enable it if the AP + an upstream STA link are both up.
     * The M1 polls this ~1s while the Hotspot menu is open, so passthrough turns
     * on as soon as the conditions are met, regardless of the order the hotspot
     * and WiFi were brought up. Idempotent. */
    wifi_mgr_napt_refresh();

    uint8_t resp[2];
    resp[0] = wifi_mgr_softap_sta_count();               /* connected clients */
    resp[1] = wifi_mgr_softap_internet_shared() ? 1 : 0; /* internet passthrough */
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

/* ---------- Screen push (M1 -> ESP -> qMonstatek) ---------- */

static void handle_screen_push(const m1_rpc_header_t *hdr,
                               const uint8_t *payload, uint16_t len)
{
    rpc_server_update_screen(payload, len);
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

/* qMonstatek relay: M1 pulls a queued desktop command; and forwards its reply. */
static void handle_qmon_poll(const m1_rpc_header_t *hdr)
{
    static uint8_t qbuf[QMON_MAX_FRAME];
    int n = rpc_server_relay_dequeue(qbuf, sizeof(qbuf));   /* 0 = nothing pending */
    send_resp(hdr->msg_id, qbuf, n > 0 ? (uint16_t)n : 0);
}

static void handle_qmon_resp(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t len)
{
    if (len > 0) rpc_server_send_raw(payload, len);        /* forward to TCP client */
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

/* ---------- Master dispatch ---------- */

static void dispatch_request(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t payload_len)
{
    switch (hdr->msg_id) {
    /* System */
    case M1_RPC_SYS_PING:
        /* echo the cookie payload straight back */
        send_resp(hdr->msg_id, payload, payload_len);
        break;
    case M1_RPC_SYS_GET_STATUS:
        handle_get_status(hdr);
        break;
    case M1_RPC_SYS_GET_FW_VERSION:
        handle_fw_version(hdr);
        break;
    case M1_RPC_SYS_SNTP_SYNC:
        handle_sntp_sync(hdr);
        break;
    case M1_RPC_SYS_RESET:
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        vTaskDelay(pdMS_TO_TICKS(50));
        esp_restart();
        break;

    /* WiFi station */
    case M1_RPC_WIFI_SCAN:
        handle_wifi_scan(hdr);
        break;
    case M1_RPC_WIFI_CONNECT:
        handle_wifi_connect(hdr, payload, payload_len);
        break;
    case M1_RPC_WIFI_DISCONNECT:
        wifi_mgr_disconnect();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_WIFI_GET_STATUS:
        handle_wifi_status(hdr);
        break;

    /* SoftAP ("WiFi Hotspot") */
    case M1_RPC_SOFTAP_START:
        handle_softap_start(hdr, payload, payload_len);
        break;
    case M1_RPC_SOFTAP_STOP:
        handle_softap_stop(hdr);
        break;
    case M1_RPC_SOFTAP_STA_LIST:
        handle_softap_sta_list(hdr);
        break;

    /* Offensive WiFi */
    case M1_RPC_OFF_DEAUTH_START:
        handle_deauth_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_DEAUTH_STOP:
        handle_deauth_stop(hdr);
        break;
    case M1_RPC_OFF_STA_SCAN_START:
        handle_sta_scan_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_STA_SCAN_RESULTS:
        handle_sta_scan_results(hdr);
        break;
    case M1_RPC_OFF_HS_START:
        handle_hs_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_HS_STATUS:
        handle_hs_status(hdr);
        break;
    case M1_RPC_OFF_HS_GET:
        handle_hs_get(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_HS_STOP:
        wifi_handshake_stop();
        wifi_attack_deauth_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_OFF_BEACON_START:
        handle_beacon_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_BEACON_STOP:
        wifi_attack_beacon_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_OFF_PROBE_START:
        handle_probe_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_PROBE_STOP:
        wifi_attack_probe_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_OFF_KARMA_START:
        handle_karma_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_KARMA_STOP:
        wifi_attack_karma_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_OFF_RAW_TX:
        handle_raw_tx(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_MONITOR_START:
        handle_monitor_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_MONITOR_STOP:
        handle_monitor_stop(hdr);
        break;
    case M1_RPC_OFF_MONITOR_STATS:
        handle_monitor_stats(hdr);
        break;
    case M1_RPC_OFF_MONITOR_READ:
        handle_monitor_read(hdr);
        break;
    case M1_RPC_OFF_CAPTIVE_START:
        handle_captive_start(hdr, payload, payload_len);
        break;
    case M1_RPC_OFF_CAPTIVE_STOP:
        handle_captive_stop(hdr);
        break;
    case M1_RPC_OFF_CAPTIVE_CREDS:
        handle_captive_creds(hdr);
        break;
    case M1_RPC_OFF_CAPTIVE_DIAG:
        handle_captive_diag(hdr);
        break;

    /* BLE HID (native NimBLE — BadBT) */
    case M1_RPC_BLE_HID_INIT:
        handle_ble_hid_init(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_HID_KEY:
        handle_ble_hid_key(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_HID_DEINIT:
        /* HID teardown is asynchronous in NimBLE. Wait for its disconnect
         * event before ACKing so the next BLE app never starts against a
         * still-connected keyboard. */
        if (ble_hid_stop_and_wait(1500) == ESP_OK) {
            if (s_ble_direct_restore_after_hid && s_ble_direct_enabled)
                ble_nus_adv_start();
            s_ble_direct_restore_after_hid = false;
            send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        } else {
            send_nak(hdr->msg_id, M1_RPC_ERR_TIMEOUT);
        }
        break;
    case M1_RPC_BLE_HID_STATUS:
        handle_ble_hid_status(hdr);
        break;

    /* BLE scan */
    case M1_RPC_BLE_SCAN_START:
        handle_ble_scan_start(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_SCAN_RESULTS:
        handle_ble_scan_results(hdr);
        break;
    case M1_RPC_BLE_CONNECT:
        handle_ble_connect(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_DISCONNECT:
        ble_conn_disconnect();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_BLE_ADV_START:
        handle_ble_advertise(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_ADV_STOP:
        ble_adv_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_BLE_SPAM_START:
        handle_ble_spam_start(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_RPC_ADV:
        handle_ble_rpc_adv(hdr, payload, payload_len);
        break;
    case M1_RPC_BLE_STATE:
        handle_ble_state(hdr);
        break;
    case M1_RPC_BLE_SPAM_STOP:
        ble_spam_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;

    /* 802.15.4 (Zigbee/Thread) device discovery */
    case M1_RPC_ZB_SNIFF_START:
        handle_zb_sniff_start(hdr, payload, payload_len);
        break;
    case M1_RPC_ZB_SNIFF_STOP:
        handle_zb_sniff_stop(hdr);
        break;
    case M1_RPC_ZB_SNIFF_GET:
        handle_zb_sniff_get(hdr);
        break;
    case M1_RPC_ZB_FLOOD_START:
        handle_zb_flood_start(hdr, payload, payload_len);
        break;
    case M1_RPC_ZB_FLOOD_STOP:
        ieee802154_flood_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_ZB_INJECT:
        handle_zb_inject(hdr, payload, payload_len);
        break;

    /* ESP-NOW peer-to-peer M1<->M1 link */
    case M1_RPC_NOW_START:
        handle_now_start(hdr, payload, payload_len);
        break;
    case M1_RPC_NOW_STOP:
        esp_now_link_stop();
        send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
        break;
    case M1_RPC_NOW_ANNOUNCE: {
        esp_err_t e = esp_now_link_announce();
        send_resp(hdr->msg_id,
                  (const uint8_t[]){ e == ESP_OK ? M1_RPC_OK : M1_RPC_ERR_NOT_RUNNING }, 1);
        break;
    }
    case M1_RPC_NOW_PEERS_GET:
        handle_now_peers_get(hdr);
        break;
    case M1_RPC_NOW_SEND:
        handle_now_send(hdr, payload, payload_len);
        break;
    case M1_RPC_NOW_RECV_GET:
        handle_now_recv_get(hdr);
        break;

    /* Screen streaming */
    case M1_RPC_SCREEN_PUSH:
        handle_screen_push(hdr, payload, payload_len);
        break;
    case M1_RPC_QMON_POLL:
        handle_qmon_poll(hdr);
        break;
    case M1_RPC_QMON_RESP:
        handle_qmon_resp(hdr, payload, payload_len);
        break;
    case M1_RPC_RPC_STATUS: {
        uint8_t status = rpc_server_client_status();
        send_resp(hdr->msg_id, &status, 1);
        break;
    }

    default:
        send_nak(hdr->msg_id, M1_RPC_ERR_UNSUPPORTED);
        break;
    }
}

/* ---------- 802.15.4 (Zigbee/Thread) device discovery ---------- */

static void handle_zb_sniff_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len)
{
    uint8_t channel = (len >= 1) ? payload[0] : 0;   /* 0 = hop all 11-26 */
    esp_err_t err = ieee802154_sniff_start(channel);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

static void handle_zb_sniff_stop(const m1_rpc_header_t *hdr)
{
    ieee802154_sniff_stop();
    send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
}

static void handle_zb_sniff_get(const m1_rpc_header_t *hdr)
{
    static uint8_t buf[1 + 64 * sizeof(m1_rpc_zb_device_t)];   /* [count][devices] */
    int n = ieee802154_sniff_get(buf, sizeof(buf));
    send_resp(hdr->msg_id, buf, (uint16_t)n);
}

static void handle_zb_flood_start(const m1_rpc_header_t *hdr,
                                  const uint8_t *payload, uint16_t len)
{
    uint8_t channel = (len >= 1) ? payload[0] : 0;   /* 0 = sweep 11-26 */
    esp_err_t err = ieee802154_flood_start(channel);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

static void handle_zb_inject(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t len)
{
    if (len < 1 || len > 125) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t err = ieee802154_inject(payload, (uint8_t)len);
    if (err == ESP_OK) send_resp(hdr->msg_id, (const uint8_t[]){ M1_RPC_OK }, 1);
    else               send_nak(hdr->msg_id, M1_RPC_ERR_HARDWARE);
}

/* ---------- ESP-NOW peer-to-peer M1<->M1 link ---------- */

static void handle_now_start(const m1_rpc_header_t *hdr,
                             const uint8_t *payload, uint16_t len)
{
    uint8_t ch = (len >= 1) ? payload[0] : 1;
    char    name[ENL_NAME_MAX + 1] = {0};
    if (len > 1) {
        int nlen = len - 1;
        if (nlen > ENL_NAME_MAX) nlen = ENL_NAME_MAX;
        memcpy(name, payload + 1, nlen);
    }
    esp_err_t rc = esp_now_link_start(ch, name);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "now_start failed: %s (0x%x)", esp_err_to_name(rc), (unsigned)rc);
        /* Diagnostic: return the raw esp_err_t (LE) so the M1 can show it.
         * resp[0] is the low byte (non-zero => != M1_RPC_OK, so M1 reports failure). */
        uint8_t resp[4] = {
            (uint8_t)(rc & 0xFF), (uint8_t)((rc >> 8) & 0xFF),
            (uint8_t)((rc >> 16) & 0xFF), (uint8_t)((rc >> 24) & 0xFF),
        };
        send_resp(hdr->msg_id, resp, sizeof(resp));
        return;
    }
    uint8_t resp[7];
    resp[0] = M1_RPC_OK;
    esp_now_link_get_mac(&resp[1]);          /* our MAC so the M1 can show it */
    send_resp(hdr->msg_id, resp, sizeof(resp));
}

static void handle_now_peers_get(const m1_rpc_header_t *hdr)
{
    enl_peer_t peers[ENL_MAX_PEERS];
    int n = esp_now_link_get_peers(peers, ENL_MAX_PEERS);

    uint8_t resp[1 + ENL_MAX_PEERS * (6 + 1 + 1 + ENL_NAME_MAX)];
    int off = 0;
    resp[off++] = (uint8_t)n;
    for (int i = 0; i < n; i++) {
        memcpy(&resp[off], peers[i].mac, 6);      off += 6;
        resp[off++] = (uint8_t)peers[i].rssi;
        int nlen = strlen(peers[i].name);
        resp[off++] = (uint8_t)nlen;
        memcpy(&resp[off], peers[i].name, nlen);  off += nlen;
    }
    send_resp(hdr->msg_id, resp, (uint16_t)off);
}

static void handle_now_send(const m1_rpc_header_t *hdr,
                            const uint8_t *payload, uint16_t len)
{
    if (len < 6) { send_nak(hdr->msg_id, M1_RPC_ERR_INVALID_ARGS); return; }
    esp_err_t e = esp_now_link_send(payload, payload + 6, (uint16_t)(len - 6));
    send_resp(hdr->msg_id,
              (const uint8_t[]){ e == ESP_OK ? M1_RPC_OK : M1_RPC_ERR_HARDWARE }, 1);
}

static void handle_now_recv_get(const m1_rpc_header_t *hdr)
{
    uint8_t *resp = malloc(M1_RPC_MAX_PAYLOAD);
    if (!resp) { send_nak(hdr->msg_id, M1_RPC_ERR_NO_MEM); return; }
    int n = esp_now_link_drain_rx(resp, M1_RPC_MAX_PAYLOAD);
    send_resp(hdr->msg_id, resp, (uint16_t)n);
    free(resp);
}

/* ---------- app_main ---------- */

void app_main(void)
{
    ESP_LOGI(TAG, "=== M1 ESP32-C6 Network Coprocessor (m1_rpc) ===");

    ESP_ERROR_CHECK(m1_link_init());

    wifi_mgr_config_t wifi_cfg = { .mode = WIFI_MGR_MODE_STATION };
    ESP_ERROR_CHECK(wifi_mgr_init(&wifi_cfg));

    rpc_server_config_t rpc_cfg = RPC_SERVER_DEFAULT_CONFIG();
    ESP_ERROR_CHECK(rpc_server_init(&rpc_cfg));

    xTaskCreate(cmd_dispatch_task, "cmd_dispatch", 8192, NULL, 8, NULL);

    ESP_LOGI(TAG, "Ready. Waiting for m1_rpc requests from M1...");
}
