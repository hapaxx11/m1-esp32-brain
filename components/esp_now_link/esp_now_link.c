/*
 * esp_now_link.c — see esp_now_link.h. Peer-to-peer M1<->M1 over ESP-NOW.
 */
#include "esp_now_link.h"
#include <string.h>
#include "esp_now.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#define TAG "esp_now_link"

#define ENL_TYPE_ANNOUNCE 0
#define ENL_TYPE_DATA     1
#define ENL_RX_QUEUE      32    /* buffered received messages (deep enough for file-transfer bursts) */

static const uint8_t ENL_BCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

typedef struct {
    uint8_t  mac[6];
    uint16_t len;
    uint8_t  data[ENL_MSG_MAX];
} enl_rx_msg_t;

typedef struct {
    enl_peer_t entry;
    int64_t    last_us;
    bool       used;
} enl_peer_slot_t;

static bool               s_running;
static uint8_t            s_channel;
static char               s_name[ENL_NAME_MAX + 1];
static uint8_t            s_mac[6];
static SemaphoreHandle_t  s_mtx;

static enl_peer_slot_t    s_peers[ENL_MAX_PEERS];

static enl_rx_msg_t       s_rx[ENL_RX_QUEUE];
static uint8_t            s_rx_head, s_rx_tail, s_rx_count;

/* ------------------------------------------------------------------ */

static void update_peer(const uint8_t *mac, int8_t rssi, const uint8_t *name, int name_len)
{
    int free_slot = -1, oldest = -1;
    int64_t oldest_us = INT64_MAX;

    for (int i = 0; i < ENL_MAX_PEERS; i++) {
        if (s_peers[i].used && memcmp(s_peers[i].entry.mac, mac, 6) == 0) {
            s_peers[i].entry.rssi = rssi;
            s_peers[i].last_us = esp_timer_get_time();
            if (name_len > 0) {
                int n = name_len > ENL_NAME_MAX ? ENL_NAME_MAX : name_len;
                memcpy(s_peers[i].entry.name, name, n);
                s_peers[i].entry.name[n] = '\0';
            }
            return;
        }
        if (!s_peers[i].used && free_slot < 0) free_slot = i;
        if (s_peers[i].used && s_peers[i].last_us < oldest_us) {
            oldest_us = s_peers[i].last_us;
            oldest = i;
        }
    }

    int slot = (free_slot >= 0) ? free_slot : oldest;   /* evict oldest if full */
    if (slot < 0) return;

    memset(&s_peers[slot], 0, sizeof(s_peers[slot]));
    s_peers[slot].used = true;
    memcpy(s_peers[slot].entry.mac, mac, 6);
    s_peers[slot].entry.rssi = rssi;
    s_peers[slot].last_us = esp_timer_get_time();
    if (name_len > 0) {
        int n = name_len > ENL_NAME_MAX ? ENL_NAME_MAX : name_len;
        memcpy(s_peers[slot].entry.name, name, n);
        s_peers[slot].entry.name[n] = '\0';
    }
}

static void push_rx(const uint8_t *mac, const uint8_t *data, int len)
{
    if (len <= 0) return;
    if (len > ENL_MSG_MAX) len = ENL_MSG_MAX;

    if (s_rx_count == ENL_RX_QUEUE) {          /* full — drop oldest */
        s_rx_tail = (s_rx_tail + 1) % ENL_RX_QUEUE;
        s_rx_count--;
    }
    enl_rx_msg_t *m = &s_rx[s_rx_head];
    memcpy(m->mac, mac, 6);
    m->len = (uint16_t)len;
    memcpy(m->data, data, len);
    s_rx_head = (s_rx_head + 1) % ENL_RX_QUEUE;
    s_rx_count++;
}

static void recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    if (!info || len < 3 || data[0] != 'M' || data[1] != '1') return;

    uint8_t type = data[2];
    const uint8_t *pl = data + 3;
    int pl_len = len - 3;
    int8_t rssi = info->rx_ctrl ? (int8_t)info->rx_ctrl->rssi : 0;

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    if (type == ENL_TYPE_ANNOUNCE) {
        update_peer(info->src_addr, rssi, pl, pl_len);
    } else if (type == ENL_TYPE_DATA) {
        update_peer(info->src_addr, rssi, NULL, 0);   /* refresh presence/RSSI */
        push_rx(info->src_addr, pl, pl_len);
    }
    xSemaphoreGive(s_mtx);
}

/* Ensure `mac` is a registered ESP-NOW peer so unicast to it succeeds. */
static esp_err_t ensure_peer(const uint8_t *mac)
{
    if (esp_now_is_peer_exist(mac)) return ESP_OK;
    esp_now_peer_info_t p = {0};
    memcpy(p.peer_addr, mac, 6);
    p.channel = s_channel;
    p.ifidx = WIFI_IF_STA;
    p.encrypt = false;
    return esp_now_add_peer(&p);
}

/* ------------------------------------------------------------------ */

esp_err_t esp_now_link_start(uint8_t channel, const char *name)
{
    if (!s_mtx) {
        s_mtx = xSemaphoreCreateMutex();
        if (!s_mtx) return ESP_ERR_NO_MEM;
    }

    if (channel < 1 || channel > 13) channel = 1;
    s_channel = channel;
    memset(s_name, 0, sizeof(s_name));
    if (name) { strncpy(s_name, name, ENL_NAME_MAX); }

    /* WiFi must be initialised + started for ESP-NOW. wifi_manager brings up
     * NVS + esp_wifi_init at boot; here we just ensure STA mode is running and
     * pin the channel (ESP-NOW peers must share a channel when there's no AP). */
    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) == ESP_ERR_WIFI_NOT_INIT) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_err_t e = esp_wifi_init(&cfg);
        if (e != ESP_OK) return e;
    }
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();                                   /* no-op if already up */
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(false);                    /* drop leftover monitor mode */
    esp_wifi_get_mac(WIFI_IF_STA, s_mac);

    /* Force a clean ESP-NOW state on EVERY start. If a previous M1 session
     * rebooted or dropped without calling stop, s_running is still true and the
     * receive callback is wedged for the new session (TX keeps working, RX is
     * dead — peers stay 0, no ACKs). The ESP never reboots with the M1, so this
     * teardown + re-init is what makes re-entering Peer Link self-healing instead
     * of needing an ESP power-cycle. Both calls are harmless if already clean. */
    esp_now_unregister_recv_cb();
    esp_now_deinit();
    s_running = false;

    if (s_mtx) {                                        /* clear stale peer/RX state */
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        memset(s_peers, 0, sizeof(s_peers));
        s_rx_head = s_rx_tail = s_rx_count = 0;
        xSemaphoreGive(s_mtx);
    }

    esp_err_t e = esp_now_init();
    if (e != ESP_OK) return e;
    esp_now_register_recv_cb(recv_cb);

    /* Broadcast peer for discovery/announce. */
    esp_now_peer_info_t bc = {0};
    memcpy(bc.peer_addr, ENL_BCAST, 6);
    bc.channel = s_channel;
    bc.ifidx = WIFI_IF_STA;
    bc.encrypt = false;
    esp_now_add_peer(&bc);

    s_running = true;
    ESP_LOGI(TAG, "started ch=%u name='%s' mac=%02x:%02x:%02x:%02x:%02x:%02x",
             s_channel, s_name, s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);

    esp_now_link_announce();
    return ESP_OK;
}

void esp_now_link_stop(void)
{
    if (!s_running) return;
    esp_now_unregister_recv_cb();
    esp_now_deinit();
    s_running = false;
    if (s_mtx) {
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        memset(s_peers, 0, sizeof(s_peers));
        s_rx_head = s_rx_tail = s_rx_count = 0;
        xSemaphoreGive(s_mtx);
    }
    ESP_LOGI(TAG, "stopped");
}

bool esp_now_link_running(void) { return s_running; }

bool esp_now_link_get_mac(uint8_t mac[6])
{
    if (!s_running) return false;
    memcpy(mac, s_mac, 6);
    return true;
}

esp_err_t esp_now_link_announce(void)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    uint8_t frame[3 + ENL_NAME_MAX + 1];
    frame[0] = 'M'; frame[1] = '1'; frame[2] = ENL_TYPE_ANNOUNCE;
    int nlen = strlen(s_name);
    memcpy(frame + 3, s_name, nlen);
    return esp_now_send(ENL_BCAST, frame, 3 + nlen);
}

esp_err_t esp_now_link_send(const uint8_t mac[6], const uint8_t *data, uint16_t len)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    if (len > ENL_MSG_MAX) return ESP_ERR_INVALID_ARG;

    bool bcast = (memcmp(mac, ENL_BCAST, 6) == 0);
    if (!bcast) {
        esp_err_t e = ensure_peer(mac);
        if (e != ESP_OK) return e;
    }

    uint8_t frame[3 + ENL_MSG_MAX];
    frame[0] = 'M'; frame[1] = '1'; frame[2] = ENL_TYPE_DATA;
    if (len) memcpy(frame + 3, data, len);
    return esp_now_send(mac, frame, 3 + len);
}

int esp_now_link_get_peers(enl_peer_t *out, int max)
{
    if (!s_running || !s_mtx) return 0;
    int n = 0;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    for (int i = 0; i < ENL_MAX_PEERS && n < max; i++) {
        if (s_peers[i].used) out[n++] = s_peers[i].entry;
    }
    xSemaphoreGive(s_mtx);
    return n;
}

int esp_now_link_drain_rx(uint8_t *out, int cap)
{
    if (!s_running || !s_mtx || cap < 1) return 0;

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    int off = 1;                 /* reserve byte 0 for count */
    uint8_t count = 0;
    while (s_rx_count > 0) {
        enl_rx_msg_t *m = &s_rx[s_rx_tail];
        int need = 6 + 2 + m->len;
        if (off + need > cap) break;
        memcpy(out + off, m->mac, 6);            off += 6;
        out[off++] = (uint8_t)(m->len & 0xFF);
        out[off++] = (uint8_t)(m->len >> 8);
        memcpy(out + off, m->data, m->len);      off += m->len;
        count++;
        s_rx_tail = (s_rx_tail + 1) % ENL_RX_QUEUE;
        s_rx_count--;
    }
    out[0] = count;
    xSemaphoreGive(s_mtx);
    return off;
}
