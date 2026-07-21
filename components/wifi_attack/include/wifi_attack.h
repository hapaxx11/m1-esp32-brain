/*
 * WiFi Attack — Deauth, captive portal, packet injection
 *
 * All attack functions run entirely on ESP32 — no SPI to M1 needed.
 * Uses wifi_manager for raw frame TX and monitor mode.
 */

#ifndef WIFI_ATTACK_H
#define WIFI_ATTACK_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Deauth ---------- */

typedef struct {
    uint8_t target_mac[6];     /* Target station MAC (FF:FF:FF:FF:FF:FF = broadcast) */
    uint8_t ap_mac[6];         /* AP BSSID */
    uint8_t channel;
    uint16_t count;            /* Number of deauth frames (0 = continuous) */
    uint16_t interval_ms;      /* Delay between frames */
} wifi_attack_deauth_config_t;

esp_err_t wifi_attack_deauth_start(const wifi_attack_deauth_config_t *config);
esp_err_t wifi_attack_deauth_stop(void);
bool wifi_attack_deauth_running(void);

/* ---------- Captive Portal ---------- */

typedef struct {
    char ssid[33];             /* AP SSID to broadcast */
    char portal_title[64];     /* HTML page title */
    uint8_t channel;
} wifi_attack_captive_config_t;

/* Starts AP + DNS redirect + HTTP server with credential capture page */
esp_err_t wifi_attack_captive_start(const wifi_attack_captive_config_t *config);
esp_err_t wifi_attack_captive_stop(void);
bool wifi_attack_captive_running(void);

/* Get captured credentials (returns count, fills buffer) */
typedef struct {
    char username[128];
    char password[128];
    uint32_t timestamp;
} wifi_attack_credential_t;

int wifi_attack_captive_get_creds(wifi_attack_credential_t *out, int max_count);

/* Live diagnostics: DNS queries answered, HTTP page hits, and currently
 * associated AP clients since captive_start. Lets the M1 see which stage of the
 * portal chain (client join -> DNS -> HTTP) is actually working. */
void wifi_attack_captive_diag(uint32_t *dns_q, uint32_t *http_hits, uint8_t *clients,
                              char *last_post, int last_post_cap);

/* ---------- Beacon Spam ---------- */

typedef struct {
    char ssids[32][33];        /* Up to 32 SSIDs to broadcast */
    uint8_t ssid_count;
    uint8_t channel;
    uint16_t interval_ms;
} wifi_attack_beacon_config_t;

esp_err_t wifi_attack_beacon_start(const wifi_attack_beacon_config_t *config);
esp_err_t wifi_attack_beacon_stop(void);

/* ---------- Packet Monitor ---------- */

/* Optional push callback. The RPC path leaves this NULL and pulls captured
 * frames with wifi_attack_monitor_read() instead (the M1 is SPI master and
 * polls), which avoids doing SPI from the Wi-Fi RX context. */
typedef void (*wifi_attack_pkt_cb_t)(const uint8_t *frame, uint32_t len,
                                     int8_t rssi, uint8_t channel);

esp_err_t wifi_attack_monitor_start(uint8_t channel, wifi_attack_pkt_cb_t callback);
esp_err_t wifi_attack_monitor_stop(void);

/* Channel hop across the 2.4GHz channels (1-13). channel is reported per frame. */
esp_err_t wifi_attack_monitor_hop_start(uint16_t dwell_ms, wifi_attack_pkt_cb_t callback);
esp_err_t wifi_attack_monitor_hop_stop(void);

bool wifi_attack_monitor_running(void);

/* Pull the oldest buffered captured frame into out (up to out_cap bytes) and
 * report its rssi/channel. Returns the frame length copied, or 0 if none. */
uint16_t wifi_attack_monitor_read(uint8_t *out, uint16_t out_cap,
                                  int8_t *rssi, uint8_t *channel);

/* Capture counters. total = frames seen, dropped = frames lost to a full
 * buffer, buffered = frames currently waiting to be read. */
void wifi_attack_monitor_stats(uint32_t *total, uint32_t *dropped, uint8_t *buffered);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_ATTACK_H */
