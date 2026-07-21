/*
 * WiFi Manager — Station + AP + attack modes
 *
 * Handles WiFi initialization, connection management, mDNS,
 * and provides the foundation for offensive WiFi features
 * (deauth, captive portal, packet injection).
 */

#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WIFI_MGR_MODE_STATION,      /* Connect to AP */
    WIFI_MGR_MODE_AP,           /* Run as AP (captive portal, etc.) */
    WIFI_MGR_MODE_APSTA,        /* Both */
    WIFI_MGR_MODE_MONITOR,      /* Promiscuous / monitor mode */
} wifi_mgr_mode_t;

typedef struct {
    wifi_mgr_mode_t mode;
    char sta_ssid[33];
    char sta_pass[65];
    char ap_ssid[33];
    char ap_pass[65];
    uint8_t ap_channel;
    uint8_t ap_max_conn;
} wifi_mgr_config_t;

typedef void (*wifi_mgr_scan_cb_t)(const wifi_ap_record_t *records, uint16_t count);
typedef void (*wifi_mgr_pkt_cb_t)(const uint8_t *buf, uint32_t len, wifi_pkt_rx_ctrl_t *rx_ctrl);

/* Initialize WiFi subsystem + NVS + netif + event loop */
esp_err_t wifi_mgr_init(const wifi_mgr_config_t *config);

/* Connect to configured station AP (blocking: waits up to ~15s for got-IP). */
esp_err_t wifi_mgr_connect(void);

/* Kick off an association without waiting for the result. Returns as soon as
 * esp_wifi_connect() is accepted; poll wifi_mgr_is_connected() for completion.
 * Used so a connect issued over the shared SPI link doesn't block the ESP's
 * command dispatcher (and the M1's link mutex) for the whole association. */
esp_err_t wifi_mgr_connect_async(void);

/* Disconnect */
esp_err_t wifi_mgr_disconnect(void);

/* Power-save policy knob. active=true  -> WIFI_PS_NONE (low latency, used while a
 * control client is connected); active=false -> WIFI_PS_MIN_MODEM (battery default). */
void wifi_mgr_set_ps_active(bool active);

/* Start AP mode */
esp_err_t wifi_mgr_start_ap(void);

/* Scan for nearby APs */
esp_err_t wifi_mgr_scan(wifi_mgr_scan_cb_t callback);

/* Get current IP address (station mode). Returns ESP_ERR_NOT_FOUND if not connected. */
esp_err_t wifi_mgr_get_ip(char *ip_str, size_t len);

/* Is station connected? */
bool wifi_mgr_is_connected(void);

/* Register mDNS service for device discovery */
esp_err_t wifi_mgr_register_mdns(const char *hostname, const char *service,
                                  uint16_t port);

/* --- Monitor / Attack modes --- */

/* Enter promiscuous mode. All packets delivered to callback. */
esp_err_t wifi_mgr_start_monitor(uint8_t channel, wifi_mgr_pkt_cb_t callback);

/* Exit promiscuous mode, restore previous mode */
esp_err_t wifi_mgr_stop_monitor(void);

/* Set channel (monitor mode) */
esp_err_t wifi_mgr_set_channel(uint8_t channel);

/* Send raw 802.11 frame (requires monitor or AP mode) */
esp_err_t wifi_mgr_send_raw(const uint8_t *frame, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_MANAGER_H */
