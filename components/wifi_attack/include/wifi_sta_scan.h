/*
 * WiFi Station (Client) Discovery — promiscuous-mode sniffing
 *
 * Given a target AP BSSID + channel, sniffs 802.11 mgmt/data frames and
 * collects the MAC addresses of stations (clients) communicating with
 * that AP. Runs entirely on the ESP32 in promiscuous mode.
 */

#ifndef WIFI_STA_SCAN_H
#define WIFI_STA_SCAN_H

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t mac[6];   /* Station (client) MAC address */
    int8_t  rssi;     /* Last observed RSSI (dBm) */
} wifi_sta_dev_t;

/*
 * Start station discovery.
 *   bssid        : target AP BSSID (6 bytes)
 *   channel      : channel the AP operates on (1..14)
 *   duration_sec : auto-stop after this many seconds (0 = run until
 *                  wifi_sta_scan_stop() is called)
 *
 * Enables promiscuous mode, filters mgmt+data frames, locks to channel,
 * and begins collecting stations into the internal results table.
 */
esp_err_t wifi_sta_scan_start(const uint8_t bssid[6], uint8_t channel, uint16_t duration_sec);

/* Stop discovery, leave promiscuous mode, and restore normal STA mode. */
void wifi_sta_scan_stop(void);

/*
 * Copy discovered stations into 'out' (up to 'max' entries).
 * Returns the number of entries written.
 */
int wifi_sta_scan_get_results(wifi_sta_dev_t *out, int max);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_STA_SCAN_H */
