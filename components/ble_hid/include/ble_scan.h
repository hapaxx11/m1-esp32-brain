/*
 * ble_scan.h — BLE central (observer) scan capability for the shared NimBLE
 * host (ESP32-C6, ESP-IDF v5.1). Coexists with the ble_hid peripheral: both
 * share one NimBLE host via ble_host_ensure_started(). Scanning does NOT stop
 * HID advertising.
 *
 * Usage:
 *   ble_scan_start(10);                        // scan for 10 s (0 = forever)
 *   vTaskDelay(pdMS_TO_TICKS(10000));
 *   ble_scan_dev_t devs[32];
 *   int n = ble_scan_get_results(devs, 32);    // snapshot discovered devices
 *   ble_scan_stop();                           // cancel an in-progress scan
 */
#ifndef BLE_SCAN_H
#define BLE_SCAN_H

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A single discovered advertiser. */
typedef struct {
    uint8_t addr[6];      /**< Advertiser address, little-endian (val[0..5]). */
    uint8_t addr_type;    /**< BLE_ADDR_* address type. */
    int8_t  rssi;         /**< Last-seen RSSI in dBm (127 = unavailable). */
    char    name[32];     /**< NUL-terminated local name ("" if none seen). */
} ble_scan_dev_t;

/**
 * Ensure the shared NimBLE host is up, clear the results table, and start a
 * general-discovery scan (active, so scan-response names are collected). If
 * the host has not yet synced the scan is deferred and begins automatically
 * once sync completes.
 *
 * @param duration_sec  Scan duration in seconds; 0 scans until ble_scan_stop().
 * @return ESP_OK on success, error code otherwise.
 */
esp_err_t ble_scan_start(uint16_t duration_sec);

/** Cancel an in-progress scan (ble_gap_disc_cancel). Safe if not scanning. */
void ble_scan_stop(void);

/**
 * Copy up to `max` discovered devices into out[].
 * @return the number of entries written.
 */
int ble_scan_get_results(ble_scan_dev_t *out, int max);

/**
 * Internal: invoked by the shared host sync callback (ble_hid.c) so a scan
 * requested before the host synced can start once an address is available.
 * Not intended for application use.
 */
void ble_scan_on_host_sync(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_SCAN_H */
