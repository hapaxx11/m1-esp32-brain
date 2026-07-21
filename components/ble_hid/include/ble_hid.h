/*
 * ble_hid.h — Self-contained NimBLE BLE HID keyboard component (ESP32-C6, ESP-IDF v5.1)
 *
 * Ports the proven HID GATT implementation from the esp32-at-hid AT firmware
 * (at_custom_hid_cmd.c) into a native ESP-IDF component that owns its own
 * NimBLE host init + advertising. Presents a standard HID-over-GATT keyboard
 * (BadBT-compatible): HID service 0x1812 + DIS 0x180A + Battery 0x180F.
 *
 * Usage:
 *   ble_hid_start("MyKeyboard");                 // init host, register GATT, advertise
 *   while (!ble_hid_is_connected()) vTaskDelay;  // wait for central to pair
 *   uint8_t keys[6] = { 0x04 };                  // 'a'
 *   ble_hid_send_key(0x00, keys, 1);             // press
 *   ble_hid_send_key(0x00, NULL, 0);             // release (all-zero report)
 */
#ifndef BLE_HID_H
#define BLE_HID_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bring up the shared NimBLE host exactly once (NVS, nimble_port_init,
 * ble_hs_cfg, GATT registration, bond store, host task). Both ble_hid_start()
 * and ble_scan_start() call this so the peripheral (HID) and central (scan)
 * roles share a single host. Idempotent: returns ESP_OK immediately if the
 * host is already running. Intended for use by sibling modules in this
 * component (e.g. ble_scan.c); application code normally calls ble_hid_start().
 *
 * @return ESP_OK on success, error code otherwise.
 */
esp_err_t ble_host_ensure_started(void);

/**
 * @return the resolved own address type once the host has synced, or -1 if the
 * host has not yet completed sync (address type not yet known). Used by the
 * scan module to pass own_addr_type to ble_gap_disc().
 */
int ble_host_own_addr_type(void);

/**
 * Initialize the NimBLE host (once, via ble_host_ensure_started), register the
 * HID GATT services, and start advertising as `device_name` with the HID
 * keyboard appearance. Safe to call more than once; subsequent calls only
 * (re)apply the name and (re)start advertising. Does not disturb any active
 * scan sharing the same host.
 *
 * @param device_name  Complete local name advertised (NULL -> "ESP32-C6 KB").
 * @return ESP_OK on success, error code otherwise.
 */
esp_err_t ble_hid_start(const char *device_name);

/**
 * Stop advertising and disconnect any active central. The NimBLE host stays
 * initialized so ble_hid_start() can resume quickly.
 */
void ble_hid_stop(void);

/**
 * @return true once a central has connected.
 */
bool ble_hid_is_connected(void);

/**
 * Send a single 8-byte HID keyboard report [modifier, 0x00, k0..k5] as a
 * notification on the Report Input characteristic. The caller is responsible
 * for sending the matching release (modifier=0, keys=NULL/all-zero) afterwards.
 *
 * @param modifier  HID modifier bitmask (e.g. 0x02 = Left Shift).
 * @param keys      Array of up to 6 HID usage keycodes (may be NULL if nkeys==0).
 * @param nkeys     Number of valid keycodes in `keys` (0..6).
 * @return ESP_OK if the notification was queued, ESP_ERR_INVALID_STATE if not
 *         connected/registered, ESP_ERR_INVALID_ARG on bad args.
 */
esp_err_t ble_hid_send_key(uint8_t modifier, const uint8_t *keys, uint8_t nkeys);

#ifdef __cplusplus
}
#endif

#endif /* BLE_HID_H */
