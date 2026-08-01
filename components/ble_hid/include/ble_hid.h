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
#include "host/ble_gap.h"   /* ble_gap_event_fn — shared ext-adv helper below */

#ifdef __cplusplus
extern "C" {
#endif

/* Extended-advertising instance ids. With ext-adv each set has its OWN
 * static-random address, so Bad-BT (HID) and Bluetooth Direct (NUS) are
 * genuinely separate BLE identities (the C6 exposes no public address, so
 * legacy advertising was forced to share one). */
/* Instance 0 is kept for the NON-connectable set (spam): esp-idf's ble_multi_adv
 * example puts connectable advertising on a non-zero instance and non-connectable
 * on instance 0, and connectable on instance 0 fails to start on the C6 (Direct on
 * instance 1 works, HID on instance 0 did not). Keep every connectable set >0. */
#define BLE_ADV_INST_SPAM  0   /* non-connectable */
#define BLE_ADV_INST_NUS   1   /* connectable (confirmed working) */
#define BLE_ADV_INST_HID   2   /* connectable */
#define BLE_ADV_INST_GEN   3   /* connectable */

/* Derive a stable static-random address from the BT MAC (top two bits of the
 * MSByte forced to 0b11). `salt` is XORed into the low byte to make each role's
 * address distinct (HID/NUS/generic each pass a different salt). */
void ble_static_rnd_addr(uint8_t out[6], uint8_t salt);

/* Start an extended advertisement on `instance` with static-random `rnd_addr`.
 * `connectable` sets connectable adv; `use_legacy` selects legacy PDUs (broadest
 * scanner compat, non-connectable/scannable only) vs extended PDUs (needed for a
 * connectable set when running MULTIPLE instances on the C6 — connectable legacy
 * ADV_IND is not supported alongside other sets here). The complete AD payload
 * (including the device name) goes in `adv`; there is no separate scan response.
 * Reconfigures the instance each call so name/address changes take effect. */
int  ble_extadv_start(uint8_t instance, bool connectable, bool use_legacy,
                      const uint8_t rnd_addr[6],
                      const uint8_t *adv, uint8_t adv_len,
                      ble_gap_event_fn *cb, void *cb_arg);

/* Stop the extended advertisement on `instance` (harmless if not advertising). */
void ble_extadv_stop(uint8_t instance);

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
 * @param device_name  Complete local name advertised (NULL -> "ESP32-C6 KB"),
 *                     truncated to 29 characters so it always fits in BLE scan
 *                     response data alongside the HID advertisement.
 * @return ESP_OK on success, error code otherwise.
 */
esp_err_t ble_hid_start(const char *device_name);

/**
 * Stop advertising and request disconnect of any active central. The NimBLE
 * host stays initialized so ble_hid_start() can resume quickly.
 */
void ble_hid_stop(void);

/**
 * Stop HID and wait for the GAP disconnect event to complete. This is used by
 * Bad-BT's exit RPC so the next BLE app cannot start against a half-closed HID
 * link. A timeout leaves the current state intact and reports failure.
 *
 * @param timeout_ms Maximum time to wait for the disconnect event.
 * @return ESP_OK only once no HID connection remains.
 */
esp_err_t ble_hid_stop_and_wait(uint32_t timeout_ms);

/**
 * @return true once a central has established the BLE link.
 */
bool ble_hid_is_connected(void);

/** @return true only after encryption and HID input notifications are ready. */
bool ble_hid_is_ready(void);

/** @return true while Bad-BT is advertising (enabled, synced, not yet connected). */
bool ble_hid_is_advertising(void);

/** @return the last ble_gap_ext_adv_start() rc for the HID set (0 = ok). Diag. */
int ble_hid_last_adv_rc(void);

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
