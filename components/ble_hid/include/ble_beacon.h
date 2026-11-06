/*
 * ble_beacon.h — BLE beacon emulator (iBeacon / Eddystone-URL).
 *
 * Broadcasts a single stable non-connectable advertisement so beacon-aware apps
 * and scanners range on the M1 as a fixed beacon. Shares the non-connectable
 * ext-adv slot with BLE spam (the two are mutually exclusive — the M1 runs one
 * app at a time and stops it on exit).
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* iBeacon: 16-byte proximity UUID + major/minor + calibrated 1 m TX power (dBm,
 * e.g. -59 = 0xC5). Advertises until ble_beacon_stop(). */
esp_err_t ble_beacon_start_ibeacon(const uint8_t uuid[16], uint16_t major,
                                   uint16_t minor, int8_t tx_power);

/* Eddystone-URL: a short URL (scheme auto-detected; body compressed with the
 * standard suffix codes; truncated to the ~17 bytes that fit one adv). */
esp_err_t ble_beacon_start_eddystone_url(const char *url);

/* Raw non-connectable legacy advertisement. When addr is NULL a stable local
 * random-static address is generated; otherwise addr supplies the identity
 * (for protocols such as Find My that derive it from the payload key). */
esp_err_t ble_beacon_start_raw_custom(const uint8_t *adv, uint8_t len,
                                      const uint8_t addr[6], uint16_t interval_ms);

void ble_beacon_stop(void);
bool ble_beacon_is_running(void);
