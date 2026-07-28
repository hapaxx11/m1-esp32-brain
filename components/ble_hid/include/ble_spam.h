/*
 * ble_spam.h — BLE advertising-spam ("proximity pair" popup flooder) for the
 * ESP32-C6, on the shared NimBLE host (ESP-IDF v5.1).
 *
 * Rapidly cycles raw manufacturer/service-data advertisements that trip the
 * vendor "a device is nearby" pairing popups on phones/PCs, rotating a random
 * advertiser address each burst so every frame looks like a fresh device:
 *   - Apple proximity pairing  (iOS AirPods/AirTag/"setup" cards)
 *   - Google Fast Pair         (Android pairing sheet)
 *   - Samsung EasySetup        (Galaxy Buds/Watch popups)
 *   - Microsoft Swift Pair      (Windows "Add a device?" toast)
 *   - All: round-robins the four with randomized models each cycle
 *
 * Uses the single legacy advertising instance, so it is mutually exclusive with
 * ble_hid / ble_adv (they stop each other via ble_gap_adv_stop). Advertising is
 * non-connectable + general-discoverable (ADV_NONCONN_IND) so the fast rotation
 * never stalls on a half-open connection.
 *
 * NOTE: popup effectiveness is empirical and target-OS-version dependent — the
 * payload/model constants below follow the well-known public formats but may
 * need tuning against a specific target. This is a pentest/awareness tool.
 */
#ifndef BLE_SPAM_H
#define BLE_SPAM_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BLE_SPAM_MODE_APPLE     = 0,
    BLE_SPAM_MODE_FASTPAIR  = 1,
    BLE_SPAM_MODE_SAMSUNG   = 2,
    BLE_SPAM_MODE_SWIFTPAIR = 3,
    BLE_SPAM_MODE_ALL       = 4,   /* round-robin the four above */
} ble_spam_mode_t;

/* Start the spam worker in `mode` (a ble_spam_mode_t; out-of-range -> ALL).
 * Brings up the shared NimBLE host if needed. Idempotent restart-safe. */
esp_err_t ble_spam_start(uint8_t mode);

/* Stop advertising and tear down the worker (blocks until it parks). */
void ble_spam_stop(void);

/* @return true while the spam worker is active. */
bool ble_spam_is_running(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_SPAM_H */
