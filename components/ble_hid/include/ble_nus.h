/*
 * ble_nus.h — Nordic UART Service (NUS) GATT server for "Bluetooth Direct".
 *
 * A phone connects to the M1's ESP32-C6 over BLE and speaks the exact same RPC
 * framing it uses over WiFi/USB. RX writes are fed into the shared RPC frame
 * parser + relay queue (rpc_server); M1->host responses are sent back as TX
 * notifications, chunked to the negotiated MTU.
 *
 * Lives in the ble_hid component so it shares the single NimBLE host and GATT
 * table (dynamic service registration is disabled — services must be registered
 * before the host task starts).
 */
#ifndef BLE_NUS_H_
#define BLE_NUS_H_

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register the NUS service into the GATT table. MUST be called from
 * ble_host_ensure_started() before the host task starts. Also registers
 * ble_nus_send() as rpc_server's BLE tx path. */
esp_err_t ble_nus_gatt_register(void);

/* Start / stop advertising "Bluetooth Direct" (device name M1-XXXX). Driven by
 * the M1 "Bluetooth Direct" toggle over RPC (M1_RPC_BLE_RPC_ADV). Mutually
 * exclusive with Bad-BT advertising for the single legacy adv slot. */
esp_err_t ble_nus_adv_start(void);
void      ble_nus_adv_stop(void);

/* True while a phone is connected over the NUS link. */
bool ble_nus_connected(void);

/* True while the Direct/NUS link is advertising (enabled and not yet connected). */
bool ble_nus_is_advertising(void);

/* Set the Direct/NUS advertised name (independent of the Bad-BT HID name).
 * Applied on the next ble_nus_adv_start(); ignored if name is NULL/empty. */
void ble_nus_set_name(const char *name);

/* Called from the shared NimBLE host sync callback (ble_host_on_sync) so a
 * pending advertise-start requested before sync completes gets applied. */
void ble_nus_on_host_synced(void);

/* Send M1->host bytes to the connected phone over the TX notify characteristic,
 * chunked to (MTU-3). Returns true if all bytes were queued. Registered with
 * rpc_server as the BLE tx callback; safe to call when disconnected (no-op). */
bool ble_nus_send(const uint8_t *data, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* BLE_NUS_H_ */
