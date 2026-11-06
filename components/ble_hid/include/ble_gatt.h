#ifndef BLE_GATT_H
#define BLE_GATT_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

esp_err_t ble_gatt_start(const uint8_t addr[6], uint8_t addr_type);
int ble_gatt_next(uint8_t *out, uint16_t cap);
void ble_gatt_stop(void);
esp_err_t ble_gatt_write(uint16_t handle, uint8_t flags,
                         const uint8_t *value, uint8_t value_len);
esp_err_t ble_gatt_subscribe(uint16_t handle, bool enable, uint8_t mode);
int ble_gatt_notify_next(uint8_t *out, uint16_t cap);

#endif /* BLE_GATT_H */
