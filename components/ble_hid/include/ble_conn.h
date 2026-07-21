/*
 * ble_conn.h — BLE central-connect + generic (non-HID) advertising for the
 * shared NimBLE host (ESP32-C6, ESP-IDF v5.1).
 *
 * Shares the single NimBLE host brought up by ble_hid (ble_host_ensure_started)
 * alongside the HID peripheral (ble_hid.c) and the central scanner (ble_scan.c).
 * This module adds two independent capabilities that use their own GAP callback
 * and do not touch ble_hid.c / ble_scan.c internal state:
 *
 *   1. Central connect — actively connect to a peer advertiser and hold the
 *      link (e.g. one found via ble_scan). Blocking with a timeout.
 *   2. Generic advertise — advertise as an undirected connectable peripheral
 *      with an arbitrary complete name (no HID GATT semantics implied).
 */
#ifndef BLE_CONN_H
#define BLE_CONN_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Central connect to a peer. Ensures the shared host is started, cancels any
 * in-progress discovery (a connect cannot be initiated while scanning), and
 * initiates a GAP connect. Blocks up to `timeout_ms` for the connection to be
 * established.
 *
 * @param addr       6-byte peer device address, little-endian (addr[0] = LSB),
 *                   matching the layout returned by ble_scan (ble_addr_t.val).
 * @param addr_type  Peer address type (BLE_ADDR_PUBLIC / BLE_ADDR_RANDOM / ...).
 * @param timeout_ms Max time to wait for connection establishment.
 * @return ESP_OK if connected within the timeout, ESP_ERR_TIMEOUT if not,
 *         or another esp_err_t on failure to start the host / initiate connect.
 */
esp_err_t ble_conn_connect(const uint8_t addr[6], uint8_t addr_type, uint32_t timeout_ms);

/** Terminate the central-initiated connection, if any. */
void      ble_conn_disconnect(void);

/** @return true while the central-initiated connection is established. */
bool      ble_conn_is_connected(void);

/**
 * Start generic (non-HID) undirected connectable peripheral advertising with
 * the complete local name `name`, general-discoverable + BLE-only flags, and a
 * generic appearance. Coexists with an active scan.
 *
 * NOTE: legacy advertising is a single instance, so this and HID advertising
 * (ble_hid_start) are mutually exclusive — starting this stops HID advertising,
 * and starting HID advertising later stops this.
 *
 * @param name  Complete local name to advertise (NULL/empty -> "ESP32-C6").
 * @return ESP_OK on success, error code otherwise.
 */
esp_err_t ble_adv_start(const char *name);

/** Stop generic advertising started by ble_adv_start(). */
void      ble_adv_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_CONN_H */
