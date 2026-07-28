/*
 * ieee802154_sniff.h — passive 802.15.4 (Zigbee/Thread) device discovery.
 *
 * Puts the ESP32-C6 native 802.15.4 radio in promiscuous mode, hops channels
 * 11-26 (or dwells on one), parses each MAC header, and aggregates a deduped
 * table of the DEVICES heard (by source address) with PAN ID, channel, and
 * peak RSSI. The M1 polls the table to display a "who's on the mesh + signal
 * strength" view — not a raw frame dump.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* Start discovery. channel 0 = hop all (11-26); 11..26 = dwell that channel.
 * Clears the device table. */
esp_err_t ieee802154_sniff_start(uint8_t channel);

/* Stop discovery and release the radio. */
esp_err_t ieee802154_sniff_stop(void);

/* Serialize the current device table into buf as:
 *   [u8 count][m1_rpc_zb_device_t x count]   (capped to what fits in `cap`).
 * Returns the number of bytes written. Safe to call while running (live view). */
int ieee802154_sniff_get(uint8_t *buf, int cap);

/* ---- Offensive TX (shares the single radio; mutually exclusive with sniff) ----
 * Beacon-request flood: hammer broadcast MAC Beacon-Request commands, which every
 * Zigbee coordinator/router is obliged to answer — floods the channel and the
 * devices' request handlers. channel 0 = sweep 11-26, else dwell that channel. */
esp_err_t ieee802154_flood_start(uint8_t channel);
esp_err_t ieee802154_flood_stop(void);

/* One-shot raw injection: transmit an arbitrary 802.15.4 MAC frame (the caller
 * supplies the MPDU WITHOUT the 2-byte FCS; hardware appends it). Uses the
 * current radio channel. len 1..125. Returns ESP_OK if the frame was queued. */
esp_err_t ieee802154_inject(const uint8_t *mpdu, uint8_t len);
