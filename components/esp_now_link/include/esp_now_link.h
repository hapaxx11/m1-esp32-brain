/*
 * esp_now_link.h — peer-to-peer M1<->M1 link over ESP-NOW.
 *
 * Lets two M1 units (each an ESP32-C6) discover each other and exchange short
 * messages directly over 2.4 GHz, with no AP. The ESP does the radio work; the
 * STM32 host drives it over m1_link RPC (M1_RPC_NOW_* / M1ESP_NOW_*).
 *
 * Wire framing of every ESP-NOW packet: [ 'M', '1', type, payload... ]
 *   type 0 = ANNOUNCE : payload = device name string (presence broadcast)
 *   type 1 = DATA     : payload = user message bytes
 */
#ifndef ESP_NOW_LINK_H
#define ESP_NOW_LINK_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define ENL_NAME_MAX   23     /* device name, NUL-terminated */
#define ENL_MSG_MAX    240    /* user bytes per message (ESP-NOW 250 - framing) */
#define ENL_MAX_PEERS  16     /* discovered-peer table size */

typedef struct {
    uint8_t mac[6];
    int8_t  rssi;
    char    name[ENL_NAME_MAX + 1];
} enl_peer_t;

/* Init ESP-NOW on the given WiFi channel (1-13) and announce as `name`.
 * Idempotent-ish: safe to call again to change name/channel. */
esp_err_t esp_now_link_start(uint8_t channel, const char *name);
void      esp_now_link_stop(void);
bool      esp_now_link_running(void);

/* This unit's STA MAC (the address peers send to). */
bool      esp_now_link_get_mac(uint8_t mac[6]);

/* Broadcast a presence ANNOUNCE so nearby M1s learn our MAC + name. */
esp_err_t esp_now_link_announce(void);

/* Unicast `data` to `mac` (or the broadcast address for all). len <= ENL_MSG_MAX. */
esp_err_t esp_now_link_send(const uint8_t mac[6], const uint8_t *data, uint16_t len);

/* Copy the current discovered-peer table into `out`; returns the count. */
int       esp_now_link_get_peers(enl_peer_t *out, int max);

/* Drain queued received DATA messages into `out`, packed as:
 *   [count:1] then per message [from_mac:6][len:2 LE][bytes]
 * Returns the number of bytes written. */
int       esp_now_link_drain_rx(uint8_t *out, int cap);

#endif /* ESP_NOW_LINK_H */
