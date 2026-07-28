/*
 * RPC Server — TCP server for qMonstatek communication
 *
 * Accepts TCP connections from qMonstatek, translates RPC commands
 * into SPI requests to M1, and streams responses back.
 *
 * The ESP32 is the brain — it decides when to poll M1 for screen data,
 * caches device info, and manages the client connection lifecycle.
 */

#ifndef RPC_SERVER_H
#define RPC_SERVER_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RPC_SERVER_PORT         3333
#define RPC_SERVER_MAX_CLIENTS  2

typedef struct {
    uint16_t port;
    uint8_t  max_clients;
} rpc_server_config_t;

#define RPC_SERVER_DEFAULT_CONFIG() { \
    .port        = RPC_SERVER_PORT, \
    .max_clients = RPC_SERVER_MAX_CLIENTS, \
}

/* Initialize RPC server (creates TCP listener task) */
esp_err_t rpc_server_init(const rpc_server_config_t *config);

/* Check if a client is connected */
bool rpc_server_client_connected(void);

/* Send a frame to connected client. Thread-safe. */
esp_err_t rpc_server_send(uint8_t cmd, uint8_t seq,
                          const uint8_t *payload, uint16_t payload_len);

/* Broadcast to all connected clients */
esp_err_t rpc_server_broadcast(uint8_t cmd,
                               const uint8_t *payload, uint16_t payload_len);

/* Update cached screen frame (called when M1 pushes a frame over SPI) */
void rpc_server_update_screen(const uint8_t *fb, uint16_t len);

/* qMonstatek wire protocol (matches rpc_protocol.h):
 *   [0xAA][CMD:1][SEQ:1][LEN:2 LE][PAYLOAD][CRC16:2], CRC-16/CCITT over CMD..PAYLOAD */
#define QMON_SYNC           0xAA
#define QMON_CMD_PING       0x01
#define QMON_CMD_PONG       0x02
#define QMON_CMD_SCREEN_START 0x10  /* [fps:u8][udp_port:u16 LE] — arms UDP screen */
#define QMON_CMD_SCREEN_STOP  0x11  /* stops UDP screen */
#define QMON_CMD_SCREEN     0x12    /* legacy screen-over-TCP poll — now ignored */
#define QMON_MAX_PAYLOAD    1400
#define QMON_MAX_FRAME      (5 + QMON_MAX_PAYLOAD + 2)

/* Send a pre-built qMonstatek frame (0xAA..CRC) to the TCP client — used to
 * relay a response the M1 produced back to the desktop app. */
esp_err_t rpc_server_send_raw(const uint8_t *frame, uint16_t len);

/* Dequeue the next qMonstatek command frame that must be handled by the M1
 * (the ESP couldn't answer it locally). For the M1's QMON_POLL. 0 if none. */
int rpc_server_relay_dequeue(uint8_t *buf, int max);

/* --- BLE (Bluetooth Direct) transport bridge ---
 * BLE and TCP are mutually exclusive as the active RPC client. ble_nus registers
 * a TX callback and feeds RX bytes here; both reuse the same parser + relay. */
typedef bool (*rpc_ble_tx_fn)(const uint8_t *data, uint16_t len);

/* Register the callback that sends M1->host bytes over the BLE NUS link. */
void rpc_server_set_ble_tx(rpc_ble_tx_fn fn);

/* Mark BLE as the active client (true on BLE connect, false on disconnect). */
void rpc_server_ble_set_active(bool active);

/* Feed bytes received on the BLE RX characteristic into the RPC parser/relay. */
void rpc_server_feed_ble(const uint8_t *data, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* RPC_SERVER_H */
