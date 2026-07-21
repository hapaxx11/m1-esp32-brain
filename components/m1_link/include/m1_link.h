/*
 * m1_link.h — "M1 Link" reliable full-duplex SPI transport (Option B), ESP32-C6 slave.
 *
 * Replaces the ESP-AT SPI-HD status-register/WRBUF protocol with a simple,
 * fixed-size, full-duplex framed link:
 *
 *   - STM32H573 = SPI master, ESP32-C6 = SPI slave (spi_slave + DMA).
 *   - Every transaction clocks EXACTLY M1L_MTU bytes both ways at once.
 *   - One m1_rpc frame rides inside each buffer (IDLE frame when nothing to send).
 *   - HANDSHAKE GPIO (ESP->M1, GPIO14): raised in post_setup (slave armed = safe
 *     to clock), lowered in post_trans. The master MUST wait for it high before
 *     clocking. This is the reliability gate (per esp-hosted spi_drv.c).
 *   - DATA_READY GPIO (ESP->M1, optional): "TX queue non-empty" level. Disabled
 *     by default (pin unknown on this board); when enabled it lets the master
 *     skip polling for async ESP->M1 data.
 *
 * Design refs: Reference Guides/kb/ref_esp_spi_slave.md,
 *              ref_esp_hosted_spi_protocol.md, ref_stm32h5_spi_master.md
 */
#ifndef M1_LINK_H
#define M1_LINK_H

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the SPI slave, GPIOs, queues, and the link task. */
esp_err_t m1_link_init(void);

/* Enqueue a complete m1_rpc frame to send to the M1 (bytes are copied).
 * Returns ESP_OK, or ESP_ERR_NO_MEM / ESP_ERR_TIMEOUT. */
esp_err_t m1_link_send(const uint8_t *frame, size_t len, uint32_t timeout_ms);

/* Send a logical message, fragmenting into M1_RPC_FRAG frames if payload
 * exceeds one transaction (M1L_PAYLOAD_MAX). Preferred over m1_link_send. */
esp_err_t m1_link_send_msg(uint8_t type, uint16_t msg_id,
                           const uint8_t *payload, uint32_t len, uint32_t timeout_ms);

/* Receive the next complete m1_rpc frame from the M1. Copies up to buf_size
 * bytes into buf. Returns frame length (>0), or 0 on timeout. */
int m1_link_receive(uint8_t *buf, size_t buf_size, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* M1_LINK_H */
