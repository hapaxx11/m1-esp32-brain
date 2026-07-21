/*
 * SPI Link — ESP32 SPI SLAVE driver for M1 communication
 *
 * ESP32 is the SPI slave. M1 (STM32H573) is the SPI master.
 * Uses spi_slave_hd (half-duplex) driver matching the existing
 * AT firmware's protocol so M1's SPI master code works unchanged.
 *
 * Handshake GPIO: ESP32 asserts HIGH when it has data for M1 to read
 * or is ready for M1 to write. M1 sees rising edge → initiates transaction.
 *
 * Pin config (matches M1 PCB wiring):
 *   SCLK = GPIO7   (M1 drives)
 *   MOSI = GPIO12  (M1 drives → ESP32 receives)
 *   MISO = GPIO13  (ESP32 drives → M1 receives)
 *   CS   = GPIO15  (M1 drives)
 *   HS   = GPIO14  (ESP32 drives → M1 reads as interrupt)
 */

#ifndef SPI_LINK_H
#define SPI_LINK_H

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pin assignments — default to M1 PCB wiring (Kconfig: "M1 SPI Link").
 * Override for the XIAO/Pico bench via sdkconfig.bench.defaults, which keeps
 * the M1-target defaults untouched. Fallbacks below apply if Kconfig is absent. */
#ifdef CONFIG_M1_SPI_PIN_SCLK
#define SPI_LINK_PIN_SCLK       CONFIG_M1_SPI_PIN_SCLK
#define SPI_LINK_PIN_MOSI       CONFIG_M1_SPI_PIN_MOSI
#define SPI_LINK_PIN_MISO       CONFIG_M1_SPI_PIN_MISO
#define SPI_LINK_PIN_CS         CONFIG_M1_SPI_PIN_CS
#define SPI_LINK_PIN_HS         CONFIG_M1_SPI_PIN_HS
#define SPI_LINK_MODE           CONFIG_M1_SPI_MODE
#else
#define SPI_LINK_PIN_SCLK       7
#define SPI_LINK_PIN_MOSI       12
#define SPI_LINK_PIN_MISO       13
#define SPI_LINK_PIN_CS         15
#define SPI_LINK_PIN_HS         14
#define SPI_LINK_MODE           1   /* CPOL=0, CPHA=1 — matches M1 SPI3 */
#endif

#define SPI_LINK_MAX_TRANSFER   4092

/* Initialize SPI slave and start the rx/tx task */
esp_err_t spi_link_init(void);

/*
 * Receive data from M1 (blocking).
 * Returns number of bytes received, or -1 on error.
 */
int spi_link_receive(uint8_t *buf, size_t buf_size, uint32_t timeout_ms);

/*
 * Send data to M1 (blocking).
 * Asserts handshake GPIO so M1 knows to read.
 * Returns ESP_OK on success.
 */
esp_err_t spi_link_send(const uint8_t *data, size_t len, uint32_t timeout_ms);

/*
 * Check how many bytes are available to read (received from M1).
 */
size_t spi_link_rx_available(void);

#ifdef __cplusplus
}
#endif

#endif /* SPI_LINK_H */
