/*
 * m1_link.c — reliable full-duplex SPI transport (Option B), ESP32-C6 slave side.
 * Implemented against Reference Guides/kb/ref_esp_spi_slave.md and
 * ref_esp_hosted_spi_protocol.md.
 */
#include "m1_link.h"
#include "m1_rpc.h"
#include "driver/spi_slave.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_attr.h"
#include <string.h>

static const char *TAG = "m1_link";

/* ---- Pins (from the spi_link Kconfig; fall back to real M1 board wiring).
 * These are the ESP32-C6-MINI GPIOs on the Monstatek M1 (confirmed in
 * M1_PINOUT.txt): SCLK=7 MOSI=12 MISO=13 CS=15 HANDSHAKE=14. ---- */
#ifdef CONFIG_M1_SPI_PIN_SCLK
#define PIN_SCLK   CONFIG_M1_SPI_PIN_SCLK
#define PIN_MOSI   CONFIG_M1_SPI_PIN_MOSI
#define PIN_MISO   CONFIG_M1_SPI_PIN_MISO
#define PIN_CS     CONFIG_M1_SPI_PIN_CS
#define PIN_HS     CONFIG_M1_SPI_PIN_HS
#define SPI_MODE   CONFIG_M1_SPI_MODE
#else
#define PIN_SCLK   7
#define PIN_MOSI   12
#define PIN_MISO   13
#define PIN_CS     15
#define PIN_HS     14
#define SPI_MODE   1        /* Mode 1 — matches the M1 SPI3 master */
#endif

/* Optional DATA_READY output. -1 = disabled (unknown ESP GPIO on this board);
 * set to the real GPIO once the schematic confirms PC1's ESP-side pin. */
#ifndef CONFIG_M1_SPI_PIN_DATA_READY
#define PIN_DATA_READY  (-1)
#else
#define PIN_DATA_READY  CONFIG_M1_SPI_PIN_DATA_READY
#endif

#define HOST        SPI2_HOST
#define TXQ_DEPTH   8
#define RXQ_DEPTH   8

typedef struct { uint8_t *data; uint16_t len; } link_item_t;

static QueueHandle_t s_tx_q;      /* link_item_t — frames waiting to go to M1 */
static QueueHandle_t s_rx_q;      /* link_item_t — frames received from M1 */
static uint8_t      *s_txbuf;     /* DMA, M1L_MTU */
static uint8_t      *s_rxbuf;     /* DMA, M1L_MTU */
static volatile int  s_tx_pending;/* for DATA_READY level */

/* RX reassembly of fragmented (M1_RPC_FRAG) messages. */
static uint8_t   s_reasm[M1_RPC_MAX_PAYLOAD];
static bool      s_reasm_active;
static uint16_t  s_reasm_id;
static uint16_t  s_reasm_len;

/* ---- Handshake callbacks (ISR context — keep tiny, ISR-safe) ---- */
static void IRAM_ATTR cb_post_setup(spi_slave_transaction_t *t)
{
    gpio_set_level(PIN_HS, 1);          /* armed & safe to clock */
}
static void IRAM_ATTR cb_post_trans(spi_slave_transaction_t *t)
{
    gpio_set_level(PIN_HS, 0);          /* transfer done; re-arm before next */
}

static inline void data_ready_set(int level)
{
    if (PIN_DATA_READY >= 0) gpio_set_level(PIN_DATA_READY, level ? 1 : 0);
}

/* ---- Link task: one fixed-size full-duplex transaction at a time ---- */
static void link_task(void *arg)
{
    ESP_LOGI(TAG, "link task up (MTU=%u mode=%d SCLK=%d MOSI=%d MISO=%d CS=%d HS=%d DR=%d)",
             (unsigned)M1L_MTU, SPI_MODE, PIN_SCLK, PIN_MOSI, PIN_MISO, PIN_CS,
             PIN_HS, PIN_DATA_READY);

    while (1) {
        /* Prepare the outgoing frame: a queued frame, else an IDLE filler. */
        link_item_t it;
        if (xQueueReceive(s_tx_q, &it, 0) == pdTRUE) {
            uint16_t n = it.len > M1L_MTU ? M1L_MTU : it.len;
            memcpy(s_txbuf, it.data, n);
            if (n < M1L_MTU) memset(s_txbuf + n, 0, M1L_MTU - n);
            free(it.data);
        } else {
            size_t n = m1_rpc_build(s_txbuf, M1L_MTU, M1_RPC_IDLE, 0, NULL, 0);
            if (n < M1L_MTU) memset(s_txbuf + n, 0, M1L_MTU - n);
        }
        /* DATA_READY reflects whether more frames are still queued. */
        s_tx_pending = uxQueueMessagesWaiting(s_tx_q) > 0;
        data_ready_set(s_tx_pending);

        /* One full-duplex transaction. Blocks until the master clocks it.
         * post_setup raises HANDSHAKE (armed); post_trans lowers it. */
        spi_slave_transaction_t t = {
            .length    = M1L_MTU * 8,     /* bits */
            .tx_buffer = s_txbuf,
            .rx_buffer = s_rxbuf,
        };
        esp_err_t err = spi_slave_transmit(HOST, &t, portMAX_DELAY);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "spi_slave_transmit: %s", esp_err_to_name(err));
            continue;
        }

        /* Parse the received frame; reassemble FRAGs; deliver logical messages. */
        m1_rpc_header_t h;
        const uint8_t *pl;
        uint16_t pll;
        if (m1_rpc_parse(s_rxbuf, M1L_MTU, &h, &pl, &pll) != 0 ||
            h.msg_type == M1_RPC_IDLE) {
            continue;
        }

        if (h.msg_type == M1_RPC_FRAG) {
            /* Non-terminating fragment — accumulate (keyed by msg_id). */
            if (!s_reasm_active || s_reasm_id != h.msg_id) {
                s_reasm_active = true; s_reasm_id = h.msg_id; s_reasm_len = 0;
            }
            if ((uint32_t)s_reasm_len + pll <= M1_RPC_MAX_PAYLOAD) {
                memcpy(s_reasm + s_reasm_len, pl, pll);
                s_reasm_len += pll;
            }
            continue;
        }

        /* Terminating (real-type) frame — reassemble if fragments preceded it. */
        const uint8_t *out_payload = pl;
        uint16_t out_len = pll;
        if (s_reasm_active && s_reasm_id == h.msg_id) {
            if ((uint32_t)s_reasm_len + pll <= M1_RPC_MAX_PAYLOAD) {
                memcpy(s_reasm + s_reasm_len, pl, pll);
                s_reasm_len += pll;
            }
            out_payload = s_reasm;
            out_len = s_reasm_len;
            s_reasm_active = false; s_reasm_len = 0;
        }

        uint16_t flen = M1_RPC_HEADER_SIZE + out_len + M1_RPC_CRC_SIZE;
        uint8_t *cp = malloc(flen);
        if (cp) {
            m1_rpc_build(cp, flen, h.msg_type, h.msg_id, out_payload, out_len);
            link_item_t ri = { cp, flen };
            if (xQueueSend(s_rx_q, &ri, 0) != pdTRUE) {
                ESP_LOGW(TAG, "rx queue full, dropping frame");
                free(cp);
            }
        }
    }
}

esp_err_t m1_link_init(void)
{
    s_txbuf = heap_caps_malloc(M1L_MTU, MALLOC_CAP_DMA);
    s_rxbuf = heap_caps_malloc(M1L_MTU, MALLOC_CAP_DMA);
    s_tx_q  = xQueueCreate(TXQ_DEPTH, sizeof(link_item_t));
    s_rx_q  = xQueueCreate(RXQ_DEPTH, sizeof(link_item_t));
    if (!s_txbuf || !s_rxbuf || !s_tx_q || !s_rx_q) return ESP_ERR_NO_MEM;

    /* HANDSHAKE (and optional DATA_READY) as outputs, default low. */
    uint64_t mask = (1ULL << PIN_HS);
    if (PIN_DATA_READY >= 0) mask |= (1ULL << PIN_DATA_READY);
    gpio_config_t io = {
        .pin_bit_mask = mask,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0, .pull_down_en = 0, .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);
    gpio_set_level(PIN_HS, 0);
    data_ready_set(0);

    spi_bus_config_t bus = {
        .mosi_io_num = PIN_MOSI,
        .miso_io_num = PIN_MISO,
        .sclk_io_num = PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = M1L_MTU,
    };
    spi_slave_interface_config_t slv = {
        .spics_io_num = PIN_CS,
        .flags = 0,
        .queue_size = 3,
        .mode = SPI_MODE,
        .post_setup_cb = cb_post_setup,
        .post_trans_cb = cb_post_trans,
    };
    esp_err_t err = spi_slave_initialize(HOST, &bus, &slv, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "spi_slave_initialize: %s", esp_err_to_name(err));
        return err;
    }

    xTaskCreate(link_task, "m1_link", 4096, NULL, 12, NULL);
    ESP_LOGI(TAG, "M1 Link (full-duplex) initialized");
    return ESP_OK;
}

esp_err_t m1_link_send_msg(uint8_t type, uint16_t msg_id,
                           const uint8_t *payload, uint32_t len, uint32_t timeout_ms)
{
    static uint8_t frame[M1L_MTU];   /* single caller (main dispatch task) */
    if (len <= M1L_PAYLOAD_MAX) {
        size_t n = m1_rpc_build(frame, sizeof(frame), type, msg_id, payload, (uint16_t)len);
        return n ? m1_link_send(frame, n, timeout_ms) : ESP_ERR_INVALID_ARG;
    }
    /* Split: FRAG frames of M1L_PAYLOAD_MAX, then a terminating real-type frame. */
    uint32_t off = 0;
    while (len - off > M1L_PAYLOAD_MAX) {
        size_t n = m1_rpc_build(frame, sizeof(frame), M1_RPC_FRAG, msg_id,
                                payload + off, M1L_PAYLOAD_MAX);
        esp_err_t e = m1_link_send(frame, n, timeout_ms);
        if (e != ESP_OK) return e;
        off += M1L_PAYLOAD_MAX;
    }
    size_t n = m1_rpc_build(frame, sizeof(frame), type, msg_id,
                            payload + off, (uint16_t)(len - off));
    return m1_link_send(frame, n, timeout_ms);
}

esp_err_t m1_link_send(const uint8_t *frame, size_t len, uint32_t timeout_ms)
{
    if (!frame || len == 0 || len > M1L_MTU) return ESP_ERR_INVALID_ARG;
    uint8_t *cp = malloc(len);
    if (!cp) return ESP_ERR_NO_MEM;
    memcpy(cp, frame, len);
    link_item_t it = { cp, (uint16_t)len };
    if (xQueueSend(s_tx_q, &it, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        free(cp);
        return ESP_ERR_TIMEOUT;
    }
    data_ready_set(1);   /* signal async data pending (if DR wired) */
    return ESP_OK;
}

int m1_link_receive(uint8_t *buf, size_t buf_size, uint32_t timeout_ms)
{
    link_item_t it;
    if (xQueueReceive(s_rx_q, &it, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) return 0;
    uint16_t n = it.len > buf_size ? (uint16_t)buf_size : it.len;
    memcpy(buf, it.data, n);
    free(it.data);
    return n;
}
