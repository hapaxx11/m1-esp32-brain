/*
 * SPI Link — ESP32 SPI half-duplex slave
 *
 * Replicates the EXACT same SPI protocol as the AT firmware's at_spi_task.c
 * so M1's existing SPI master code works without changes.
 *
 * Flow (event-driven, NOT polling):
 *   1. M1 writes to WRBUF register → master_write_buffer_cb fires
 *   2. Callback queues SPI_SLAVE_RD message
 *   3. SPI task: writes status reg (dir=RD, seq, len), queues RX DMA, asserts HS
 *   4. M1 clocks data in → ESP32 receives, pushes to RX ring buffer
 *
 *   1. Binary protocol handler puts response in TX ring buffer
 *   2. at_spi_write_data queues SPI_SLAVE_WR message
 *   3. SPI task: reads from TX ring, writes status reg (dir=WR, seq, len), queues TX DMA, asserts HS
 *   4. M1 clocks data out → transfer complete
 */

#include "spi_link.h"
#include "driver/spi_slave_hd.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/stream_buffer.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "spi_link";

/* Config — must match AT firmware exactly */
#define AT_SPI_DMA_SIZE         4092
#define RX_STREAM_BUFFER_SIZE   8192
#define TX_STREAM_BUFFER_SIZE   8192
#define SLAVE_CONFIG_ADDR       4

/* Direction codes — match M1's spi_mode_t enum (esp_driver_spi/spi_master.h):
 *   SPI_NULL  = 0
 *   SPI_READ  = 1  (slave -> master, ESP32 sends data to M1)
 *   SPI_WRITE = 2  (master -> slave, M1 sends data to ESP32)
 */
#define SPI_SLAVE_RD    2   /* M1 (master) writes, ESP32 (slave) reads */
#define SPI_SLAVE_WR    1   /* ESP32 (slave) writes, M1 (master) reads */

/* Status register layout — matches M1's spi_recv_opt_t exactly */
typedef struct __attribute__((packed)) {
    uint8_t  direct;
    uint8_t  seq_num;
    uint16_t transmit_len;
} spi_rd_status_opt_t;

/* Message for SPI task queue */
typedef struct {
    uint8_t direct;
} spi_msg_t;

/* State */
static StreamBufferHandle_t s_rx_ring;
static StreamBufferHandle_t s_tx_ring;
static SemaphoreHandle_t    s_rw_sema;
static QueueHandle_t        s_msg_queue;
static TaskHandle_t         s_task_handle;

static uint8_t s_tx_seq;
static uint8_t s_rx_seq;
static uint8_t s_init_tx_flag;

/* ---------- Status register write (both offsets — M1 reads from offset 0) ---------- */

static void spi_write_transmit_len(uint8_t spi_mode, uint16_t transmit_len)
{
    spi_rd_status_opt_t status;
    status.direct = spi_mode;
    status.transmit_len = transmit_len;

    if (spi_mode == SPI_SLAVE_WR) {
        status.seq_num = ++s_tx_seq;
    } else {
        status.seq_num = ++s_rx_seq;
    }

    spi_slave_hd_write_buffer(SPI2_HOST, SLAVE_CONFIG_ADDR,
                              (uint8_t *)&status, sizeof(status));
    spi_slave_hd_write_buffer(SPI2_HOST, 0,
                              (uint8_t *)&status, sizeof(status));
}

/* ---------- WRBUF callback (ISR context) ---------- */

static bool master_write_buffer_cb(void *arg, spi_slave_hd_event_t *event,
                                   BaseType_t *awoken)
{
    spi_msg_t msg = { .direct = SPI_SLAVE_RD };
    xQueueSendFromISR(s_msg_queue, &msg, awoken);
    return true;
}

/* ---------- SPI task (replicates at_spi_task exactly) ---------- */

static void spi_link_task(void *arg)
{
    uint8_t *buffer = malloc(AT_SPI_DMA_SIZE);
    if (!buffer) {
        ESP_LOGE(TAG, "malloc failed");
        return;
    }

    spi_slave_hd_data_t *ret_trans;

    while (1) {
        memset(buffer, 0, AT_SPI_DMA_SIZE);
        spi_msg_t msg = {0};

        /* Deassert handshake */
        gpio_set_level(SPI_LINK_PIN_HS, 0);

        /* Wait for event (M1 write or our TX data ready) */
        xQueueReceive(s_msg_queue, &msg, portMAX_DELAY);

        spi_slave_hd_data_t slave_trans;
        memset(&slave_trans, 0, sizeof(slave_trans));

        if (msg.direct == SPI_SLAVE_RD) {
            /* M1 → ESP32: master wants to send us data */
            spi_write_transmit_len(SPI_SLAVE_RD, AT_SPI_DMA_SIZE);

            slave_trans.data = buffer;
            slave_trans.len = AT_SPI_DMA_SIZE;
            ESP_ERROR_CHECK(spi_slave_hd_queue_trans(SPI2_HOST, SPI_SLAVE_CHAN_RX,
                                                     &slave_trans, portMAX_DELAY));

            /* Assert handshake — tell M1 we're ready */
            gpio_set_level(SPI_LINK_PIN_HS, 1);

            ESP_ERROR_CHECK(spi_slave_hd_get_trans_res(SPI2_HOST, SPI_SLAVE_CHAN_RX,
                                                       &ret_trans, portMAX_DELAY));

            if (ret_trans->trans_len > 0 && ret_trans->trans_len <= RX_STREAM_BUFFER_SIZE) {
                xStreamBufferSend(s_rx_ring, buffer, ret_trans->trans_len, portMAX_DELAY);
            }

        } else if (msg.direct == SPI_SLAVE_WR) {
            /* ESP32 → M1: we have data to send */
            uint32_t remain_len = xStreamBufferBytesAvailable(s_tx_ring);
            if (remain_len == 0) {
                s_init_tx_flag = 0;
                continue;
            }

            uint32_t to_send = remain_len > AT_SPI_DMA_SIZE ? AT_SPI_DMA_SIZE : remain_len;
            spi_write_transmit_len(SPI_SLAVE_WR, to_send);

            uint32_t actual = xStreamBufferReceive(s_tx_ring, buffer, to_send, 0);
            if (actual != to_send) {
                ESP_LOGE(TAG, "TX read len mismatch (expect:%lu actual:%lu)", to_send, actual);
                continue;
            }

            slave_trans.data = buffer;
            slave_trans.len = to_send;
            ESP_ERROR_CHECK(spi_slave_hd_queue_trans(SPI2_HOST, SPI_SLAVE_CHAN_TX,
                                                     &slave_trans, portMAX_DELAY));

            /* Assert handshake — tell M1 to read */
            gpio_set_level(SPI_LINK_PIN_HS, 1);

            ESP_ERROR_CHECK(spi_slave_hd_get_trans_res(SPI2_HOST, SPI_SLAVE_CHAN_TX,
                                                       &ret_trans, portMAX_DELAY));

            /* Check if more TX data pending */
            xSemaphoreTake(s_rw_sema, portMAX_DELAY);
            remain_len = xStreamBufferBytesAvailable(s_tx_ring);
            if (remain_len > 0) {
                spi_msg_t tx_msg = { .direct = SPI_SLAVE_WR };
                xQueueSend(s_msg_queue, &tx_msg, 0);
            } else {
                s_init_tx_flag = 0;
            }
            xSemaphoreGive(s_rw_sema);
        }
    }
}

/* ---------- Public API ---------- */

esp_err_t spi_link_init(void)
{
    s_rw_sema = xSemaphoreCreateMutex();
    s_msg_queue = xQueueCreate(10, sizeof(spi_msg_t));
    s_rx_ring = xStreamBufferCreate(RX_STREAM_BUFFER_SIZE, 1);
    s_tx_ring = xStreamBufferCreate(TX_STREAM_BUFFER_SIZE, 1);
    if (!s_rw_sema || !s_msg_queue || !s_rx_ring || !s_tx_ring) {
        ESP_LOGE(TAG, "Failed to create buffers");
        return ESP_ERR_NO_MEM;
    }

    s_tx_seq = 0;
    s_rx_seq = 0;
    s_init_tx_flag = 0;

    /* Handshake GPIO — output, default low */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << SPI_LINK_PIN_HS),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_down_en = 0,
        .pull_up_en   = 0,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(SPI_LINK_PIN_HS, 0);

    /* SPI bus config */
    spi_bus_config_t bus_cfg = {
        .mosi_io_num     = SPI_LINK_PIN_MOSI,
        .miso_io_num     = SPI_LINK_PIN_MISO,
        .sclk_io_num     = SPI_LINK_PIN_SCLK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = AT_SPI_DMA_SIZE,
    };

    /* SPI slave half-duplex config — matches AT firmware exactly */
    spi_slave_hd_slot_config_t slave_cfg = {
        .spics_io_num  = SPI_LINK_PIN_CS,
        .flags         = 0,
        .mode          = SPI_LINK_MODE,
        .command_bits  = 8,
        .address_bits  = 8,
        .dummy_bits    = 8,
        .queue_size    = 4,
        .dma_chan       = SPI_DMA_CH_AUTO,
        .cb_config = {
            .cb_buffer_rx = master_write_buffer_cb,
            .cb_recv      = NULL,
        },
    };

    esp_err_t err = spi_slave_hd_init(SPI2_HOST, &bus_cfg, &slave_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "spi_slave_hd_init failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "SPI slave HD initialized (SCLK=%d MOSI=%d MISO=%d CS=%d HS=%d mode=%d)",
             SPI_LINK_PIN_SCLK, SPI_LINK_PIN_MOSI, SPI_LINK_PIN_MISO,
             SPI_LINK_PIN_CS, SPI_LINK_PIN_HS, SPI_LINK_MODE);

    xTaskCreate(spi_link_task, "spi_link", 4096, NULL, 10, &s_task_handle);
    return ESP_OK;
}

int spi_link_receive(uint8_t *buf, size_t buf_size, uint32_t timeout_ms)
{
    return (int)xStreamBufferReceive(s_rx_ring, buf, buf_size,
                                     pdMS_TO_TICKS(timeout_ms));
}

esp_err_t spi_link_send(const uint8_t *data, size_t len, uint32_t timeout_ms)
{
    size_t sent = xStreamBufferSend(s_tx_ring, data, len,
                                     pdMS_TO_TICKS(timeout_ms));
    if (sent != len) return ESP_ERR_TIMEOUT;

    /* Trigger TX if not already in progress */
    xSemaphoreTake(s_rw_sema, portMAX_DELAY);
    if (s_init_tx_flag == 0) {
        s_init_tx_flag = 1;
        spi_msg_t msg = { .direct = SPI_SLAVE_WR };
        xQueueSend(s_msg_queue, &msg, 0);
    }
    xSemaphoreGive(s_rw_sema);

    return ESP_OK;
}

size_t spi_link_rx_available(void)
{
    return xStreamBufferBytesAvailable(s_rx_ring);
}
