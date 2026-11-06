#include "ota_update.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include <string.h>

static esp_ota_handle_t s_handle;
static const esp_partition_t *s_target;
static uint32_t s_expected;
static uint32_t s_written;
static bool s_active;

bool ota_update_available(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    return running && running->subtype != ESP_PARTITION_SUBTYPE_APP_FACTORY &&
           esp_ota_get_next_update_partition(NULL) != NULL;
}

esp_err_t ota_update_begin(uint32_t image_size)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    if (!ota_update_available() || image_size < 1024) return ESP_ERR_INVALID_ARG;
    s_target = esp_ota_get_next_update_partition(NULL);
    if (!s_target || image_size > s_target->size) return ESP_ERR_INVALID_ARG;
    esp_err_t err = esp_ota_begin(s_target, OTA_SIZE_UNKNOWN, &s_handle);
    if (err != ESP_OK) return err;
    s_expected = image_size;
    s_written = 0;
    s_active = true;
    return ESP_OK;
}

esp_err_t ota_update_write(const uint8_t *data, uint16_t len)
{
    if (!s_active || (!data && len) || s_written + len > s_expected)
        return ESP_ERR_INVALID_ARG;
    if (!len) return ESP_OK;
    esp_err_t err = esp_ota_write(s_handle, data, len);
    if (err != ESP_OK) {
        ota_update_abort();
        return err;
    }
    s_written += len;
    return ESP_OK;
}

esp_err_t ota_update_end(void)
{
    if (!s_active || s_written != s_expected) return ESP_ERR_INVALID_STATE;
    esp_err_t err = esp_ota_end(s_handle);
    s_active = false;
    if (err != ESP_OK) return err;
    return esp_ota_set_boot_partition(s_target);
}

void ota_update_abort(void)
{
    if (!s_active) return;
    esp_ota_abort(s_handle);
    s_active = false;
    s_expected = 0;
    s_written = 0;
    s_target = NULL;
}
