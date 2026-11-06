#ifndef OTA_UPDATE_H
#define OTA_UPDATE_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

bool ota_update_available(void);
esp_err_t ota_update_begin(uint32_t image_size);
esp_err_t ota_update_write(const uint8_t *data, uint16_t len);
esp_err_t ota_update_end(void);
void ota_update_abort(void);

#endif /* OTA_UPDATE_H */
