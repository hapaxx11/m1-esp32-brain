#ifndef WIFI_CSI_H
#define WIFI_CSI_H

#include "esp_err.h"
#include <stdint.h>

esp_err_t wifi_csi_start(uint8_t mode, uint8_t channel, const uint8_t source_mac[6]);
int wifi_csi_status(uint8_t *out, uint16_t cap);
void wifi_csi_stop(void);

#endif /* WIFI_CSI_H */
