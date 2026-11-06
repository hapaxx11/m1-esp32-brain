#ifndef WIFI_WPS_H
#define WIFI_WPS_H

#include "esp_err.h"
#include <stdint.h>

esp_err_t wifi_wps_start(uint16_t hop_dwell_ms);
int wifi_wps_next(uint8_t *out, uint16_t cap);
void wifi_wps_stop(void);

#endif /* WIFI_WPS_H */
