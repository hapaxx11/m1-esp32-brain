#ifndef WIFI_CHANNEL_MONITOR_H
#define WIFI_CHANNEL_MONITOR_H

#include "esp_err.h"
#include <stdint.h>

esp_err_t wifi_channel_monitor_start(uint8_t mode, uint16_t dwell_ms);
int wifi_channel_monitor_stats(uint8_t *out, uint16_t cap);
void wifi_channel_monitor_stop(void);

#endif /* WIFI_CHANNEL_MONITOR_H */
