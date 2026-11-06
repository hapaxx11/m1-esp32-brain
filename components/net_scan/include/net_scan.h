#ifndef NET_SCAN_H
#define NET_SCAN_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

esp_err_t net_scan_start(uint8_t mode, uint8_t timeout_ms, uint8_t base_ip[4]);
int net_scan_next(uint8_t *out, uint16_t cap);
void net_scan_stop(void);
bool net_scan_running(void);

#endif /* NET_SCAN_H */
