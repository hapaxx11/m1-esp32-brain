#ifndef WIFI_PMKID_H
#define WIFI_PMKID_H

#include "esp_err.h"
#include <stdint.h>

typedef enum {
    PMKID_IDLE = 0,
    PMKID_CAPTURING = 1,
    PMKID_COMPLETE = 2,
    PMKID_FAILED = 3,
} pmkid_state_t;

esp_err_t wifi_pmkid_start(const uint8_t bssid[6], uint8_t channel,
                           const char *ssid);
void wifi_pmkid_stop(void);
pmkid_state_t wifi_pmkid_state(void);
uint32_t wifi_pmkid_len(void);
int wifi_pmkid_read(uint32_t offset, uint8_t *out, uint16_t max);

#endif /* WIFI_PMKID_H */
