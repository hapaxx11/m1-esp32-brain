/*
 * WPA 4-way handshake (EAPOL) capture via promiscuous mode.
 *
 * Sniffs 802.11 frames on the target AP's channel, captures the AP beacon
 * and the EAPOL-Key handshake messages (M1..M4), and stores them in a
 * static PCAP-format buffer (LINKTYPE_IEEE802_11) that the host can pull
 * out in chunks with wifi_handshake_read().
 *
 * NOTE: only ONE promiscuous RX callback can be registered at a time.
 * Do not run this concurrently with wifi_sta_scan — this module owns the
 * promiscuous callback while capturing.
 */
#ifndef WIFI_HANDSHAKE_H
#define WIFI_HANDSHAKE_H

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HS_IDLE      = 0,
    HS_CAPTURING = 1,
    HS_COMPLETE  = 2,
} hs_state_t;

/* Begin capturing on the given BSSID/channel. Enters promiscuous mode. */
esp_err_t  wifi_handshake_start(const uint8_t bssid[6], uint8_t channel);

/* Stop capture, unregister callback, and restore normal STA mode. */
void       wifi_handshake_stop(void);

/* Current capture state. */
hs_state_t wifi_handshake_state(void);

/* Bytes of captured PCAP data currently available. */
uint32_t   wifi_handshake_len(void);

/* Copy up to max bytes of PCAP data starting at offset into out.
 * Returns the number of bytes copied (0 at or past end of buffer). */
int        wifi_handshake_read(uint32_t offset, uint8_t *out, uint16_t max);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_HANDSHAKE_H */
