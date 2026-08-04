/*
 * ble_beacon.c — BLE beacon emulator. See ble_beacon.h.
 *
 * Unlike ble_spam (which rotates payload+address on a worker), a beacon is a
 * single static non-connectable advertisement, so one ble_extadv_start() call
 * (which advertises forever) is all it takes — no worker task. Reuses the
 * non-connectable ext-adv slot (BLE_ADV_INST_SPAM); beacon and spam never run
 * together (one M1 app at a time).
 */

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"

#include "nimble/ble.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"

#include "ble_hid.h"        /* ble_host_ensure_started, ble_extadv_start/stop, ble_static_rnd_addr, BLE_ADV_INST_SPAM */
#include "ble_beacon.h"

#define TAG "BLE_BEACON"
#define BLE_ADV_INST_BEACON  BLE_ADV_INST_SPAM   /* shared non-connectable slot */

static volatile bool s_running;

/* Non-connectable, but drop any stray central just in case. */
static int beacon_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event->type == BLE_GAP_EVENT_CONNECT && event->connect.status == 0)
        ble_gap_terminate(event->connect.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    return 0;
}

static esp_err_t beacon_start_raw(const uint8_t *adv, uint8_t len)
{
    esp_err_t err = ble_host_ensure_started();
    if (err != ESP_OK) return err;

    ble_extadv_stop(BLE_ADV_INST_BEACON);

    uint8_t addr[6];
    ble_static_rnd_addr(addr, 0x03);   /* stable beacon identity (distinct salt) */

    int rc = ble_extadv_start(BLE_ADV_INST_BEACON, false /*non-conn*/, true /*legacy*/,
                              addr, adv, len, beacon_gap_event, NULL);
    if (rc != 0) { ESP_LOGE(TAG, "adv start rc=%d", rc); return ESP_FAIL; }

    s_running = true;
    return ESP_OK;
}

esp_err_t ble_beacon_start_ibeacon(const uint8_t uuid[16], uint16_t major,
                                   uint16_t minor, int8_t tx_power)
{
    if (uuid == NULL) return ESP_ERR_INVALID_ARG;
    uint8_t b[30];
    b[0] = 0x02; b[1] = 0x01; b[2] = 0x06;            /* flags: LE general disc, BR/EDR unsup */
    b[3] = 0x1A; b[4] = 0xFF; b[5] = 0x4C; b[6] = 0x00; /* len 26, mfg-specific, Apple 0x004C */
    b[7] = 0x02; b[8] = 0x15;                         /* iBeacon type 0x02, length 0x15 (21) */
    memcpy(&b[9], uuid, 16);                          /* proximity UUID */
    b[25] = (uint8_t)(major >> 8); b[26] = (uint8_t)(major & 0xFF);  /* big-endian */
    b[27] = (uint8_t)(minor >> 8); b[28] = (uint8_t)(minor & 0xFF);
    b[29] = (uint8_t)tx_power;                        /* measured power @ 1 m */
    ESP_LOGI(TAG, "iBeacon major=%u minor=%u tx=%d", major, minor, tx_power);
    return beacon_start_raw(b, 30);
}

esp_err_t ble_beacon_start_eddystone_url(const char *url)
{
    if (url == NULL || url[0] == '\0') return ESP_ERR_INVALID_ARG;

    /* Scheme prefix code. */
    uint8_t scheme;
    const char *p = url;
    if      (strncmp(p, "https://www.", 12) == 0) { scheme = 0x01; p += 12; }
    else if (strncmp(p, "http://www.",  11) == 0) { scheme = 0x00; p += 11; }
    else if (strncmp(p, "https://",      8) == 0) { scheme = 0x03; p += 8;  }
    else if (strncmp(p, "http://",       7) == 0) { scheme = 0x02; p += 7;  }
    else                                          { scheme = 0x03; }          /* assume https:// */

    /* Body: substitute the standard suffix expansion codes, else raw. Cap at the
     * 17 encoded bytes that fit alongside the flags + service-UUID + header. */
    static const char *exp[] = {
        ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
        ".com",  ".org",  ".edu",  ".net",  ".info",  ".biz",  ".gov",
    };
    uint8_t enc[17];
    int elen = 0;
    while (*p && elen < (int)sizeof(enc)) {
        int m = -1;
        for (int i = 0; i < 14; i++) {
            size_t l = strlen(exp[i]);
            if (strncmp(p, exp[i], l) == 0) { m = i; p += l; break; }
        }
        enc[elen++] = (m >= 0) ? (uint8_t)m : (uint8_t)*p++;
    }

    uint8_t b[31];
    int i = 0;
    b[i++] = 0x02; b[i++] = 0x01; b[i++] = 0x06;              /* flags */
    b[i++] = 0x03; b[i++] = 0x03; b[i++] = 0xAA; b[i++] = 0xFE; /* complete 16-bit svc UUID 0xFEAA */
    b[i++] = (uint8_t)(6 + elen);   /* service-data AD length: type+AAFE+frame+tx+scheme+url */
    b[i++] = 0x16;                  /* service data - 16-bit UUID */
    b[i++] = 0xAA; b[i++] = 0xFE;   /* Eddystone */
    b[i++] = 0x10;                  /* frame type: URL */
    b[i++] = 0x00;                  /* TX power @ 0 m (informational) */
    b[i++] = scheme;
    memcpy(&b[i], enc, (size_t)elen); i += elen;

    ESP_LOGI(TAG, "Eddystone-URL scheme=%u urllen=%d", scheme, elen);
    return beacon_start_raw(b, (uint8_t)i);
}

void ble_beacon_stop(void)
{
    if (!s_running) return;
    s_running = false;
    ble_extadv_stop(BLE_ADV_INST_BEACON);
    ESP_LOGI(TAG, "beacon stop");
}

bool ble_beacon_is_running(void)
{
    return s_running;
}
