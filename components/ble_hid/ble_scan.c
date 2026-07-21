/*
 * ble_scan.c — BLE central (observer) scan for the shared NimBLE host.
 *
 * Shares the single NimBLE host brought up by ble_hid (ble_host_ensure_started)
 * so the ESP32-C6 acts as HID peripheral and scanning central simultaneously.
 * Discovered advertisers are deduped by address into a static, mutex-protected
 * table; the GAP discovery callback runs in the NimBLE host task context.
 */

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "nimble/ble.h"            /* ble_addr_t, BLE_ADDR_* */
#include "host/ble_gap.h"
#include "host/ble_hs_adv.h"       /* struct ble_hs_adv_fields, parse */

#include "ble_hid.h"               /* ble_host_ensure_started, ble_host_own_addr_type */
#include "ble_scan.h"

#define TAG "BLE_SCAN"

#define BLE_SCAN_MAX_DEVS  32

/* ---- Results table (static, mutex-protected) --------------------------- */

static ble_scan_dev_t   s_devs[BLE_SCAN_MAX_DEVS];
static int              s_dev_count;

static StaticSemaphore_t s_mutex_buf;
static SemaphoreHandle_t s_mutex;          /* guards s_devs / s_dev_count */

/* ---- Deferred-scan state (start requested before host sync) ------------ */

static bool     s_scan_requested;          /* a scan is desired/active */
static uint16_t s_scan_duration_sec;

static void
scan_lock_init_once(void)
{
    if (s_mutex == NULL)
        s_mutex = xSemaphoreCreateMutexStatic(&s_mutex_buf);
}

/* ---- Discovery report handling ----------------------------------------- */

static void
scan_store_report(const struct ble_gap_disc_desc *disc)
{
    struct ble_hs_adv_fields fields;
    char    name[sizeof(((ble_scan_dev_t *)0)->name)] = {0};
    int     name_len = 0;

    /* Parse advertisement fields for the local name. NimBLE places both the
     * complete (0x09) and shortened (0x08) name into fields.name. */
    if (disc->data != NULL && disc->length_data > 0 &&
        ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data) == 0 &&
        fields.name != NULL && fields.name_len > 0) {
        name_len = fields.name_len;
        if (name_len > (int)sizeof(name) - 1)
            name_len = (int)sizeof(name) - 1;
        memcpy(name, fields.name, name_len);
        name[name_len] = '\0';
    }

    if (s_mutex == NULL)
        return;
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    /* Dedupe by address (val + type). */
    int idx = -1;
    for (int i = 0; i < s_dev_count; i++) {
        if (s_devs[i].addr_type == disc->addr.type &&
            memcmp(s_devs[i].addr, disc->addr.val, 6) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        if (s_dev_count < BLE_SCAN_MAX_DEVS) {
            idx = s_dev_count++;
            memcpy(s_devs[idx].addr, disc->addr.val, 6);
            s_devs[idx].addr_type = disc->addr.type;
            s_devs[idx].name[0] = '\0';
        }
    }

    if (idx >= 0) {
        s_devs[idx].rssi = disc->rssi;          /* refresh RSSI each sighting */
        /* Fill the name once we have seen it (scan response may arrive late). */
        if (name_len > 0 && s_devs[idx].name[0] == '\0')
            memcpy(s_devs[idx].name, name, name_len + 1);
    }

    xSemaphoreGive(s_mutex);
}

static int
ble_scan_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        scan_store_report(&event->disc);
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        ESP_LOGI(TAG, "scan complete; reason=%d", event->disc_complete.reason);
        s_scan_requested = false;
        return 0;

    default:
        return 0;
    }
}

/* ---- Scan start (own_addr_type must be known) -------------------------- */

static esp_err_t
scan_begin(uint8_t own_addr_type, uint16_t duration_sec)
{
    struct ble_gap_disc_params params;
    int32_t duration_ms = (duration_sec == 0)
                        ? BLE_HS_FOREVER
                        : (int32_t)duration_sec * 1000;

    memset(&params, 0, sizeof params);
    params.passive = 0;            /* active scan -> collect scan-response names */
    params.limited = 0;            /* general discovery */
    params.filter_duplicates = 0;  /* we dedupe ourselves and refresh RSSI */
    params.filter_policy = 0;      /* accept all */
    /* itvl/window = 0 -> NimBLE defaults. */

    int rc = ble_gap_disc(own_addr_type, duration_ms, &params,
                          ble_scan_gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "ble_gap_disc failed; rc=%d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "scanning (duration=%us, addr_type=%d)",
             duration_sec, own_addr_type);
    return ESP_OK;
}

/* ---- Public API -------------------------------------------------------- */

esp_err_t
ble_scan_start(uint16_t duration_sec)
{
    esp_err_t err;

    scan_lock_init_once();

    /* Clear the results table. */
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_dev_count = 0;
    memset(s_devs, 0, sizeof s_devs);
    xSemaphoreGive(s_mutex);

    /* Bring up the shared host (no-op if HID already started it). */
    err = ble_host_ensure_started();
    if (err != ESP_OK)
        return err;

    s_scan_duration_sec = duration_sec;
    s_scan_requested = true;

    /* If the host has already synced, start immediately; otherwise the sync
     * callback will call ble_scan_on_host_sync() to begin the scan. */
    int at = ble_host_own_addr_type();
    if (at >= 0)
        return scan_begin((uint8_t)at, duration_sec);

    ESP_LOGI(TAG, "scan queued; will start after host sync");
    return ESP_OK;
}

void
ble_scan_stop(void)
{
    s_scan_requested = false;
    int rc = ble_gap_disc_cancel();
    if (rc != 0 && rc != BLE_HS_EALREADY)
        ESP_LOGW(TAG, "ble_gap_disc_cancel; rc=%d", rc);
}

int
ble_scan_get_results(ble_scan_dev_t *out, int max)
{
    if (out == NULL || max <= 0 || s_mutex == NULL)
        return 0;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = s_dev_count;
    if (n > max)
        n = max;
    for (int i = 0; i < n; i++)
        out[i] = s_devs[i];
    xSemaphoreGive(s_mutex);

    return n;
}

void
ble_scan_on_host_sync(void)
{
    if (!s_scan_requested)
        return;
    if (ble_gap_disc_active())
        return;

    int at = ble_host_own_addr_type();
    if (at >= 0)
        scan_begin((uint8_t)at, s_scan_duration_sec);
}
