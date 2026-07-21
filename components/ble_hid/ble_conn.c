/*
 * ble_conn.c — BLE central-connect + generic advertising on the shared NimBLE
 * host (ESP32-C6, ESP-IDF v5.1).
 *
 * Both capabilities here share the single NimBLE host brought up by ble_hid
 * (ble_host_ensure_started / ble_host_own_addr_type). They use their own GAP
 * callback and their own connection-handle state so they do NOT interfere with
 * the HID peripheral (ble_hid.c) or the central scanner (ble_scan.c).
 *
 *   - ble_conn_connect() initiates a GAP connect and blocks on a binary
 *     semaphore that the GAP callback gives on BLE_GAP_EVENT_CONNECT.
 *   - ble_adv_start() starts undirected connectable advertising with a generic
 *     (non-HID) name/appearance.
 *
 * NimBLE runs its host in its own task; the GAP callback below executes in that
 * host-task context, so shared state is published with a mutex-free, single-
 * writer discipline plus the connect handshake semaphore.
 */

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "nimble/ble.h"            /* ble_addr_t, BLE_ADDR_* */
#include "host/ble_gap.h"
#include "host/ble_hs.h"          /* BLE_HS_FOREVER, BLE_HS_CONN_HANDLE_NONE, err codes */
#include "host/ble_hs_adv.h"      /* struct ble_hs_adv_fields */
#include "host/ble_uuid.h"

#include "ble_hid.h"              /* ble_host_ensure_started, ble_host_own_addr_type */
#include "ble_conn.h"

#define TAG "BLE_CONN"

/* Generic "Unknown" appearance for non-HID advertising. */
#define GENERIC_APPEARANCE  0x0000

/* ---- Central-connect state (single writer: the host-task GAP callback) ---- */

static bool     s_conn_active   = false;                    /* link established */
static uint16_t s_conn_handle   = BLE_HS_CONN_HANDLE_NONE;
static int      s_conn_status   = -1;                       /* status from CONNECT event */

static StaticSemaphore_t s_conn_sem_buf;
static SemaphoreHandle_t s_conn_sem;      /* binary: given on CONNECT event */

/* ---- Generic-advertising state ----------------------------------------- */

static char     s_adv_name[32];
static bool     s_adv_active = false;

static void     ble_adv_begin(void);

static void
conn_sem_init_once(void)
{
    if (s_conn_sem == NULL)
        s_conn_sem = xSemaphoreCreateBinaryStatic(&s_conn_sem_buf);
}

/* ========================================================================
 * GAP callback — owns ONLY this module's connect + generic-adv instances.
 * ======================================================================== */

static int
ble_conn_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        s_conn_status = event->connect.status;
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_conn_active = true;
            ESP_LOGI(TAG, "connected; conn_handle=%d", s_conn_handle);
        } else {
            s_conn_active = false;
            s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
            ESP_LOGW(TAG, "connect failed; status=%d", event->connect.status);
        }
        /* Wake ble_conn_connect() whether it succeeded or failed. */
        if (s_conn_sem != NULL)
            xSemaphoreGive(s_conn_sem);
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        /* Only our own link is reported through this callback. */
        ESP_LOGI(TAG, "disconnect; reason=%d", event->disconnect.reason);
        s_conn_active = false;
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        /* Generic adv uses BLE_HS_FOREVER so this normally only fires on stop. */
        ESP_LOGI(TAG, "generic adv complete; reason=%d",
                 event->adv_complete.reason);
        if (s_adv_active)
            ble_adv_begin();          /* keep advertising if still requested */
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "encryption change; status=%d", event->enc_change.status);
        return 0;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "mtu update; conn=%d mtu=%d",
                 event->mtu.conn_handle, event->mtu.value);
        return 0;

    default:
        return 0;
    }
}

/* ========================================================================
 * Central connect
 * ======================================================================== */

esp_err_t
ble_conn_connect(const uint8_t addr[6], uint8_t addr_type, uint32_t timeout_ms)
{
    esp_err_t err;
    int       rc;

    if (addr == NULL)
        return ESP_ERR_INVALID_ARG;

    conn_sem_init_once();

    /* Bring up the shared host (no-op if HID / scan already started it). */
    err = ble_host_ensure_started();
    if (err != ESP_OK)
        return err;

    /* own_addr_type is only known after host sync. */
    int at = ble_host_own_addr_type();
    if (at < 0) {
        ESP_LOGE(TAG, "host not synced; cannot connect yet");
        return ESP_ERR_INVALID_STATE;
    }

    /* A connect cannot be initiated while a discovery/scan is in progress. */
    if (ble_gap_disc_active()) {
        rc = ble_gap_disc_cancel();
        if (rc != 0 && rc != BLE_HS_EALREADY)
            ESP_LOGW(TAG, "ble_gap_disc_cancel; rc=%d", rc);
    }

    /* Reset handshake state and drain any stale semaphore token. */
    s_conn_active = false;
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_conn_status = -1;
    xSemaphoreTake(s_conn_sem, 0);

    ble_addr_t peer;
    peer.type = addr_type;
    memcpy(peer.val, addr, 6);

    /* Default connection parameters (params = NULL). Duration for connection
     * establishment mirrors the caller's timeout. */
    int32_t duration_ms = (timeout_ms == 0)
                        ? BLE_HS_FOREVER
                        : (int32_t)timeout_ms;

    rc = ble_gap_connect((uint8_t)at, &peer, duration_ms, NULL,
                         ble_conn_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_connect failed; rc=%d", rc);
        return ESP_FAIL;
    }

    /* Block for the CONNECT event (or timeout). */
    TickType_t wait = (timeout_ms == 0)
                    ? portMAX_DELAY
                    : pdMS_TO_TICKS(timeout_ms);

    if (xSemaphoreTake(s_conn_sem, wait) != pdTRUE) {
        /* Timed out waiting for establishment — abort the pending connect. */
        ESP_LOGW(TAG, "connect timed out after %lums", (unsigned long)timeout_ms);
        rc = ble_gap_conn_cancel();
        if (rc != 0 && rc != BLE_HS_EALREADY)
            ESP_LOGW(TAG, "ble_gap_conn_cancel; rc=%d", rc);
        return ESP_ERR_TIMEOUT;
    }

    if (!s_conn_active) {
        ESP_LOGW(TAG, "connect completed but not established; status=%d",
                 s_conn_status);
        return ESP_ERR_TIMEOUT;
    }

    return ESP_OK;
}

void
ble_conn_disconnect(void)
{
    if (s_conn_active && s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        int rc = ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        if (rc != 0 && rc != BLE_HS_EALREADY)
            ESP_LOGW(TAG, "ble_gap_terminate; rc=%d", rc);
    }
}

bool
ble_conn_is_connected(void)
{
    return s_conn_active;
}

/* ========================================================================
 * Generic (non-HID) advertising
 * ======================================================================== */

static void
ble_adv_begin(void)
{
    struct ble_gap_adv_params adv_params;
    struct ble_hs_adv_fields  fields;
    int rc;

    int at = ble_host_own_addr_type();
    if (at < 0) {
        ESP_LOGE(TAG, "host not synced; cannot advertise yet");
        return;
    }

    memset(&fields, 0, sizeof fields);

    /* General discoverable + BLE-only (BR/EDR unsupported). */
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

    fields.appearance = GENERIC_APPEARANCE;
    fields.appearance_is_present = 1;

    fields.name = (uint8_t *)s_adv_name;
    fields.name_len = strlen(s_adv_name);
    fields.name_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields failed; rc=%d", rc);
        return;
    }

    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;   /* undirected connectable */
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;   /* general discoverable */

    rc = ble_gap_adv_start((uint8_t)at, NULL, BLE_HS_FOREVER,
                           &adv_params, ble_conn_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start failed; rc=%d", rc);
        return;
    }
    ESP_LOGI(TAG, "generic advertising as \"%s\"", s_adv_name);
}

esp_err_t
ble_adv_start(const char *name)
{
    esp_err_t err;

    if (name != NULL && name[0] != '\0') {
        strncpy(s_adv_name, name, sizeof(s_adv_name) - 1);
        s_adv_name[sizeof(s_adv_name) - 1] = '\0';
    } else {
        strcpy(s_adv_name, "ESP32-C6");
    }

    err = ble_host_ensure_started();
    if (err != ESP_OK)
        return err;

    s_adv_active = true;

    /* Legacy advertising is a single instance: stop whatever is advertising
     * (e.g. HID) before starting ours. Harmless if nothing is advertising. */
    ble_gap_adv_stop();

    /* If the host hasn't synced yet, ble_adv_begin() will log and no-op; the
     * caller is expected to start advertising after the host is up (as HID and
     * scan do). Once synced, start immediately. */
    if (ble_host_own_addr_type() >= 0)
        ble_adv_begin();
    else
        ESP_LOGI(TAG, "generic adv queued; host not yet synced");

    return ESP_OK;
}

void
ble_adv_stop(void)
{
    s_adv_active = false;
    int rc = ble_gap_adv_stop();
    if (rc != 0 && rc != BLE_HS_EALREADY)
        ESP_LOGW(TAG, "ble_gap_adv_stop; rc=%d", rc);
}
