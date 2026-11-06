#include "ble_gatt.h"
#include "ble_hid.h"
#include "ble_scan.h"
#include "ble_conn.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs_mbuf.h"
#include <string.h>

#define TAG "ble_gatt"
#define MAX_GATT_ENTRIES 64
#define MAX_GATT_SERVICES 12
#define MAX_GATT_NOTIFS 8
#define MAX_GATT_NOTIFY_VALUE 48
#define GATT_ENTRY_SVC 1
#define GATT_ENTRY_CHR 2
#define GATT_ENTRY_DSC 3
#define GATT_WRITE_NO_RSP 0x01

typedef struct {
    uint8_t type;
    uint16_t handle1;
    uint16_t handle2;
    uint8_t props;
    uint8_t uuid_len;
    uint8_t uuid[16];
    uint8_t value_len;
    uint8_t value[16];
} gatt_entry_t;

typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
} gatt_service_t;

typedef struct {
    uint16_t handle;
    uint8_t indication;
    uint8_t value_len;
    uint8_t value[MAX_GATT_NOTIFY_VALUE];
} gatt_notif_t;

static SemaphoreHandle_t s_sem;
static gatt_entry_t s_entries[MAX_GATT_ENTRIES];
static gatt_service_t s_services[MAX_GATT_SERVICES];
static QueueHandle_t s_notif_queue;
static StaticQueue_t s_notif_queue_ctrl;
static uint8_t s_notif_queue_store[MAX_GATT_NOTIFS * sizeof(gatt_notif_t)];
static uint16_t s_entry_count;
static uint16_t s_entry_index;
static uint8_t s_service_count;
static uint16_t s_conn = BLE_HS_CONN_HANDLE_NONE;
static volatile int s_status;
static volatile uint8_t s_state;
static volatile bool s_stop;
static bool s_worker_active;
static ble_addr_t s_peer;
static gatt_entry_t *s_read_target;
static uint32_t s_session;

static void notify_reset(void)
{
    if (s_notif_queue)
        xQueueReset(s_notif_queue);
}

static bool session_current(const void *arg)
{
    return (uint32_t)(uintptr_t)arg == s_session;
}

static void procedure_abort(void)
{
    s_read_target = NULL;
    s_session++;
    if (s_conn != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
        s_conn = BLE_HS_CONN_HANDLE_NONE;
    } else {
        ble_gap_conn_cancel();
    }
}

static bool procedure_wait(uint32_t timeout_ms)
{
    if (xSemaphoreTake(s_sem, pdMS_TO_TICKS(timeout_ms)) == pdTRUE && s_status == 0)
        return true;
    procedure_abort();
    return false;
}

static void uuid_store(const ble_uuid_any_t *uuid, gatt_entry_t *entry)
{
    if (uuid->u.type == BLE_UUID_TYPE_16) {
        uint16_t v = BLE_UUID16(uuid)->value;
        entry->uuid_len = 2;
        entry->uuid[0] = (uint8_t)v;
        entry->uuid[1] = (uint8_t)(v >> 8);
    } else if (uuid->u.type == BLE_UUID_TYPE_32) {
        uint32_t v = BLE_UUID32(uuid)->value;
        entry->uuid_len = 4;
        entry->uuid[0] = (uint8_t)v;
        entry->uuid[1] = (uint8_t)(v >> 8);
        entry->uuid[2] = (uint8_t)(v >> 16);
        entry->uuid[3] = (uint8_t)(v >> 24);
    } else {
        entry->uuid_len = 16;
        memcpy(entry->uuid, BLE_UUID128(uuid)->value, 16);
    }
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    if (!session_current(arg))
        return 0;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        s_status = event->connect.status;
        if (!event->connect.status) s_conn = event->connect.conn_handle;
        if (s_sem) xSemaphoreGive(s_sem);
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        s_conn = BLE_HS_CONN_HANDLE_NONE;
        s_status = -1;
        if (s_sem) xSemaphoreGive(s_sem);
        break;
    case BLE_GAP_EVENT_NOTIFY_RX: {
        if (!s_notif_queue)
            break;
        gatt_notif_t n = {0};
        n.handle = event->notify_rx.attr_handle;
        n.indication = event->notify_rx.indication ? 1 : 0;
        if (event->notify_rx.om) {
            uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
            if (len > sizeof(n.value)) len = sizeof(n.value);
            if (len && os_mbuf_copydata(event->notify_rx.om, 0, len, n.value) == 0)
                n.value_len = len;
        }
        gatt_notif_t discarded;
        if (xQueueSend(s_notif_queue, &n, 0) != pdTRUE) {
            (void)xQueueReceive(s_notif_queue, &discarded, 0);
            (void)xQueueSend(s_notif_queue, &n, 0);
        }
        break;
    }
    default:
        break;
    }
    return 0;
}

static int svc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                  const struct ble_gatt_svc *service, void *arg)
{
    (void)conn_handle;
    if (!session_current(arg))
        return 0;
    if (error->status == BLE_HS_EDONE || error->status != 0) {
        s_status = error->status == BLE_HS_EDONE ? 0 : error->status;
        if (s_sem) xSemaphoreGive(s_sem);
        return 0;
    }
    if (s_entry_count < MAX_GATT_ENTRIES) {
        gatt_entry_t *e = &s_entries[s_entry_count++];
        memset(e, 0, sizeof(*e));
        e->type = GATT_ENTRY_SVC;
        e->handle1 = service->start_handle;
        e->handle2 = service->end_handle;
        uuid_store(&service->uuid, e);
    }
    if (s_service_count < MAX_GATT_SERVICES) {
        s_services[s_service_count].start_handle = service->start_handle;
        s_services[s_service_count].end_handle = service->end_handle;
        s_service_count++;
    }
    return 0;
}

static int chr_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                  const struct ble_gatt_chr *chr, void *arg)
{
    (void)conn_handle;
    if (!session_current(arg))
        return 0;
    if (error->status == BLE_HS_EDONE || error->status != 0) {
        s_status = error->status == BLE_HS_EDONE ? 0 : error->status;
        if (s_sem) xSemaphoreGive(s_sem);
        return 0;
    }
    if (s_entry_count < MAX_GATT_ENTRIES) {
        gatt_entry_t *e = &s_entries[s_entry_count++];
        memset(e, 0, sizeof(*e));
        e->type = GATT_ENTRY_CHR;
        e->handle1 = chr->def_handle;
        e->handle2 = chr->val_handle;
        e->props = chr->properties;
        uuid_store(&chr->uuid, e);
    }
    return 0;
}

static int dsc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                  uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    (void)conn_handle;
    if (!session_current(arg))
        return 0;
    if (error->status == BLE_HS_EDONE || error->status != 0) {
        s_status = error->status == BLE_HS_EDONE ? 0 : error->status;
        if (s_sem) xSemaphoreGive(s_sem);
        return 0;
    }
    if (s_entry_count < MAX_GATT_ENTRIES) {
        gatt_entry_t *e = &s_entries[s_entry_count++];
        memset(e, 0, sizeof(*e));
        e->type = GATT_ENTRY_DSC;
        e->handle1 = dsc->handle;
        e->handle2 = chr_val_handle;
        uuid_store(&dsc->uuid, e);
    }
    return 0;
}

static int read_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                   struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle;
    if (!session_current(arg))
        return 0;
    if (!error->status && attr && attr->om && s_read_target) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        if (len > sizeof(s_read_target->value)) len = sizeof(s_read_target->value);
        if (len && os_mbuf_copydata(attr->om, 0, len, s_read_target->value) == 0)
            s_read_target->value_len = len;
    }
    s_status = error->status;
    if (s_sem) xSemaphoreGive(s_sem);
    return 0;
}

static int write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                    struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle;
    (void)attr;
    if (!session_current(arg))
        return 0;
    s_status = error->status;
    if (s_sem) xSemaphoreGive(s_sem);
    return 0;
}

static bool discover(void)
{
    int own = ble_host_own_addr_type();
    if (own < 0) return false;
    s_status = 0;
    int rc = ble_gap_connect((uint8_t)own, &s_peer, 7000, NULL, gap_event,
                             (void *)(uintptr_t)s_session);
    if (rc != 0) {
        procedure_abort();
        return false;
    }
    if (!procedure_wait(8000) || s_conn == BLE_HS_CONN_HANDLE_NONE)
        return false;

    s_status = 0;
    rc = ble_gattc_disc_all_svcs(s_conn, svc_cb, (void *)(uintptr_t)s_session);
    if (rc != 0 || !procedure_wait(7000)) {
        if (rc != 0) procedure_abort();
        return false;
    }

    for (uint8_t i = 0; i < s_service_count && !s_stop; i++) {
        uint16_t first = s_entry_count;
        s_status = 0;
        rc = ble_gattc_disc_all_chrs(s_conn, s_services[i].start_handle,
                                     s_services[i].end_handle, chr_cb,
                                     (void *)(uintptr_t)s_session);
        if (rc != 0 || !procedure_wait(5000)) {
            if (rc != 0) procedure_abort();
            return false;
        }
        uint16_t last = s_entry_count;
        for (uint16_t j = first; j < last && !s_stop; j++) {
            gatt_entry_t *chr = &s_entries[j];
            if (chr->type != GATT_ENTRY_CHR) continue;
            if (chr->props & BLE_GATT_CHR_F_READ) {
                s_read_target = chr;
                s_status = 0;
                rc = ble_gattc_read(s_conn, chr->handle2, read_cb,
                                    (void *)(uintptr_t)s_session);
                if (rc != 0 || !procedure_wait(2500)) {
                    if (rc != 0) procedure_abort();
                    return false;
                }
                s_read_target = NULL;
            }
            uint16_t desc_start = chr->handle2;
            uint16_t desc_end = s_services[i].end_handle;
            for (uint16_t k = j + 1; k < last; k++) {
                if (s_entries[k].type == GATT_ENTRY_CHR) {
                    desc_end = s_entries[k].handle1 - 1;
                    break;
                }
            }
            if (desc_start <= desc_end && s_entry_count < MAX_GATT_ENTRIES) {
                s_status = 0;
                rc = ble_gattc_disc_all_dscs(s_conn, desc_start, desc_end, dsc_cb,
                                             (void *)(uintptr_t)s_session);
                if (rc != 0 || !procedure_wait(3000)) {
                    if (rc != 0) procedure_abort();
                    return false;
                }
            }
        }
    }
    return !s_stop;
}

static void discovery_task(void *arg)
{
    bool ok = discover();
    if (s_conn != BLE_HS_CONN_HANDLE_NONE && (!ok || s_stop)) {
        ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
        s_conn = BLE_HS_CONN_HANDLE_NONE;
    }
    s_state = ok ? 2 : 3;
    s_worker_active = false;
    vTaskDelete(NULL);
}

esp_err_t ble_gatt_start(const uint8_t addr[6], uint8_t addr_type)
{
    if (!addr || s_worker_active || s_conn != BLE_HS_CONN_HANDLE_NONE)
        return ESP_ERR_INVALID_STATE;
    esp_err_t err = ble_host_ensure_started();
    if (err != ESP_OK) return err;
    if (!s_sem) s_sem = xSemaphoreCreateBinary();
    if (!s_sem) return ESP_ERR_NO_MEM;
    if (!s_notif_queue)
        s_notif_queue = xQueueCreateStatic(MAX_GATT_NOTIFS, sizeof(gatt_notif_t),
                                           s_notif_queue_store, &s_notif_queue_ctrl);
    if (!s_notif_queue) return ESP_ERR_NO_MEM;

    ble_scan_stop();
    ble_conn_disconnect();
    memset(s_entries, 0, sizeof(s_entries));
    memset(s_services, 0, sizeof(s_services));
    notify_reset();
    s_entry_count = 0;
    s_entry_index = 0;
    s_service_count = 0;
    s_conn = BLE_HS_CONN_HANDLE_NONE;
    s_status = 0;
    s_stop = false;
    s_read_target = NULL;
    s_session++;
    s_state = 1;
    s_peer.type = addr_type;
    memcpy(s_peer.val, addr, 6);
    xSemaphoreTake(s_sem, 0);
    s_worker_active = true;
    if (xTaskCreate(discovery_task, "ble_gatt_disc", 6144, NULL, 6, NULL) != pdPASS) {
        s_worker_active = false;
        s_state = 3;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

int ble_gatt_next(uint8_t *out, uint16_t cap)
{
    if (!out || cap < 1) return 0;
    if (s_state == 1) { out[0] = 0xFE; return 1; }
    if (s_state == 3) { out[0] = 0xFD; return 1; }
    if (s_entry_index >= s_entry_count) { out[0] = 0; return 1; }

    gatt_entry_t *e = &s_entries[s_entry_index++];
    uint16_t need = 8 + e->uuid_len + e->value_len;
    if (cap < need) return 0;
    out[0] = e->type;
    out[1] = (uint8_t)e->handle1;
    out[2] = (uint8_t)(e->handle1 >> 8);
    out[3] = (uint8_t)e->handle2;
    out[4] = (uint8_t)(e->handle2 >> 8);
    out[5] = e->props;
    out[6] = e->uuid_len;
    memcpy(&out[7], e->uuid, e->uuid_len);
    uint16_t pos = 7 + e->uuid_len;
    out[pos++] = e->value_len;
    memcpy(&out[pos], e->value, e->value_len);
    return (int)(pos + e->value_len);
}

void ble_gatt_stop(void)
{
    s_stop = true;
    procedure_abort();
    notify_reset();
}

esp_err_t ble_gatt_write(uint16_t handle, uint8_t flags,
                         const uint8_t *value, uint8_t value_len)
{
    if (s_worker_active || s_state == 1)
        return ESP_ERR_INVALID_STATE;
    if (!handle || !value || !value_len || s_conn == BLE_HS_CONN_HANDLE_NONE || !s_sem)
        return ESP_ERR_INVALID_ARG;
    if (flags & GATT_WRITE_NO_RSP)
        return ble_gattc_write_no_rsp_flat(s_conn, handle, value, value_len) == 0
               ? ESP_OK : ESP_FAIL;
    s_status = 0;
    int rc = ble_gattc_write_flat(s_conn, handle, value, value_len, write_cb,
                                  (void *)(uintptr_t)s_session);
    if (rc != 0 || !procedure_wait(4000))
        return ESP_FAIL;
    return ESP_OK;
}

esp_err_t ble_gatt_subscribe(uint16_t handle, bool enable, uint8_t mode)
{
    if (s_worker_active || s_state == 1)
        return ESP_ERR_INVALID_STATE;
    if (!handle || s_conn == BLE_HS_CONN_HANDLE_NONE || !s_sem) return ESP_ERR_INVALID_ARG;
    uint16_t cccd = 0;
    for (uint16_t i = 0; i < s_entry_count; i++) {
        gatt_entry_t *e = &s_entries[i];
        if (e->type == GATT_ENTRY_DSC && e->handle2 == handle &&
            e->uuid_len == 2 && e->uuid[0] == 0x02 && e->uuid[1] == 0x29) {
            cccd = e->handle1;
            break;
        }
    }
    if (!cccd) return ESP_ERR_NOT_FOUND;
    uint8_t value[2] = { enable ? (mode == 2 ? 2 : 1) : 0, 0 };
    s_status = 0;
    int rc = ble_gattc_write_flat(s_conn, cccd, value, sizeof(value), write_cb,
                                  (void *)(uintptr_t)s_session);
    if (rc != 0 || !procedure_wait(4000))
        return ESP_FAIL;
    if (enable) notify_reset();
    return ESP_OK;
}

int ble_gatt_notify_next(uint8_t *out, uint16_t cap)
{
    if (!out || cap < 1) return 0;
    gatt_notif_t n;
    if (!s_notif_queue || xQueueReceive(s_notif_queue, &n, 0) != pdTRUE) {
        out[0] = 0;
        return 1;
    }
    if (n.value_len > MAX_GATT_NOTIFY_VALUE || cap < 5 + n.value_len) return 0;
    out[0] = 1;
    out[1] = (uint8_t)n.handle;
    out[2] = (uint8_t)(n.handle >> 8);
    out[3] = n.indication;
    out[4] = n.value_len;
    memcpy(&out[5], n.value, n.value_len);
    return 5 + n.value_len;
}
