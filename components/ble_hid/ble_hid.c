/*
 * ble_hid.c — Self-contained NimBLE BLE HID keyboard component (ESP32-C6).
 *
 * The HID report map, GATT service definitions, char/descriptor access
 * callbacks and the 8-byte report notify logic are ported VERBATIM from the
 * proven esp32-at-hid firmware (main/at_custom_hid_cmd.c). The NimBLE host
 * init + advertising (which the AT firmware got from the AT library) is
 * implemented here following the ESP-IDF bleprph example.
 */

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"

#include "nvs_flash.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"
#include "host/ble_hs_id.h"
#include "host/util/util.h"
#include "os/os_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ble_hid.h"
#include "ble_nus.h"

#define TAG "BLE_HID"

/* Provided by NimBLE's store/config module (no public header, matches the
 * ESP-IDF bleprph example which forward-declares it the same way). */
void ble_store_config_init(void);

#define HID_APPEARANCE_KEYBOARD   0x03C1
#define HID_SVC_UUID              0x1812

/* ========================================================================
 * HID Data (ported verbatim from at_custom_hid_cmd.c)
 * ======================================================================== */

/* Standard keyboard Report Map descriptor (no Report ID) */
static const uint8_t hid_report_map[] = {
    0x05, 0x01,       /* Usage Page (Generic Desktop)       */
    0x09, 0x06,       /* Usage (Keyboard)                   */
    0xA1, 0x01,       /* Collection (Application)           */
    0x05, 0x07,       /*   Usage Page (Key Codes)           */
    0x19, 0xE0,       /*   Usage Min (224 = Left Control)   */
    0x29, 0xE7,       /*   Usage Max (231 = Right GUI)      */
    0x15, 0x00,       /*   Logical Min (0)                  */
    0x25, 0x01,       /*   Logical Max (1)                  */
    0x75, 0x01,       /*   Report Size (1)                  */
    0x95, 0x08,       /*   Report Count (8)                 */
    0x81, 0x02,       /*   Input (Data, Var, Abs) — Mods    */
    0x95, 0x01,       /*   Report Count (1)                 */
    0x75, 0x08,       /*   Report Size (8)                  */
    0x81, 0x01,       /*   Input (Const) — Reserved         */
    0x95, 0x06,       /*   Report Count (6)                 */
    0x75, 0x08,       /*   Report Size (8)                  */
    0x15, 0x00,       /*   Logical Min (0)                  */
    0x25, 0x65,       /*   Logical Max (101)                */
    0x19, 0x00,       /*   Usage Min (0)                    */
    0x29, 0x65,       /*   Usage Max (101)                  */
    0x81, 0x00,       /*   Input (Data, Array) — Keys       */
    0x95, 0x05,       /*   Report Count (5)                 */
    0x75, 0x01,       /*   Report Size (1)                  */
    0x05, 0x08,       /*   Usage Page (LEDs)                */
    0x19, 0x01,       /*   Usage Min (1 = Num Lock)         */
    0x29, 0x05,       /*   Usage Max (5 = Kana)             */
    0x91, 0x02,       /*   Output (Data, Var, Abs) — LEDs   */
    0x95, 0x01,       /*   Report Count (1)                 */
    0x75, 0x03,       /*   Report Size (3)                  */
    0x91, 0x01,       /*   Output (Const) — Padding         */
    0xC0              /* End Collection                      */
};

/* HID Information: v1.11, country=0, flags=0x02 (normally connectable) */
static const uint8_t hid_info[] = { 0x11, 0x01, 0x00, 0x02 };

/* Protocol Mode: 1 = Report Protocol */
static uint8_t protocol_mode = 0x01;

/* Report Reference descriptors — ID=0 since Report Map has no Report ID */
static const uint8_t report_ref_input[]  = { 0x00, 0x01 }; /* ID=0, Type=Input  */
static const uint8_t report_ref_output[] = { 0x00, 0x02 }; /* ID=0, Type=Output */

/* Characteristic value handles (populated by NimBLE during registration) */
static uint16_t s_report_input_handle  = 0;
static uint16_t s_report_output_handle = 0;

/* Live values */
static uint8_t keyboard_report[8] = {0};
static uint8_t led_report = 0;

/* Device Information Service data */
/* PnP ID: USB vendor source, Espressif VID 0x02E5, PID 1, version 1.0 */
static const uint8_t pnp_id[] = {
    0x02,       /* Vendor ID Source: USB Implementer's Forum */
    0xE5, 0x02, /* Vendor ID: 0x02E5 (Espressif) LE */
    0x01, 0x00, /* Product ID: 1 LE */
    0x00, 0x01  /* Product Version: 1.0.0 LE */
};

/* Battery level — static 100% */
static uint8_t battery_level = 100;

/* ========================================================================
 * Component state (host / connection)
 * ======================================================================== */

static bool     s_host_inited = false;   /* host brought up (once) */
static bool     s_synced      = false;   /* controller/host sync completed */
static bool     s_hid_enabled = false;   /* HID advertising requested */
static bool     s_connected   = false;
/* HID-over-GATT is only usable once the link is ENCRYPTED and the host has
 * SUBSCRIBED to the input-report CCCD. Track both; "ready to type" = all three. */
static bool     s_encrypted        = false;
static bool     s_input_subscribed = false;
static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint8_t  s_own_addr_type;
static char     s_device_name[32] = "ESP32-C6 KB";

static void ble_hid_advertise(void);

/* Defined by the scan module (same component). Invoked from the shared host
 * sync callback so a scan requested before sync can start once the host is
 * ready. Weak so ble_hid links standalone if ble_scan.c is ever excluded. */
void __attribute__((weak)) ble_scan_on_host_sync(void) { }

/* ========================================================================
 * GATT Callbacks (ported verbatim from at_custom_hid_cmd.c)
 * ======================================================================== */

static int
hid_chr_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        switch (uuid16) {
        case 0x2A4A: /* HID Information */
            os_mbuf_append(ctxt->om, hid_info, sizeof(hid_info));
            return 0;
        case 0x2A4B: /* Report Map */
            os_mbuf_append(ctxt->om, hid_report_map, sizeof(hid_report_map));
            return 0;
        case 0x2A4E: /* Protocol Mode */
            os_mbuf_append(ctxt->om, &protocol_mode, 1);
            return 0;
        case 0x2A4D: /* Report (Input or Output — distinguish by handle) */
            if (attr_handle == s_report_input_handle)
                os_mbuf_append(ctxt->om, keyboard_report, sizeof(keyboard_report));
            else
                os_mbuf_append(ctxt->om, &led_report, 1);
            return 0;
        }
    }

    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        switch (uuid16) {
        case 0x2A4C: /* HID Control Point — accept silently */
            return 0;
        case 0x2A4E: /* Protocol Mode */
            if (OS_MBUF_PKTLEN(ctxt->om) >= 1)
                os_mbuf_copydata(ctxt->om, 0, 1, &protocol_mode);
            return 0;
        case 0x2A4D: /* Report Output (LED) */
            if (OS_MBUF_PKTLEN(ctxt->om) >= 1)
                os_mbuf_copydata(ctxt->om, 0, 1, &led_report);
            return 0;
        }
    }

    return 0;
}

static int
hid_dsc_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_DSC) {
        const uint8_t *ref = (const uint8_t *)arg;
        os_mbuf_append(ctxt->om, ref, 2);
    }
    return 0;
}

static int
dis_chr_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        if (uuid16 == 0x2A50) { /* PnP ID */
            os_mbuf_append(ctxt->om, pnp_id, sizeof(pnp_id));
            return 0;
        }
        if (uuid16 == 0x2A29) { /* Manufacturer Name */
            const char *name = "Monstatek";
            os_mbuf_append(ctxt->om, name, strlen(name));
            return 0;
        }
    }
    return 0;
}

static int
bas_chr_access(uint16_t conn_handle, uint16_t attr_handle,
               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        os_mbuf_append(ctxt->om, &battery_level, 1);
    }
    return 0;
}

/* ========================================================================
 * GATT Service Definitions (DIS + Battery + HID) — verbatim
 * ======================================================================== */

static const struct ble_gatt_svc_def hid_svcs[] = {
    /* Device Information Service (0x180A) — required by HOGP for Windows */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180A),
        .characteristics = (struct ble_gatt_chr_def[]) {
            /* PnP ID (0x2A50) — required for Windows HID driver binding */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A50),
                .access_cb = dis_chr_access,
                .flags = BLE_GATT_CHR_F_READ,
            },
            /* Manufacturer Name (0x2A29) */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A29),
                .access_cb = dis_chr_access,
                .flags = BLE_GATT_CHR_F_READ,
            },
            { 0 }
        },
    },
    /* Battery Service (0x180F) — required by HOGP */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180F),
        .characteristics = (struct ble_gatt_chr_def[]) {
            /* Battery Level (0x2A19) — Read + Notify, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A19),
                .access_cb = bas_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY
                       | BLE_GATT_CHR_F_READ_ENC,
            },
            { 0 }
        },
    },
    /* HID Service (0x1812) */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x1812),
        .characteristics = (struct ble_gatt_chr_def[]) {
            /* HID Information (0x2A4A) — Read, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4A),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            /* Report Map (0x2A4B) — Read, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4B),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            /* HID Control Point (0x2A4C) — Write No Response, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4C),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC,
            },
            /* Protocol Mode (0x2A4E) — Read + Write No Response, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4E),
                .access_cb = hid_chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE_NO_RSP
                       | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
            },
            /* Report Input (0x2A4D) — Read + Notify, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4D),
                .access_cb = hid_chr_access,
                .val_handle = &s_report_input_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY
                       | BLE_GATT_CHR_F_READ_ENC,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2908),
                        .access_cb = hid_dsc_access,
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_READ_ENC,
                        .arg = (void *)report_ref_input,
                    },
                    { 0 }
                },
            },
            /* Report Output (0x2A4D) — Read + Write + Write No Response, encrypted */
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4D),
                .access_cb = hid_chr_access,
                .val_handle = &s_report_output_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE
                       | BLE_GATT_CHR_F_WRITE_NO_RSP
                       | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2908),
                        .access_cb = hid_dsc_access,
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_READ_ENC,
                        .arg = (void *)report_ref_output,
                    },
                    { 0 }
                },
            },
            { 0 }  /* End of characteristics */
        },
    },
    { 0 }  /* End of services */
};

/* ========================================================================
 * GAP event handler
 * ======================================================================== */

static int
ble_hid_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_connected = true;
            s_encrypted = false;          /* not usable until encrypted + subscribed */
            s_input_subscribed = false;
            ESP_LOGI(TAG, "connected; conn_handle=%d", s_conn_handle);
        } else {
            ESP_LOGW(TAG, "connect failed; status=%d, re-advertising",
                     event->connect.status);
            s_connected = false;
            s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
            ble_hid_advertise();
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnect; reason=%d", event->disconnect.reason);
        s_connected = false;
        s_encrypted = false;
        s_input_subscribed = false;
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        ble_hid_advertise();
        return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI(TAG, "adv complete; reason=%d, restarting",
                 event->adv_complete.reason);
        ble_hid_advertise();
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        ESP_LOGI(TAG, "subscribe; conn=%d attr=%d cur_notify=%d",
                 event->subscribe.conn_handle,
                 event->subscribe.attr_handle,
                 event->subscribe.cur_notify);
        /* The host enabling notifications on the input report is the real
         * "ready to receive keystrokes" signal — without it, notifications are
         * silently discarded by the host. */
        if (event->subscribe.attr_handle == s_report_input_handle)
            s_input_subscribed = event->subscribe.cur_notify ? true : false;
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "encryption change; status=%d",
                 event->enc_change.status);
        if (event->enc_change.status == 0) {
            s_encrypted = true;
        } else {
            /* Encryption failed — almost always a stale/mismatched bond (the
             * host kept a bond from an earlier flash; ours is gone). Delete the
             * peer so the next connection performs a FRESH pairing instead of
             * looping connect -> encrypt-fail -> disconnect -> re-advertise. */
            s_encrypted = false;
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(event->enc_change.conn_handle, &desc) == 0)
                ble_store_util_delete_peer(&desc.peer_id_addr);
        }
        return 0;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "mtu update; conn=%d mtu=%d",
                 event->mtu.conn_handle, event->mtu.value);
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
        /* Peer re-pairing: drop old bond and accept the new link. */
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0)
            ble_store_util_delete_peer(&desc.peer_id_addr);
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    default:
        return 0;
    }
}

/* ========================================================================
 * Advertising
 * ======================================================================== */

static void
ble_hid_advertise(void)
{
    struct ble_gap_adv_params adv_params;
    struct ble_hs_adv_fields fields;
    int rc;

    memset(&fields, 0, sizeof fields);

    /* General discoverable + BLE-only (BR/EDR unsupported). */
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

    /* Appearance = HID Keyboard so hosts show a keyboard icon and HOGP binds. */
    fields.appearance = HID_APPEARANCE_KEYBOARD;
    fields.appearance_is_present = 1;

    fields.name = (uint8_t *)s_device_name;
    fields.name_len = strlen(s_device_name);
    fields.name_is_complete = 1;

    /* Advertise the HID service UUID (0x1812). */
    fields.uuids16 = (ble_uuid16_t[]) {
        BLE_UUID16_INIT(HID_SVC_UUID)
    };
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields failed; rc=%d", rc);
        return;
    }

    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &adv_params, ble_hid_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start failed; rc=%d", rc);
        return;
    }
    ESP_LOGI(TAG, "advertising as \"%s\"", s_device_name);
}

/* ========================================================================
 * NimBLE host callbacks
 * ======================================================================== */

static void
ble_hid_on_reset(int reason)
{
    ESP_LOGW(TAG, "nimble host reset; reason=%d", reason);
    s_connected = false;
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
}

static void
ble_host_on_sync(void)
{
    int rc;

    /* Make sure we have a proper identity address (public preferred). */
    rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(TAG, "ensure_addr failed; rc=%d", rc);
        return;
    }

    rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "infer_auto failed; rc=%d", rc);
        return;
    }

    uint8_t addr_val[6] = {0};
    ble_hs_id_copy_addr(s_own_addr_type, addr_val, NULL);
    ESP_LOGI(TAG, "device addr %02x:%02x:%02x:%02x:%02x:%02x",
             addr_val[5], addr_val[4], addr_val[3],
             addr_val[2], addr_val[1], addr_val[0]);

    s_synced = true;

    /* Only advertise the HID keyboard if HID was actually started. Scanning
     * can share this host without turning us into an advertiser. */
    if (s_hid_enabled && !s_connected)
        ble_hid_advertise();

    /* Let a scan that was requested before sync begin now. */
    ble_scan_on_host_sync();

    /* Apply a Bluetooth-Direct (NUS) advertise-start requested before sync. */
    ble_nus_on_host_synced();
}

static void
ble_hid_host_task(void *param)
{
    ESP_LOGI(TAG, "BLE host task started");
    nimble_port_run();               /* returns only on nimble_port_stop() */
    nimble_port_freertos_deinit();
}

/* ========================================================================
 * GATT registration
 * ======================================================================== */

static esp_err_t
ble_hid_gatt_register(void)
{
    int rc;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    rc = ble_gatts_count_cfg(hid_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_count_cfg failed; rc=%d", rc);
        return ESP_FAIL;
    }

    rc = ble_gatts_add_svcs(hid_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_add_svcs failed; rc=%d", rc);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

/*
 * Shared one-time NimBLE host bring-up. Both ble_hid_start() and
 * ble_scan_start() call this; the host (NVS, nimble_port_init, ble_hs_cfg,
 * GATT registration, bond store, host task) is initialized exactly once no
 * matter which capability starts first. NimBLE supports simultaneous
 * peripheral (HID advertising) and central (scanning) on one host.
 *
 * The HID GATT services are registered here unconditionally: they are inert
 * unless HID actually advertises, and registering them BEFORE the host task
 * starts is required (ble_gatts_start() runs inside the host task at sync).
 * This guarantees HID works even when a scan brings the host up first.
 */
esp_err_t
ble_host_ensure_started(void)
{
    int rc;
    esp_err_t err;

    if (s_host_inited)
        return ESP_OK;

    /* NVS is required for BLE (PHY calibration + bond store). */
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_flash_init failed; err=%d", err);
        return err;
    }

    err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed; err=%d", err);
        return err;
    }

    /* Host configuration. */
    ble_hs_cfg.reset_cb = ble_hid_on_reset;
    ble_hs_cfg.sync_cb  = ble_host_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    /* Security: bonding + secure connections, "just works" (no MITM), so a
     * host can encrypt the link and read the encrypted HID characteristics. */
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist   = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    err = ble_hid_gatt_register();
    if (err != ESP_OK)
        return err;

    /* Register the NUS ("Bluetooth Direct") service into the same GATT table.
     * Inert until ble_nus_adv_start() is called via the M1 toggle. Must happen
     * here, before the host task starts (dynamic service registration is off). */
    err = ble_nus_gatt_register();
    if (err != ESP_OK)
        return err;

    rc = ble_svc_gap_device_name_set(s_device_name);
    if (rc != 0) {
        ESP_LOGE(TAG, "device_name_set failed; rc=%d", rc);
        return ESP_FAIL;
    }
    ble_svc_gap_device_appearance_set(HID_APPEARANCE_KEYBOARD);

    /* Persistent bond store (weak default provided by nimble store config). */
    ble_store_config_init();

    s_host_inited = true;
    nimble_port_freertos_init(ble_hid_host_task);

    ESP_LOGI(TAG, "nimble host started");
    return ESP_OK;
}

int
ble_host_own_addr_type(void)
{
    return s_synced ? (int)s_own_addr_type : -1;
}

esp_err_t
ble_hid_start(const char *device_name)
{
    esp_err_t err;

    if (device_name != NULL && device_name[0] != '\0') {
        strncpy(s_device_name, device_name, sizeof(s_device_name) - 1);
        s_device_name[sizeof(s_device_name) - 1] = '\0';
    }

    s_hid_enabled = true;

    err = ble_host_ensure_started();
    if (err != ESP_OK)
        return err;

    /* (Re)apply the advertised name/appearance (name may have changed). */
    ble_svc_gap_device_name_set(s_device_name);
    ble_svc_gap_device_appearance_set(HID_APPEARANCE_KEYBOARD);

    /* If the host has already synced (e.g. a scan brought it up first), the
     * sync callback has already run without advertising — start advertising
     * now. Otherwise ble_host_on_sync() will advertise once sync completes. */
    if (s_synced && !s_connected) {
        ble_gap_adv_stop();
        ble_hid_advertise();
    }

    if (s_report_input_handle == 0)
        ESP_LOGW(TAG, "report input handle not yet populated");

    ESP_LOGI(TAG, "ble_hid started (input_handle=%d)", s_report_input_handle);
    return ESP_OK;
}

void
ble_hid_stop(void)
{
    if (!s_host_inited)
        return;

    s_hid_enabled = false;
    ble_gap_adv_stop();

    if (s_connected && s_conn_handle != BLE_HS_CONN_HANDLE_NONE)
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);

    s_connected = false;
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
}

bool
ble_hid_is_connected(void)
{
    /* Report "connected" to the M1 only when the keyboard is actually usable:
     * link up AND encrypted AND the host subscribed to the input report. This
     * gates ble_hid_wait_connect() so the M1 doesn't start typing into a host
     * that will drop the notifications. */
    return s_connected && s_encrypted && s_input_subscribed;
}

esp_err_t
ble_hid_send_key(uint8_t modifier, const uint8_t *keys, uint8_t nkeys)
{
    if (nkeys > 6 || (nkeys > 0 && keys == NULL))
        return ESP_ERR_INVALID_ARG;

    if (!s_connected || s_conn_handle == BLE_HS_CONN_HANDLE_NONE
        || s_report_input_handle == 0 || !s_encrypted || !s_input_subscribed)
        return ESP_ERR_INVALID_STATE;   /* not paired/subscribed yet — don't notify into the void */

    /* Build 8-byte keyboard report: [modifier, 0x00, key1..key6]. */
    uint8_t report[8];
    report[0] = modifier;
    report[1] = 0x00;
    for (int i = 0; i < 6; i++)
        report[2 + i] = (i < nkeys) ? keys[i] : 0x00;

    /* Keep the read-back value in sync with the last notified report. */
    memcpy(keyboard_report, report, sizeof(report));

    struct os_mbuf *om = ble_hs_mbuf_from_flat(report, sizeof(report));
    if (om == NULL) {
        ESP_LOGE(TAG, "mbuf alloc failed");
        return ESP_ERR_NO_MEM;
    }

    int rc = ble_gatts_notify_custom(s_conn_handle, s_report_input_handle, om);
    if (rc != 0) {
        ESP_LOGE(TAG, "notify failed; rc=%d", rc);
        return ESP_FAIL;
    }

    return ESP_OK;
}
