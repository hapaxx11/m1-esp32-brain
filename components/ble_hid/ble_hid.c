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
#include "esp_mac.h"      /* esp_read_mac — derive the HID static-random address */

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
#define HID_MAX_ADV_NAME_LEN  29  /* scan response: AD length + type fit in 31 bytes */

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
/* Bad-BT/HID advertises on its OWN stable static-random address, distinct from
 * the public address that Bluetooth-Direct (NUS) uses. This keeps the PC's HID
 * bond tied to a different BLE identity, so the PC no longer auto-reconnects to
 * (and camps) the Direct connection at boot. MAC-derived => stable across
 * reboots so the bonded keyboard host still reconnects. */
static uint8_t  s_hid_rnd_addr[6];
static bool     s_hid_addr_ready = false;
static char     s_device_name[HID_MAX_ADV_NAME_LEN + 1] = "ESP32-C6 KB";

/* A HID stop is asynchronous at the GAP layer.  Keep a private completion
 * semaphore so the Bad-BT exit RPC can wait for the actual disconnect event
 * instead of ACKing while Windows still owns the keyboard connection. */
static StaticSemaphore_t s_stop_sem_buf;
static SemaphoreHandle_t s_stop_sem;
static bool              s_stop_waiting;


static int ble_hid_advertise(void);

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

            /* Initiate security for both a new pair and a known bonded host.
             * Relying on the central to request encryption works on some hosts
             * but leaves others connected without an encrypted HID link after
             * an app restart. */
            int rc = ble_gap_security_initiate(s_conn_handle);
            if (rc != 0 && rc != BLE_HS_EALREADY)
                ESP_LOGW(TAG, "security initiate failed; rc=%d", rc);
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
        if (s_stop_waiting) {
            s_stop_waiting = false;
            if (s_stop_sem != NULL)
                xSemaphoreGive(s_stop_sem);
        }
        if (s_hid_enabled)
            ble_hid_advertise();
        return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI(TAG, "adv complete; reason=%d, restarting",
                 event->adv_complete.reason);
        if (s_hid_enabled && !s_connected)
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
            /* Do not delete a peer record merely because one encryption attempt
             * failed.  The device name is mutable but the bonded keyboard
             * identity is not; deleting its key here is what made a harmless
             * name edit require the user to forget the keyboard in Windows.
             * Repeat-pairing has its own explicit callback below. */
            s_encrypted = false;
            ESP_LOGW(TAG, "encryption failed; preserving existing bond (status=%d)",
                     event->enc_change.status);
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

static int
ble_hid_advertise(void)
{
    struct ble_gap_adv_params adv_params;
    struct ble_hs_adv_fields fields;
    int rc;

    if (!s_hid_enabled || s_connected || !s_synced)
        return 0;

    /* Re-assert OUR name into the shared GAP Device Name (0x2A00) every time we
     * (re)advertise, so a prior Bluetooth-Direct/NUS name can't linger on the
     * one global characteristic and get read back as the keyboard's name. */
    ble_svc_gap_device_name_set(s_device_name);

    memset(&fields, 0, sizeof fields);

    /* General discoverable + BLE-only (BR/EDR unsupported). */
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

    /* Appearance = HID Keyboard so hosts show a keyboard icon and HOGP binds. */
    fields.appearance = HID_APPEARANCE_KEYBOARD;
    fields.appearance_is_present = 1;

    /* Advertise the HID service UUID (0x1812). */
    fields.uuids16 = (ble_uuid16_t[]) {
        BLE_UUID16_INIT(HID_SVC_UUID)
    };
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields failed; rc=%d", rc);
        return rc;
    }

    /* The primary advertisement already carries flags, TX power, appearance,
     * and the HID UUID. Putting a user-editable name there limits it to about
     * 15 characters; longer names made advertising fail silently. Keep the
     * name in the scan response, where all 29 supported characters fit. */
    struct ble_hs_adv_fields rsp_fields;
    memset(&rsp_fields, 0, sizeof rsp_fields);
    rsp_fields.name = (uint8_t *)s_device_name;
    rsp_fields.name_len = strlen(s_device_name);
    rsp_fields.name_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_rsp_set_fields failed; rc=%d", rc);
        return rc;
    }

    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    /* Advertise + bond on the HID static-random address (Bad-BT's own identity),
     * so the PC's keyboard bond does not apply to the Direct/public address.
     * Fall back to the public address if the random one couldn't be set. */
    uint8_t own_addr = s_hid_addr_ready ? BLE_OWN_ADDR_RANDOM : s_own_addr_type;
    rc = ble_gap_adv_start(own_addr, NULL, BLE_HS_FOREVER,
                           &adv_params, ble_hid_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start failed; rc=%d", rc);
        return rc;
    }
    ESP_LOGI(TAG, "advertising as \"%s\"", s_device_name);
    return 0;
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

    /* Register the HID static-random address (Bad-BT's own identity). Derived
     * from the BT MAC with the top two bits of the MSByte forced to 0b11 (the
     * static-random requirement) and one LSB flipped so it can never equal the
     * public address. Set once; NUS/Direct keeps using the public address. */
    if (!s_hid_addr_ready) {
        uint8_t mac[6] = {0};
        if (esp_read_mac(mac, ESP_MAC_BT) == ESP_OK) {
            memcpy(s_hid_rnd_addr, mac, 6);
            s_hid_rnd_addr[5] |= 0xC0;   /* static-random: MSByte bits 7:6 = 11 */
            s_hid_rnd_addr[0] ^= 0x01;   /* guarantee it differs from the public MAC */
            if (ble_hs_id_set_rnd(s_hid_rnd_addr) == 0)
                s_hid_addr_ready = true;
            else
                ESP_LOGW(TAG, "ble_hs_id_set_rnd failed; HID will use public addr");
        }
    }

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

    if (s_stop_sem == NULL)
        s_stop_sem = xSemaphoreCreateBinaryStatic(&s_stop_sem_buf);

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
        if (ble_hid_advertise() != 0)
            return ESP_FAIL;
    }

    if (s_report_input_handle == 0)
        ESP_LOGW(TAG, "report input handle not yet populated");

    ESP_LOGI(TAG, "ble_hid started (input_handle=%d)", s_report_input_handle);
    return ESP_OK;
}

void
ble_hid_stop(void)
{
    (void)ble_hid_stop_and_wait(0);
}

esp_err_t
ble_hid_stop_and_wait(uint32_t timeout_ms)
{
    if (!s_host_inited)
        return ESP_OK;

    /* Disable intent before stopping GAP so neither ADV_COMPLETE nor the
     * disconnect callback can revive this advertiser. */
    s_hid_enabled = false;
    int rc = ble_gap_adv_stop();
    if (rc != 0 && rc != BLE_HS_EALREADY)
        ESP_LOGW(TAG, "adv_stop during HID teardown; rc=%d", rc);

    if (!s_connected || s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        s_connected = false;
        s_encrypted = false;
        s_input_subscribed = false;
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        return ESP_OK;
    }

    if (timeout_ms > 0 && s_stop_sem != NULL)
        xSemaphoreTake(s_stop_sem, 0);  /* discard a stale completion */
    s_stop_waiting = timeout_ms > 0;

    rc = ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        s_stop_waiting = false;
        ESP_LOGW(TAG, "terminate HID connection failed; rc=%d", rc);
        return ESP_FAIL;
    }

    if (timeout_ms == 0)
        return ESP_OK;

    if (s_stop_sem == NULL ||
        xSemaphoreTake(s_stop_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        /* A GAP callback may have run immediately before the wait was entered. */
        if (!s_connected || s_conn_handle == BLE_HS_CONN_HANDLE_NONE)
            return ESP_OK;
        s_stop_waiting = false;
        ESP_LOGW(TAG, "timed out waiting for HID disconnect");
        return ESP_ERR_TIMEOUT;
    }

    return ESP_OK;
}

bool
ble_hid_is_connected(void)
{
    return s_connected && s_conn_handle != BLE_HS_CONN_HANDLE_NONE;
}

bool
ble_hid_is_ready(void)
{
    /* A host can report a connected keyboard slightly before it has completed
     * encryption and subscribed to the input-report characteristic.  Keep that
     * stricter state separate from the visible link state. */
    return ble_hid_is_connected() && s_encrypted && s_input_subscribed;
}

bool
ble_hid_is_advertising(void)
{
    /* Bad-BT is advertising when it is enabled, synced, and not yet connected. */
    return s_hid_enabled && s_synced && !s_connected;
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
