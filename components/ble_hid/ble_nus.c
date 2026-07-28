/*
 * ble_nus.c — Nordic UART Service (NUS) GATT server for "Bluetooth Direct".
 * See ble_nus.h. Bridges BLE RX/TX to the existing RPC relay in rpc_server.
 */

#include <string.h>
#include "ble_nus.h"
#include "ble_hid.h"          /* ble_host_ensure_started() — shared NimBLE host */
#include "rpc_server.h"       /* rpc_server_feed_ble / _set_ble_tx / _ble_set_active */
#include "wifi_manager.h"     /* wifi_mgr_set_ps_active — low-latency while BLE up */

#include "esp_log.h"
#include "esp_mac.h"
#include "nimble/ble.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "services/gap/ble_svc_gap.h"

static const char *TAG = "ble_nus";

/* Nordic UART Service UUIDs (128-bit, little-endian byte order for NimBLE). */
/* Service 6e400001-b5a3-f393-e0a9-e50e24dcca9e */
static const ble_uuid128_t nus_svc_uuid =
    BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
                     0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e);
/* RX  6e400002-... (phone -> M1, Write / Write No Response) */
static const ble_uuid128_t nus_rx_uuid =
    BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
                     0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40, 0x6e);
/* TX  6e400003-... (M1 -> phone, Notify) */
static const ble_uuid128_t nus_tx_uuid =
    BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
                     0x93, 0xf3, 0xa3, 0xb5, 0x03, 0x00, 0x40, 0x6e);

static uint16_t s_conn      = BLE_HS_CONN_HANDLE_NONE;
static uint16_t s_tx_handle = 0;       /* TX characteristic value handle */
static uint16_t s_mtu       = 23;      /* negotiated ATT MTU (BLE default until updated) */
static bool     s_tx_subscribed = false;
static bool     s_advertising   = false;
static uint8_t  s_own_addr_type = 0;
static char     s_name[16]      = "M1-BLE";

static int nus_gap_event(struct ble_gap_event *event, void *arg);

/* ---- RX characteristic access: forward written bytes into the RPC relay ---- */
static int
nus_rx_access(uint16_t conn_handle, uint16_t attr_handle,
              struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR)
        return BLE_ATT_ERR_UNLIKELY;

    uint8_t  buf[512];
    uint16_t out_len = 0;
    int rc = ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &out_len);
    if (rc != 0)
        return BLE_ATT_ERR_UNLIKELY;

    if (out_len > 0)
        rpc_server_feed_ble(buf, out_len);   /* same parser + relay as WiFi */

    return 0;
}

static const struct ble_gatt_svc_def nus_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &nus_svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {   /* RX: phone -> M1 */
                .uuid = &nus_rx_uuid.u,
                .access_cb = nus_rx_access,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
            },
            {   /* TX: M1 -> phone (notify) */
                .uuid = &nus_tx_uuid.u,
                .access_cb = nus_rx_access,   /* unused for notify-only, but required non-NULL */
                .val_handle = &s_tx_handle,
                .flags = BLE_GATT_CHR_F_NOTIFY,
            },
            { 0 }
        },
    },
    { 0 }
};

esp_err_t
ble_nus_gatt_register(void)
{
    int rc = ble_gatts_count_cfg(nus_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "count_cfg failed; rc=%d", rc);
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(nus_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "add_svcs failed; rc=%d", rc);
        return ESP_FAIL;
    }

    /* Register our TX path with the RPC relay (no compile-time dependency the
     * other way — rpc_server just holds a function pointer). */
    rpc_server_set_ble_tx(ble_nus_send);

    /* Device name M1-XXXX from the low 2 bytes of the BT MAC. */
    uint8_t mac[6] = {0};
    if (esp_read_mac(mac, ESP_MAC_BT) == ESP_OK)
        snprintf(s_name, sizeof(s_name), "M1-%02X%02X", mac[4], mac[5]);

    return ESP_OK;
}

bool
ble_nus_connected(void)
{
    return s_conn != BLE_HS_CONN_HANDLE_NONE;
}

bool
ble_nus_send(const uint8_t *data, uint16_t len)
{
    if (s_conn == BLE_HS_CONN_HANDLE_NONE || !s_tx_subscribed || data == NULL)
        return false;

    uint16_t chunk = (s_mtu > 3) ? (uint16_t)(s_mtu - 3) : 20;
    uint16_t off = 0;

    while (off < len) {
        uint16_t n = (uint16_t)(len - off);
        if (n > chunk) n = chunk;

        struct os_mbuf *om = ble_hs_mbuf_from_flat(data + off, n);
        if (om == NULL)
            return false;   /* out of mbufs — caller drops (stale screen frames ok) */

        int rc = ble_gatts_notify_custom(s_conn, s_tx_handle, om);
        if (rc != 0)
            return false;   /* host TX queue full — apply backpressure by dropping */

        off += n;
    }
    return true;
}

/* ---- Advertising ---- */
esp_err_t
ble_nus_adv_start(void)
{
    esp_err_t err = ble_host_ensure_started();
    if (err != ESP_OK)
        return err;

    /* The host may not be synced yet on the very first call; infer_auto fails
     * until sync, in which case we mark intent and (re)start on the sync path
     * via the GAP restart. Try now; NimBLE returns an error we can log. */
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGW(TAG, "infer_auto not ready (rc=%d) — will advertise once synced", rc);
        s_advertising = true;   /* intent latched; see note below */
        return ESP_OK;
    }

    /* The 128-bit NUS UUID (18 bytes) + flags nearly fill the 31-byte adv packet,
     * so the name goes in the SCAN RESPONSE — otherwise ble_gap_adv_set_fields
     * fails with EMSGSIZE and nothing ever advertises. No tx-power field either. */
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof fields);
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = (ble_uuid128_t *)&nus_svc_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields failed; rc=%d", rc);
        return ESP_FAIL;
    }

    /* Device name M1-XXXX in the scan response. */
    struct ble_hs_adv_fields rsp;
    memset(&rsp, 0, sizeof rsp);
    rsp.name = (uint8_t *)s_name;
    rsp.name_len = strlen(s_name);
    rsp.name_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&rsp);
    if (rc != 0)
        ESP_LOGW(TAG, "adv_rsp_set_fields failed; rc=%d (name only)", rc);

    struct ble_gap_adv_params adv_params;
    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &adv_params, nus_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start failed; rc=%d", rc);
        return ESP_FAIL;
    }
    s_advertising = true;
    ESP_LOGI(TAG, "advertising as \"%s\"", s_name);
    return ESP_OK;
}

void
ble_nus_adv_stop(void)
{
    s_advertising = false;
    ble_gap_adv_stop();
    ESP_LOGI(TAG, "advertising stopped");
}

/* Called from the shared host sync callback: if advertising was requested before
 * the host finished syncing (infer_auto not ready), start it now. */
void
ble_nus_on_host_synced(void)
{
    if (s_advertising && s_conn == BLE_HS_CONN_HANDLE_NONE)
        ble_nus_adv_start();
}

static int
nus_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn = event->connect.conn_handle;
            s_mtu = 23;
            s_tx_subscribed = false;
            ESP_LOGI(TAG, "connected; conn=%d", s_conn);
            rpc_server_ble_set_active(true);   /* BLE becomes the active RPC client */
            wifi_mgr_set_ps_active(true);      /* keep BLE latency low */
        } else {
            ESP_LOGW(TAG, "connect failed; status=%d", event->connect.status);
            if (s_advertising)
                ble_nus_adv_start();
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnect; reason=%d", event->disconnect.reason);
        s_conn = BLE_HS_CONN_HANDLE_NONE;
        s_tx_subscribed = false;
        rpc_server_ble_set_active(false);
        wifi_mgr_set_ps_active(false);
        if (s_advertising)
            ble_nus_adv_start();
        return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        if (s_advertising)
            ble_nus_adv_start();
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == s_tx_handle)
            s_tx_subscribed = event->subscribe.cur_notify ? true : false;
        return 0;

    case BLE_GAP_EVENT_MTU:
        s_mtu = event->mtu.value;
        ESP_LOGI(TAG, "mtu=%d", s_mtu);
        return 0;

    default:
        return 0;
    }
}
