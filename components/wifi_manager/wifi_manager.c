/*
 * WiFi Manager — Station + AP + monitor mode
 */

#include "wifi_manager.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "mdns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include <string.h>

static const char *TAG = "wifi_mgr";

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

#define WIFI_RECONNECT_MAX  10

static EventGroupHandle_t  s_wifi_events;
static wifi_mgr_config_t   s_config;
static esp_netif_t        *s_sta_netif;
static esp_netif_t        *s_ap_netif;

/* WiFi Hotspot internet passthrough (NAT). Enabled when the AP is up AND the STA
 * has an upstream IP; refreshed on STA got-IP and hotspot start. */
static bool s_napt_on = false;
bool wifi_mgr_napt_refresh(void);
static wifi_mgr_pkt_cb_t   s_pkt_cb;
static bool                s_initialized;

/* Gated auto-reconnect. connect_async() arms it; disconnect() disarms it so a
 * deliberate disconnect does not immediately reconnect. Retries are bounded and
 * reset to 0 on connect_async() and on GOT_IP. */
static volatile bool       s_auto_reconnect;
static volatile int        s_reconnect_retries;

static void event_handler(void *arg, esp_event_base_t base,
                          int32_t id, void *data)
{
    if (base == WIFI_EVENT) {
        switch (id) {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            /* Runs on the event-loop task — NEVER block here. Clear CONNECTED,
             * flag FAIL, and reconnect only when armed and under the retry cap
             * (a failed/empty SSID must not spin-reconnect forever). */
            xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
            if (s_auto_reconnect && s_reconnect_retries < WIFI_RECONNECT_MAX) {
                s_reconnect_retries++;
                ESP_LOGW(TAG, "Disconnected, reconnect %d/%d",
                         s_reconnect_retries, WIFI_RECONNECT_MAX);
                esp_wifi_connect();
            } else {
                ESP_LOGW(TAG, "Disconnected (no reconnect)");
            }
            break;
        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *ev = data;
            ESP_LOGI(TAG, "AP client connected: " MACSTR, MAC2STR(ev->mac));
            break;
        }
        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *ev = data;
            ESP_LOGI(TAG, "AP client disconnected: " MACSTR, MAC2STR(ev->mac));
            break;
        }
        default:
            break;
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&ev->ip_info.ip));
        s_reconnect_retries = 0;   /* association succeeded; reset the retry cap */
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
        /* Advertise the qMonstatek RPC service so the desktop app can find us.
         * Matches qMonstatek's mDNS browse: _m1rpc._tcp.local, port 3333. The
         * service type MUST carry the leading underscore ("_m1rpc") — mdns_service_add
         * expects "_http"-style names; without it the advertised type is malformed
         * and the desktop's _m1rpc._tcp browse never matches (why discovery broke). */
        wifi_mgr_register_mdns("m1", "_m1rpc", 3333);
        /* If the hotspot is up, we now have upstream internet — turn on NAT so
         * hotspot clients can reach it. */
        wifi_mgr_napt_refresh();
    }
}

static void promiscuous_rx(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_pkt_cb) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    s_pkt_cb(pkt->payload, pkt->rx_ctrl.sig_len, &pkt->rx_ctrl);
}

esp_err_t wifi_mgr_init(const wifi_mgr_config_t *config)
{
    if (s_initialized) return ESP_OK;

    s_config = *config;
    s_wifi_events = xEventGroupCreate();

    /* NVS — required by WiFi driver */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif  = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    /* Configure based on mode */
    wifi_mode_t mode;
    switch (config->mode) {
    case WIFI_MGR_MODE_AP:    mode = WIFI_MODE_AP;    break;
    case WIFI_MGR_MODE_APSTA: mode = WIFI_MODE_APSTA; break;
    default:                  mode = WIFI_MODE_STA;    break;
    }
    ESP_ERROR_CHECK(esp_wifi_set_mode(mode));

    /* Station config */
    if (mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA) {
        wifi_config_t sta_cfg = {0};
        strncpy((char *)sta_cfg.sta.ssid, config->sta_ssid, sizeof(sta_cfg.sta.ssid));
        strncpy((char *)sta_cfg.sta.password, config->sta_pass, sizeof(sta_cfg.sta.password));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));
    }

    /* AP config */
    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
        wifi_config_t ap_cfg = {
            .ap = {
                .channel        = config->ap_channel ? config->ap_channel : 1,
                .max_connection = config->ap_max_conn ? config->ap_max_conn : 4,
                .authmode       = strlen(config->ap_pass) > 0 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN,
            },
        };
        strncpy((char *)ap_cfg.ap.ssid, config->ap_ssid, sizeof(ap_cfg.ap.ssid));
        ap_cfg.ap.ssid_len = strlen(config->ap_ssid);
        strncpy((char *)ap_cfg.ap.password, config->ap_pass, sizeof(ap_cfg.ap.password));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    }

    ESP_ERROR_CHECK(esp_wifi_start());

    /* Battery device: default to modem power-save. Bumped to WIFI_PS_NONE while
     * a control client is connected (wifi_mgr_set_ps_active) for low latency. */
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    s_initialized = true;
    ESP_LOGI(TAG, "WiFi initialized, mode=%d", mode);
    return ESP_OK;
}

esp_err_t wifi_mgr_connect(void)
{
    s_auto_reconnect    = true;
    s_reconnect_retries = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) return err;

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) return ESP_OK;
    return ESP_ERR_WIFI_NOT_CONNECT;
}

esp_err_t wifi_mgr_connect_async(void)
{
    s_auto_reconnect    = true;
    s_reconnect_retries = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    return esp_wifi_connect();
}

esp_err_t wifi_mgr_disconnect(void)
{
    s_auto_reconnect = false;   /* deliberate disconnect: do not auto-reconnect */
    return esp_wifi_disconnect();
}

void wifi_mgr_set_ps_active(bool active)
{
    esp_wifi_set_ps(active ? WIFI_PS_NONE : WIFI_PS_MIN_MODEM);
}

esp_err_t wifi_mgr_start_ap(void)
{
    /* AP starts automatically in AP/APSTA mode */
    return ESP_OK;
}

/* Bring up a SoftAP ("WiFi Hotspot") at runtime. Uses APSTA when a station
 * connection already exists so a joined network survives, else plain AP. WPA2 if
 * the password is >= 8 chars, else open. The AP netif (created in wifi_mgr_init)
 * runs a DHCP server so clients get an IP and reach the RPC server on :3333. */
esp_err_t wifi_mgr_softap_start(const char *ssid, const char *pass, uint8_t channel)
{
    if (ssid == NULL || ssid[0] == '\0') return ESP_ERR_INVALID_ARG;

    if (!s_initialized) {
        wifi_mgr_config_t cfg = {0};
        cfg.mode = WIFI_MGR_MODE_AP;
        cfg.ap_channel = channel;
        strncpy(cfg.ap_ssid, ssid, sizeof(cfg.ap_ssid) - 1);
        if (pass) strncpy(cfg.ap_pass, pass, sizeof(cfg.ap_pass) - 1);
        return wifi_mgr_init(&cfg);
    }

    wifi_mode_t cur = WIFI_MODE_NULL;
    esp_wifi_get_mode(&cur);
    wifi_mode_t want = (cur == WIFI_MODE_STA || cur == WIFI_MODE_APSTA)
                     ? WIFI_MODE_APSTA : WIFI_MODE_AP;
    esp_err_t err = esp_wifi_set_mode(want);
    if (err != ESP_OK) return err;

    wifi_config_t ap_cfg = {
        .ap = {
            .channel        = channel ? channel : 1,
            .max_connection = 4,
            .authmode       = (pass && strlen(pass) >= 8) ? WIFI_AUTH_WPA2_PSK
                                                          : WIFI_AUTH_OPEN,
        },
    };
    strncpy((char *)ap_cfg.ap.ssid, ssid, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = strlen(ssid);
    if (pass) strncpy((char *)ap_cfg.ap.password, pass, sizeof(ap_cfg.ap.password));

    err = esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    if (err != ESP_OK) return err;

    esp_wifi_start();   /* no-op if already started */
    ESP_LOGI(TAG, "SoftAP up: \"%s\" ch=%u %s", ssid, channel,
             (ap_cfg.ap.authmode == WIFI_AUTH_OPEN) ? "open" : "wpa2");

    /* If an upstream STA link already has internet, share it to AP clients now.
     * (Otherwise it turns on automatically when the STA gets an IP.) */
    wifi_mgr_napt_refresh();
    return ESP_OK;
}

/* Tear the SoftAP down, returning to STA-only. */
esp_err_t wifi_mgr_softap_stop(void)
{
    if (!s_initialized) return ESP_OK;
    s_napt_on = false;
    return esp_wifi_set_mode(WIFI_MODE_STA);
}

/* Number of stations currently associated to the SoftAP. */
uint8_t wifi_mgr_softap_sta_count(void)
{
    wifi_sta_list_t list = {0};
    if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) return 0;
    return (uint8_t)list.num;
}

/* Enable/refresh internet passthrough (NAT) for hotspot clients when the AP is
 * up AND the STA has an upstream IP. Also offers the STA's DNS to AP clients so
 * names resolve. Idempotent; returns whether passthrough is active. */
bool wifi_mgr_napt_refresh(void)
{
    if (!s_initialized || !s_ap_netif) { s_napt_on = false; return false; }

    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_AP && mode != WIFI_MODE_APSTA) { s_napt_on = false; return false; }

    /* Upstream = STA associated with a real IP. */
    esp_netif_ip_info_t sta_ip = {0};
    bool upstream = (mode == WIFI_MODE_APSTA) && s_sta_netif
                 && esp_netif_get_ip_info(s_sta_netif, &sta_ip) == ESP_OK
                 && sta_ip.ip.addr != 0;
    if (!upstream) { s_napt_on = false; return false; }

    /* napt_enable is idempotent — safe to re-assert every status poll. */
    if (esp_netif_napt_enable(s_ap_netif) != ESP_OK) { s_napt_on = false; return false; }

    /* Do the DHCP/DNS reconfigure ONCE, on the off→on transition. Restarting the
     * DHCP server on every poll (this is re-run ~1s from the hotspot status) would
     * churn AP clients' leases. */
    if (!s_napt_on) {
        esp_netif_dns_info_t dns = {0};
        if (esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK
            && dns.ip.u_addr.ip4.addr != 0) {
            uint8_t offer = 1;
            esp_netif_dhcps_stop(s_ap_netif);
            esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &dns);
            esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET,
                                   ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof(offer));
            esp_netif_dhcps_start(s_ap_netif);
        }
        ESP_LOGI(TAG, "Hotspot internet passthrough (NAT) on");
    }

    s_napt_on = true;
    return true;
}

/* True while hotspot clients are being NAT'd out to the internet. */
bool wifi_mgr_softap_internet_shared(void)
{
    return s_napt_on;
}

esp_err_t wifi_mgr_scan(wifi_mgr_scan_cb_t callback)
{
    wifi_scan_config_t scan_cfg = {
        .show_hidden = true,
    };
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) return err;

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    if (count == 0) {
        if (callback) callback(NULL, 0);
        return ESP_OK;
    }

    wifi_ap_record_t *records = malloc(count * sizeof(wifi_ap_record_t));
    if (!records) {
        /* Free the driver's internal AP list even when we can't allocate for it,
         * otherwise it leaks every scan under memory pressure. */
        esp_wifi_clear_ap_list();
        return ESP_ERR_NO_MEM;
    }

    esp_wifi_scan_get_ap_records(&count, records);
    if (callback) callback(records, count);
    free(records);

    return ESP_OK;
}

esp_err_t wifi_mgr_get_ip(char *ip_str, size_t len)
{
    esp_netif_ip_info_t info;
    esp_err_t err = esp_netif_get_ip_info(s_sta_netif, &info);
    if (err != ESP_OK) return err;
    if (info.ip.addr == 0) return ESP_ERR_NOT_FOUND;
    snprintf(ip_str, len, IPSTR, IP2STR(&info.ip));
    return ESP_OK;
}

bool wifi_mgr_is_connected(void)
{
    EventBits_t bits = xEventGroupGetBits(s_wifi_events);
    return (bits & WIFI_CONNECTED_BIT) != 0;
}

esp_err_t wifi_mgr_register_mdns(const char *hostname, const char *service,
                                  uint16_t port)
{
    esp_err_t err = mdns_init();
    if (err != ESP_OK) return err;

    mdns_hostname_set(hostname);
    mdns_instance_name_set(hostname);
    mdns_service_add(hostname, service, "_tcp", port, NULL, 0);

    ESP_LOGI(TAG, "mDNS: %s.local, service %s._tcp:%d", hostname, service, port);
    return ESP_OK;
}

esp_err_t wifi_mgr_start_monitor(uint8_t channel, wifi_mgr_pkt_cb_t callback)
{
    s_pkt_cb = callback;
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous failed: %s", esp_err_to_name(err));
        s_pkt_cb = NULL;
        return err;
    }
    esp_wifi_set_promiscuous_rx_cb(promiscuous_rx);
    if (channel > 0) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }
    ESP_LOGI(TAG, "Monitor mode started, channel=%d", channel);
    return ESP_OK;
}

esp_err_t wifi_mgr_stop_monitor(void)
{
    esp_wifi_set_promiscuous(false);
    s_pkt_cb = NULL;
    ESP_LOGI(TAG, "Monitor mode stopped");
    return ESP_OK;
}

esp_err_t wifi_mgr_set_channel(uint8_t channel)
{
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

esp_err_t wifi_mgr_send_raw(const uint8_t *frame, size_t len)
{
    return esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
}
