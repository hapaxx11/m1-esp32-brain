#include "net_scan.h"
#include "wifi_manager.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_ping.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"
#include "lwip/sockets.h"
#include "ping/ping_sock.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <errno.h>

#define TAG "net_scan"
#define SCAN_MAX_RESULTS 32
#define SCAN_MAX_HOSTS 254

typedef struct {
    uint8_t ip[4];
    uint16_t port;
    uint8_t mac[6];
    bool has_mac;
} scan_result_t;

typedef struct {
    uint8_t ip[4];
    uint16_t port;
} scan_seen_t;

static QueueHandle_t s_results;
static StaticQueue_t s_queue_ctrl;
static uint8_t s_queue_store[SCAN_MAX_RESULTS * sizeof(scan_result_t)];
static scan_seen_t s_seen[SCAN_MAX_RESULTS];
static uint8_t s_seen_count;
static TaskHandle_t s_task;
static TaskHandle_t s_ping_wait_task;
static esp_ping_handle_t s_ping_handle;
static volatile bool s_running;
static volatile bool s_done;
static volatile bool s_stop;
static volatile bool s_ping_success;
static volatile uint8_t s_progress;
static uint8_t s_mode;
static uint8_t s_timeout_ms;
static struct netif *s_netif;
static uint32_t s_network;
static uint32_t s_broadcast;
static uint32_t s_hosts;

static void result_add(const ip4_addr_t *ip, uint16_t port, const struct eth_addr *mac)
{
    scan_seen_t key;
    memcpy(key.ip, &ip->addr, 4);
    key.port = port;
    for (uint8_t i = 0; i < s_seen_count; i++) {
        if (!memcmp(s_seen[i].ip, key.ip, 4) && s_seen[i].port == key.port) return;
    }
    if (s_seen_count >= SCAN_MAX_RESULTS) return;

    scan_result_t result = { .port = port, .has_mac = mac != NULL };
    memcpy(result.ip, &ip->addr, 4);
    if (mac) memcpy(result.mac, mac, 6);
    if (xQueueSend(s_results, &result, 0) == pdTRUE)
        s_seen[s_seen_count++] = key;
}

static void read_arp_table(void)
{
    LOCK_TCPIP_CORE();
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip = NULL;
        struct netif *iface = NULL;
        struct eth_addr *mac = NULL;
        if (etharp_get_entry(i, &ip, &iface, &mac) && ip && iface == s_netif) {
            uint32_t host = ntohl(ip->addr);
            if (host > s_network && host < s_broadcast)
                result_add(ip, 0, mac);
        }
    }
    UNLOCK_TCPIP_CORE();
}

static void ping_success_cb(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    (void)args;
    s_ping_success = true;
}

static void ping_end_cb(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    (void)args;
    if (s_ping_wait_task) xTaskNotifyGive(s_ping_wait_task);
}

static void scan_ping_host(uint32_t host)
{
    ip4_addr_t target = { .addr = htonl(host) };
    ip_addr_t addr;
    IP_ADDR4(&addr, 0, 0, 0, 0);
    addr.u_addr.ip4 = target;

    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.target_addr = addr;
    cfg.count = 1;
    cfg.timeout_ms = s_timeout_ms ? s_timeout_ms : 80;
    cfg.data_size = 16;
    esp_ping_callbacks_t cbs = {
        .cb_args = NULL,
        .on_ping_success = ping_success_cb,
        .on_ping_timeout = NULL,
        .on_ping_end = ping_end_cb,
    };
    s_ping_success = false;
    s_ping_wait_task = xTaskGetCurrentTaskHandle();
    if (esp_ping_new_session(&cfg, &cbs, &s_ping_handle) != ESP_OK) return;
    if (esp_ping_start(s_ping_handle) == ESP_OK) {
        uint32_t wait_ms = cfg.timeout_ms + 100;
        if (ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait_ms)) == 0)
            esp_ping_stop(s_ping_handle);
        if (s_ping_success) result_add(&target, 0, NULL);
    }
    esp_ping_delete_session(s_ping_handle);
    s_ping_handle = NULL;
    s_ping_wait_task = NULL;
}

static bool tcp_port_open(const ip4_addr_t *ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = ip->addr,
    };
    fcntl(fd, F_SETFL, O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno == EINPROGRESS) {
        fd_set writes;
        FD_ZERO(&writes);
        FD_SET(fd, &writes);
        struct timeval tv = {
            .tv_sec = 0,
            .tv_usec = (s_timeout_ms ? s_timeout_ms : 80) * 1000,
        };
        if (select(fd + 1, NULL, &writes, NULL, &tv) > 0) {
            int err = 0;
            socklen_t err_len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) == 0 && err == 0)
                rc = 0;
        }
    }
    close(fd);
    return rc == 0;
}

static void update_progress(uint32_t scanned, uint32_t total, uint8_t offset, uint8_t span)
{
    if (!total) return;
    uint32_t pct = offset + (scanned * span) / total;
    s_progress = pct > 100 ? 100 : (uint8_t)pct;
}

static void arp_phase(void)
{
    for (uint32_t host = s_network + 1, scanned = 0;
         host < s_broadcast && scanned < s_hosts && !s_stop;
         host++, scanned++) {
        ip4_addr_t target = { .addr = htonl(host) };
        LOCK_TCPIP_CORE();
        if (s_netif) etharp_request(s_netif, &target);
        UNLOCK_TCPIP_CORE();
        if ((scanned & 7u) == 7u) read_arp_table();
        update_progress(scanned + 1, s_hosts,
                        s_mode == 4 ? 0 : 0, s_mode == 4 ? 100 : 50);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (!s_stop) read_arp_table();
}

static void scan_task(void *arg)
{
    static const uint16_t common_ports[] = {
        20, 21, 22, 23, 25, 80, 137, 139, 443, 445, 3306, 3389, 8080, 8443, 9090,
    };

    if (s_mode == 3) {
        for (uint32_t host = s_network + 1, scanned = 0;
             host < s_broadcast && scanned < s_hosts && !s_stop;
             host++, scanned++) {
            scan_ping_host(host);
            update_progress(scanned + 1, s_hosts, 0, 100);
        }
    } else {
        arp_phase();
        if (s_mode != 4 && !s_stop) {
            for (uint32_t host = s_network + 1, scanned = 0;
                 host < s_broadcast && scanned < s_hosts && !s_stop;
                 host++, scanned++) {
                ip4_addr_t target = { .addr = htonl(host) };
                if (s_mode == 0 || s_mode == 1) {
                    uint16_t port = s_mode == 0 ? 22 : 23;
                    if (tcp_port_open(&target, port)) result_add(&target, port, NULL);
                } else {
                    for (uint8_t i = 0; i < sizeof(common_ports) / sizeof(common_ports[0]); i++) {
                        if (s_stop) break;
                        if (tcp_port_open(&target, common_ports[i]))
                            result_add(&target, common_ports[i], NULL);
                    }
                }
                update_progress(scanned + 1, s_hosts, 50, 50);
            }
        }
    }

    if (s_stop) s_progress = 100;
    s_done = true;
    s_running = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t net_scan_start(uint8_t mode, uint8_t timeout_ms, uint8_t base_ip[4])
{
    if (mode > 4 || !base_ip) return ESP_ERR_INVALID_ARG;
    if (!wifi_mgr_is_connected()) return ESP_ERR_INVALID_STATE;
    if (s_task || s_running) return ESP_ERR_INVALID_STATE;

    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if (!sta || esp_netif_get_ip_info(sta, &info) != ESP_OK || !info.ip.addr || !info.netmask.addr)
        return ESP_ERR_INVALID_STATE;
    memcpy(base_ip, &info.ip.addr, 4);
    s_netif = (struct netif *)esp_netif_get_netif_impl(sta);
    if (!s_netif) return ESP_ERR_INVALID_STATE;

    uint32_t ip = ntohl(info.ip.addr);
    uint32_t mask = ntohl(info.netmask.addr);
    s_network = ip & mask;
    s_broadcast = s_network | ~mask;
    s_hosts = s_broadcast > s_network + 1 ? s_broadcast - s_network - 1 : 0;
    if (s_hosts > SCAN_MAX_HOSTS) s_hosts = SCAN_MAX_HOSTS;
    if (!s_hosts) return ESP_ERR_INVALID_ARG;
    s_broadcast = s_network + s_hosts + 1;

    if (!s_results)
        s_results = xQueueCreateStatic(SCAN_MAX_RESULTS, sizeof(scan_result_t),
                                       s_queue_store, &s_queue_ctrl);
    if (!s_results) return ESP_ERR_NO_MEM;
    xQueueReset(s_results);
    s_seen_count = 0;
    s_mode = mode;
    s_timeout_ms = timeout_ms;
    s_progress = 0;
    s_done = false;
    s_stop = false;
    s_running = true;
    if (xTaskCreate(scan_task, "net_scan", 4096, NULL, 5, &s_task) != pdPASS) {
        s_running = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

int net_scan_next(uint8_t *out, uint16_t cap)
{
    if (!out || !s_results) return 0;
    scan_result_t result;
    if (xQueueReceive(s_results, &result, 0) == pdTRUE) {
        if (cap < 16) return 0;
        out[0] = 1;
        memcpy(&out[1], result.ip, 4);
        out[5] = (uint8_t)result.port;
        out[6] = (uint8_t)(result.port >> 8);
        out[7] = 0;
        out[8] = s_progress;
        out[9] = result.has_mac ? 1 : 0;
        memcpy(&out[10], result.mac, 6);
        return 16;
    }
    if (cap < 3) return 0;
    out[0] = s_done ? 2 : 0;
    out[1] = 0;
    out[2] = s_progress;
    return 3;
}

void net_scan_stop(void)
{
    s_stop = true;
    s_progress = 100;
}

bool net_scan_running(void)
{
    return s_running && !s_done;
}
