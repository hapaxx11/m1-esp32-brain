/*
 * RPC Server — control channel (TCP :3333) + screen channel (UDP), decoupled.
 *
 * Control (TCP): a SINGLE select()-driven, non-blocking task owns {listen_fd,
 * client_fd}. It answers PING->PONG locally and relays every other command to
 * the M1 via s_relay_q (the M1 pulls with QMON_POLL). M1 responses come back
 * through rpc_server_send_raw() -> s_out_q and are drained onto the client
 * socket by the same control task (single writer, no send mutex).
 *
 * Screen (UDP): the M1 pushes framebuffers over SPI (SCREEN_PUSH ->
 * rpc_server_update_screen), which land in a depth-1 OVERWRITE mailbox. A
 * dedicated low-priority screen_tx task sends ONE 1032-byte UDP datagram per
 * frame to the recorded client_ip:client_udp_port with MSG_DONTWAIT (dropped on
 * EWOULDBLOCK). Screen has NO independent lifetime: SCREEN_STOP or TCP close
 * clears the target. Screen and control share no socket and no mutex.
 */

#include "rpc_server.h"
#include "m1_rpc.h"          /* m1_rpc_crc16 — same CRC-16/CCITT as qMonstatek */
#include "wifi_manager.h"    /* wifi_mgr_set_ps_active — PS_NONE during a session */
#include "esp_log.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static const char *TAG = "rpc_srv";

#define SCREEN_FB_SIZE      1024                        /* 128x64 / 8 */
#define SCREEN_DGRAM_SIZE   (2 + 2 + 4 + SCREEN_FB_SIZE) /* "SC" seq epoch fb = 1032 */

static int s_listen_fd = -1;
static int s_client_fd = -1;

/* Relay queue: qMonstatek command frames the ESP can't answer locally are
 * queued here for the M1 to pull via QMON_POLL. */
typedef struct { uint8_t *data; uint16_t len; } relay_item_t;
static QueueHandle_t s_relay_q;

/* Outbound-to-client queue: raw qMonstatek response frames the M1 produced
 * (QMON_RESP). Filled by rpc_server_send_raw()/rpc_server_send() from other
 * tasks; drained onto the socket ONLY by the control task, so the client fd has
 * exactly one writer and needs no send mutex. */
typedef struct { uint8_t *data; uint16_t len; } out_item_t;
static QueueHandle_t s_out_q;

/* Reason the last client session/frame ended, logged on disconnect for field
 * support. */
#define RPC_EXIT_NONE       0
#define RPC_EXIT_RECV_SYNC  1   /* recv returned 0 (peer closed) */
#define RPC_EXIT_RECV_HDR   2
#define RPC_EXIT_RECV_PAY   3
#define RPC_EXIT_RECV_CRC   4   /* recv error (not EWOULDBLOCK) */
#define RPC_EXIT_LEN_BAD    5   /* declared payload len exceeded max */
static uint16_t s_last_exit_reason;

/* --- Screen UDP target + depth-1 mailbox --- */
static SemaphoreHandle_t s_udp_mutex;      /* guards s_client_ip / s_udp_dst / s_udp_active / s_screen_epoch */
static struct in_addr    s_client_ip;      /* recorded from the accepted TCP peer */
static struct sockaddr_in s_udp_dst;       /* client_ip : client_udp_port */
static bool              s_udp_active;      /* true between SCREEN_START and SCREEN_STOP/close */
static uint32_t         s_screen_epoch;    /* bumped on every SCREEN_START */
static int              s_udp_fd = -1;
static QueueHandle_t    s_screen_mbox;     /* length 1, item = SCREEN_FB_SIZE (overwrite) */

/* --- BLE "Bluetooth Direct" transport: one client at a time with TCP ---
 * The BLE side (ble_nus) feeds RX bytes here and registers a tx callback; the
 * active client determines where responses + screen frames are routed. */
typedef enum { CLIENT_NONE, CLIENT_TCP, CLIENT_BLE } client_kind_t;
static volatile client_kind_t s_active = CLIENT_NONE;
static volatile bool          s_ble_connected = false;  /* a BLE phone is linked */
static rpc_ble_tx_fn          s_ble_tx = NULL;
static volatile bool          s_screen_ble = false;   /* screen mirroring over BLE (marker) */
#define SCREEN_FRAME_CMD   0x12   /* RPC_CMD_SCREEN_FRAME on the M1/host side */

/* Defined below; forward-declared because screen_tx_task (BLE path) uses it. */
static uint16_t build_frame(uint8_t *frame, uint8_t cmd, uint8_t seq,
                            const uint8_t *payload, uint16_t payload_len);

/* --- Screen cache path: M1 SCREEN_PUSH -> depth-1 overwrite mailbox (newest
 * wins). Called from the command-dispatch task. --- */
void rpc_server_update_screen(const uint8_t *fb, uint16_t len)
{
    uint8_t frame[SCREEN_FB_SIZE];
    if (len > SCREEN_FB_SIZE) len = SCREEN_FB_SIZE;
    memcpy(frame, fb, len);
    if (len < SCREEN_FB_SIZE) memset(frame + len, 0, SCREEN_FB_SIZE - len);
    if (s_screen_mbox) xQueueOverwrite(s_screen_mbox, frame);   /* depth-1 overwrite */
}

static void udp_target_set(uint16_t port)
{
    xSemaphoreTake(s_udp_mutex, portMAX_DELAY);
    memset(&s_udp_dst, 0, sizeof(s_udp_dst));
    s_udp_dst.sin_family = AF_INET;
    s_udp_dst.sin_addr   = s_client_ip;
    s_udp_dst.sin_port   = htons(port);
    s_udp_active = true;
    s_screen_epoch++;
    xSemaphoreGive(s_udp_mutex);
}

static void udp_target_clear(void)
{
    xSemaphoreTake(s_udp_mutex, portMAX_DELAY);
    s_udp_active = false;
    xSemaphoreGive(s_udp_mutex);
}

/* Dedicated low-priority screen sender. Drains the depth-1 mailbox and emits
 * ONE best-effort UDP datagram per frame; never blocks, never acks. */
static void screen_tx_task(void *arg)
{
    static uint8_t dg[SCREEN_DGRAM_SIZE];
    static uint8_t bf[5 + SCREEN_FB_SIZE + 2];   /* framed SCREEN_FRAME for BLE */
    uint8_t fb[SCREEN_FB_SIZE];
    uint16_t frame_seq = 0;
    TickType_t last_ble_tick = 0;

    for (;;) {
        if (xQueueReceive(s_screen_mbox, fb, portMAX_DELAY) != pdTRUE) continue;

        /* BLE (Bluetooth Direct) screen path: no UDP channel — send the frame
         * inline as a SCREEN_FRAME control frame over the NUS TX characteristic
         * (ble_nus_send chunks it to the MTU). Throttle to ~5fps: BLE is low
         * bandwidth and this competes with WiFi/BLE coex airtime. */
        if (s_screen_ble && s_ble_tx) {
            TickType_t now = xTaskGetTickCount();
            if ((now - last_ble_tick) < pdMS_TO_TICKS(200))
                continue;                 /* drop this frame — 5fps cap */
            last_ble_tick = now;
            uint16_t n = build_frame(bf, SCREEN_FRAME_CMD, (uint8_t)frame_seq,
                                     fb, SCREEN_FB_SIZE);
            s_ble_tx(bf, n);
            frame_seq++;
            continue;
        }

        struct sockaddr_in dst;
        uint32_t epoch;
        bool active;
        xSemaphoreTake(s_udp_mutex, portMAX_DELAY);
        active = s_udp_active;
        dst    = s_udp_dst;
        epoch  = s_screen_epoch;
        xSemaphoreGive(s_udp_mutex);

        if (!active || s_udp_fd < 0) continue;

        dg[0] = 0x53; dg[1] = 0x43;                     /* "SC" */
        dg[2] = (uint8_t)(frame_seq & 0xFF);
        dg[3] = (uint8_t)(frame_seq >> 8);
        dg[4] = (uint8_t)(epoch & 0xFF);
        dg[5] = (uint8_t)((epoch >> 8) & 0xFF);
        dg[6] = (uint8_t)((epoch >> 16) & 0xFF);
        dg[7] = (uint8_t)((epoch >> 24) & 0xFF);
        memcpy(&dg[8], fb, SCREEN_FB_SIZE);

        /* Best-effort: drop on EWOULDBLOCK/ENOMEM. */
        (void)sendto(s_udp_fd, dg, sizeof(dg), MSG_DONTWAIT,
                     (struct sockaddr *)&dst, sizeof(dst));
        frame_seq++;
    }
}

/* --- Frame build helper --- */

static uint16_t build_frame(uint8_t *frame, uint8_t cmd, uint8_t seq,
                            const uint8_t *payload, uint16_t payload_len)
{
    uint16_t i = 0;
    frame[i++] = QMON_SYNC;
    frame[i++] = cmd;
    frame[i++] = seq;
    frame[i++] = (uint8_t)(payload_len & 0xFF);
    frame[i++] = (uint8_t)(payload_len >> 8);
    if (payload_len && payload) { memcpy(&frame[i], payload, payload_len); i += payload_len; }
    uint16_t crc = m1_rpc_crc16(&frame[1], 4 + payload_len);   /* CMD..PAYLOAD */
    frame[i++] = (uint8_t)(crc & 0xFF);
    frame[i++] = (uint8_t)(crc >> 8);
    return i;
}

/* --- Client send path (control task only) ---
 * Send the whole buffer or fail. A partial control frame desyncs the qMonstatek
 * parser, so on a persistent stall we shut the socket down for a clean
 * reconnect. The socket is non-blocking; a transient EWOULDBLOCK is waited out
 * briefly (bounded) rather than dropping the frame. */
static bool client_send_all(const uint8_t *buf, int len)
{
    int off = 0, stalls = 0;
    while (off < len) {
        int n = send(s_client_fd, buf + off, len - off, 0);
        if (n > 0) { off += n; stalls = 0; continue; }
        if (n < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            if (++stalls > 5) {                 /* ~1s of a wedged window */
                if (s_client_fd >= 0) shutdown(s_client_fd, SHUT_RDWR);
                return false;
            }
            fd_set wf; FD_ZERO(&wf); FD_SET(s_client_fd, &wf);
            struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
            select(s_client_fd + 1, NULL, &wf, NULL, &tv);
            continue;
        }
        if (s_client_fd >= 0) shutdown(s_client_fd, SHUT_RDWR);
        return false;
    }
    return true;
}

/* Send a complete framed buffer to whichever transport is the active client.
 * BLE goes out the NUS notify path; TCP uses the socket (control task only). */
static bool send_to_active(const uint8_t *frame, uint16_t len)
{
    if (s_active == CLIENT_BLE)
        return s_ble_tx ? s_ble_tx(frame, len) : false;
    return client_send_all(frame, (int)len);
}

/* --- Public send API: queue for the control task to write --- */

esp_err_t rpc_server_send(uint8_t cmd, uint8_t seq,
                          const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len > QMON_MAX_PAYLOAD) return ESP_ERR_INVALID_ARG;

    /* BLE active client: frame it and notify directly (no TCP socket/queue). */
    if (s_active == CLIENT_BLE) {
        uint8_t bf[5 + QMON_MAX_PAYLOAD + 2];
        uint16_t n = build_frame(bf, cmd, seq, payload, payload_len);
        return (s_ble_tx && s_ble_tx(bf, n)) ? ESP_OK : ESP_FAIL;
    }

    if (s_client_fd < 0) return ESP_ERR_INVALID_STATE;
    if (!s_out_q) return ESP_ERR_INVALID_STATE;

    uint8_t *frame = malloc(5 + payload_len + 2);
    if (!frame) return ESP_ERR_NO_MEM;
    uint16_t n = build_frame(frame, cmd, seq, payload, payload_len);
    out_item_t it = { frame, n };
    if (xQueueSend(s_out_q, &it, 0) != pdTRUE) { free(frame); return ESP_FAIL; }
    return ESP_OK;
}

esp_err_t rpc_server_send_raw(const uint8_t *frame, uint16_t len)
{
    /* BLE active client: send directly over NUS notify (no TCP socket/queue). */
    if (s_active == CLIENT_BLE)
        return (s_ble_tx && s_ble_tx(frame, len)) ? ESP_OK : ESP_FAIL;
    if (s_client_fd < 0) return ESP_ERR_INVALID_STATE;
    if (!s_out_q) return ESP_ERR_INVALID_STATE;
    uint8_t *cp = malloc(len);
    if (!cp) return ESP_ERR_NO_MEM;
    memcpy(cp, frame, len);
    out_item_t it = { cp, len };
    if (xQueueSend(s_out_q, &it, 0) != pdTRUE) { free(cp); return ESP_FAIL; }
    return ESP_OK;
}

int rpc_server_relay_dequeue(uint8_t *buf, int max)
{
    relay_item_t it;
    if (!s_relay_q || xQueueReceive(s_relay_q, &it, 0) != pdTRUE) return 0;
    int n = it.len > max ? max : it.len;
    memcpy(buf, it.data, n);
    free(it.data);
    return n;
}

esp_err_t rpc_server_broadcast(uint8_t cmd,
                               const uint8_t *payload, uint16_t payload_len)
{
    return rpc_server_send(cmd, 0, payload, payload_len);
}

bool rpc_server_client_connected(void)
{
    /* A BLE (Bluetooth Direct) client counts too, so the M1 relays to it even
     * when WiFi is down. */
    return s_client_fd >= 0 || s_ble_connected;
}

/* Queue a raw qMonstatek command frame for the M1 to pull via QMON_POLL. */
static void relay_to_m1(const uint8_t *frame, uint16_t frame_len)
{
    uint8_t *cp = malloc(frame_len);
    if (!cp) return;
    memcpy(cp, frame, frame_len);
    relay_item_t it = { cp, frame_len };
    if (!s_relay_q || xQueueSend(s_relay_q, &it, 0) != pdTRUE) free(cp);
}

/* --- Control-frame dispatch (called from the control task) --- */

static void dispatch_frame(const uint8_t *frame, uint8_t cmd, uint8_t seq,
                           const uint8_t *payload, uint16_t len, uint16_t frame_len,
                           client_kind_t src)
{
    switch (cmd) {
    case QMON_CMD_PING: {
        uint8_t pf[7];
        uint16_t n = build_frame(pf, QMON_CMD_PONG, seq, NULL, 0);
        /* Answer on the transport the ping arrived on. */
        if (src == CLIENT_BLE) { if (s_ble_tx) s_ble_tx(pf, n); }
        else                   client_send_all(pf, n);
        break;
    }
    case QMON_CMD_SCREEN_START:
        /* Route the screen by the transport that DELIVERED this SCREEN_START, not
         * by the global active client — that's what keeps a BLE screen on BLE even
         * if a WiFi/TCP session also exists. Over BLE there's no UDP channel (the
         * app sends udp_port==0); the frames go inline over the NUS TX char
         * (screen_tx_task). Either way relay to the M1 to match its stream state. */
        if (src == CLIENT_BLE) {
            s_screen_ble = true;
            udp_target_clear();
        } else if (len >= 3) {
            uint16_t udp_port = (uint16_t)payload[1] | ((uint16_t)payload[2] << 8);
            s_screen_ble = false;
            udp_target_set(udp_port);
        } else {
            s_screen_ble = false;
            udp_target_clear();
        }
        relay_to_m1(frame, frame_len);
        break;
    case QMON_CMD_SCREEN_STOP:
        s_screen_ble = false;
        udp_target_clear();
        relay_to_m1(frame, frame_len);
        break;
    case QMON_CMD_SCREEN:
        /* Screen no longer travels over TCP — ignore (do NOT relay). */
        break;
    default:
        relay_to_m1(frame, frame_len);
        break;
    }
}

/* --- Incremental (non-blocking) frame parser --- */

typedef enum { PS_SYNC, PS_HDR, PS_PAYLOAD, PS_CRC } parse_state_t;

typedef struct {
    parse_state_t st;
    uint8_t  frame[QMON_MAX_FRAME];  /* [0xAA][cmd][seq][len:2][payload][crc:2] */
    uint16_t got;
    uint8_t  cmd, seq;
    uint16_t len;
    client_kind_t src;               /* transport this parser feeds (TCP or BLE) */
} parser_t;

static void parser_reset(parser_t *p) { p->st = PS_SYNC; p->got = 0; }

static void parser_feed(parser_t *p, uint8_t b)
{
    switch (p->st) {
    case PS_SYNC:
        if (b == QMON_SYNC) { p->frame[0] = b; p->st = PS_HDR; p->got = 0; }
        break;
    case PS_HDR:
        p->frame[1 + p->got] = b;
        if (++p->got == 4) {
            p->cmd = p->frame[1];
            p->seq = p->frame[2];
            p->len = (uint16_t)p->frame[3] | ((uint16_t)p->frame[4] << 8);
            if (p->len > QMON_MAX_PAYLOAD) {
                s_last_exit_reason = RPC_EXIT_LEN_BAD;
                parser_reset(p);
            } else if (p->len == 0) {
                p->st = PS_CRC;     p->got = 0;
            } else {
                p->st = PS_PAYLOAD; p->got = 0;
            }
        }
        break;
    case PS_PAYLOAD:
        p->frame[5 + p->got] = b;
        if (++p->got == p->len) { p->st = PS_CRC; p->got = 0; }
        break;
    case PS_CRC:
        p->frame[5 + p->len + p->got] = b;
        if (++p->got == 2) {
            uint16_t rxcrc = (uint16_t)p->frame[5 + p->len] |
                             ((uint16_t)p->frame[6 + p->len] << 8);
            if (rxcrc == m1_rpc_crc16(&p->frame[1], 4 + p->len)) {
                uint16_t frame_len = 7 + p->len;
                dispatch_frame(p->frame, p->cmd, p->seq,
                               &p->frame[5], p->len, frame_len, p->src);
            } else {
                ESP_LOGW(TAG, "bad CRC, dropping cmd=0x%02X", p->cmd);
            }
            parser_reset(p);
        }
        break;
    }
}

/* --- BLE (Bluetooth Direct) bridge: a second parser instance feeds the SAME
 * dispatch/relay path as TCP. dispatch_frame routes its local replies (PONG) and
 * the relay routes commands to the M1 exactly as for WiFi. --- */
static parser_t s_ble_parser;

void rpc_server_set_ble_tx(rpc_ble_tx_fn fn)
{
    s_ble_tx = fn;
}

void rpc_server_ble_set_active(bool active)
{
    if (active) {
        parser_reset(&s_ble_parser);
        s_ble_parser.src = CLIENT_BLE;
        s_ble_connected = true;
        s_active = CLIENT_BLE;
    } else {
        s_ble_connected = false;
        s_screen_ble = false;
        /* Fall back to a TCP client if one happens to be connected, else idle. */
        s_active = (s_client_fd >= 0) ? CLIENT_TCP : CLIENT_NONE;
    }
}

void rpc_server_feed_ble(const uint8_t *data, uint16_t len)
{
    if (s_active != CLIENT_BLE) return;   /* ignore stray writes when not active */
    for (uint16_t i = 0; i < len; i++)
        parser_feed(&s_ble_parser, data[i]);
}

/* --- Session lifecycle --- */

static void close_client(void)
{
    if (s_client_fd >= 0) {
        shutdown(s_client_fd, SHUT_RDWR);
        close(s_client_fd);
        s_client_fd = -1;
    }
    udp_target_clear();                 /* screen has no life beyond the session */
    /* Revert the active client: back to BLE if a Bluetooth-Direct phone is still
     * linked, otherwise idle. (Never strand a live BLE session at NONE.) */
    if (s_active == CLIENT_TCP)
        s_active = s_ble_connected ? CLIENT_BLE : CLIENT_NONE;
    wifi_mgr_set_ps_active(false);      /* back to battery power-save */
    ESP_LOGI(TAG, "Client disconnected (reason=%u)", s_last_exit_reason);
}

static void accept_new(void)
{
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int fd = accept(s_listen_fd, (struct sockaddr *)&caddr, &clen);
    if (fd < 0) return;

    /* One client at a time: displace any existing session cleanly. */
    if (s_client_fd >= 0) {
        shutdown(s_client_fd, SHUT_RDWR);
        close(s_client_fd);
        s_client_fd = -1;
    }

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    int idle = 10, intvl = 5, cnt = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
    struct timeval rcv_to = { .tv_sec = 20, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    /* Record the peer IP for the UDP screen target (port arrives with
     * SCREEN_START). No screen target is active until then. */
    xSemaphoreTake(s_udp_mutex, portMAX_DELAY);
    s_client_ip  = caddr.sin_addr;
    s_udp_active = false;
    xSemaphoreGive(s_udp_mutex);

    s_client_fd = fd;
    s_active = CLIENT_TCP;               /* TCP is now the active RPC client */
    wifi_mgr_set_ps_active(true);        /* low-latency while a client is connected */
    ESP_LOGI(TAG, "Client connected (fd=%d)", fd);
}

/* Drain the outbound queue onto the client socket (control task only). */
static void drain_out_q(void)
{
    out_item_t it;
    if (s_client_fd < 0) {               /* no client — free any orphaned frames */
        while (s_out_q && xQueueReceive(s_out_q, &it, 0) == pdTRUE) free(it.data);
        return;
    }
    while (s_out_q && xQueueReceive(s_out_q, &it, 0) == pdTRUE) {
        bool ok = client_send_all(it.data, it.len);
        free(it.data);
        if (!ok) {
            s_last_exit_reason = RPC_EXIT_RECV_CRC;
            close_client();
            while (xQueueReceive(s_out_q, &it, 0) == pdTRUE) free(it.data);
            break;
        }
    }
}

/* --- Control task: single select() loop over {listen_fd, client_fd} --- */

static void rpc_control_task(void *arg)
{
    rpc_server_config_t *config = (rpc_server_config_t *)arg;

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(config->port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    s_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s_listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(s_listen_fd, 1);
    int fl = fcntl(s_listen_fd, F_GETFL, 0);
    fcntl(s_listen_fd, F_SETFL, fl | O_NONBLOCK);

    ESP_LOGI(TAG, "RPC control server listening on port %d", config->port);

    parser_t parser;
    parser_reset(&parser);
    parser.src = CLIENT_TCP;   /* this parser feeds the WiFi/TCP transport */

    uint8_t rbuf[512];

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s_listen_fd, &rfds);
        int maxfd = s_listen_fd;
        if (s_client_fd >= 0) {
            FD_SET(s_client_fd, &rfds);
            if (s_client_fd > maxfd) maxfd = s_client_fd;
        }

        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  /* ~100ms tick */
        int r = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        /* Every tick: push any M1-produced control responses to the client. */
        drain_out_q();

        if (r <= 0) continue;   /* timeout (0) or error (<0, re-loop) */

        if (FD_ISSET(s_listen_fd, &rfds)) {
            accept_new();
            parser_reset(&parser);          /* fresh session, fresh parse state */
        }

        if (s_client_fd >= 0 && FD_ISSET(s_client_fd, &rfds)) {
            int n = recv(s_client_fd, rbuf, sizeof(rbuf), 0);
            if (n > 0) {
                for (int i = 0; i < n; i++) parser_feed(&parser, rbuf[i]);
            } else if (n == 0) {
                s_last_exit_reason = RPC_EXIT_RECV_SYNC;
                close_client();
                parser_reset(&parser);
            } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                s_last_exit_reason = RPC_EXIT_RECV_CRC;
                close_client();
                parser_reset(&parser);
            }
        }
    }
}

static rpc_server_config_t s_config;

esp_err_t rpc_server_init(const rpc_server_config_t *config)
{
    s_config = *config;

    s_udp_mutex   = xSemaphoreCreateMutex();
    s_relay_q     = xQueueCreate(8, sizeof(relay_item_t));
    s_out_q       = xQueueCreate(32, sizeof(out_item_t));   /* headroom under screen back-pressure */
    s_screen_mbox = xQueueCreate(1, SCREEN_FB_SIZE);   /* depth-1 overwrite mailbox */
    if (!s_udp_mutex || !s_relay_q || !s_out_q || !s_screen_mbox) return ESP_ERR_NO_MEM;

    s_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_udp_fd < 0) return ESP_FAIL;

    /* rpc_ctrl at priority 11 — ABOVE cmd_dispatch(8)/the SPI screen-ingest so the
     * desktop heartbeat (ping->pong) is always serviced, still below m1_link(12) to
     * preserve SPI framing. Screen streaming was starving this task at prio 6 on the
     * single core -> pongs stopped -> "link dead" every ~18s (transport-independent).
     * Heavy screen egress stays on the isolated UDP screen_tx task, not here. */
    xTaskCreate(rpc_control_task, "rpc_ctrl", 8192, &s_config, 11, NULL);
    xTaskCreate(screen_tx_task,   "screen_tx", 4096, NULL,       3, NULL);
    return ESP_OK;
}
