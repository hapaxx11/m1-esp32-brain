/*
 * m1_rpc.h — Unified M1 <-> ESP32-C6 binary RPC protocol (canonical shared header)
 *
 * Include this SAME file on both sides:
 *   - STM32H573 host  (m1-experimental-firmware/Core/Inc/m1_rpc.h)
 *   - ESP32-C6 slave  (esp32-experimental-firmware/components/m1_rpc/include/m1_rpc.h)
 *
 * ============================================================================
 * TRANSPORT (read this — it is the #1 thing that was wrong before)
 * ============================================================================
 *   STM32H573 = SPI **MASTER**.   ESP32-C6 = SPI **SLAVE** (esp spi_slave_hd).
 *
 *   The M1 (master) drives the ESP-AT-compatible SPI Half-Duplex command
 *   protocol (command/address/dummy phases + a status register + RD/WR data
 *   buffers). The ESP32 asserts a HANDSHAKE / DATA_READY GPIO to tell the
 *   master when it has data to move or is ready for a transfer. The frames
 *   defined in THIS header are the bytes carried *inside* the HD data buffers —
 *   the SPI-HD transport itself is unchanged from the stock AT firmware.
 *
 *   NOTE: the previous experimental STM32 side (spi_slave.c, SPI_MODE_SLAVE)
 *   was configured as a slave — WRONG. Both ends were slaves, so no clock was
 *   ever generated. The host must be the master (reuse the stock M1 Esp_spi_at
 *   master driver). The ESP32 spi_link.c (spi_slave_hd) side is correct as-is.
 *
 * Design lineage:
 *   - Frame format  : dagnazty M1-T-800  docs/M1_RPC_SPEC.md  (0x4D31 framing)
 *   - Capability neg: hapaxx11 M1         m1_csrc/m1_esp32_caps.h
 *   - Transport      : our native ESP-IDF spi_slave_hd (NOT layered on ESP-AT)
 *   See: Reference Guides/kb/refs/PROTOCOL_COMPARISON.md
 *
 * All multi-byte integers are LITTLE-ENDIAN (native for both Cortex-M33 and
 * RISC-V, so packed structs map directly — but do not assume it, we state it).
 */

#ifndef M1_RPC_H
#define M1_RPC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================== */
/*  Frame format                                                            */
/* ======================================================================== */
/*
 *   [ header : 8 bytes ][ payload : payload_len bytes ][ CRC16 : 2 bytes ]
 *
 *   Offset Size Field
 *   0      2    magic         M1_RPC_MAGIC (0x4D31, "M1")
 *   2      1    version       M1_RPC_VERSION (0x01)
 *   3      1    msg_type      m1_rpc_msgtype_t (REQ/RESP/EVENT/FRAG)
 *   4      2    msg_id        m1_rpc_id_t (command / response / event id)
 *   6      2    payload_len   number of payload bytes that follow the header
 *
 *   CRC16-CCITT covers header+payload and is stored AFTER the payload. It is
 *   OUTSIDE payload_len, so the on-wire / DMA length = 8 + payload_len + 2.
 */

#define M1_RPC_MAGIC            0x4D31u
#define M1_RPC_VERSION          0x01u
#define M1_RPC_HEADER_SIZE      8u
#define M1_RPC_CRC_SIZE         2u

/* ---- "M1 Link" full-duplex transport (Option B) ----
 * Every SPI transaction clocks EXACTLY M1L_MTU bytes in both directions at
 * once (STM32 master frame on MOSI, ESP32 slave frame on MISO). One m1_rpc
 * frame rides inside each fixed buffer; unused tail bytes are zero padding.
 * A logical message larger than M1L_PAYLOAD_MAX is split with M1_RPC_FRAG.
 * MUST be identical on both firmwares (compile-time agreement = no desync). */
#define M1L_MTU                 512u
#define M1L_PAYLOAD_MAX         (M1L_MTU - M1_RPC_HEADER_SIZE - M1_RPC_CRC_SIZE) /* 502 */

/* Max DMA payload of the underlying SPI-HD transport (matches AT_SPI_DMA_SIZE
 * / SPI_DMA_MAX_LEN = 4092). One frame must fit header+payload+CRC in that. */
#define M1_RPC_DMA_MAX_LEN      4092u
#define M1_RPC_MAX_PAYLOAD      (M1_RPC_DMA_MAX_LEN - M1_RPC_HEADER_SIZE - M1_RPC_CRC_SIZE) /* 4082 */

typedef struct __attribute__((packed)) {
    uint16_t magic;         /* M1_RPC_MAGIC */
    uint8_t  version;       /* M1_RPC_VERSION */
    uint8_t  msg_type;      /* m1_rpc_msgtype_t */
    uint16_t msg_id;        /* m1_rpc_id_t */
    uint16_t payload_len;   /* 0 .. M1_RPC_MAX_PAYLOAD */
} m1_rpc_header_t;

_Static_assert(sizeof(m1_rpc_header_t) == M1_RPC_HEADER_SIZE, "m1_rpc header size");

/* ---------- Message type ---------- */
typedef enum {
    M1_RPC_IDLE  = 0x00,   /* either          : no-op filler frame (len=0). A transaction
                            *                   with nothing to send carries this so both
                            *                   directions are always valid framing. */
    M1_RPC_REQ   = 0x01,   /* STM32 -> ESP32  : command request */
    M1_RPC_RESP  = 0x02,   /* ESP32 -> STM32  : successful response (payload = data) */
    M1_RPC_EVENT = 0x03,   /* ESP32 -> STM32  : unsolicited async notification */
    M1_RPC_FRAG  = 0x04,   /* either          : continuation fragment */
    M1_RPC_NAK   = 0x05,   /* ESP32 -> STM32  : error response; payload = [status:1] (m1_rpc_status_t),
                            *                   msg_id echoes the failed request. RESP always = success. */
} m1_rpc_msgtype_t;

/*
 * Fragmentation: a logical message larger than M1_RPC_MAX_PAYLOAD is split.
 *   - first fragment : normal header, payload_len = bytes in THIS fragment,
 *                      msg_type = REQ/RESP/EVENT as appropriate
 *   - continuations  : msg_type = FRAG, msg_id = same id as the first fragment
 *   Receiver reassembles by tracking (msg_type-of-first, msg_id). A FRAG with
 *   payload_len < MAX is the last fragment.
 */

/* ======================================================================== */
/*  Message IDs (16-bit, range-grouped)                                     */
/* ======================================================================== */
typedef enum {
    /* ---- System 0x0000-0x00FF ---- */
    M1_RPC_SYS_PING            = 0x0001, /* REQ  u8[4] cookie -> RESP u8[4] echo */
    M1_RPC_SYS_GET_STATUS      = 0x0002, /* REQ  (none)       -> RESP m1_rpc_devstatus_t (capability probe) */
    M1_RPC_SYS_GET_FW_VERSION  = 0x0003, /* REQ  (none)       -> RESP m1_rpc_fw_version_t */
    M1_RPC_SYS_GET_HEAP        = 0x0004, /* REQ  (none)       -> RESP u32 free, u32 min */
    M1_RPC_SYS_RESET           = 0x0005, /* REQ  u8 flags     -> (device resets, no resp) */
    M1_RPC_SYS_OTA_BEGIN       = 0x0006, /* REQ  u32 img_size -> RESP u8 status */
    M1_RPC_SYS_OTA_DATA        = 0x0007, /* REQ  u8[] data    -> RESP u8 status */
    M1_RPC_SYS_OTA_END         = 0x0008, /* REQ  u8 reboot    -> RESP u8 status */
    M1_RPC_SYS_SNTP_SYNC       = 0x0009, /* REQ  (none, WiFi up) -> RESP m1_rpc_time_t (or NAK) */

    /* ---- WiFi station 0x0100-0x01FF ---- */
    M1_RPC_WIFI_GET_MODE       = 0x0100,
    M1_RPC_WIFI_SET_MODE       = 0x0101, /* REQ u8 mode */
    M1_RPC_WIFI_GET_MAC        = 0x0102, /* REQ u8 iface (0=sta,1=ap) -> u8[6] */
    M1_RPC_WIFI_SCAN           = 0x0103, /* REQ u8 band -> u16 count + scan_entry[] */
    M1_RPC_WIFI_CONNECT        = 0x0104, /* REQ connect_req */
    M1_RPC_WIFI_DISCONNECT     = 0x0105,
    M1_RPC_WIFI_GET_STATUS     = 0x0106,

    /* ---- WiFi AP 0x0200-0x02FF ---- */
    M1_RPC_SOFTAP_START        = 0x0200, /* REQ softap_config */
    M1_RPC_SOFTAP_STOP         = 0x0201,
    M1_RPC_SOFTAP_STA_LIST     = 0x0202,

    /* ---- Offensive WiFi 0x0300-0x03FF ---- */
    M1_RPC_OFF_MONITOR_START   = 0x0300, /* REQ u8 channel, u8 band */
    M1_RPC_OFF_MONITOR_STOP    = 0x0301,
    M1_RPC_OFF_DEAUTH_START    = 0x0302, /* REQ deauth_req */
    M1_RPC_OFF_DEAUTH_STOP     = 0x0303,
    M1_RPC_OFF_BEACON_START    = 0x0304, /* REQ beacon_req */
    M1_RPC_OFF_BEACON_STOP     = 0x0305,
    M1_RPC_OFF_PROBE_START     = 0x0306,
    M1_RPC_OFF_PROBE_STOP      = 0x0307,
    M1_RPC_OFF_PMKID_CAPTURE   = 0x0308,
    M1_RPC_OFF_KARMA_START     = 0x0309,
    M1_RPC_OFF_KARMA_STOP      = 0x030A,
    M1_RPC_OFF_HANDSHAKE_CAP   = 0x030B, /* REQ hscap_req */
    M1_RPC_OFF_RAW_TX          = 0x030C,
    M1_RPC_OFF_DEAUTH_STATUS   = 0x030D, /* RESP u32 sent, u8 running */
    M1_RPC_OFF_STA_SCAN_START  = 0x030E, /* REQ [bssid:6][channel:1][dur:1] — find STAs on an AP */
    M1_RPC_OFF_STA_SCAN_RESULTS= 0x030F, /* RESP [count:2][per sta: mac:6, rssi:i8] */
    M1_RPC_OFF_HS_START        = 0x0310, /* REQ [bssid:6][channel:1][deauth_count:2] — start EAPOL capture */
    M1_RPC_OFF_HS_STATUS       = 0x0311, /* RESP [state:1][total_len:4] — 0=idle,1=capturing,2=complete */
    M1_RPC_OFF_HS_GET          = 0x0312, /* REQ [offset:4][len:2] -> RESP raw .pcap bytes (chunked) */
    M1_RPC_OFF_HS_STOP         = 0x0313,
    M1_RPC_OFF_MONITOR_STATS   = 0x0314, /* RESP [total:4][dropped:4][buffered:1] */
    M1_RPC_OFF_MONITOR_READ    = 0x0315, /* RESP one frame [ch:1][rssi:i8][len:2][frame] or empty */
    M1_RPC_OFF_CAPTIVE_START   = 0x0316, /* REQ [channel:1][ssid_len:1][ssid][title] — rogue AP portal */
    M1_RPC_OFF_CAPTIVE_STOP    = 0x0317,
    M1_RPC_OFF_CAPTIVE_CREDS   = 0x0318, /* RESP [count:1] then per cred [ts:4][ulen:1][u][plen:1][p] */
    M1_RPC_OFF_CAPTIVE_DIAG    = 0x0319, /* RESP [dns_q:4][http_hits:4][clients:1] */

    /* ---- BLE 0x0400-0x04FF ---- */
    M1_RPC_BLE_INIT            = 0x0400,
    M1_RPC_BLE_SCAN_START      = 0x0401,
    M1_RPC_BLE_SCAN_RESULTS    = 0x0402,
    M1_RPC_BLE_ADV_START       = 0x0403,
    M1_RPC_BLE_ADV_STOP        = 0x0404,
    M1_RPC_BLE_HID_INIT        = 0x0405,
    M1_RPC_BLE_HID_KEY         = 0x0406, /* REQ hid_keypress */
    M1_RPC_BLE_HID_STRING      = 0x0407, /* REQ u8[] utf8 — ESP types autonomously */
    M1_RPC_BLE_HID_SCRIPT      = 0x0408, /* REQ Bad-BT script blob — ESP runs it */
    M1_RPC_BLE_CONNECT         = 0x0409,
    M1_RPC_BLE_DISCONNECT      = 0x040A,
    M1_RPC_BLE_HID_DEINIT      = 0x040B, /* stop advertising / tear down HID */
    M1_RPC_BLE_HID_STATUS      = 0x040C, /* REQ -> RESP u8 connected */
    M1_RPC_BLE_SPAM_START      = 0x040D, /* REQ u8 mode -> RESP u8 status (adv-spam popups) */
    M1_RPC_BLE_SPAM_STOP       = 0x040E, /* REQ (none) -> RESP u8 status */

    /* ---- Zigbee / 802.15.4 0x0500-0x05FF ---- */
    M1_RPC_ZB_INIT             = 0x0500,
    M1_RPC_ZB_SCAN             = 0x0501,
    M1_RPC_ZB_SNIFF_START      = 0x0502, /* REQ u8 channel (11-26) -> RESP u8 status */
    M1_RPC_ZB_SNIFF_STOP       = 0x0503, /* REQ (none) -> RESP u8 status */
    M1_RPC_ZB_SNIFF_GET        = 0x0504, /* REQ (none) -> RESP [count:1] then [ch:1][rssi:i8][len:2][bytes] per frame */
    M1_RPC_ZB_FLOOD_START      = 0x0505, /* REQ u8 channel (0=sweep 11-26) -> RESP u8 status (beacon-request flood) */
    M1_RPC_ZB_FLOOD_STOP       = 0x0506, /* REQ (none) -> RESP u8 status */
    M1_RPC_ZB_INJECT           = 0x0507, /* REQ raw MPDU (no FCS) -> RESP u8 status */
    M1_RPC_THREAD_SCAN         = 0x0510,

    /* ---- ESP-NOW peer-to-peer M1<->M1 link 0x0600-0x06FF ---- */
    M1_RPC_NOW_START           = 0x0600, /* REQ [ch:1][name...] -> RESP [status:1][mac:6] */
    M1_RPC_NOW_STOP            = 0x0601, /* REQ (none) -> RESP u8 status */
    M1_RPC_NOW_ANNOUNCE        = 0x0602, /* REQ (none) -> RESP u8 status (broadcast presence) */
    M1_RPC_NOW_PEERS_GET       = 0x0603, /* REQ (none) -> RESP [count:1] then [mac:6][rssi:i8][namelen:1][name] per peer */
    M1_RPC_NOW_SEND            = 0x0604, /* REQ [mac:6][data...] -> RESP u8 status (mac=FF..FF = broadcast) */
    M1_RPC_NOW_RECV_GET        = 0x0605, /* REQ (none) -> RESP [count:1] then [mac:6][len:2 LE][data] per msg */

    /* ---- Screen / qMonstatek bridge 0x0700-0x07FF ---- */
    M1_RPC_SCREEN_PUSH         = 0x0700, /* REQ u8[] framebuffer -> RESP u8 status */
    M1_RPC_RPC_STATUS          = 0x0701, /* REQ (none) -> RESP u8 qmonstatek_connected */
    M1_RPC_QMON_POLL           = 0x0702, /* M1 polls ESP for a queued qMonstatek(TCP) frame -> RESP raw frame or empty */
    M1_RPC_QMON_RESP           = 0x0703, /* M1 -> ESP: a qMonstatek response frame to forward to the TCP client */
} m1_rpc_id_t;

/* ---------- Event IDs 0xE000-0xEFFF (ESP32 -> STM32, msg_type = EVENT) ---------- */
typedef enum {
    M1_RPC_EVT_WIFI_SCAN_DONE  = 0xE001, /* u16 ap_count */
    M1_RPC_EVT_WIFI_CONNECTED  = 0xE002, /* u8[6] bssid, u8 channel */
    M1_RPC_EVT_WIFI_DISCONN    = 0xE003, /* u8 reason */
    M1_RPC_EVT_MONITOR_PACKET  = 0xE010, /* u8 ch, i8 rssi, u16 len, u8[] frame */
    M1_RPC_EVT_MONITOR_DEAUTH  = 0xE011,
    M1_RPC_EVT_PMKID_RESULT    = 0xE020,
    M1_RPC_EVT_HANDSHAKE_RESULT= 0xE021,
    M1_RPC_EVT_KARMA_PROBE     = 0xE030,
    M1_RPC_EVT_BLE_SCAN_RESULT = 0xE040,
    M1_RPC_EVT_BLE_HID_STATUS  = 0xE041, /* u8 connected, u16 progress */
    M1_RPC_EVT_ZB_FRAME        = 0xE050, /* u8 ch, u16 len, u8[] frame */
    M1_RPC_EVT_STA_CONNECTED   = 0xE060,
    M1_RPC_EVT_STA_DISCONN     = 0xE061,
    M1_RPC_EVT_LOG             = 0xE0F0, /* u8 level, u8[] utf8 text */
    M1_RPC_EVT_ERROR           = 0xE0FF, /* u16 err_code, u8 msg_len, char[] */
} m1_rpc_evt_t;

/* ======================================================================== */
/*  Status codes (uint8 status field in RESP payloads)                      */
/* ======================================================================== */
typedef enum {
    M1_RPC_OK                = 0x00,
    M1_RPC_ERR_UNKNOWN       = 0x01,
    M1_RPC_ERR_INVALID_ARGS  = 0x02,
    M1_RPC_ERR_BUSY          = 0x03,
    M1_RPC_ERR_TIMEOUT       = 0x04,
    M1_RPC_ERR_NO_MEM        = 0x05,
    M1_RPC_ERR_NOT_INIT      = 0x06,
    M1_RPC_ERR_ALREADY_RUN   = 0x07,
    M1_RPC_ERR_NOT_RUNNING   = 0x08,
    M1_RPC_ERR_HARDWARE      = 0x09,
    M1_RPC_ERR_UNSUPPORTED   = 0x0A, /* command not supported / capability absent */
    M1_RPC_ERR_BAD_CRC       = 0x0B,
    M1_RPC_ERR_PENDING       = 0xFF, /* accepted, result will arrive as an EVENT */
} m1_rpc_status_t;

/* ======================================================================== */
/*  Capability negotiation (hapaxx11 model)                                 */
/* ======================================================================== */
/*
 * One ESP32 firmware may implement a different subset of features than another
 * (SiN360 binary-SPI, dag T-800, our native firmware, ...). The host queries
 * M1_RPC_SYS_GET_STATUS at boot and gates each feature on a capability bit,
 * so ONE host firmware supports many ESP builds without hard-coding names.
 *
 * IMPORTANT (hapaxx11 bug fix): the bitmap is serialized on the wire as
 * uint8_t[8] LITTLE-ENDIAN, NOT a packed uint64_t — packing/alignment of a
 * uint64_t inside a __packed struct bit them. Use the [8] array on the wire
 * and rebuild a u64 in code with m1_rpc_caps_get()/m1_rpc_caps_set().
 */
#define M1_CAP_WIFI_SCAN     (UINT64_C(1) <<  0)
#define M1_CAP_STA_SCAN      (UINT64_C(1) <<  1)
#define M1_CAP_BLE_SCAN      (UINT64_C(1) <<  2)
#define M1_CAP_BLE_ADV       (UINT64_C(1) <<  3)
#define M1_CAP_DEAUTH        (UINT64_C(1) <<  4)
#define M1_CAP_BEACON        (UINT64_C(1) <<  5)
#define M1_CAP_PROBE_FLOOD   (UINT64_C(1) <<  6)
#define M1_CAP_KARMA         (UINT64_C(1) <<  7)
#define M1_CAP_PKTMON        (UINT64_C(1) <<  8)
#define M1_CAP_PORTAL        (UINT64_C(1) <<  9)
#define M1_CAP_WIFI_JOIN     (UINT64_C(1) << 10)
#define M1_CAP_WIFI_SET_MAC  (UINT64_C(1) << 11)
#define M1_CAP_WIFI_SET_CHAN (UINT64_C(1) << 12)
#define M1_CAP_NETSCAN       (UINT64_C(1) << 13)
#define M1_CAP_BLE_HID       (UINT64_C(1) << 14)
#define M1_CAP_BT_MANAGE     (UINT64_C(1) << 15)
#define M1_CAP_802154        (UINT64_C(1) << 16)
#define M1_CAP_BLE_GATT      (UINT64_C(1) << 17)
#define M1_CAP_PMKID         (UINT64_C(1) << 18)
#define M1_CAP_HANDSHAKE     (UINT64_C(1) << 19)
#define M1_CAP_OTA           (UINT64_C(1) << 20)
#define M1_CAP_BLE_SPAM      (UINT64_C(1) << 21)
#define M1_CAP_802154_TX     (UINT64_C(1) << 22)

#define M1_RPC_FW_NAME_LEN   32

/* M1_RPC_SYS_GET_STATUS response payload (protocol version 1). */
typedef struct __attribute__((packed)) {
    uint8_t  proto_ver;                    /* == M1_RPC_VERSION */
    uint8_t  cap_bitmap[8];                /* M1_CAP_* bits, LITTLE-ENDIAN u64 */
    char     fw_name[M1_RPC_FW_NAME_LEN];  /* null-terminated ASCII fw id */
} m1_rpc_devstatus_t;

_Static_assert(sizeof(m1_rpc_devstatus_t) == 1 + 8 + M1_RPC_FW_NAME_LEN, "status payload size");

/* Pack/unpack the LE cap bitmap <-> uint64_t (defined in m1_rpc.c). */
uint64_t m1_rpc_caps_get(const uint8_t bitmap[8]);
void     m1_rpc_caps_set(uint8_t bitmap[8], uint64_t caps);

/* ======================================================================== */
/*  Common payload structs                                                  */
/* ======================================================================== */
typedef struct __attribute__((packed)) {
    uint8_t major, minor, patch;
    char    git_hash[16];   /* null-terminated */
} m1_rpc_fw_version_t;

/* SYS_SNTP_SYNC response: UTC time obtained from NTP. */
typedef struct __attribute__((packed)) {
    uint16_t year;     /* e.g. 2026 */
    uint8_t  month;    /* 1-12 */
    uint8_t  day;      /* 1-31 */
    uint8_t  hour;     /* 0-23 */
    uint8_t  minute;   /* 0-59 */
    uint8_t  second;   /* 0-59 */
    uint8_t  weekday;  /* 0=Sun .. 6=Sat */
} m1_rpc_time_t;

/* One discovered 802.15.4 (Zigbee/Thread) device. ZB_SNIFF_GET response is
 * [u8 count] followed by `count` of these (aggregated + deduped on the ESP). */
typedef struct __attribute__((packed)) {
    uint8_t  addr_mode;   /* 2 = short (2B in addr[0..1]), 3 = extended (8B) */
    uint8_t  addr[8];     /* source address, little-endian as received */
    uint16_t panid;       /* source PAN ID (0xFFFF if unknown) */
    uint8_t  channel;     /* 11-26 the device was heard on */
    int8_t   rssi;        /* peak RSSI seen (dBm) */
    uint8_t  lqi;         /* last link-quality */
    uint8_t  flags;       /* bit0=beacon(coordinator/router) bit1=data bit2=cmd */
    uint16_t frames;      /* frames heard from this device */
    uint8_t  proto;       /* 'Z'=Zigbee, 'T'=Thread, 0/'U'=unknown (heuristic) */
} m1_rpc_zb_device_t;     /* 17 bytes */

/* WIFI_SCAN response: u16 count, then `count` of these (ssid is variable, so
 * this is the fixed prefix; ssid bytes follow, ssid_len long). */
typedef struct __attribute__((packed)) {
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  authmode;
    uint8_t  ssid_len;      /* ssid bytes follow this struct */
} m1_rpc_scan_entry_t;

/* OFF_DEAUTH_START */
typedef struct __attribute__((packed)) {
    uint8_t  bssid[6];
    uint8_t  channel;
    uint8_t  station[6];    /* ff:ff:ff:ff:ff:ff = broadcast */
    uint16_t count;         /* 0 = infinite */
    uint16_t interval_ms;   /* 0 = fastest */
} m1_rpc_deauth_req_t;

/* BLE_HID_KEY */
typedef struct __attribute__((packed)) {
    uint8_t modifier;       /* ctrl/shift/alt/gui bitfield */
    uint8_t key_count;      /* HID usage ids follow, max 6 */
} m1_rpc_hid_key_t;

/* ======================================================================== */
/*  Transport wiring (STM32 master <-> ESP32 slave)                         */
/* ======================================================================== */
/*
 * ESP32-C6 GPIO numbers (SPI2_HOST / FSPI, spi_slave_hd):
 *   SCLK = GPIO7    (M1 master drives)
 *   MOSI = GPIO12   (M1 -> ESP32)
 *   MISO = GPIO13   (ESP32 -> M1)
 *   CS   = GPIO15   (M1 master drives)
 *   HS / DATA_READY = GPIO14  (ESP32 OUTPUT -> M1 input; slave signals master)
 *
 * STM32H573 SPI3 pins (M1 PCB), configured as MASTER:
 *   SCLK = PB3 (AF6)  MOSI = PB2 (AF7)  MISO = PB4 (AF6)  CS = PB10  HS = PD7 (input)
 *
 * SPI mode 1 (CPOL=0, CPHA=1), MSB-first — matches the ESP-AT SPI-HD slave.
 * Clock: TODO validate on hardware. Prior AT bench ran 4.6875 MHz (75MHz/16);
 * Option-C target is up to 10 MHz. Start conservative, raise after PING is
 * stable at speed.
 */
#define M1_RPC_HS_ASSERTED_HIGH   1        /* ESP drives HS high = data ready */
#define M1_RPC_SPI_CLOCK_HZ       4687500  /* start here; validate then raise toward 10 MHz */

/* ======================================================================== */
/*  Protocol helpers (implemented in m1_rpc.c, shared source)               */
/* ======================================================================== */

/* CRC-16/CCITT (poly 0x1021, init 0xFFFF) over header+payload. */
uint16_t m1_rpc_crc16(const uint8_t *data, size_t len);

/* Build a frame into buf. Returns total bytes written (8+payload_len+2) or 0. */
size_t m1_rpc_build(uint8_t *buf, size_t buf_size,
                    m1_rpc_msgtype_t type, uint16_t msg_id,
                    const uint8_t *payload, uint16_t payload_len);

/* Parse/validate a frame. Returns 0 on success, negative on error:
 *   -1 bad magic/version   -2 truncated/short   -3 bad CRC   -4 bad length */
int m1_rpc_parse(const uint8_t *buf, size_t buf_len,
                 m1_rpc_header_t *hdr_out,
                 const uint8_t **payload_out, uint16_t *payload_len_out);

#ifdef __cplusplus
}
#endif

#endif /* M1_RPC_H */
