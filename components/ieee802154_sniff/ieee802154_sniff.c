/*
 * ieee802154_sniff.c — passive 802.15.4 device discovery on the ESP32-C6.
 * See ieee802154_sniff.h. Parses only the clear-text MAC header (addresses,
 * PAN ID, frame type) + radio RSSI/LQI — payloads may be AES-encrypted and are
 * not touched. Aggregates by source address into a deduped device table.
 */
#include "ieee802154_sniff.h"
#include "m1_rpc.h"                 /* m1_rpc_zb_device_t (shared record) */
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"
#include "esp_phy_init.h"          /* esp_phy_disable / esp_btbb_disable — release the shared radio */
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "zb_sniff";

#define ZB_MAX_DEVICES  64
#define ZB_CH_MIN       11
#define ZB_CH_MAX       26
#define ZB_DWELL_MS     700        /* per-channel dwell when hopping — longer =
                                    * catches more of the sporadic 802.15.4 traffic,
                                    * so device counts converge run-to-run and quiet
                                    * networks get classified instead of staying '?' */
#define ZB_HOP_STACK    3072       /* hop-task stack, bytes */

static m1_rpc_zb_device_t s_devs[ZB_MAX_DEVICES];
static uint8_t            s_dev_count;
static SemaphoreHandle_t  s_lock;
static volatile bool      s_running;         /* app wants a scan active */
static bool               s_radio_enabled;   /* esp_ieee802154_enable() done once, latched */
static volatile bool      s_idle;            /* hop task has slept the radio and parked */
static volatile uint8_t   s_fixed_channel;   /* 0 = hop all channels */
static TaskHandle_t       s_hop_task;        /* created ONCE, lives for the app lifetime */

/* Static storage for the persistent hop task. Allocating it in BSS (not the
 * heap) means creation can NEVER fail with NO_MEM — the failure mode that
 * produced "802.15.4 radio start failed" when WiFi/BLE had the heap fragmented.
 * Safe because the task is created once and never deleted, so the buffers are
 * never reused. */
static StackType_t  s_hop_stack[ZB_HOP_STACK / sizeof(StackType_t)];
static StaticTask_t s_hop_tcb;

/* Enable the shared 2.4GHz radio for 802.15.4 EXACTLY ONCE for the app lifetime.
 * esp_ieee802154_enable() turns on the modem clock + PHY + BTBB and runs mac_init.
 * We deliberately never esp_ieee802154_disable()/phy_disable() afterwards: the
 * disable -> re-enable cycle is unreliable on this SoC (the 2nd enable fails, which
 * is exactly why a re-scan reported "radio start failed" until a reboot). Instead
 * we free the airwaves between scans with esp_ieee802154_sleep() (see radio_sleep),
 * which rf_disable()s the 802.15.4 path so WiFi/BLE coexistence gets the antenna
 * back, WITHOUT tearing down the MAC/PHY. On failure of the one-time enable, unwind
 * the PHY/BTBB refs it leaves held. */
static bool radio_ensure_enabled(void)
{
    if (s_radio_enabled) return true;
    esp_err_t err = esp_ieee802154_enable();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "enable: %s", esp_err_to_name(err));
        esp_ieee802154_disable();
        esp_btbb_disable();
        esp_phy_disable(PHY_MODEM_IEEE802154);
        return false;
    }
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(true);
    s_radio_enabled = true;
    return true;
}

/* Put the radio to sleep between scans: stops RX and rf_disable()s the 802.15.4
 * path so coexistence hands the antenna back to WiFi/BLE, while keeping the MAC/PHY
 * enabled so the next scan just wakes it with esp_ieee802154_receive(). This is the
 * reliable alternative to a full disable (which can't be cleanly re-enabled). */
static void radio_sleep(void)
{
    esp_ieee802154_sleep();
}

/* --- device table (mutex-protected) --- */
static void dev_update(uint8_t addr_mode, const uint8_t *addr, uint16_t panid,
                       uint8_t channel, int8_t rssi, uint8_t lqi, uint8_t type_flag,
                       char proto)
{
    uint8_t alen = (addr_mode == 2) ? 2 : 8;

    xSemaphoreTake(s_lock, portMAX_DELAY);

    m1_rpc_zb_device_t *d = NULL;
    for (int i = 0; i < s_dev_count; i++) {
        if (s_devs[i].addr_mode == addr_mode &&
            memcmp(s_devs[i].addr, addr, alen) == 0) { d = &s_devs[i]; break; }
    }
    if (!d) {
        if (s_dev_count >= ZB_MAX_DEVICES) { xSemaphoreGive(s_lock); return; }
        d = &s_devs[s_dev_count++];
        memset(d, 0, sizeof(*d));
        d->addr_mode = addr_mode;
        memcpy(d->addr, addr, alen);
        d->panid = panid;
        d->rssi  = rssi;
        d->proto = 'U';
    }
    d->channel = channel;
    if (rssi > d->rssi) d->rssi = rssi;        /* keep peak signal */
    d->lqi = lqi;
    if (panid != 0xFFFF) d->panid = panid;
    d->flags |= type_flag;
    if (d->frames < 0xFFFF) d->frames++;
    /* Lock in the first definite classification (Zigbee beacon / Thread MAC-sec)
     * — a device only gets promoted out of 'U', never flip-flopped. */
    if ((d->proto == 0 || d->proto == 'U') && proto != 'U')
        d->proto = (uint8_t)proto;

    xSemaphoreGive(s_lock);
}

/* Dest/Src PAN ID presence in the MAC header.
 * Frame version 0/1 (802.15.4-2003/2006): dest PAN present iff a dest address is
 *   present; src PAN present iff a src address is present AND not PAN-ID-compressed.
 * Frame version 2 (802.15.4-2015): per Table 7-2 — presence is decoupled from the
 *   addresses and the compression bit means different things. Getting this right is
 *   what lets Thread (which is all frame-version-2) parse instead of being dropped. */
static void pan_presence(uint8_t fver, uint8_t dmode, uint8_t smode, uint8_t pan_comp,
                         bool *dst_pan, bool *src_pan)
{
    bool d = (dmode != 0), s = (smode != 0);
    if (fver < 2) {
        *dst_pan = d;
        *src_pan = s && !pan_comp;
        return;
    }
    if (!d && !s)      { *dst_pan = pan_comp;  *src_pan = false;      }  /* rows 1,2 */
    else if (d && !s)  { *dst_pan = !pan_comp; *src_pan = false;      }  /* rows 3,4 */
    else if (!d && s)  { *dst_pan = false;     *src_pan = !pan_comp;  }  /* rows 5,6 */
    else if (dmode == 3 && smode == 3)
                       { *dst_pan = !pan_comp; *src_pan = false;      }  /* rows 7,8 (both ext) */
    else               { *dst_pan = true;      *src_pan = !pan_comp;  }  /* rows 9-14 (a short) */
}

/* --- 802.15.4 MAC header parse: pull the SOURCE addr + PAN ID + frame type ---
 * FCF[2] | [seq[1]] | [dstPAN[2]] [dstAddr[2|8]] | [srcPAN[2]] [srcAddr[2|8]] | ... */
static void parse_frame(const uint8_t *mpdu, uint8_t len, uint8_t channel,
                        int8_t rssi, uint8_t lqi)
{
    if (len < 3) return;
    uint16_t fcf       = (uint16_t)mpdu[0] | ((uint16_t)mpdu[1] << 8);
    uint8_t  ftype     = fcf & 0x7;
    uint8_t  sec_en    = (fcf >> 3) & 0x1;
    uint8_t  pan_comp  = (fcf >> 6) & 0x1;
    uint8_t  dest_mode = (fcf >> 10) & 0x3;
    uint8_t  fver      = (fcf >> 12) & 0x3;
    uint8_t  src_mode  = (fcf >> 14) & 0x3;
    /* Frame-version-2 (2015) toggles: sequence-number suppression and info elements. */
    bool seq_suppr  = (fver >= 2) && (fcf & 0x0100);
    bool ie_present = (fver >= 2) && (fcf & 0x0200);

    if (src_mode == 0) return;                 /* no source -> can't ID a device */

    int off = 2 + (seq_suppr ? 0 : 1);         /* FCF(2) + optional seq(1) */

    bool dst_pan_present, src_pan_present;
    pan_presence(fver, dest_mode, src_mode, pan_comp, &dst_pan_present, &src_pan_present);

    uint16_t dest_panid = 0xFFFF;
    if (dst_pan_present) {
        if (off + 2 > len) return;
        dest_panid = (uint16_t)mpdu[off] | ((uint16_t)mpdu[off + 1] << 8);
        off += 2;
    }
    if (dest_mode != 0) {
        int dlen = (dest_mode == 2) ? 2 : 8;
        if (off + dlen > len) return;
        off += dlen;
    }

    uint16_t src_panid;
    if (src_pan_present) {
        if (off + 2 > len) return;
        src_panid = (uint16_t)mpdu[off] | ((uint16_t)mpdu[off + 1] << 8);
        off += 2;
    } else {
        src_panid = dest_panid;                /* compressed: shares the dest PAN */
    }

    int slen = (src_mode == 2) ? 2 : 8;
    if (off + slen > len) return;
    const uint8_t *src_addr = &mpdu[off];
    int payload_off = off + slen;

    uint8_t tflag = (ftype == 0) ? 0x01 :      /* beacon = coordinator/router */
                    (ftype == 1) ? 0x02 :      /* data */
                    (ftype == 3) ? 0x04 : 0x00;/* MAC command */

    /* --- heuristic Zigbee vs Thread classification ---
     * Zigbee: uses 802.15.4 beacons (Thread doesn't) and NWK-layer security
     *         (MAC frame usually unencrypted).
     * Thread: mandates MAC-layer security + 802.15.4-2015 frame version, and
     *         carries 6LoWPAN/IPv6 (MLE) — visible as a 6LoWPAN dispatch byte
     *         when a frame isn't encrypted. */
    char proto = 'U';
    if (ftype == 0) {
        proto = 'Z';                           /* beacon -> Zigbee coordinator/router */
    } else if (sec_en && fver >= 2) {
        proto = 'T';                           /* MAC-secured 2015 frame -> Thread */
    } else if (!sec_en && !ie_present && payload_off < len) {
        uint8_t p0 = mpdu[payload_off];
        /* 6LoWPAN IPv6 dispatch -> Thread. Kept narrow (0x41 uncompressed IPv6,
         * 0x42 HC1, 0x60-0x7F LOWPAN_IPHC) — NOT the mesh/frag 0x80+ range, which
         * overlaps Zigbee NWK frame-control bytes (protocol version 2) and would
         * misclassify Zigbee data frames as Thread. */
        if (p0 == 0x41 || p0 == 0x42 || (p0 >= 0x60 && p0 <= 0x7F)) {
            proto = 'T';
        } else {
            /* Zigbee NWK-layer frame control (first payload byte on an
             * unsecured-MAC frame): bits[1:0] = NWK frame type (0 data,
             * 1 command, 3 inter-PAN), bits[5:2] = protocol version. Zigbee
             * PRO stamps protocol version 2 on every NWK frame — a reliable
             * positive Zigbee signature (Thread carries no NWK layer). This is
             * what finally IDs plain Zigbee data frames (e.g. Hue) as 'Z'
             * instead of leaving them Unknown; PAN propagation then tags the
             * rest of that network. */
            uint8_t nwk_ver  = (p0 >> 2) & 0x0F;
            uint8_t nwk_type = p0 & 0x03;
            if (nwk_ver == 2 && (nwk_type == 0 || nwk_type == 1 || nwk_type == 3))
                proto = 'Z';
        }
    }

    dev_update(src_mode, src_addr, src_panid, channel, rssi, lqi, tflag, proto);
}

/* Radio RX-done callback — overrides the weak driver symbol. Runs in the
 * 802.15.4 driver task context. frame[0] = PSDU length (incl 2-byte FCS). */
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)
{
    if (s_running && frame && frame_info) {
        uint8_t flen = frame[0];
        if (flen >= 2 && flen <= 127) {
            parse_frame(&frame[1], (uint8_t)(flen - 2), frame_info->channel,
                        frame_info->rssi, frame_info->lqi);
        }
    }
}

/* Active probe: broadcast an 802.15.4 Beacon Request MAC command on the current
 * channel. Zigbee coordinators/routers are required to answer with a beacon (the
 * same mechanism a joining device uses to find networks), which is a definitive
 * Zigbee signature carrying the PAN ID — so quiet networks that passive sniffing
 * never overhears still get discovered and tagged 'Z'. (Thread doesn't answer
 * classic beacon requests; it uses MLE Discovery, so this is a Zigbee aid.)
 *
 * Frame: FCF=0x0803 (MAC command, dest short broadcast, no source, frame ver 0),
 * seq, dest PAN 0xFFFF, dest addr 0xFFFF, command id 0x07 (Beacon Request). The
 * driver appends the 2-byte FCS, so frame[0] (PSDU length) counts it. */
static void send_beacon_request(void)
{
    static uint8_t seq;
    uint8_t f[11] = {
        10,             /* [0] PSDU length: 8 MAC bytes + 2 FCS */
        0x03, 0x08,     /* FCF */
        seq++,          /* sequence number */
        0xFF, 0xFF,     /* dest PAN  = broadcast */
        0xFF, 0xFF,     /* dest addr = broadcast (short) */
        0x07,           /* MAC command: Beacon Request */
        0x00, 0x00      /* FCS placeholder (hardware fills) */
    };
    esp_ieee802154_transmit(f, false);   /* best-effort; radio returns to RX after */
}

/* Single PERSISTENT worker for the whole app lifetime, allocated from static
 * storage (never NO_MEM). start()/stop() enable-once/wake/sleep the radio from the
 * RPC-task context and flip s_running; the worker only channel-hops while
 * s_running, and parks otherwise. Keeping radio enable/wake/sleep out of the worker
 * (and never disabling) is what makes re-scans reliable. */
static void hop_task(void *arg)
{
    (void)arg;
    uint8_t ch = ZB_CH_MIN;
    for (;;) {
        if (!s_running) {           /* parked between scans; radio owned by start/stop */
            s_idle = true;
            ch = ZB_CH_MIN;
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        /* The radio was enabled synchronously by start() before s_running was
         * set, so we only hop here. set_channel only marks the channel PENDING in
         * the PIB; it is flushed to the radio by ieee802154_pib_update() inside
         * receive(). Without the explicit receive() re-arm, rx_when_idle keeps the
         * receiver pinned to the previous channel and the sweep never advances —
         * which is why only channel 11 was ever captured. */
        esp_ieee802154_set_channel(s_fixed_channel ? s_fixed_channel : ch);
        esp_ieee802154_receive();
        /* Dwell in short slices (so we react to a stop request within ~20ms) and
         * actively solicit beacons TWICE during the visit — early and midway — so a
         * responding Zigbee coordinator/router is caught even if the first request
         * collides or is missed. */
        const int slices = ZB_DWELL_MS / 20;
        for (int t = 0; t < slices && s_running; t++) {
            if (t == 1 || t == slices / 2)
                send_beacon_request();
            vTaskDelay(pdMS_TO_TICKS(20));
        }
        if (!s_fixed_channel && ++ch > ZB_CH_MAX) ch = ZB_CH_MIN;
    }
}

esp_err_t ieee802154_sniff_start(uint8_t channel)
{
    if (!s_lock) s_lock = xSemaphoreCreateMutex();

    /* If a prior scan is somehow still active, wind it down first so the worker
     * is parked and the radio is in a known state before we re-acquire. */
    if (s_running) ieee802154_sniff_stop();

    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_dev_count = 0;
    memset(s_devs, 0, sizeof(s_devs));
    xSemaphoreGive(s_lock);

    /* Spin up the persistent worker exactly once, from static storage so it can
     * never fail on heap pressure. It parks itself whenever s_running is false. */
    if (!s_hop_task) {
        s_hop_task = xTaskCreateStatic(hop_task, "zb_hop",
                                       ZB_HOP_STACK / sizeof(StackType_t), NULL, 5,
                                       s_hop_stack, &s_hop_tcb);
        if (!s_hop_task) {
            ESP_LOGE(TAG, "hop task create failed");
            return ESP_ERR_NO_MEM;
        }
    }

    /* Enable the radio ONCE (synchronously, in the RPC-task context — never in the
     * worker: deferring it made the RPC reply wait on PHY calibration + coex, so
     * the M1's ZB_SNIFF_START timed out and reported a bogus "start failed"). On
     * re-scans it is already enabled; esp_ieee802154_receive() below simply wakes it
     * from the sleep that stop() put it in. A genuine one-time enable failure
     * surfaces as a clean NAK. Safe to touch the radio because the worker is parked
     * (s_running == false) until we set it below. */
    if (!radio_ensure_enabled()) {
        ESP_LOGE(TAG, "radio enable failed");
        return ESP_FAIL;
    }
    esp_ieee802154_set_channel(channel ? channel : ZB_CH_MIN);
    esp_ieee802154_receive();     /* wakes the radio from sleep into RX */

    s_fixed_channel = channel;
    s_idle = false;
    s_running = true;              /* worker begins hopping */
    ESP_LOGI(TAG, "sniff start ch=%u", channel);
    return ESP_OK;
}

esp_err_t ieee802154_sniff_stop(void)
{
    s_running = false;
    /* Wait for the worker to park (stop touching the radio), up to ~1s. */
    for (int i = 0; i < 100 && s_hop_task && !s_idle; i++)
        vTaskDelay(pdMS_TO_TICKS(10));
    /* Sleep the radio (rf off) so WiFi/BLE coexistence gets the antenna back, but
     * keep it enabled so the next scan just wakes it — the disable/re-enable cycle
     * is what made re-scans fail. */
    if (s_radio_enabled)
        radio_sleep();
    ESP_LOGI(TAG, "sniff stop (%u devices)", s_dev_count);
    return ESP_OK;
}

int ieee802154_sniff_get(uint8_t *buf, int cap)
{
    if (cap < 1) return 0;
    if (!s_lock) { buf[0] = 0; return 1; }

    xSemaphoreTake(s_lock, portMAX_DELAY);

    /* PAN-based propagation: an 802.15.4 network (PAN) is entirely Zigbee OR
     * entirely Thread. Once ANY device on a PAN is classified from a definitive
     * frame (Zigbee beacon / Thread MAC-sec or 6LoWPAN), apply that protocol to
     * every other device sharing the PAN. This is what stops the cross-spillover
     * — you only need one identifiable frame per network. */
    for (int i = 0; i < s_dev_count; i++) {
        if ((s_devs[i].proto != 'Z' && s_devs[i].proto != 'T') ||
            s_devs[i].panid == 0xFFFF)
            continue;
        for (int j = 0; j < s_dev_count; j++) {
            if (j != i && s_devs[j].panid == s_devs[i].panid &&
                s_devs[j].proto != 'Z' && s_devs[j].proto != 'T')
                s_devs[j].proto = s_devs[i].proto;
        }
    }

    int max_fit = (cap - 1) / (int)sizeof(m1_rpc_zb_device_t);
    int n = s_dev_count;
    if (n > max_fit) n = max_fit;
    buf[0] = (uint8_t)n;
    memcpy(&buf[1], s_devs, (size_t)n * sizeof(m1_rpc_zb_device_t));
    xSemaphoreGive(s_lock);
    return 1 + n * (int)sizeof(m1_rpc_zb_device_t);
}
