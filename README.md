<!-- See COPYING.txt for license details. -->

# M1 ESP32-C6 Brain Firmware

Native ESP-IDF co-processor firmware for the [Monstatek M1](https://monstatek.com)'s
ESP32-C6. It runs the M1's radio features (WiFi, Bluetooth, 802.15.4, ESP-NOW peer
link) natively and talks to the M1's STM32 over a custom binary SPI link
(`m1_link`).

Version 1.6.0 includes:

- Raw BLE scan/advertising and Find My payload emulation, plus NimBLE GATT
  discovery, read/write, and notifications.
- Active PMKID capture with PCAP export and replay/station-validated WPA
  handshakes.
- Ping, ARP, SSH, Telnet, and common-port network scans.
- Passive WPS-PIN candidate discovery, per-channel airtime/deauth monitoring,
  and experimental CSI motion/presence processing.
- Streaming HTTPS for release listings and firmware downloads over
  `NET_HTTP_OPEN/READ/CLOSE` (`M1_CAP_HTTP`, bit 28).
- Dual-slot application OTA with boot-time validation and rollback support.

This is the ESP32 firmware used by **C3** M1 firmware (v0.8.0.0-C3.107 and later).
Version 1.5.1 advertises the ESP-NOW peer-link capability bit expected by the
Hapax ESP-NOW peer-link compatibility layer.

> **This is a community project and is not affiliated with or endorsed by Monstatek.**

## Compatibility

The M1 and its ESP32-C6 must run matching firmware. This brain firmware pairs with
**C3 v0.8.0.0-C3.107+**. It is **not** compatible with genuine stock Monstatek
firmware (which uses a different ESP32 firmware). See the full
[compatibility reference](https://github.com/bedge117/M1/blob/main/COMPATIBILITY.md).

## Flashing and OTA migration

Flash via the qMonstatek desktop app (ESP32 Update) — "Download latest (SPI brain)"
fetches the current factory image and writes it at `0x0`.

- `factory_ESP32C6-SPI.bin` (or `factory_m1-esp32-brain.bin` in some builds) — full
  image (bootloader + OTA data + partition table + app), flash at `0x0`.
- `app_m1-esp32-brain.bin` — application only. On OTA-capable installations the
  M1 streams this to the inactive slot over M1_RPC. For ROM-based recovery, use a
  full factory image at `0x0`; do not write an app-only image to a fixed slot
  address because the bootloader may have selected the other OTA slot.

**The first 1.6.0 installation requires a full factory flash.** Older releases have
a single factory app partition and do not advertise `M1_CAP_OTA`. The factory flash
migrates the device to the dual-slot layout; later app-only updates can use native
OTA. Newly booted images validate themselves after the SPI link, WiFi, RPC server,
and dispatch task start successfully. An unvalidated image rolls back automatically.

## Build and releases

The GitHub Actions workflow builds the ESP32-C6 firmware on pushes to `main`,
pull requests targeting `main`, and manual runs. Pushing a version tag such as
`v1.6.0` also publishes a GitHub release containing the factory image and
application-only image. To publish manually, run the workflow on the desired
source branch and enter a `v`-prefixed tag (for example, `v1.6.0`) in the
`release_tag` field. Leave it empty to build without publishing.
