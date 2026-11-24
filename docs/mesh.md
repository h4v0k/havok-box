# LoRa link: the box ↔ your phone (Meshtastic)

Two Heltec LoRa 32 V4 boards (915 MHz):

- **Box node:** plugged into the hub over USB. The `havokbox-mesh` service owns it.
- **Your node:** battery-powered and paired to your phone over Bluetooth in the Meshtastic app.

## Setup (once)

1. Flash both boards with Meshtastic. The web flasher at flasher.meshtastic.org works from a
   Mac in Chrome. In the app, set **Region = US**.
2. Put both nodes on the **same private channel**. In the app on your node, create a channel and
   share its QR code. On the box node, open the Meshtastic web client or plug it into your phone
   once and scan the same QR. The private key keeps other people's nodes from reading your messages.
3. Find your node's id in the app (it starts with `!`), then on the box run:
   `sudo scripts/mesh-owner.sh '!a1b2c3d4'`
4. From your phone, message the box node: `status`.

## What it does

- **Alerts to your phone with no internet:** Drive Guard warnings and other box alerts go to
  Discord when the box is online, and to your node over LoRa at the same time. They're
  rate-limited (each kind once per 10 min, at most 10 an hour) because LoRa airtime is limited.
- **Ask the box:** send `status` (uptime, which Wi-Fi it's on, last scan), `hw` (hardware
  check summary), `last` (last scan result) or `help`.
  - The box answers **only your node**, at most once every 10 seconds.
  - **These only report.** Nothing can be started, approved or changed over LoRa. Active work
    still goes through the dashboard.
- **Meshtastic nodes nearby:** a dashboard button lists the nodes the box's radio has heard:
  name, last heard, signal, hops, and position if that person shares it. It's passive.
- **915 MHz in "Who's talking":** the RTL-SDR sweep includes 902–928 MHz. It shows LoRa and
  sensor activity, but doesn't decode it.

## Checks

- `hb hw` includes **LoRa node (Meshtastic)**. It shows whether the bridge has the radio and
  whether your node is set.
- `journalctl -u havokbox-mesh -f` shows the bridge's log.
- If the box picks the wrong serial port, set `hw.mesh_port` in `config/box.json` to the node's
  `/dev/serial/by-id/...` path.
