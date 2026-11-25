# havok-box

An AI-assisted, **lab-only** network/RF recon and testing platform for a Raspberry Pi 5 in a portable case.
A planner agent reads findings and proposes the next step; cheap workers each run one standard tool and
summarise its output; a non-AI watchdog keeps the box alive and shuts it down cleanly. A dashboard walks
the attack path phase by phase, and every active action waits for human approval.

> **Scope:** this platform operates only against networks and devices listed in the scope file
> (`config/scope.yaml`). It is built for authorized testing of the owner's own lab. Anything outside the
> scope file is a hard refuse. Active actions (deauth, injection, replay, auth attacks, tool runs that
> transmit or modify) never execute without per-action approval in the dashboard.

## Design boundary

This repo is **orchestration, not exploits**. It wraps standard, already-installed tools (nmap, Kismet,
bettercap, the Sniffle BLE sniffer, the Flipper/Marauder, RTL-SDR utilities) and gates them. It does not
contain hand-authored exploit code or payloads; the "testing" phase drives those standard tools, with
approval, against in-scope lab targets.

## Status

Phases 1, 3 and 4 built: box-served dashboard plus 19 gated tools across wired, Wi-Fi, BLE, sub-GHz, RTL-SDR and Marauder. Phase 2 (read-only Cloudflare snapshot) built. Tool output parsers are fixture-tested; verify them on real hardware. Run on the Pi:

```
cp config/box.example.json config/box.json      # edit lan_cidrs / box_address
cp config/scope.example.yaml config/scope.yaml  # edit to your lab
pip install starlette uvicorn pyyaml pyserial
sudo apt install nmap tcpdump kismet aircrack-ng smbclient whatweb tshark bluez rtl-sdr rtl-433 ttyd
# Sniffle: clone to /opt/sniffle and flash the SONOFF dongle (see the Sniffle README)
python3 -m havokbox.provision                   # token + self-signed cert; prints the SHA-256 fingerprint
python3 -m havokbox.watchdog                    # serves the dashboard on https://<box>:8443
python3 -m unittest discover -s tests
```

Interfaces and serial ports: `"hw"` in `config/box.json` (defaults in `havokbox/tools/__init__.py`;
use `/dev/serial/by-id/...` paths for the Flipper, Marauder and Sniffle dongle). Kismet: create an API key in Kismet's web UI, then write `Cookie: KISMET=<key>` to
`/data/havokbox/secrets/kismet.header` (`chmod 600`); the key never appears on a command line.
Wardrive (Drive tab): receive-only; needs gpsd (`-b`), Kismet with `gps=gpsd` and its log dir in
`hw.kismet_log_dir`, and your own devices in `wardrive_mine` so they never alert. Drives and Kismet
logs are deleted after 7 days. Design: `docs/design-wardrive.md`.
Drive Guard (Phase 5): mount a tablet on the box's Wi-Fi, install `box-ca.crt` from provisioning as a
trusted CA, open `https://<box>:8443/guard.html` and enter `guard_token` (it reaches only the guard
screen). Turn on Android "Stay awake while charging". Phone alerts: set `HAVOKBOX_DISCORD_WEBHOOK`
(env only); add `guard_quiet_zones` for home/work. Camera data: Report → refresh, or
`POST /api/alpr/refresh` while online. Design: `docs/design-drive-guard.md`.
Phase 6 extras: set dongle serials with `rtl_eeprom -s` and put them in `hw.sdr_serial` /
`hw.sdr2_serial` (ADS-B/AIS get their own lane only with a second dongle); AIS-catcher picks a
dongle by index (`hw.ais_device_index`). Rayhunter: tether the Orbic over USB and set
`rayhunter_url` (e.g. `http://192.168.1.1:8080`). Baseline drift: set `lab_gateway` (and
`pinned_static`), scan the lab, then Recon → Learn baseline. Site survey: Recon → Wi-Fi site survey.
Formats still to confirm on hardware: Remote ID offsets, readsb `--device` serial, AIS-catcher `-o 5`,
Rayhunter endpoints. Design: `docs/design-phase6.md`.
Snapshot publishing (Phase 2): deploy the Worker in `cloudflare/` (see its README), set
`publish_url` in `config/box.json` and `HAVOKBOX_PUBLISH_TOKEN` in the watchdog's environment. Publishing
waits until the clock is NTP-synced (the Pi has no RTC battery). Then use Report → Publish.
Adding a tool:
`docs/tool-contract.md`. Console setup: `docs/console.md`. Full Kali desktop in the browser (noVNC): `docs/desktop.md`. Dashboard design + checklist: `docs/design-dashboard.md`. Requirements: `docs/requirements.md`. Design: `docs/architecture.md`.

## Hardware

Pi 5 (8GB) · Alfa AWUS036ACM (Wi-Fi) · SONOFF ZBDongle-P running Sniffle (BLE) · Flipper Zero + Marauder
board (sub-GHz / ESP Wi-Fi) · RTL-SDR Blog V3 (wideband RX) · GPYes u-blox 8 (GPS). HackRF/PortaPack is
not part of this build.
