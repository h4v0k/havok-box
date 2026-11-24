# havok-box

A lab-only network/RF recon box: Raspberry Pi 5 running Kali, in a hard case, with an Alfa
AWUS036ACM (Wi-Fi), two RTL-SDR Blog V4 dongles, a SONOFF CC2652P dongle running Sniffle (BLE), a
Yard Stick One (sub-GHz), and a u-blox GPS. The owner (havok) drives it from a phone dashboard, the
`hb` command, SSH, or the Kali desktop.

## Ground rules (apply to every session, on the box or in the repo)

- **Lab only.** Targets are only what `config/scope.yaml` lists. Never scan, probe or transmit at
  anything else, and don't widen the scope file. Ask the owner, who edits it by hand.
- **Standard tools only.** Orchestrate installed Kali tools. Don't write exploits, payloads or
  malware, and don't automate exploitation.
- **Use the gated paths.** For network scans, prefer `hb` (it checks scope and skips excludes)
  over raw `nmap`. Anything active (deauth, replay/transmit, poisoning, credential attempts) goes
  through the dashboard, where it needs the owner's per-action approval. Don't start those from a
  shell.
- **Receive is fine, transmit isn't.** The SDRs only listen. Never run Yard Stick/rfcat transmit,
  aireplay-ng, mdk4 or similar from here.
- **Don't touch secrets.** Leave `/etc/havokbox/`, `/data/havokbox/secrets/`, `config/box.json` and
  the dashboard token alone.
- **Ask before you change** system config: networking (`havokbox-net`, NetworkManager), firewall,
  systemd units, or udev.

## Useful commands on the box

- `hb`: menus. `hb hw`: is every board working? `hb profiles`, `hb scan <ip/cidr> -p quiet|standard|robust`,
  `hb hosts [--port N]`, `hb ports`, `hb flow <cidr>`, `hb diff old.xml new.xml`.
  Scans are saved in `/data/havokbox/scans/`.
- `havokbox-net status`: which Wi-Fi the box is on.
- `systemctl status havokbox-dashboard havokbox-watchdog`, `journalctl -u havokbox-watchdog -f`.
- Results to read: `/data/havokbox/scans/*/scan.xml` and `report.md`, plus the evidence log in
  `/data/havokbox/evidence/`.

## Code

- Python package `havokbox/`. Tools are in `havokbox/tools/`, registered in `tools/registry.py`
  with a gate category. Helpers that own a device are in `havokbox/helpers/`.
- Tests: `python3 -m pytest -q`. Keep them passing; parsers are tested without hardware.
- Setup: `scripts/kali-setup.sh` (idempotent). Docs in `docs/` (`setup.md`, `hb.md`).
- UI rules: big tap targets, readable with enlarged text, no notification count badges.
