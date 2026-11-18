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

Phase 1 (Wi-Fi + wired recon, box-served dashboard) built. Run on the Pi:

```
cp config/box.example.json config/box.json      # edit lan_cidrs / box_address
cp config/scope.example.yaml config/scope.yaml  # edit to your lab
pip install fastapi uvicorn pyyaml
HAVOKBOX_TOKEN=... python3 -m havokbox.watchdog # serves the dashboard on :8080
python3 -m unittest discover -s tests
```

Console setup: `docs/console.md`. Requirements: `docs/requirements.md`. Design: `docs/architecture.md`.

## Hardware

Pi 5 (8GB) · Alfa AWUS036ACM (Wi-Fi) · SONOFF ZBDongle-P running Sniffle (BLE) · Flipper Zero + Marauder
board (sub-GHz / ESP Wi-Fi) · RTL-SDR Blog V4 (wideband RX) · GPYes u-blox 8 (GPS). HackRF/PortaPack is
not part of this build.
