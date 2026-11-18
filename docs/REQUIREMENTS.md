# havok-box requirements

A headless recon and testing box (Raspberry Pi 5, Kali ARM64) for the owner's own
networks. It runs recon, proposes and runs tests under approval, and shows every
phase in a dashboard.

## Numbered requirements

1. **Platform.** Runs headless on a Pi 5 under Kali ARM64 with Python 3.11+.
   Also runs on any dev machine in *replay mode*, where each tool returns recorded
   sample output, so everything is testable without hardware.
2. **Scope file.** A YAML file names what may be tested: SSIDs/BSSIDs, IP ranges,
   BLE addresses, and an optional time window. Every task is checked against it
   before it runs. Out-of-scope tasks are refused and logged. Passive receive
   hears everything, so out-of-scope observations keep only identity fields
   (BSSID, SSID, channel, signal) needed for rogue detection.
3. **Three tool tiers.**
   - *passive* (listen only): runs automatically.
   - *active* (in-scope scans): runs automatically, only against scope targets.
   - *intrusive* (deauth, credential attacks, exploitation): needs a per-action
     approval made in the local dashboard. An approval is bound to the exact
     tool, arguments and target, is single-use, and expires.
4. **Roles.** A commander (LLM, model set in config) plans and proposes; it never
   executes. Workers run one tool each and parse output with deterministic
   parsers first; an LLM summarises only what parsers cannot. A watchdog (no AI)
   restarts crashed parts and enforces session limits.
5. **Milestone 1 tools.** Wi-Fi recon (Kismet with the Alfa, GPS tagging), LAN
   recon (nmap, arp-scan), passive LAN watch (rogue DHCP, ARP spoofing, new
   MACs), and rogue AP / evil-twin detection against a saved baseline.
6. **Milestone 2 tools.** BLE (Sniffle on the SONOFF CC2652P), Flipper Zero
   sub-GHz over USB serial, Marauder board over serial. The HackRF is out of
   this build.
7. **Findings store.** One SQLite database on the Pi is the single source of
   truth. An append-only, hash-chained event log records every task, approval
   and result as audit evidence.
8. **Dashboard.** A local web app in three phases: Recon, Test, Report. The Test
   phase is an attack-path stepper: finding, proposed step, approve or deny,
   result. Readable at enlarged text sizes, no count badges, and a Shut Down
   button that says when it is safe to unplug. Login by token.
9. **Offline mode.** With no internet, playbooks keep running passive and
   in-scope active tools. LLM requests queue on disk and drain when online.
10. **Cloud copy.** One-way push from the Pi to Cloudflare (Worker + D1) for
    review afterwards. The cloud copy is read-only and behind Cloudflare Access.
    Approvals and commands can never originate from the cloud.
11. **Data protection.** The API key lives in a root-only env file, never in the
    repo. Captured secrets (PSKs, handshakes, credentials) are never sent to the
    LLM or the cloud; a redaction pass enforces it. The data partition is
    encrypted at deploy time.
12. **Power-loss safety.** Results are written to disk as they arrive. The root
    filesystem is read-only in deployment; data sits on its own partition.
13. **Network.** The Pi joins a configured hotspot and serves the dashboard on
    that LAN. With no hotspot it raises its own access point (offline mode).
14. **Cost control.** A per-session token budget with a hard stop. Model per
    role is configurable.
15. **Tests.** Unit tests cover the scope gate, approval gate, redaction,
    parsers and the store, and run without hardware or network.

## Out of scope
- HackRF / PortaPack integration.
- Any target not listed in the scope file.
- Local LLM inference on the Pi.

## Stack
Python, Flask + Jinja2, SQLite (stdlib), PyYAML, pytest. Claude API over plain
HTTPS. No front-end build step.
