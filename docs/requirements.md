# Requirements

Numbered so reviews can point at them. Lab use only.

1. **Recon.** Discover hosts/devices on in-scope networks (nmap); Wi-Fi APs/clients with rogue-AP and
   evil-twin detection (Kismet + Alfa); BLE devices (Sniffle on the SONOFF); sub-GHz devices (Flipper);
   a wideband RX survey (RTL-SDR, incl. rtl_433 for 315/433/915 MHz IoT). Passive by default.
2. **Anomaly detection.** Flag rogue APs, evil twins, rogue DHCP, unexpected BLE/IoT devices, and wired
   anomalies (ARP spoofing, new MACs) — against a learned baseline of the lab.
3. **Testing / exploitation.** For in-scope targets only, the commander proposes next actions that drive
   standard installed tools. Active actions (deauth, injection, replay, auth attempts, any TX or
   state-changing run) execute **only** after per-action human approval in the dashboard. No action runs
   against anything not in the scope file.
4. **AI orchestration.** Commander (planner; never executes a tool) + Haiku workers (one tool each, parse
   output, return a short summary) + non-AI watchdog (restart, time limits, clean shutdown). Only
   summaries go to the API; raw output is parsed on-box.
5. **Scope enforcement.** The scope file is the single authority for what is in scope. Every worker task
   is checked against it before dispatch; out-of-scope is a hard refuse, logged.
6. **Dashboard.** Phase-by-phase attack-path view: recon → finding → suggested next step → approval →
   result, plus an evidence log. No notification count badges.
7. **Offline mode.** With no internet, recon playbooks keep running and results queue; the queue syncs to
   the API when back online. No local LLM.
8. **Data & security.** Findings + evidence in a local encrypted store; a dedicated API key with a spend
   cap; OS partition read-only, data on its own partition so a yanked USB-C cable can't corrupt the OS.
9. **Cloudflare.** A one-way, read-only published snapshot of findings and the attack path for
   after-action review. The box stays the only writer; the Cloudflare copy is never written back.
10. **Hardware.** Runs on the Pi 5 case build. Tools: Kismet/Alfa, nmap/wired, Sniffle (BLE),
    Flipper + Marauder (sub-GHz / ESP Wi-Fi), RTL-SDR (wideband RX), GPS. HackRF/PortaPack excluded.

## Build order

1. Wi-Fi + wired recon and the box-served dashboard, end to end (scope engine, commander/worker/watchdog,
   nmap + Kismet workers, approval gate, evidence log, offline queue).
2. Cloudflare one-way read-only snapshot.
3. BLE (Sniffle), Flipper sub-GHz, Marauder, RTL-SDR workers.
4. Testing-phase actions behind the approval gate.
