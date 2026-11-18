# Dashboard workflows — Kali tools mapped to phases and buttons

Every button maps to one gate category (see `docs/architecture.md`). Passive/discovery is one tap;
anything active opens an approval sheet showing the exact command + target before it runs. The commander
highlights the suggested next button per finding, so the normal path is "tap the glowing button."

Phases: **Recon** (listen/enumerate the signal space) → **Enumerate** (pull detail per target) →
**Test** (active checks, approval) → **Report** (compile findings + attack path, publish snapshot).

New gate category this introduces: `recon.discovery` — host discovery (ARP / ping sweep) confined to
in-scope networks; auto-allowable because it's low-impact on your own lab. Service/version/vuln scans stay
`recon.active` (approval).

## Modes — Stealth vs Standard

A global toggle in the dashboard header. It changes which tool and flags each button uses; the scope gate
still applies the same way. **Default = Stealth.**

| Action | Standard (faster, louder) | Stealth (quiet) |
|--------|---------------------------|-----------------|
| Discover hosts | nmap -sn / arp-scan — active sweep → `recon.discovery` | passive listen: bettercap / arpwatch / p0f on ARP, DHCP, mDNS — sends nothing → `recon.passive` |
| Scan services | nmap -sV -sC -T4 (all ports) | nmap -sS -T1 --scan-delay, top ports only, fragmented |
| Capture handshake | aireplay-ng deauth to force reassoc | hcxdumptool PMKID / wait for natural reassoc — no deauth |

Stealth prefers passive equivalents and throttled timing; Standard trades noise for speed. The mode is
shown in the header and recorded with every finding so the report says how it was gathered.

## Wi-Fi — Alfa (monitor mode)
| Phase | Kali tool | Button | Gate |
|-------|-----------|--------|------|
| Recon | Kismet | Scan Wi-Fi | recon.passive |
| Recon | Kismet alerts (rogue AP / evil twin / deauth flood) | surfaced as findings | — |
| Enumerate | airodump-ng (single channel) | Watch this AP | recon.passive |
| Test | aireplay-ng + airodump/hcxdumptool | Capture handshake | wifi.deauth |
| Test | aireplay-ng (targeted client, or broadcast) | Deauth | wifi.deauth |

**Deauth** is a first-class Test-phase button, not just a finding follow-up: pick a target AP from recon,
optionally a single client, and fire. Targeted (one client MAC) is quieter; broadcast drops every client
on the AP and is louder — the confirm sheet says which. The gate requires the AP's BSSID to be in
`wifi.bssids`; each deauth needs its own approval. Runs on the Alfa or, as a second radio, the Marauder/ESP.

Cracking is offloaded to the homelab/hashcat — the box captures, it doesn't crack.

## Wired / IP — Pi NIC on the lab network
| Phase | Kali tool | Button | Gate |
|-------|-----------|--------|------|
| Recon | nmap -sn / arp-scan (Standard) · passive ARP/DHCP/mDNS listen (Stealth) | Discover hosts | recon.discovery / recon.passive |
| Recon | bettercap / arpwatch (ARP spoofing, new MACs) | Watch ARP | recon.passive |
| Enumerate | nmap -sV -sC | Scan services | recon.active |
| Test | nmap --script vuln (standard NSE) | Vuln scan (NSE) | recon.active |
| Test | enum4linux / smbclient | Enumerate SMB | recon.active |
| Test | whatweb / nikto | Scan web service | recon.active |

## BLE — SONOFF + Sniffle
| Phase | Kali tool | Button | Gate |
|-------|-----------|--------|------|
| Recon | Sniffle scan, bluetoothctl | Scan BLE | recon.passive |
| Enumerate | gatttool / nRF (GATT services) | Enumerate services | recon.active |

## Sub-GHz — Flipper Zero (+ CC1101)
| Phase | Kali tool | Button | Gate |
|-------|-----------|--------|------|
| Recon | Flipper freq analyzer (CLI) | Scan sub-GHz | recon.passive |
| Test | Flipper replay saved capture | Replay signal | rf.replay (+ band check) |

## Wideband RX — RTL-SDR
| Phase | Kali tool | Button | Gate |
|-------|-----------|--------|------|
| Recon | rtl_power sweep | Spectrum survey | recon.passive |
| Recon | rtl_433 | Decode IoT (315/433/915) | recon.passive |

## ESP Wi-Fi — Marauder board
| Phase | Kali tool | Button | Gate |
|-------|-----------|--------|------|
| Recon | Marauder scan / sniff | Scan (ESP) | recon.passive |
| Test | Marauder deauth | Deauth (ESP) | wifi.deauth |

## Report
| Phase | Action | Button | Gate |
|-------|--------|--------|------|
| Report | compile findings + attack path, publish read-only snapshot | Generate report | — |

## Direct Kali access (Console)

A **Console** tab in the dashboard: a web terminal (ttyd / xterm.js over the box LAN) that drops you into a
real Kali shell on the Pi for when the buttons aren't enough. It's you at the keyboard, so it bypasses the
gate — but every console session is logged to the evidence store, it sits behind the same dashboard auth,
it's reachable only on the box LAN, and it's off by default in config until you turn it on. The dashboard
stays the primary surface; the console is the escape hatch.

## Dashboard UX rules
- Phone-first. Big cards (one per signal space), one primary button each for Recon. Large tap targets.
- Each finding row carries its gate-approved next-step buttons; the commander's suggested one is highlighted.
- Active actions open a confirm sheet: exact command, target, and that it can't be undone — one tap to run.
- A phase bar across the top (Recon → Enumerate → Test → Report). No notification count badges anywhere.
- Offline: cards still scan and findings still appear; the commander's suggestions queue and fill in on reconnect.
