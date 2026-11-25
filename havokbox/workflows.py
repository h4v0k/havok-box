"""Workflow registry: which standard Kali tool sits behind each dashboard button.

This is the single place that maps signal space -> phase -> button -> tool -> gate category.
The dashboard renders its buttons from here; the orchestrator builds tasks from here; the
scope gate decides each task. Nothing in this file runs a tool.

Phases:
  discover  passive listening; runs on one tap, no approval
  identify  look closer at one thing you tapped; some steps are active and need approval
  test      active checks of a control; always needs approval

`needs` is what the user must have selected before the button is enabled.
"""
from __future__ import annotations

SPACES = [
    {
        "id": "wifi",
        "label": "Wi-Fi",
        "radio": "Alfa AWUS036ACH, Marauder board",
        "discover": [
            {"id": "wifi.scan", "label": "Scan Wi-Fi", "tool": "kismet", "category": "recon.passive",
             "needs": None, "what": "List every access point and client in range, tagged with GPS."},
            {"id": "wifi.rogues", "label": "Watch for rogues", "tool": "kismet-alerts + marauder",
             "category": "recon.passive", "needs": None,
             "what": "Flag evil twins, unknown APs on lab SSIDs and deauth floods."},
        ],
        "identify": [
            {"id": "wifi.clients", "label": "Show clients", "tool": "kismet", "category": "recon.passive",
             "needs": "ap", "what": "Which devices are talking to this access point."},
            {"id": "wifi.security", "label": "Check security", "tool": "kismet + wash",
             "category": "recon.passive", "needs": "ap",
             "what": "Encryption, WPS state and whether management-frame protection is on."},
            {"id": "wifi.handshake", "label": "Capture handshake", "tool": "airodump-ng",
             "category": "recon.passive", "needs": "ap",
             "what": "Wait for a client to join and save the handshake. Listening only."},
        ],
        "test": [
            {"id": "wifi.deauth", "label": "Deauth test", "tool": "aireplay-ng", "category": "wifi.deauth",
             "needs": "ap", "what": "Check that protected management frames stop a forced disconnect."},
            {"id": "wifi.pmkid", "label": "PMKID request", "tool": "hcxdumptool", "category": "wifi.inject",
             "needs": "ap", "what": "Ask the AP for a PMKID to see if it leaks one."},
        ],
    },
    {
        "id": "lan",
        "label": "Network",
        "radio": "Ethernet or joined lab Wi-Fi",
        "discover": [
            {"id": "lan.listen", "label": "Listen on network", "tool": "tcpdump + bettercap (recon only)",
             "category": "recon.passive", "needs": None,
             "what": "Watch ARP and DHCP for rogue DHCP servers, ARP spoofing and new devices."},
        ],
        "identify": [
            {"id": "lan.hosts", "label": "Find hosts", "tool": "nmap -sn", "category": "recon.active",
             "needs": "subnet", "what": "Ping sweep of one in-scope subnet."},
            {"id": "lan.services", "label": "Scan services", "tool": "nmap -sV -sC", "category": "recon.active",
             "needs": "host", "what": "Open ports and service versions on one host."},
            {"id": "lan.vulns", "label": "Check known vulns", "tool": "nmap --script vuln", "category": "recon.active",
             "needs": "host", "what": "Match services against known vulnerabilities. Detection only."},
        ],
        "test": [
            {"id": "lan.defaults", "label": "Default logins", "tool": "netexec / hydra (small default list)",
             "category": "auth.attempt", "needs": "host",
             "what": "Try vendor default credentials on one service."},
            {"id": "lan.arp", "label": "ARP spoof test", "tool": "bettercap arp.spoof", "category": "exploit.tool",
             "needs": "host", "what": "Check that the switch or IDS catches ARP spoofing."},
            {"id": "lan.verify", "label": "Verify a finding", "tool": "metasploit (check)", "category": "exploit.tool",
             "needs": "host", "what": "Run the stock module's check for a vuln the scan reported."},
        ],
    },
    {
        "id": "ble",
        "label": "Bluetooth",
        "radio": "SONOFF CC2652P (Sniffle)",
        "discover": [
            {"id": "ble.scan", "label": "Scan Bluetooth", "tool": "sniffle", "category": "recon.passive",
             "needs": None, "what": "List BLE devices advertising nearby."},
        ],
        "identify": [
            {"id": "ble.follow", "label": "Follow connection", "tool": "sniffle", "category": "recon.passive",
             "needs": "ble", "what": "Capture one device's connection to see if it is encrypted."},
            {"id": "ble.services", "label": "List services", "tool": "bleak / gatttool", "category": "ble.connect",
             "needs": "ble", "what": "Connect and list what the device exposes."},
        ],
        "test": [
            {"id": "ble.read", "label": "Read without pairing", "tool": "bleak / gatttool", "category": "ble.connect",
             "needs": "ble", "what": "Check whether data can be read with no pairing."},
        ],
    },
    {
        "id": "subghz",
        "label": "Sub-GHz",
        "radio": "Yard Stick One (rfcat); Flipper Zero as backup",
        "discover": [
            {"id": "subghz.listen", "label": "Listen for signals", "tool": "rfcat (lowball RX)",
             "category": "recon.passive", "needs": None,
             "what": "Catch remotes, fobs and sensors on 315/433/915 MHz."},
        ],
        "identify": [
            {"id": "subghz.record", "label": "Record signal", "tool": "rfcat (saves each signal)",
             "category": "recon.passive", "needs": "signal", "what": "Save one signal and name its protocol."},
        ],
        "test": [
            {"id": "subghz.replay", "label": "Replay test", "tool": "rfcat RFxmit",
             "category": "rf.replay", "needs": "signal",
             "what": "Check that the receiver rejects a replayed signal."},
        ],
    },
    {
        "id": "radio",
        "label": "Ham & two-way radio",
        "radio": "RTL-SDR Blog V3 (receive only)",
        "discover": [
            {"id": "radio.bands", "label": "Who's talking", "tool": "rtl_power", "category": "recon.passive",
             "needs": None, "what": "Which FRS/GMRS, MURS, NOAA, 2m and 70cm channels are active."},
            {"id": "radio.aprs", "label": "APRS stations", "tool": "rtl_fm + direwolf",
             "category": "recon.passive", "needs": None, "what": "Ham stations on 144.390 MHz, with positions."},
        ],
        "identify": [],
        "test": [],
    },
    {
        "id": "spectrum",
        "label": "Spectrum",
        "radio": "RTL-SDR Blog V3",
        "discover": [
            {"id": "spectrum.sweep", "label": "Sweep spectrum", "tool": "rtl_power", "category": "recon.passive",
             "needs": None, "what": "Show where the radio activity is."},
            {"id": "spectrum.decode", "label": "Decode sensors", "tool": "rtl_433", "category": "recon.passive",
             "needs": None, "what": "Decode weather stations, tire sensors, alarm sensors and similar."},
        ],
        "identify": [],
        "test": [],
    },
]

PHASES = ("discover", "identify", "test")


def actions():
    """Every action, flattened, with its space and phase attached."""
    for space in SPACES:
        for phase in PHASES:
            for action in space[phase]:
                yield {**action, "space