"""Flipper Zero sub-GHz helper (Momentum firmware, USB CLI).

    python3 -m havokbox.helpers.flipper scan   --port P --freq-mhz 433.92 --seconds 30
    python3 -m havokbox.helpers.flipper replay --port P --id NAME --freq-mhz 433.92

`scan` and `replay` take an injected session object (send/read_for/read_until/send_ctrl_c/close)
so they are testable without hardware; `main()` only parses args, builds a SerialSession, and
prints one JSON object to stdout.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

PROMPT = ">: "
BAUD = 230400
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
FREQ_TOL_MHZ = 0.01
MAX_FILES = 32
_FREQ_LINE = re.compile(r"^\s*Frequency:\s*(\d+)\s*$", re.M)


def parse_received(text: str) -> list[dict]:
    """Best-effort parse of `subghz rx` console lines into protocol/bit/key records."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("subghz") or s.startswith(PROMPT.strip()):
            continue
        m = re.match(
            r"^(?P<proto>[A-Za-z][\w .+-]*?)\s+(?P<bits>\d+)\s*bit\b.*?"
            r"(?:Key\s*[:=]?\s*)?(?P<key>(?:0x)?[0-9A-Fa-f ]{4,})?\s*$",
            s,
        )
        if m:
            out.append({
                "protocol": m.group("proto").strip(),
                "bits": int(m.group("bits")),
                "key": (m.group("key") or "").strip() or None,
                "raw": s[:120],
            })
        elif (km := re.match(r"^Key\s*[:=]\s*(?P<key>(?:0x)?[0-9A-Fa-f ]{2,})\s*$", s, re.I)) \
                and out and out[-1].get("protocol") and not out[-1].get("key"):
            # Flipper prints "Princeton 24bit" then "Key:0x..." on the next line: attach it
            out[-1]["key"] = km.group("key").strip()
            out[-1]["raw"] = (out[-1]["raw"] + " | " + s)[:120]
        elif re.search(r"\bkey\b\s*[:=]", s, re.I) or re.search(r"\bprotocol\b", s, re.I):
            out.append({"raw": s[:120]})
        if len(out) >= 64:
            break
    return out


def parse_listing(text: str) -> list[str]:
    """Pull candidate capture names out of `storage list /ext/subghz` output."""
    names = []
    for line in text.splitlines():
        m = re.match(r"^\s*\[F\]\s+(\S+\.sub)\b", line) or re.match(r"^\s*(\S+\.sub)\s*$", line.strip())
        if not m:
            continue
        base = m.group(1)[:-4]
        if NAME_RE.match(base):
            names.append(base)
    return names


def parse_frequency_hz(text: str):
    m = _FREQ_LINE.search(text)
    return int(m.group(1)) if m else None


def scan(session, freq_mhz: float, seconds: int) -> dict:
    hz = int(round(float(freq_mhz) * 1_000_000))
    session.send(f"subghz rx {hz}")
    rx_text = session.read_for(seconds)
    session.send_ctrl_c()
    session.read_until(PROMPT, 3)
    received = parse_received(rx_text)

    session.send("storage list /ext/subghz")
    listing = session.read_until(PROMPT, 10)
    captures = []
    for name in parse_listing(listing)[:MAX_FILES]:
        session.send(f"storage read /ext/subghz/{name}.sub")
        body = session.read_until(PROMPT, 10)
        fhz = parse_frequency_hz(body)
        if fhz is not None:
            captures.append({"id": name, "freq_mhz": round(fhz / 1_000_000, 3)})

    return {"received": received[:64], "captures": captures}


def replay(session, cap_id: str, freq_mhz: float) -> dict:
    """Transmit a previously captured .sub file, but only if its own stored Frequency matches
    the caller-approved freq_mhz within tolerance. Refuses (and sends no tx command) otherwise."""
    if not isinstance(cap_id, str) or not NAME_RE.match(cap_id):
        return {"status": "refused", "reason": "invalid capture id"}

    path = f"/ext/subghz/{cap_id}.sub"
    session.read_until(PROMPT, 3)            # drain the CLI banner's own ">: " prompt first
    session.send(f"storage read {path}")
    body = session.read_until(PROMPT, 10)
    fhz = parse_frequency_hz(body)
    if fhz is None:
        return {"status": "refused", "reason": "capture file missing or has no Frequency field"}

    actual_mhz = fhz / 1_000_000
    if abs(actual_mhz - float(freq_mhz)) > FREQ_TOL_MHZ:
        return {
            "status": "refused",
            "reason": f"file frequency {actual_mhz:.3f} MHz differs from approved {float(freq_mhz):.3f} MHz",
        }

    session.send(f"subghz tx_from_file {path}")
    out = session.read_until(PROMPT, 30)
    return {"status": "transmitted", "id": cap_id, "freq_mhz": round(actual_mhz, 3), "output": out.strip()[:300]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="havokbox.helpers.flipper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--port", required=True)
    p_scan.add_argument("--freq-mhz", type=float, required=True)
    p_scan.add_argument("--seconds", type=int, required=True)

    p_replay = sub.add_parser("replay")
    p_replay.add_argument("--port", required=True)
    p_replay.add_argument("--id", required=True)
    p_replay.add_argument("--freq-mhz", type=float, required=True)

    args = ap.parse_args(argv)

    if args.cmd == "replay" and not NAME_RE.match(args.id):
        print(json.dumps({"status": "refused", "reason": "invalid capture id"}))
        return 0

    try:
        from .serialcli import SerialSession
        session = SerialSession(args.port, BAUD, PROMPT)
        try:
            if args.cmd == "scan":
                result = scan(session, args.freq_mhz, args.seconds)
            else:
                result = replay(session, args.id, args.freq_mhz)
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001 - always emit one JSON object, never crash
        result = {"status": "error", "error": str(exc)[:200]}

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
