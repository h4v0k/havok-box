"""Yard Stick One sub-GHz helper (rfcat / rflib, USB).

    python3 -m havokbox.helpers.yardstick scan   --freq-mhz 433.92 --seconds 30 --work-dir W
    python3 -m havokbox.helpers.yardstick replay --id NAME --freq-mhz 433.92 --work-dir W

scan: ASK/OOK receive in rfcat's "lowball" mode (no sync word, no filtering) on one frequency.
Each burst that isn't flat noise is saved as a capture file (W/subghz/<id>.json) so it can be
replayed later. Output matches the old Flipper helper: {"received": [...], "captures": [...]}.

replay: transmits ONE saved capture, only if the capture's own frequency matches the approved
frequency. The scope gate has already checked the band (rf.tx_bands) and consumed an approval
before this runs; this is the helper's second check.

Both functions take an injected radio object (the rflib RfCat API subset below), so they are
testable without hardware; main() builds the real RfCat and prints one JSON object.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
FREQ_TOL_MHZ = 0.01
MAX_RECEIVED = 64
MAX_CAPTURES = 32
DEFAULT_DRATE = 4800          # typical for fobs, doorbells and sensors (ASK/OOK, ~2-5 kbaud)
REPEAT = 3


def _hz(freq_mhz: float) -> int:
    return int(round(float(freq_mhz) * 1_000_000))


def is_noise(data: bytes) -> bool:
    """Lowball mode returns a fixed-size chunk every time; flat chunks are nothing."""
    if not data:
        return True
    distinct = set(data)
    return len(distinct) <= 1 or distinct <= {0x00, 0xFF}


def cap_dir(work_dir: str) -> str:
    d = os.path.join(work_dir, "subghz")
    os.makedirs(d, exist_ok=True)
    return d


def list_captures(work_dir: str) -> list[dict]:
    d = cap_dir(work_dir)
    out = []
    names = sorted((f for f in os.listdir(d) if f.endswith(".json")),
                   key=lambda f: os.path.getmtime(os.path.join(d, f)), reverse=True)
    for f in names[:MAX_CAPTURES]:
        try:
            with open(os.path.join(d, f)) as fh:
                c = json.load(fh)
            out.append({"id": c["id"], "freq_mhz": round(c["freq_hz"] / 1_000_000, 3)})
        except (OSError, ValueError, KeyError):
            continue
    return out


def setup_rx(radio, mods, hz: int, drate: int) -> None:
    radio.setFreq(hz)
    radio.setMdmModulation(mods["ASK_OOK"])
    radio.setMdmDRate(drate)
    radio.lowball(1)


def scan(radio, mods, freq_mhz: float, seconds: int, work_dir: str, clock=time.time) -> dict:
    hz = _hz(freq_mhz)
    setup_rx(radio, mods, hz, DEFAULT_DRATE)
    received, saved = [], 0
    stamp = time.strftime("%Y%m%d%H%M%S")
    end = clock() + max(1, int(seconds))
    try:
        while clock() < end and len(received) < MAX_RECEIVED:
            try:
                data, _ts = radio.RFrecv(timeout=1000)
            except Exception:           # rflib raises on timeout (ChipconUsbTimeoutException)
                continue
            data = bytes(data or b"")
            if is_noise(data):
                continue
            rec = {"bytes": len(data), "hex": data[:32].hex(), "freq_mhz": round(hz / 1e6, 3)}
            if saved < MAX_CAPTURES:
                cid = f"ys_{stamp}_{saved + 1}"
                with open(os.path.join(cap_dir(work_dir), cid + ".json"), "w") as fh:
                    json.dump({"id": cid, "freq_hz": hz, "modulation": "ASK_OOK", "drate": DEFAULT_DRATE,
                               "payload_hex": data.hex(), "saved_at": int(clock())}, fh)
                rec["id"] = cid
                saved += 1
            received.append(rec)
    finally:
        radio.setModeIDLE()
    return {"received": received, "captures": list_captures(work_dir)}


def replay(radio, mods, cap_id: str, freq_mhz: float, work_dir: str) -> dict:
    if not isinstance(cap_id, str) or not NAME_RE.match(cap_id):
        return {"status": "refused", "reason": "invalid capture id"}
    path = os.path.join(cap_dir(work_dir), cap_id + ".json")
    try:
        with open(path) as fh:
            cap = json.load(fh)
        hz, payload = int(cap["freq_hz"]), bytes.fromhex(cap["payload_hex"])
    except (OSError, ValueError, KeyError):
        return {"status": "refused", "reason": "capture missing or unreadable"}
    if abs(hz / 1e6 - float(freq_mhz)) > FREQ_TOL_MHZ:
        return {"status": "refused",
                "reason": f"capture frequency {hz / 1e6:.3f} MHz differs from approved {float(freq_mhz):.3f} MHz"}
    if not payload or len(payload) > 255:
        return {"status": "refused", "reason": "capture payload empty or too long"}
    try:
        radio.setFreq(hz)
        radio.setMdmModulation(mods.get(cap.get("modulation", "ASK_OOK"), mods["ASK_OOK"]))
        radio.setMdmDRate(int(cap.get("drate", DEFAULT_DRATE)))
        radio.RFxmit(payload, repeat=REPEAT)
    finally:
        radio.setModeIDLE()
    return {"status": "transmitted", "id": cap_id, "freq_mhz": round(hz / 1e6, 3),
            "bytes": len(payload), "repeat": REPEAT}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="havokbox.helpers.yardstick")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--freq-mhz", type=float, required=True)
    s.add_argument("--seconds", type=int, required=True)
    s.add_argument("--work-dir", required=True)
    r = sub.add_parser("replay")
    r.add_argument("--id", required=True)
    r.add_argument("--freq-mhz", type=float, required=True)
    r.add_argument("--work-dir", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "replay" and not NAME_RE.match(args.id):
        print(json.dumps({"status": "refused", "reason": "invalid capture id"}))
        return 0
    try:
        import rflib
        radio = rflib.RfCat()
        mods = {"ASK_OOK": rflib.MOD_ASK_OOK, "2FSK": rflib.MOD_2FSK, "GFSK": rflib.MOD_GFSK}
        if args.cmd == "scan":
            result = scan(radio, mods, args.freq_mhz, args.seconds, args.work_dir)
        else:
            result = replay(radio, mods, args.id, args.freq_mhz, args.work_dir)
    except ImportError:
        result = {"status": "error", "error": "rfcat (rflib) is not installed"}
    except Exception as e:  # device not found, USB error
        result = {"status": "error", "error": f"Yard Stick One: {e}"[:200]}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
