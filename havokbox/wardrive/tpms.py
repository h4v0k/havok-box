"""TPMS (tire-pressure sensor) receive-only helpers: pinned rtl_433 argv and a pure parser.

No I/O here. The SDR owner thread runs the argv through an injected runner. Only model, id and
RSSI are kept (never pressure/temperature). rtl_433 decoder numbers are not pinned here, so no
-R filter is passed; `parse_window` filters on "type" == "TPMS" instead.
"""
from __future__ import annotations

import json

FREQS = ("315M", "433.92M")

# Common rtl_433 TPMS decoders that validate a CRC/checksum (names as emitted in "model").
CHECKSUMMED_MODELS = frozenset({
    "Toyota", "Ford", "Renault", "Citroen", "Hyundai-VDO", "Schrader", "Schrader-EG53MA4",
    "Schrader-SMD3MA4", "Jansite", "Jansite-Solar", "Abarth-124Spider", "Eeztire-E618",
    "Porsche-Boxster", "PMV-107J", "Steelmate", "TRW-OOK", "Kia", "Mazda",
})
_MIC_OK = ("CRC", "CHECKSUM")
MIN_DECODES = 2


def window_argv(freq, seconds=50):
    """argv for one receive window. No -R: decoder numbers are not pinned; parse filters."""
    return ["rtl_433", "-F", "json", "-M", "level", "-T", str(int(seconds)), "-f", freq]


def next_freq(i):
    return FREQS[i % len(FREQS)]


def parse_window(stdout):
    """-> [{"model","id","rssi"}] for checksummed TPMS ids decoded >= 2 times in this window."""
    if isinstance(stdout, (bytes, bytearray)):
        stdout = stdout.decode("utf-8", "replace")
    seen: dict[str, dict] = {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("type") != "TPMS":
            continue
        model, rid = rec.get("model"), rec.get("id")
        if not isinstance(model, str) or not model or rid is None or isinstance(rid, (bool, float)):
            continue
        mic = rec.get("mic")
        if not (mic in _MIC_OK or model in CHECKSUMMED_MODELS):
            continue
        rid = str(rid).strip().lower()
        if not rid:
            continue
        key = f"{model}:{rid}"
        rssi = rec.get("rssi")
        rssi = float(rssi) if isinstance(rssi, (int, float)) and not isinstance(rssi, bool) else None
        ent = seen.setdefault(key, {"model": model, "id": rid, "rssi": None, "n": 0})
        ent["n"] += 1
        if rssi is not None and (ent["rssi"] is None or rssi > ent["rssi"]):
            ent["rssi"] = rssi
    return [{"model": e["model"], "id": e["id"], "rssi": e["rssi"]}
            for e in seen.values() if e["n"] >= MIN_DECODES]
