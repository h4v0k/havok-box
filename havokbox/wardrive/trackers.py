"""BLE tracker classification from parsed advertisement fields (pure).

classify(device) -> str | None, using device["company_ids"], ["uuid16"], ["mfg_data"].

Classes: findmy_separated, google_dult, tile, smarttag, chipolo.

Limits (documented, accepted): Samsung SmartTag and phone/other addresses rotate often, so a
single tracker may appear as many devices and follow-me will likely miss it. Find My is only
reported in the separated-from-owner frame (type 0x12, length 0x19); the short near-owner
frame is the owner's own tag and returns None.
"""
from __future__ import annotations

APPLE = 0x004C
_UUID_CLASS = {0xFEED: "tile", 0xFEEC: "tile", 0xFD5A: "smarttag", 0xFE33: "chipolo", 0xFE65: "chipolo"}


def _apple_payloads(device: dict) -> list[bytes]:
    out = []
    for h in device.get("mfg_data") or []:
        try:
            b = bytes.fromhex(h)
        except ValueError:
            continue
        if b[:2] == b"\x4c\x00":   # company id prefix included
            b = b[2:]
        out.append(b)
    return out


def classify(device: dict) -> str | None:
    cids = device.get("company_ids") or []
    uuids = device.get("uuid16") or []
    if APPLE in cids:
        for b in _apple_payloads(device):
            if len(b) >= 2 and b[0] == 0x12 and b[1] == 0x19:
                return "findmy_separated"
    if 0xFEAA in uuids:
        frames = []
        for h in device.get("mfg_data") or []:
            h = h.lower()
            if h.startswith("aafe"):
                h = h[4:]
            if len(h) >= 2:
                frames.append(int(h[:2], 16))
        if not frames or any(f in (0x40, 0x41) for f in frames):
            return "google_dult"
    for u in uuids:
        if u in _UUID_CLASS:
            return _UUID_CLASS[u]
    return None
