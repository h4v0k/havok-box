"""Meshtastic (LoRa) link between the box and your phone: shared pieces.

The radio itself is owned by one process, the bridge (havokbox/helpers/meshbridge.py, systemd
havokbox-mesh). Everything else talks to it through files in <data>/mesh/:

    outbox/*.json   alerts the dashboard wants sent to your phone's node (MeshOutbox writes them)
    nodes.json      Meshtastic nodes the box has heard (the bridge refreshes it)
    status.json     whether the bridge has the radio, its node id, the owner node

Commands from your phone (status, hw, last, help) are answered only for the owner node set in
box.json (hw.mesh_owner, e.g. "!a1b2c3d4"), and they only REPORT. Nothing can be started,
approved or changed over LoRa.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import deque

MAX_TEXT = 200                 # Meshtastic text payloads are ~200 bytes
KEY_GAP_S = 600
HOURLY_MAX = 10                # LoRa airtime is precious
NODE_ID = re.compile(r"^![0-9a-f]{8}$")
COMMANDS = ("status", "hw", "last", "help")


def mesh_dir(data_dir: str) -> str:
    return os.path.join(data_dir, "mesh")


def clip(text: str, n: int = MAX_TEXT) -> str:
    text = " ".join(str(text).split())
    while len(text.encode()) > n:
        text = text[:-2] + "…"
    return text


class MeshOutbox:
    """Notifier with the same send()/flush() shape as the Discord one; drops files for the bridge."""

    def __init__(self, data_dir: str | None, clock=time.time):
        self._dir = os.path.join(mesh_dir(data_dir), "outbox") if data_dir else None
        self.enabled = bool(self._dir)
        self._clock = clock
        self._key_last: dict[str, float] = {}
        self._sent: deque = deque()
        self._n = 0

    def __repr__(self):
        return f"MeshOutbox(enabled={self.enabled})"

    def send(self, key, kind, severity, text, ts, lat=None, lon=None) -> bool:
        if not self.enabled:
            return False
        now = self._clock()
        if key in self._key_last and now - self._key_last[key] < KEY_GAP_S:
            return False
        while self._sent and now - self._sent[0] >= 3600:
            self._sent.popleft()
        if len(self._sent) >= HOURLY_MAX:
            return False
        self._key_last[key] = now
        self._sent.append(now)
        body = f"[{str(severity).upper()}] " + (str(text) if kind is None else f"{kind} — {text}")
        if lat is not None and lon is not None:
            body += f" @{lat:.4f},{lon:.4f}"
        os.makedirs(self._dir, exist_ok=True)
        self._n += 1
        name = f"{int(now * 1000)}-{self._n}.json"
        tmp = os.path.join(self._dir, "." + name)
        with open(tmp, "w") as fh:
            json.dump({"text": clip(body), "at": now}, fh)
        os.replace(tmp, os.path.join(self._dir, name))   # atomic: the bridge never sees half a file
        return True

    def flush(self) -> int:
        return 0                                           # the bridge sends; nothing to do here


class Fanout:
    """Send each alert to every enabled notifier (Discord over internet, Meshtastic over LoRa)."""

    def __init__(self, *notifiers):
        self.notifiers = [n for n in notifiers if n is not None]

    @property
    def enabled(self) -> bool:
        return any(getattr(n, "enabled", False) for n in self.notifiers)

    def send(self, *a, **k) -> bool:
        sent = False
        for n in self.notifiers:
            if getattr(n, "enabled", False):
                try:
                    sent = bool(n.send(*a, **k)) or sent
                except Exception:
                    pass
        return sent

    def flush(self) -> int:
        total = 0
        for n in self.notifiers:
            if getattr(n, "enabled", False):
                try:
                    total += n.flush() or 0
                except Exception:
                    pass
        return total


# ---------------------------------------------------------------- snapshots

def node_rows(nodes: dict, my_id: str | None, now: float) -> list[dict]:
    """meshtastic interface.nodes -> plain rows, newest first. Never includes our own node."""
    rows = []
    for nid, n in (nodes or {}).items():
        if nid == my_id or not isinstance(n, dict):
            continue
        user = n.get("user") or {}
        pos = n.get("position") or {}
        heard = n.get("lastHeard")
        rows.append({
            "id": str(user.get("id") or nid)[:12],
            "name": str(user.get("longName") or "")[:40],
            "short": str(user.get("shortName") or "")[:8],
            "hw": str(user.get("hwModel") or "")[:24],
            "last_heard_s": int(now - heard) if isinstance(heard, (int, float)) else None,
            "snr": n.get("snr"),
            "hops": n.get("hopsAway"),
            "lat": round(pos["latitude"], 4) if isinstance(pos.get("latitude"), (int, float)) else None,
            "lon": round(pos["longitude"], 4) if isinstance(pos.get("longitude"), (int, float)) else None,
        })
    rows.sort(key=lambda r: (r["last_heard_s"] is None, r["last_heard_s"] or 0))
    return rows[:200]


def read_json(path: str, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


# ---------------------------------------------------------------- replies (report only)

def _uptime() -> str:
    try:
        secs = int(float(open("/proc/uptime").read().split()[0]))
    except (OSError, ValueError, IndexError):
        return "?"
    h, m = divmod(secs // 60, 60)
    return f"{h}h{m:02d}m"


def last_scan_line(scans_dir: str) -> str:
    try:
        from .hbcli import parse
        xs = sorted((p for p in os.scandir(scans_dir) if p.is_dir()), key=lambda p: p.stat().st_mtime)
        if not xs:
            return "no scans yet"
        d = xs[-1].path
        name = os.path.basename(d)
        stamp, _, rest = name.partition("_")
        hosts = parse(open(os.path.join(d, "scan.xml")).read())
        ports = sum(len(h["ports"]) for h in hosts)
        return f"last scan {stamp[9:11]}:{stamp[11:13]} {rest.replace('_', ' ')}: {len(hosts)} up, {ports} open ports"
    except (OSError, ValueError, ImportError):
        return "last scan: unreadable"


def reply_for(cmd: str, *, scans_dir: str, net_status=None, hw_rows=None) -> str:
    cmd = (cmd or "").strip().lower()
    if cmd == "status":
        net = net_status() if net_status else "?"
        return clip(f"havok-box up {_uptime()} · {net} · {last_scan_line(scans_dir)}")
    if cmd == "last":
        return clip(last_scan_line(scans_dir))
    if cmd == "hw":
        rows = hw_rows() if hw_rows else []
        ok = sum(1 for r in rows if r["status"] == "ok")
        bad = [r for r in rows if r["status"] != "ok"]
        tail = "; ".join(f"{r['board'].split(' (')[0]}: {r['detail']}" for r in bad[:3])
        return clip(f"hw: {ok} ok, {len(bad)} need a look" + (f" — {tail}" if tail else ""))
    return "havok-box: send status, hw or last"
