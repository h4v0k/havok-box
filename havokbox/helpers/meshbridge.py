"""Meshtastic bridge: the one process that owns the box's LoRa node (systemd havokbox-mesh).

    python3 -m havokbox.helpers.meshbridge run   --data-dir /data/havokbox [--port /dev/serial/by-id/...]
    python3 -m havokbox.helpers.meshbridge nodes --data-dir /data/havokbox      (prints the snapshot)

run: connects to the node over USB serial and loops:
  - sends queued alerts (mesh/outbox) to the owner node as direct messages
  - answers status / hw / last / help, only from the owner node, rate-limited, report-only
  - writes mesh/nodes.json (nodes heard) and mesh/status.json every 30 s
It retries the radio every 30 s if it's unplugged, and idles quietly with no owner set.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import time

from .. import mesh

OUTBOX_MAX_AGE_S = 2 * 3600
REPLY_GAP_S = 10
SNAPSHOT_EVERY_S = 30


def load_hw() -> dict:
    try:
        from ..config import BoxConfig
        return BoxConfig.load().hardware()
    except Exception:
        return {}


def net_status() -> str:
    try:
        out = subprocess.run(["havokbox-net", "status"], capture_output=True, text=True, timeout=10).stdout
        return out.strip() or "net ?"
    except (OSError, subprocess.SubprocessError):
        return "net ?"


def hw_rows() -> list[dict]:
    from .. import hwcheck
    return hwcheck.check()


def pending(outbox: str, now: float) -> list[str]:
    try:
        names = sorted(f for f in os.listdir(outbox) if f.endswith(".json") and not f.startswith("."))
    except OSError:
        return []
    keep = []
    for f in names:
        p = os.path.join(outbox, f)
        item = mesh.read_json(p, {})
        if now - float(item.get("at", 0)) > OUTBOX_MAX_AGE_S:
            os.unlink(p)                      # stale alert: drop rather than send old news
        else:
            keep.append(p)
    return keep[-50:]


class Bridge:
    def __init__(self, iface, owner: str | None, data_dir: str, scans_dir: str, clock=time.time,
                 replier=None):
        self.iface, self.owner, self.clock = iface, owner, clock
        self.dir = mesh.mesh_dir(data_dir)
        self.outbox = os.path.join(self.dir, "outbox")
        self.scans_dir = scans_dir
        self.inbox: queue.Queue = queue.Queue()
        self.last_reply = 0.0
        self.replier = replier or (lambda cmd: mesh.reply_for(cmd, scans_dir=scans_dir,
                                                              net_status=net_status, hw_rows=hw_rows))

    def my_id(self):
        try:
            return self.iface.getMyNodeInfo().get("user", {}).get("id")
        except Exception:
            return None

    def on_text(self, packet, interface=None):          # runs on the meshtastic reader thread
        try:
            frm = packet.get("fromId")
            text = (packet.get("decoded") or {}).get("text") or ""
        except AttributeError:
            return
        if self.owner and frm == self.owner:
            self.inbox.put(text[:40])

    def handle_inbox(self) -> int:
        n = 0
        while not self.inbox.empty():
            cmd = self.inbox.get_nowait().strip().lower()
            if cmd not in mesh.COMMANDS or self.clock() - self.last_reply < REPLY_GAP_S:
                continue
            self.last_reply = self.clock()
            self.iface.sendText(mesh.clip(self.replier(cmd)), destinationId=self.owner, wantAck=True)
            n += 1
        return n

    def send_outbox(self) -> int:
        if not self.owner:
            return 0
        sent = 0
        for p in pending(self.outbox, self.clock())[:3]:   # a few per tick; LoRa is slow
            item = mesh.read_json(p, {})
            if item.get("text"):
                self.iface.sendText(mesh.clip(item["text"]), destinationId=self.owner, wantAck=True)
                sent += 1
            os.unlink(p)
        return sent

    def snapshot(self, port: str | None) -> None:
        me = self.my_id()
        mesh.write_json(os.path.join(self.dir, "nodes.json"),
                        {"at": self.clock(), "nodes": mesh.node_rows(getattr(self.iface, "nodes", {}), me,
                                                                     self.clock())})
        mesh.write_json(os.path.join(self.dir, "status.json"),
                        {"connected": True, "port": port, "my_node": me, "owner": self.owner, "at": self.clock()})


def run(data_dir: str, port: str | None, scans_dir: str) -> int:
    hw = load_hw()
    port = port or hw.get("mesh_port") or None
    owner = hw.get("mesh_owner") or None
    if owner and not mesh.NODE_ID.match(owner):
        print(f"meshbridge: ignoring bad mesh_owner {owner!r} (want !xxxxxxxx)", flush=True)
        owner = None
    status_path = os.path.join(mesh.mesh_dir(data_dir), "status.json")
    try:
        import meshtastic.serial_interface
        from pubsub import pub
    except ImportError:
        mesh.write_json(status_path, {"connected": False, "error": "meshtastic library not installed"})
        print("meshbridge: pip install meshtastic", flush=True)
        return 1
    while True:
        try:
            iface = meshtastic.serial_interface.SerialInterface(devPath=port)
        except Exception as e:
            mesh.write_json(status_path, {"connected": False, "error": str(e)[:120], "owner": owner,
                                          "at": time.time()})
            time.sleep(30)
            continue
        b = Bridge(iface, owner, data_dir, scans_dir)
        pub.subscribe(b.on_text, "meshtastic.receive.text")
        print(f"meshbridge: connected ({port or 'auto'}), owner {owner or 'not set'}", flush=True)
        last_snap = 0.0
        try:
            while True:
                b.handle_inbox()
                b.send_outbox()
                if time.time() - last_snap >= SNAPSHOT_EVERY_S:
                    b.snapshot(port)
                    last_snap = time.time()
                time.sleep(2)
        except Exception as e:                       # unplugged or serial error: reconnect
            print(f"meshbridge: {type(e).__name__}: {e}", flush=True)
            try:
                pub.unsubscribe(b.on_text, "meshtastic.receive.text")
                iface.close()
            except Exception:
                pass
            time.sleep(10)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="havokbox.helpers.meshbridge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--data-dir", required=True)
    r.add_argument("--port")
    r.add_argument("--scans-dir", default=None)
    n = sub.add_parser("nodes")
    n.add_argument("--data-dir", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "nodes":
        d = mesh.mesh_dir(a.data_dir)
        snap = mesh.read_json(os.path.join(d, "nodes.json"), {"nodes": []})
        st = mesh.read_json(os.path.join(d, "status.json"), {"connected": False})
        age = time.time() - float(snap.get("at") or 0)
        print(json.dumps({"status": st, "nodes": snap.get("nodes", []), "age_s": int(age)}))
        return 0
    return run(a.data_dir, a.port, a.scans_dir or os.path.join(a.data_dir, "scans"))


if __name__ == "__main__":
    sys.exit(main())
