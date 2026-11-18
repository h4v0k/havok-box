"""Publisher — one-way, read-only snapshot to Cloudflare (req 9, architecture §5).

- The box is the only writer. This module only ever POSTs; it never GETs or reads anything back
  from Cloudflare, so the Cloudflare copy can't influence the box.
- A snapshot is one consistent read of the store (store.snapshot_read, under the store lock),
  serialised canonically, with a monotonic version and its SHA-256 sent alongside so the Worker
  can reject a tampered or replayed body.
- Version = max(last published + 1, unix time). Monotonic across restarts even if the local state
  file is lost, so the Worker's "newer only" rule never wedges publishing.
- The ingest token is write-only (it can't read the viewer); it lives in config/env, never argv.
- Offline: a publish request is queued (offline_queue kind "publish") and the drain loop sends
  the CURRENT state when the box is back online — the queue entry is a trigger, not a payload.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request

SCHEMA = 1
MAX_BYTES = 5 * 1024 * 1024
# A Pi has no RTC battery: before NTP sync its clock can read 1970 or a stale date. Versions are
# time-floored, so refuse to publish until the clock is plausible (after this build was written).
CLOCK_FLOOR = 1_793_000_000   # 2026-10-26
_PUBLISH_LOCK = threading.Lock()   # one publisher at a time: dashboard job vs drain thread


class PublishError(RuntimeError):
    pass


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class Publisher:
    def __init__(self, store, url: str, token: str, state_path: str, box: str = "havok-box",
                 scope_name: str = "", evidence_limit: int = 2000, transport=None,
                 clock=time.time):
        self.store = store
        self.url = url.rstrip("/")
        self.token = token
        self.state_path = state_path
        self.box = box
        self.scope_name = scope_name
        self.evidence_limit = evidence_limit
        self.transport = transport or self._http
        self.clock = clock

    @property
    def enabled(self) -> bool:
        return bool(self.url) and bool(self.token)

    # ---- state ------------------------------------------------------------
    def state(self) -> dict:
        try:
            with open(self.state_path) as fh:
                d = json.load(fh)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self, d: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(d, fh)
        os.replace(tmp, self.state_path)

    def next_version(self) -> int:
        last = int(self.state().get("version") or 0)
        return max(last + 1, int(self.clock()))

    # ---- snapshot ---------------------------------------------------------
    def build(self, version: int) -> bytes:
        snap = self.store.snapshot_read(self.evidence_limit)
        findings = []
        for f in snap["findings"]:
            try:
                data = json.loads(f.get("data") or "{}")
            except ValueError:
                data = {}
            findings.append({"result_id": f["result_id"], "space": f["space"], "kind": f["kind"],
                             "summary": f["summary"], "mode": f["mode"], "created": f["created"],
                             "data": data})
        path = []
        for p in snap["proposals"]:
            try:
                t = json.loads(p["task"])
            except ValueError:
                continue
            path.append({"task_id": t.get("id"), "result_id": p["result_id"], "tool": t.get("tool"),
                         "category": t.get("category"), "target": t.get("target") or {},
                         "label": t.get("label"), "mode": t.get("mode"), "status": p["status"],
                         "created": p["created"]})
        evidence = [{"ts": e["ts"], "kind": e["kind"], "detail": e["detail"]} for e in snap["evidence"]]
        doc = {"schema": SCHEMA, "version": version, "generated": _iso(self.clock()),
               "box": self.box, "scope_name": self.scope_name,
               "findings": findings, "attack_path": path, "evidence": evidence}
        body = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        if len(body) > MAX_BYTES:
            # Trim evidence first (oldest), then refuse rather than send a partial picture silently.
            while len(body) > MAX_BYTES and doc["evidence"]:
                doc["evidence"] = doc["evidence"][len(doc["evidence"]) // 4 + 1:]
                doc["evidence_truncated"] = True
                body = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            if len(body) > MAX_BYTES:
                raise PublishError(f"snapshot is {len(body)} bytes, over the {MAX_BYTES} limit")
        return body

    # ---- publish ----------------------------------------------------------
    def publish_now(self) -> dict:
        if not self.enabled:
            raise PublishError("publishing is not configured (publish_url / HAVOKBOX_PUBLISH_TOKEN)")
        if self.clock() < CLOCK_FLOOR:
            raise PublishError("box clock isn't set yet (waiting for NTP); not publishing")
        version = self.next_version()
        body = self.build(version)
        digest = hashlib.sha256(body).hexdigest()
        status, text = self.transport(self.url + "/ingest", body, {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "X-Snapshot-Version": str(version),
            "X-Snapshot-SHA256": digest,
        })
        if status != 201:
            hint = (" — Cloudflare already holds a newer snapshot; check the box clock / NTP"
                    if status == 409 else "")
            self.store.log("publish", f"snapshot v{version} rejected: HTTP {status}{hint}")
            raise PublishError(f"ingest returned HTTP {status}{hint}")
        self._save_state({"version": version, "sha256": digest, "at": self.clock(),
                          "bytes": len(body)})
        self.store.log("publish", f"snapshot v{version} published sha256={digest[:16]} "
                                  f"({len(body)} bytes)")
        return {"status": "ok", "version": version, "sha256": digest,
                "summary": f"Published snapshot v{version}"}

    def reachable(self) -> bool:
        """Can we reach the publish host? (Separate from the commander's Anthropic check.)"""
        from urllib.parse import urlparse
        from .drain import default_online
        u = urlparse(self.url)
        return bool(u.hostname) and default_online(u.hostname, u.port or 443)

    def _http(self, url: str, body: bytes, headers: dict) -> tuple[int, str]:
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read(2048).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode(errors="replace")


def request_publish(store) -> None:
    """Queue a publish trigger (idempotent per request). Survives restarts and offline periods."""
    from .store import new_id
    store.enqueue(f"publish:{new_id()}", "publish", {"requested": time.time()})


def publish_pending(store, publisher) -> dict:
    """If any publish trigger is queued, publish the CURRENT state once and clear them all."""
    with _PUBLISH_LOCK:   # the second caller waits, then finds nothing pending
        pending = [e for e in store.pending_queue() if e["kind"] == "publish"]
        if not pending:
            return {"status": "ok", "summary": "Already published"}
        res = publisher.publish_now()      # raises PublishError on failure; entries stay queued
        for e in pending:
            store.drain_empty(e["id"])
        return res
