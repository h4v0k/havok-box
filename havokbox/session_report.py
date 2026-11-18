"""AI session report: an optional, READ-ONLY end-of-session prose write-up.

Only a compact, sanitised on-box digest leaves the box. The model writes prose only: nothing it
returns is parsed into tasks or executed, and the store is never written except the local
`session_reports` table. Never published to Cloudflare.

Digest privacy rules (scope limits): the digest NEVER contains raw tool output, captured hashes,
credentials, or poison / rogue-AP capture material.
  * any data key matching password/passwd/hash/cred/ntlm/secret/token/key/raw/output/stdout/stderr/
    capture/pcap is dropped (recursively);
  * findings of kind creds_default / poison / rogue_ap are reduced to their summary alone (no data);
  * remaining data values are truncated (strings 120 chars, lists 10 items, depth 3);
  * the final JSON is cut to MAX_DIGEST_BYTES before sending.
Shares the commander's daily spend cap via commander._charge().
"""
from __future__ import annotations

import json
import re
import time

from .commander import SpendCapReached

MAX_DIGEST_BYTES = 16 * 1024
SUMMARY_ONLY_KINDS = {"creds_default", "poison", "rogue_ap"}
_SECRET_KEY = re.compile(
    r"pass|hash|cred|ntlm|secret|token|key|private|raw|output|stdout|stderr|capture|pcap|cookie",
    re.I)
_NOTABLE = ("service", "nuclei", "tls", "vuln", "smb", "evil", "twin")

SYSTEM = (
    "You write a short end-of-session security summary for the owner of a lab-only recon box, from "
    "a compact digest of its findings. Plain prose only (no JSON, no commands, no payloads): what "
    "was found, notable services and vulnerabilities, the attack path taken, and suggested next "
    "STANDARD steps (e.g. patch, re-scan, review config). Do not speculate beyond the digest."
)


def _clean(v, depth=0):
    if isinstance(v, dict):
        if depth >= 3:
            return "..."
        return {str(k)[:40]: _clean(x, depth + 1) for k, x in list(v.items())[:20]
                if not _SECRET_KEY.search(str(k))}
    if isinstance(v, (list, tuple)):
        if depth >= 3:
            return "..."
        return [_clean(x, depth + 1) for x in list(v)[:10]]
    if isinstance(v, str):
        return v[:120]
    return v if isinstance(v, (int, float, bool)) or v is None else str(v)[:120]


def _load(s):
    try:
        v = json.loads(s) if isinstance(s, str) else s
    except (ValueError, TypeError):
        return {}
    return v if isinstance(v, dict) else {}


def _shrink(d: dict, limit: int) -> dict:
    while len(json.dumps(d)) > limit:
        for key in ("notable", "attack_path"):
            if d.get(key):
                d[key].pop()
                break
        else:
            d["truncated"] = True
            d.pop("evidence_kinds", None)
            break
    return d


def session_digest(store, cap: int = 120) -> dict:
    findings = store.findings()
    counts: dict = {}
    notable = []
    for f in findings:
        kind = f.get("kind") or ""
        ck = f"{f.get('space')}/{kind}"
        counts[ck] = counts.get(ck, 0) + 1
        if len(notable) >= cap or not (kind in SUMMARY_ONLY_KINDS or any(n in kind.lower() for n in _NOTABLE)):
            continue
        item = {"kind": kind, "space": f.get("space"), "summary": (f.get("summary") or "")[:200]}
        if kind not in SUMMARY_ONLY_KINDS:
            item["data"] = _clean(_load(f.get("data")))
        notable.append(item)
    path = []
    for p in store._read("SELECT task, status FROM proposals ORDER BY created"):
        if len(path) >= cap:
            break
        t = _load(p["task"])
        path.append({"tool": str(t.get("tool", ""))[:60], "category": str(t.get("category", ""))[:30],
                     "status": p["status"]})
    ev: dict = {}
    for e in store.evidence():
        ev[e["kind"]] = ev.get(e["kind"], 0) + 1
    return _shrink({"finding_counts": counts, "notable": notable, "attack_path": path,
                    "evidence_kinds": ev}, MAX_DIGEST_BYTES - 2048)


class SessionReporter:
    def __init__(self, store, commander, clock=time.time, db_table="session_reports", transport=None):
        self.store, self.commander, self.clock = store, commander, clock
        self.table = db_table if re.fullmatch(r"[A-Za-z_]+", db_table) else "session_reports"
        self.transport = transport
        with store._lock, store.cx:
            store.cx.execute(
                f"CREATE TABLE IF NOT EXISTS {self.table}(id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " created REAL, text TEXT, model TEXT)")

    def generate(self) -> dict:
        c = self.commander
        if not c.enabled:
            return {"status": "disabled"}
        payload = json.dumps(session_digest(self.store))[:MAX_DIGEST_BYTES]
        try:
            c._charge()
        except SpendCapReached:
            return {"status": "capped"}
        body = {"model": getattr(c, "model", ""), "max_tokens": max(getattr(c, "max_tokens", 600), 800),
                "system": SYSTEM, "messages": [{"role": "user", "content": payload}]}
        try:
            resp = (self.transport or c.transport)(body)
        except Exception as e:  # network/API failure must never break the box
            return {"status": "error", "error": type(e).__name__}
        text = "".join(b.get("text", "") for b in (resp or {}).get("content", [])
                       if b.get("type") == "text").strip()
        if not text:
            return {"status": "error", "error": "empty"}
        model = getattr(c, "model", "") or ""
        with self.store._lock, self.store.cx:
            cur = self.store.cx.execute(
                f"INSERT INTO {self.table}(created,text,model) VALUES(?,?,?)",
                (self.clock(), text, model))
            rid = cur.lastrowid
        return {"status": "ok", "text": text, "id": rid}

    def latest(self):
        rows = self.list(1)
        return rows[0] if rows else None

    def list(self, n: int = 10):
        return self.store._read(f"SELECT * FROM {self.table} ORDER BY id DESC LIMIT ?", (int(n),))
