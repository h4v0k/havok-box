"""Read-only client and poller for an EFF Rayhunter device (fake cell tower detection).

NOTE: the endpoints used here (`/api/qmdl-manifest`, `/api/analysis-report/<entry>`) and the
report/manifest shapes are not a stable API. They MUST be confirmed against the pinned
Rayhunter release before this is trusted; an unseen report version is surfaced as
"unknown_version", never as clear. This module only ever issues HTTP GET to two allowlisted
paths on an RFC1918 IPv4 literal, never follows redirects, and writes nothing to the device.
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

MANIFEST_PATH = "/api/qmdl-manifest"
REPORT_PREFIX = "/api/analysis-report/"
_ENTRY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
KNOWN_REPORT_VERSIONS = {"1", "2"}
MSG_MAX = 200


class RayhunterError(Exception):
    pass


def validate_url(url: str) -> str:
    """Return the normalised base URL, or raise ValueError."""
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    try:
        p = urlsplit(url.strip())
        port = p.port
    except ValueError as e:
        raise ValueError(f"bad url: {e}")
    if p.scheme != "http":
        raise ValueError("url must use http")
    if p.username is not None or p.password is not None or "@" in p.netloc:
        raise ValueError("userinfo not allowed")
    if p.path or p.query or p.fragment:
        raise ValueError("no path, query or fragment allowed")
    if port is None or not (0 < port < 65536):
        raise ValueError("port required")
    try:
        ip = ipaddress.IPv4Address(p.hostname or "")
    except ValueError:
        raise ValueError("host must be an IPv4 literal")
    if not any(ip in n for n in _PRIVATE):
        raise ValueError("host must be an RFC1918 address")
    return f"http://{ip}:{port}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def default_transport(url: str, timeout: float, max_bytes: int) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    req = urllib.request.Request(url, method="GET", headers={"Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, OSError) as e:
        raise RayhunterError(f"unreachable: {e}")


class RayhunterClient:
    def __init__(self, url, transport=None, timeout=5, max_bytes=1_000_000):
        self.base = validate_url(url)
        self.transport = transport or default_transport
        self.timeout = timeout
        self.max_bytes = max_bytes

    def _get(self, path: str) -> str:
        status, body = self.transport(self.base + path, self.timeout, self.max_bytes)
        if 300 <= status < 400:
            raise RayhunterError(f"redirect refused ({status})")
        if status != 200:
            raise RayhunterError(f"http {status}")
        if len(body) > self.max_bytes:
            raise RayhunterError("response too large")
        return body.decode("utf-8", "replace")

    def manifest(self) -> str:
        return self._get(MANIFEST_PATH)

    def report(self, entry: str) -> str:
        if not isinstance(entry, str) or not _ENTRY_RE.match(entry):
            raise RayhunterError("bad entry name")
        return self._get(REPORT_PREFIX + entry)


# ---------------------------------------------------------------- parsing

def _s(v):
    return None if v is None or isinstance(v, (dict, list)) else str(v)


def parse_manifest(text: str) -> dict:
    out = {"current_entry": None, "version": None}
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return out
    if not isinstance(obj, dict):
        return out
    out["version"] = _s(obj.get("version") or obj.get("rayhunter_version"))
    cur = obj.get("current_entry")
    if isinstance(cur, dict):
        cur = cur.get("name")
    if cur is None:
        for key in ("current_qmdl_entry", "current"):
            c = obj.get(key)
            cur = c.get("name") if isinstance(c, dict) else c
            if cur:
                break
    out["current_entry"] = _s(cur) or None
    return out


def _severity(v) -> str:
    return "high" if v == "High" else "medium"


def _events(row: dict):
    ev = row.get("events")
    if isinstance(ev, list):
        return ev
    if isinstance(row.get("event"), dict):
        return [row["event"]]
    if "message" in row or "event_type" in row:
        return [row]
    return []


def parse_report(ndjson: str) -> dict:
    lines = [ln for ln in (ndjson or "").splitlines() if ln.strip()]
    meta, rows = {}, []
    names = []
    for i, ln in enumerate(lines):
        try:
            obj = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        if not meta and i == 0:
            meta = obj
            an = obj.get("analyzers")
            if isinstance(an, list):
                names = [(a.get("name") if isinstance(a, dict) else a) for a in an]
            continue
        ts = _s(obj.get("packet_timestamp") or obj.get("timestamp") or obj.get("ts"))
        for j, ev in enumerate(_events(obj)):
            if not isinstance(ev, dict):
                continue
            et = ev.get("event_type")
            sev = et.get("severity") if isinstance(et, dict) else ev.get("severity")
            analyzer = _s(ev.get("analyzer")) or (_s(names[j]) if j < len(names) and names[j] else None) \
                or f"analyzer{j}"
            rows.append({"ts": ts, "analyzer": analyzer, "severity": _severity(sev),
                         "message": (_s(ev.get("message")) or "")[:MSG_MAX]})
    return {"report_version": _s(meta.get("report_version")), "rows": rows}


# ---------------------------------------------------------------- poller

class RayhunterPoller:
    def __init__(self, client, clock):
        self.client = client
        self.clock = clock
        self._seen: set = set()
        self.last = {"status": "unreachable", "version": None, "entry": None, "new": [], "at": None}
        self._warnings = 0
        self._polled = False

    def poll(self) -> dict:
        res = {"status": "unreachable", "version": None, "entry": None, "new": []}
        try:
            man = parse_manifest(self.client.manifest())
            res["entry"] = man["current_entry"]
            if not man["current_entry"]:
                res["status"] = "not_recording"
                res["version"] = man["version"]
            else:
                rep = parse_report(self.client.report(man["current_entry"]))
                res["version"] = rep["report_version"]
                res["status"] = "ok" if rep["report_version"] in KNOWN_REPORT_VERSIONS else "unknown_version"
                entry = man["current_entry"]
                self._warnings = len(rep["rows"])
                for r in rep["rows"]:
                    k = (entry, r["ts"], r["analyzer"])
                    if k not in self._seen:
                        self._seen.add(k)
                        res["new"].append(r)
        except RayhunterError:
            res["status"] = "unreachable"
        res["at"] = self.clock()
        self.last = res
        self._polled = True
        return res

    def status_text(self) -> str:
        if not self._polled:
            return "Rayhunter has not been checked yet."
        st = self.last["status"]
        if st == "unreachable":
            return "Rayhunter is unreachable, so cell tower status is unknown."
        if st == "not_recording":
            return "Rayhunter is not recording, so cell tower status is unknown."
        if st == "unknown_version":
            return "Rayhunter report version is not recognised; results are shown but cannot be trusted."
        if self._warnings:
            return f"Rayhunter reported {self._warnings} warning(s) in the current recording."
        return "Rayhunter is recording and reports no warnings (all clear)."
