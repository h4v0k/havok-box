"""Rule-based planner — the offline commander seam.

Given findings, it proposes the obvious next-step tasks. This is what runs with no internet;
when online, the Claude API commander can extend these proposals. Deterministic and testable.
It only ever *proposes*: every proposal is rebuilt by tasks.make_task, and the scope gate and a
digest-bound human approval still stand between a proposal and anything active running.

When `scope` is given, Test-phase steps are only proposed for targets in scope (an out-of-scope
button would just be refused by the gate — no point cluttering the screen with it). Passive
steps (watching an AP) are proposed for anything recon saw, including evil twins.
"""
from __future__ import annotations

from .store import new_id

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}
SMB_PORTS = {139, 445}
MAX_PER_FINDING = 24


def _task(category, tool, target, step_kind, label, suggested=True) -> dict:
    return {
        "id": new_id(),
        "category": category,
        "tool": tool,
        "target": target,
        "step_kind": step_kind,
        "label": label,
        "suggested": suggested,
    }


def _p(tool, target, suggested=False) -> dict:
    # category/label/step_kind are rebuilt from the registry by tasks.make_task
    return _task(None, tool, target, None, None, suggested)


def _channel(v):
    try:
        ch = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return ch if 1 <= ch <= 196 else None


def _bssid_in(scope, bssid) -> bool:
    return scope is None or (bssid or "").lower() in scope.bssids


def plan(findings: list[dict], scope=None, mode: str = "stealth") -> list[dict]:
    """findings: dicts with parsed `data`. Returns proposed tasks (not yet gated/approved)."""
    out = []
    for f in findings:
        data = f.get("data") or {}
        kind = f.get("kind")
        steps = []
        if kind == "hosts":
            for host in data.get("hosts", [])[:64]:
                # passive listening hears everything on the wire; only propose in-scope targets
                if host.get("ip") and (scope is None or scope.ip_in_scope(host["ip"])):
                    steps.append(_p("nmap.services", {"ip": host["ip"]}, suggested=True))
        elif kind == "services":
            ips = set()
            for s in data.get("services", []):
                ip, port = s.get("ip") or data.get("ip"), s.get("port")
                if not ip:
                    continue
                ips.add(ip)
                svc = (s.get("service") or "").lower()
                if port in SMB_PORTS or "microsoft-ds" in svc or "netbios" in svc:
                    steps.append(_p("smb.enum", {"ip": ip}, suggested=True))
                if port in WEB_PORTS or "http" in svc:
                    steps.append(_p("web.scan", {"ip": ip, "port": int(port)}, suggested=True))
            for ip in sorted(ips):
                steps.append(_p("nmap.vuln", {"ip": ip}))
        elif kind == "wifi_survey":
            twins = {(t.get("bssid") or "").lower() for t in data.get("evil_twins", [])}
            for ap in data.get("aps", []):
                b, ch = (ap.get("bssid") or "").lower(), _channel(ap.get("channel"))
                if b and ch and (b in twins or _bssid_in(scope, b)):
                    steps.append(_p("wifi.watch", {"bssid": b, "channel": ch}, suggested=b in twins))
        elif kind == "ap_watch":
            b, ch = (data.get("bssid") or "").lower(), _channel(data.get("channel"))
            if b and ch and _bssid_in(scope, b):
                cap = "wifi.capture" if mode == "stealth" else "wifi.capture_deauth"
                steps.append(_p(cap, {"bssid": b, "channel": ch}, suggested=True))
                steps.append(_p("wifi.deauth", {"bssid": b, "channel": ch}))
                if ch <= 14:   # second radio (Marauder) — 2.4 GHz only
                    steps.append(_p("marauder.deauth", {"bssid": b, "channel": ch}))
                for c in data.get("clients", [])[:5]:
                    if c.get("mac"):
                        steps.append(_p("wifi.deauth", {"bssid": b, "channel": ch,
                                                        "client": c["mac"].lower()}))
        elif kind == "esp_survey":
            for ap in data.get("aps", []):
                b, ch = (ap.get("bssid") or "").lower(), _channel(ap.get("channel"))
                if b and ch and ch <= 14 and scope is not None and b in scope.bssids:
                    steps.append(_p("marauder.deauth", {"bssid": b, "channel": ch}))
        elif kind == "ble_devices":
            for d in data.get("devices", []):
                a = (d.get("addr") or "").lower()
                if a and (scope is None or a in scope.ble):
                    steps.append(_p("ble.gatt", {"addr": a}, suggested=True))
        elif kind == "subghz":
            for c in data.get("captures", []):
                cid, mhz = c.get("id"), c.get("freq_mhz")
                if cid and isinstance(mhz, (int, float)) and (scope is None or str(cid).lower() in scope.subghz):
                    steps.append(_p("subghz.replay", {"id": cid, "freq_mhz": mhz}))
        out.extend(steps[:MAX_PER_FINDING])
    return out
