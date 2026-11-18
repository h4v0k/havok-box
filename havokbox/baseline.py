"""Baseline drift (pure functions). Findings are dicts with kind, space, data, created (as Api.state builds them).

inventory(findings) -> {space: {key: attrs}}; a space appears only if it was actually scanned.
attrs always carries "kind" (host/ap/ble/iot/subghz). Counts live under inventory["_meta"].
"""
from __future__ import annotations

import re

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _latest(findings):
    best = {}
    for i, f in enumerate(findings or []):
        if not isinstance(f, dict):
            continue
        k = (f.get("space"), f.get("kind"))
        order = (f.get("created") or 0, i)
        if k not in best or order >= best[k][0]:
            best[k] = (order, f)
    return {k: v[1] for k, v in best.items()}


def _mac(v):
    m = str(v or "").strip().lower().replace("-", ":")
    return m if _MAC.match(m) else None


def inventory(findings) -> dict:
    inv: dict = {}
    meta = {"ble_random_count": 0}
    for (space, kind), f in _latest(findings).items():
        data = f.get("data") if isinstance(f.get("data"), dict) else {}
        if kind == "hosts":
            sp = inv.setdefault(space, {})
            for an in data.get("anomalies") or []:
                if isinstance(an, dict) and an.get("type") == "arp_conflict" and an.get("ip"):
                    meta.setdefault("arp_conflicts", []).append(
                        {"ip": str(an["ip"]), "macs": [str(m) for m in (an.get("macs") or [])][:8]})
            for h in data.get("hosts") or []:
                if not isinstance(h, dict) or not h.get("ip"):
                    continue
                ip, mac = str(h["ip"]), _mac(h.get("mac"))
                key = mac or f"ip:{ip}"
                cur = sp.get(key)
                if cur is None:
                    sp[key] = {"kind": "host", "ip": ip, "ips": [ip], "weak": mac is None}
                elif ip not in cur["ips"]:
                    cur["ips"].append(ip)
        elif kind == "wifi_survey":
            sp = inv.setdefault(space, {})
            for a in data.get("aps") or []:
                b = _mac(a.get("bssid")) if isinstance(a, dict) else None
                if b:
                    sp[b] = {"kind": "ap", "ssid": a.get("ssid"), "channel": a.get("channel")}
        elif kind == "ble_devices":
            sp = inv.setdefault(space, {})
            for d in data.get("devices") or []:
                if not isinstance(d, dict) or not d.get("addr"):
                    continue
                if d.get("random"):
                    meta["ble_random_count"] += 1
                else:
                    sp[str(d["addr"]).lower()] = {"kind": "ble", "name": d.get("name")}
        elif kind == "iot_devices":
            sp = inv.setdefault(space, {})
            for d in data.get("devices") or []:
                if isinstance(d, dict) and d.get("model") is not None:
                    key = f"{d.get('model')}:{d.get('id', '')}:{d.get('channel', '')}"
                    sp[key] = {"kind": "iot", "model": d.get("model")}
        elif kind == "subghz":
            sp = inv.setdefault(space, {})
            for d in data.get("received") or []:
                if isinstance(d, dict) and d.get("protocol") and d.get("key"):
                    sp[f"{d['protocol']}:{d['key']}"] = {"kind": "subghz", "protocol": d["protocol"]}
    inv["_meta"] = meta
    return inv


def _item(space, key, kind, sev, label, detail):
    return {"space": space, "key": key, "kind": kind, "severity": sev, "label": label, "detail": detail}


def drift(inv, baseline_rows, gateway_ip=None, pinned_static=()) -> list:
    out = []
    rows = [r for r in (baseline_rows or []) if isinstance(r, dict)]
    base: dict = {}
    for r in rows:
        base.setdefault(r.get("space"), {})[r.get("key")] = r
    special = {ip for ip in (gateway_ip, *pinned_static) if ip}

    # baseline ip -> mac (strong hosts only)
    base_ip_mac = {}
    for r in rows:
        a = r.get("attrs") or {}
        if (a.get("kind") == "host" or (not a.get("kind") and "ip" in a)) and not a.get("weak") \
                and not str(r.get("key", "")).startswith("ip:"):
            for ip in a.get("ips") or ([a["ip"]] if a.get("ip") else []):
                base_ip_mac[ip] = r["key"]
    base_ssids = {(r.get("attrs") or {}).get("ssid") for r in rows
                  if (r.get("attrs") or {}).get("kind") == "ap"
                  or ((r.get("attrs") or {}).get("kind") is None and r.get("space") == "wifi")} - {None, ""}

    for space, items in inv.items():
        if space.startswith("_"):
            continue
        b = base.get(space, {})
        for key, a in items.items():
            kind = a.get("kind")
            if kind == "host":
                ips = a.get("ips") or [a.get("ip")]
                # A KNOWN host taking over the gateway / a pinned IP is the classic spoof (review #1)
                spoof = None
                if not a.get("weak"):
                    for ip in ips:
                        if ip in special and base_ip_mac.get(ip) not in (None, key):
                            spoof = (ip, f"{ip} was {base_ip_mac[ip]} in the baseline, now answered by {key}")
                            break
                    if spoof is None and gateway_ip in ips and gateway_ip in base_ip_mac:
                        owned = [ip for ip in ips if ip in base_ip_mac and base_ip_mac[ip] != key]
                        if len(owned) >= 2 or (gateway_ip in owned and len(ips) >= 2):
                            spoof = (gateway_ip, f"{key} answers for {len(ips)} IPs including the gateway")
                if spoof:
                    out.append(_item(space, key, "arp_spoof", "high", spoof[0], spoof[1]))
                    continue
                if key in b:
                    old = (b[key].get("attrs") or {}).get("ip")
                    if old and old not in ips:
                        out.append(_item(space, key, "ip_reassigned", "info", a["ip"],
                                         f"{key} moved from {old} to {a['ip']}"))
                    continue
                if not a.get("weak"):
                    hit = False
                    for ip in ips:
                        if ip in special and base_ip_mac.get(ip) not in (None, key):
                            out.append(_item(space, key, "arp_spoof", "high", ip,
                                             f"{ip} was {base_ip_mac[ip]} in the baseline, now answered by {key}"))
                            hit = True
                            break
                    if not hit and gateway_ip in ips and gateway_ip in base_ip_mac:
                        owned = [ip for ip in ips if ip in base_ip_mac and base_ip_mac[ip] != key]
                        if len(owned) >= 2:
                            out.append(_item(space, key, "arp_spoof", "high", gateway_ip,
                                             f"{key} answers for {len(owned)} baseline IPs including the gateway"))
                            hit = True
                    if hit:
                        continue
                    prev = [ip for ip in ips if ip in base_ip_mac]
                    out.append(_item(space, key, "new_host", "medium", a["ip"], f"new MAC {key} at {a['ip']}"))
                    for ip in prev:
                        out.append(_item(space, key, "ip_reassigned", "info", ip,
                                         f"{ip} was {base_ip_mac[ip]}, now {key}"))
                else:
                    out.append(_item(space, key, "new_host", "medium", a["ip"],
                                     f"new host {a['ip']} (no MAC, weak identity)"))
            elif kind == "ap":
                ssid = a.get("ssid") or ""
                if key in b:
                    oldch = (b[key].get("attrs") or {}).get("channel")
                    if oldch is not None and a.get("channel") is not None and oldch != a["channel"]:
                        out.append(_item(space, key, "ap_channel_change", "info", ssid or key,
                                         f"channel {oldch} -> {a['channel']}"))
                elif ssid and ssid in base_ssids:
                    out.append(_item(space, key, "evil_twin_indicator", "high", ssid,
                                     f"new BSSID {key} advertising baseline SSID {ssid}"))
                else:
                    out.append(_item(space, key, "new_ap", "medium", ssid or key, f"new AP {key}"))
            elif kind in ("ble", "iot", "subghz"):
                if key not in b:
                    k = "new_ble" if kind == "ble" else "new_iot"
                    out.append(_item(space, key, k, "low", a.get("name") or a.get("model") or key,
                                     f"new {kind} id {key}"))
    # Same-capture conflicts reported by the passive listener (review #2): two MACs for one IP.
    for c in (inv.get("_meta") or {}).get("arp_conflicts", []):
        ip = c.get("ip")
        sev = "high" if ip in special else "medium"
        out.append(_item("wired", f"conflict:{ip}", "arp_spoof" if sev == "high" else "arp_conflict",
                         sev, ip, f"{ip} answered by {len(c.get('macs') or [])} MACs in one capture: "
                                  + ", ".join((c.get("macs") or [])[:4])))
    for space, b in base.items():
        if space not in inv:
            continue
        for key, r in b.items():
            if key not in inv[space]:
                out.append(_item(space, key, "gone", "info", r.get("label") or key, "in baseline, not seen this scan"))
    return out


class DriftCache:
    """Memoises drift() on (max finding created, max baseline rowid)."""

    def __init__(self):
        self._key = None
        self._val = None
        self.hits = 0
        self.misses = 0

    def get(self, findings, baseline_rows, gateway_ip=None, pinned_static=()):
        rows = baseline_rows or []
        key = (max((f.get("created") or 0 for f in findings or []), default=0),
               max((r.get("rowid", r.get("id", 0)) or 0 for r in rows), default=0),
               len(rows), len(findings or []), gateway_ip, tuple(pinned_static))
        if key == self._key:
            self.hits += 1
            return self._val
        self.misses += 1
        self._val = drift(inventory(findings), rows, gateway_ip, pinned_static)
        self._key = key
        return self._val
