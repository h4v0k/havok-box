"""Engagements: the time-boxed target scope for one lab session.

The lab is rebuilt constantly, so its addresses aren't written into config/scope.yaml. Instead:

  1. Find the lab: host discovery on the box's connected subnets, or a range you type
     (tools net.local / net.find, gate category recon.local).
  2. Start an engagement with the networks you picked. It lasts 12 hours by default.
  3. Every network tool's scope check uses the engagement's networks while it's active. When it
     expires or you end it, nothing is in scope again: fail-closed.

config/scope.yaml's networks.exclude is the permanent NEVER list (home network, gateways). An
engagement can't override it. Its networks.include, if any, still applies (fixed lab ranges).

Limits on what an engagement may hold: private (RFC 1918 / ULA) ranges only unless allow_public is
set explicitly; nothing larger than a /16; a network entirely inside the never list is refused.
Saved labs: every engagement you start is remembered by name in labs.json next to the engagement
file, so next time it's one tap (dashboard) or `hb engage start --lab <name>`. A saved lab is only a
shortcut: starting it re-checks the networks against the never list and the limits above, and
nothing is in scope until you start it.

Only the dashboard (token) and the owner's shell (`hb engage`) write the file; Claude Code is
denied both in .claude/settings.json.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time

DEFAULT_HOURS = 12
MAX_HOURS = 72
MIN_PREFIX = 16            # nothing bigger than a /16 (IPv4); /48 for IPv6
NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,48}$")
DEFAULT_PATH = "/data/havokbox/engagement.json"


class EngagementError(ValueError):
    pass


def _is_private(net) -> bool:
    return net.is_private and not net.is_loopback and not net.is_link_local and not net.is_multicast


def validate_networks(cidrs, never, allow_public: bool = False) -> list[str]:
    """Normalise and check the requested networks; raise EngagementError on the first bad one."""
    out = []
    for c in cidrs:
        c = str(c).strip()
        if not c:
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise EngagementError(f"{c!r} isn't an IP range (use CIDR, e.g. 10.20.0.0/24)")
        limit = MIN_PREFIX if net.version == 4 else 48
        if net.prefixlen < limit:
            raise EngagementError(f"{net} is larger than a /{limit}; narrow it down")
        if not _is_private(net) and not allow_public:
            raise EngagementError(f"{net} is not a private range; lab engagements are private ranges only")
        if any(net.subnet_of(n) for n in never if n.version == net.version):
            raise EngagementError(f"{net} is on the never-touch list")
        out.append(str(net))
    if not out:
        raise EngagementError("no networks given")
    return sorted(set(out), key=lambda s: ipaddress.ip_network(s))


def start(path: str, name: str, networks, never, hours: float = DEFAULT_HOURS, ssids=(),
          allow_public: bool = False, clock=time.time, by: str = "owner") -> dict:
    if not NAME_RE.match(name or ""):
        raise EngagementError("name: 1-48 letters, numbers, spaces, . _ -")
    hours = float(hours)
    if not 0.25 <= hours <= MAX_HOURS:
        raise EngagementError(f"length must be between 15 minutes and {MAX_HOURS} hours")
    nets = validate_networks(networks, never, allow_public)
    ssids = [s for s in (str(x).strip() for x in ssids or ()) if s][:16]
    now = clock()
    data = {"name": name, "networks": nets, "ssids": ssids, "allow_public": bool(allow_public),
            "started": now, "expires": now + hours * 3600, "by": by}
    _write(path, data)
    try:
        save_lab(labs_path(path), name, nets, clock=clock)
    except OSError:
        pass   # remembering is a convenience; never block the engagement on it
    return data


MAX_LABS = 20


def labs_path(eng_path: str) -> str:
    return os.path.join(os.path.dirname(eng_path) or ".", "labs.json")


def labs(path: str | None) -> list[dict]:
    """Saved labs, most recently used first. Unreadable or malformed -> empty."""
    if not path:
        return []
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for name, v in (data.items() if isinstance(data, dict) else []):
        if NAME_RE.match(str(name)) and isinstance(v, dict) and isinstance(v.get("networks"), list):
            out.append({"name": name, "networks": [str(n) for n in v["networks"]][:8],
                        "last_used": float(v.get("last_used") or 0)})
    return sorted(out, key=lambda x: -x["last_used"])


def save_lab(path: str, name: str, networks, clock=time.time) -> None:
    keep = {x["name"]: {"networks": x["networks"], "last_used": x["last_used"]} for x in labs(path)}
    keep[name] = {"networks": list(networks), "last_used": clock()}
    newest = sorted(keep.items(), key=lambda kv: -kv[1]["last_used"])[:MAX_LABS]
    _write(path, dict(newest))


def forget_lab(path: str, name: str) -> bool:
    keep = {x["name"]: {"networks": x["networks"], "last_used": x["last_used"]} for x in labs(path)}
    if name not in keep:
        return False
    del keep[name]
    _write(path, keep)
    return True


def lab(path: str, name: str) -> dict | None:
    return next((x for x in labs(path) if x["name"] == name), None)


def end(path: str) -> bool:
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def _write(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def read(path: str | None, clock=time.time) -> dict | None:
    """The active engagement, or None if there's none, it's expired, or the file is unreadable."""
    if not path:
        return None
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or float(data.get("expires") or 0) <= clock():
        return None
    return data


def time_left(eng: dict, clock=time.time) -> str:
    secs = max(0, int(float(eng.get("expires", 0)) - clock()))
    h, m = divmod(secs // 60, 60)
    return f"{h}h {m:02d}m"
