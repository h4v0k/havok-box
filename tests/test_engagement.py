"""Engagement scope: time-boxed lab ranges, the never list, lab discovery (net.local / net.find)."""
import ipaddress
import json

import pytest

from havokbox import engagement as E
from havokbox import hbcli
from havokbox.scope import Gate, Scope
from havokbox.tools import ToolCtx, net, validate_params
from havokbox.tools.registry import default_registry

NEVER = [ipaddress.ip_network("192.168.1.0/24")]

IP_ADDR = json.dumps([
    {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "eth0", "flags": ["BROADCAST", "UP"], "addr_info": [{"family": "inet", "local": "10.20.0.50", "prefixlen": 24}]},
    {"ifname": "wlan0", "flags": ["BROADCAST", "UP"], "addr_info": [{"family": "inet", "local": "192.168.1.54", "prefixlen": 24}]},
    {"ifname": "eth1", "flags": ["BROADCAST"], "addr_info": [{"family": "inet", "local": "10.99.0.5", "prefixlen": 24}]},
])
ARP = "10.20.0.1\t00:11:22:33:44:55\tUbiquiti Inc\n10.20.0.9\taa:bb:cc:dd:ee:ff\t(Unknown)\njunk line\n"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def scope_with(tmp_path, clock, include=()):
    data = {"networks": {"include": list(include), "exclude": ["192.168.1.0/24"]}}
    return Scope(data, engagement_path=str(tmp_path / "engagement.json"), clock=clock)


# ---------------------------------------------------------------- engagement file

def test_validate_rejects_public_big_and_never():
    with pytest.raises(E.EngagementError, match="private"):
        E.validate_networks(["8.8.8.0/24"], NEVER)
    with pytest.raises(E.EngagementError, match="larger"):
        E.validate_networks(["10.0.0.0/8"], NEVER)
    with pytest.raises(E.EngagementError, match="never"):
        E.validate_networks(["192.168.1.0/25"], NEVER)
    with pytest.raises(E.EngagementError):
        E.validate_networks(["not-a-net"], NEVER)
    assert E.validate_networks(["10.20.0.7/24", "10.20.0.0/24"], NEVER) == ["10.20.0.0/24"]


def test_start_read_expire_end(tmp_path):
    clock = Clock()
    p = str(tmp_path / "e.json")
    eng = E.start(p, "lab-a", ["10.20.0.0/24"], NEVER, clock=clock)
    assert eng["expires"] - eng["started"] == 12 * 3600
    assert E.read(p, clock)["name"] == "lab-a"
    clock.t += 12 * 3600 + 1
    assert E.read(p, clock) is None            # expired -> no scope
    assert E.end(p) is True and E.end(p) is False


def test_start_limits(tmp_path):
    p = str(tmp_path / "e.json")
    with pytest.raises(E.EngagementError):
        E.start(p, "lab", ["10.20.0.0/24"], NEVER, hours=73)
    with pytest.raises(E.EngagementError):
        E.start(p, "../etc", ["10.20.0.0/24"], NEVER)


# ---------------------------------------------------------------- scope + gate

def test_scope_include_follows_engagement(tmp_path):
    clock = Clock()
    s = scope_with(tmp_path, clock)
    assert s.include == [] and not s.ip_in_scope("10.20.0.9")
    E.start(s.engagement_path, "lab-a", ["10.20.0.0/24"], s.exclude, clock=clock)
    assert s.ip_in_scope("10.20.0.9") and s.name == "lab-a"
    assert not s.ip_in_scope("192.168.1.5")
    clock.t += 13 * 3600
    assert not s.ip_in_scope("10.20.0.9")      # engagement over -> refused again


def test_scope_rechecks_engagement_file_against_never(tmp_path):
    clock = Clock()
    s = scope_with(tmp_path, clock)
    # Hand-edited file that sneaks in the never list and a public range is ignored.
    (tmp_path / "engagement.json").write_text(json.dumps(
        {"name": "x", "networks": ["192.168.1.0/24", "8.8.8.0/24"], "expires": clock.t + 60, "started": clock.t}))
    assert not s.ip_in_scope("192.168.1.5") and not s.ip_in_scope("8.8.8.8")


def _task(target):
    return {"category": "recon.local", "target": target}


def test_gate_local(tmp_path):
    g = Gate(scope_with(tmp_path, Clock()))
    d = g.evaluate(_task({"network": "10.20.0.0/24", "connected": True}))
    assert d.allowed and not d.needs_approval
    d = g.evaluate(_task({"network": "10.30.0.0/24"}))
    assert d.allowed and d.needs_approval       # a typed range needs the owner
    for bad in ("8.8.8.0/24", "10.0.0.0/8", "192.168.1.0/24", "nope"):
        assert not g.evaluate(_task({"network": bad, "connected": True})).allowed


# ---------------------------------------------------------------- net tools

def test_parse_addrs_and_candidates():
    addrs = net.parse_addrs(IP_ADDR)
    assert [a["iface"] for a in addrs] == ["eth0", "wlan0"]     # lo and down eth1 skipped
    rows = {r["network"]: r for r in net.candidates(addrs, NEVER)}
    assert rows["10.20.0.0/24"]["usable"]
    assert not rows["192.168.1.0/24"]["usable"] and rows["192.168.1.0/24"]["why_not"] == "on the never list"
    assert net.parse_addrs("garbage") == []


def test_parse_arp_scan():
    hosts = net.parse_arp_scan(ARP)
    assert [h["ip"] for h in hosts] == ["10.20.0.1", "10.20.0.9"]
    assert hosts[0]["vendor"] == "Ubiquiti Inc"


def _ctx(tmp_path, outputs):
    calls = []

    def runner(argv):
        calls.append(argv)
        return outputs.get(argv[0], "")
    return ToolCtx(runner=runner, mode="standard", scope=scope_with(tmp_path, Clock())), calls


def test_find_connected_uses_arp_scan(tmp_path):
    ctx, calls = _ctx(tmp_path, {"ip": IP_ADDR, "arp-scan": ARP})
    r = net.find({"target": {"network": "10.20.0.0/24", "connected": True}}, ctx)
    assert r["kind"] == "hosts" and len(r["data"]["hosts"]) == 2
    assert calls[1][:3] == ["arp-scan", "--interface", "eth0"]


def test_find_refuses_false_connected_claim(tmp_path):
    ctx, calls = _ctx(tmp_path, {"ip": IP_ADDR})
    r = net.find({"target": {"network": "10.77.0.0/24", "connected": True}}, ctx)
    assert r["data"]["refused"] and len(calls) == 1          # nothing but `ip addr` ran


def test_find_typed_range_uses_nmap_with_never_list(tmp_path):
    ctx, calls = _ctx(tmp_path, {"nmap": "<nmaprun></nmaprun>"})
    r = net.find({"target": {"network": "10.30.0.0/24"}}, ctx)
    assert calls[0][:3] == ["nmap", "-sn", "-n"] and "192.168.1.0/24" in calls[0]
    assert r["data"]["hosts"] == []


def test_find_overlapping_never_list_avoids_arp_scan(tmp_path):
    s = scope_with(tmp_path, Clock())
    cmd = net.build_find({"network": "192.168.0.0/16", "connected": True}, "standard", s, {}, iface="wlan0")
    assert cmd[0][0] == "nmap" and "--exclude" in cmd[0]


def test_registry_and_bool_param():
    reg = default_registry()
    assert reg["net.find"].category == "recon.local" and reg["net.local"].category == "recon.passive"
    assert validate_params(reg["net.find"], {"network": "10.20.0.0/24", "connected": True})[0]
    assert not validate_params(reg["net.find"], {"network": "10.20.0.0/24", "connected": "yes"})[0]


# ---------------------------------------------------------------- hb engage / hb find

def test_hb_engage_cycle(tmp_path, monkeypatch, capsys):
    scope = tmp_path / "scope.yaml"
    scope.write_text("networks:\n  include: []\n  exclude: [192.168.1.0/24]\n")
    monkeypatch.setenv("HB_ENGAGEMENT", str(tmp_path / "eng.json"))
    assert hbcli.main(["--scope", str(scope), "engage"]) == 1
    assert hbcli.main(["--scope", str(scope), "engage", "start", "192.168.1.0/24"]) == 2   # never list
    assert hbcli.main(["--scope", str(scope), "engage", "start", "10.20.0.0/24", "--name", "lab-a"]) == 0
    assert hbcli.main(["--scope", str(scope), "scan", "10.20.0.9", "-n"]) == 0
    assert hbcli.main(["--scope", str(scope), "engage", "end"]) == 0
    assert hbcli.main(["--scope", str(scope), "scan", "10.20.0.9", "-n"]) == 2             # refused again
    assert "lab-a" in capsys.readouterr().out


def test_hb_find_lists_networks(tmp_path, monkeypatch, capsys):
    scope = tmp_path / "scope.yaml"
    scope.write_text("networks:\n  include: []\n  exclude: [192.168.1.0/24]\n")
    monkeypatch.setattr(hbcli, "_ip_json", lambda argv: IP_ADDR)
    assert hbcli.main(["--scope", str(scope), "find"]) == 0
    out = capsys.readouterr().out
    assert "10.20.0.0/24" in out and "never list" in out
    assert hbcli.main(["--scope", str(scope), "find", "10.20.0.0/24", "-n"]) == 0
    assert "arp-scan" in capsys.readouterr().err


# ---------------------------------------------------------------- dashboard API

def test_dashboard_engagement_endpoints(tmp_path):
    from tests.helpers import make
    h = make()[0]
    h.api.scope.engagement_path = str(tmp_path / "eng.json")
    h.api.scope.exclude = list(NEVER)
    h.local_runner = lambda argv: IP_ADDR
    assert h.engagement_state()[1]["status"] == "none"
    code, nets = h.engagement_networks()
    assert code == 200 and any(n["usable"] for n in nets["networks"])
    assert h.engagement_start({"name": "lab", "networks": ["8.8.8.0/24"]})[0] == 400
    assert h.engagement_start({"name": "lab", "networks": ["192.168.1.0/24"]})[0] == 400
    code, r = h.engagement_start({"name": "lab-a", "networks": ["10.20.0.0/24"], "hours": 12})
    assert code == 200 and r["status"] == "active"
    assert h.api.scope.ip_in_scope("10.20.0.9")
    assert h.engagement_end()[1]["ended"] is True
    assert not h.api.scope.ip_in_scope("10.20.0.9")
