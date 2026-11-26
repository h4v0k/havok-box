"""Command toolbox: catalog rules, value validation, scope gating, rendering, local GUI guard."""
import ipaddress
import json
import re

import pytest

from havokbox import kit
from havokbox.scope import Scope

NEVER = "192.168.1.0/24"


def scope(**rf):
    data = {"networks": {"include": ["10.20.0.0/24"], "exclude": [NEVER]}, "rf": rf}
    return Scope(data)


def ctx(**kw):
    kw.setdefault("ifaces", ["lo", "eth0", "wlan1", "wlan1mon"])
    kw.setdefault("file_exists", lambda p: True)
    kw.setdefault("resolve", lambda h: {"web.lab": ["10.20.0.7"], "evil.com": ["8.8.8.8"]}.get(h, []))
    return kit.Context(scope=kw.pop("scope", scope(ble_addresses=["AA:BB:CC:DD:EE:FF"])), **kw)


MINI = {
    "recipes": [
        {"id": "ping-sweep", "category": "Discovery", "name": "Ping sweep", "what": "x",
         "cmd": "nmap -sn {target} -oA {outdir}/sweep", "risk": "discovery", "root": True},
        {"id": "web-head", "category": "Web", "name": "Headers", "what": "x",
         "cmd": "curl -skI {url}", "risk": "discovery"},
        {"id": "gatt", "category": "BLE", "name": "GATT", "what": "x",
         "cmd": "gatttool -i {hci} -b {bdaddr} --primary", "risk": "probe"},
        {"id": "dns-axfr", "category": "DNS", "name": "AXFR", "what": "x",
         "cmd": "dig axfr {domain} @{host}", "risk": "probe"},
    ],
    "chains": [{"id": "first-look", "name": "First look", "what": "x", "steps": ["ping-sweep", "web-head"]}],
}


@pytest.fixture
def cat(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps(MINI))
    return kit.load(p)


@pytest.fixture(autouse=True)
def kitdir(tmp_path, monkeypatch):
    monkeypatch.setenv("HB_KIT_DIR", str(tmp_path / "kit"))


# ---------------------------------------------------------------- the shipped catalog

def test_shipped_catalog_is_valid_and_clean():
    c = kit.load()
    assert len(c.recipes) >= 30 and len(c.chains) >= 4
    for r in c.recipes.values():
        assert not kit.FORBIDDEN.search(r.cmd), r.id
        assert r.risk in kit.RISKS
        if re.search(r"\bnmap\b", r.cmd):
            assert "{outdir}" in r.cmd, f"{r.id}: nmap output should be saved"
    cats = c.categories()
    for need in ("Bluetooth", "Port"):
        assert any(need.lower() in x.lower() for x in cats), need


SAMPLE = {"target": "10.20.0.0/24", "host": "10.20.0.5", "port": "80", "ports": "22,80",
          "url": "http://10.20.0.5/", "domain": "corp.lab", "iface": "eth0", "wlan": "wlan1",
          "mon": "wlan1mon", "channel": "6", "bdaddr": "AA:BB:CC:DD:EE:FF", "hci": "hci0",
          "wordlist": "/usr/share/wordlists/dirb/common.txt", "freq": "433.92", "seconds": "30"}


def test_every_shipped_recipe_and_chain_renders():
    c = kit.load()
    for item in list(c.recipes) + list(c.chains):
        p = kit.plan(c, item, SAMPLE, ctx())
        assert p.commands and all("{" not in cmd for _, cmd, _ in p.commands), item


# ---------------------------------------------------------------- catalog rules

@pytest.mark.parametrize("cmd", ["hydra -l admin {host}", "responder -I {iface}", "aireplay-ng -0 5 {mon}",
                                 "mdk4 {mon} d", "msfconsole -q", "sqlmap -u {url}"])
def test_forbidden_tools_rejected(tmp_path, cmd):
    bad = {"recipes": [{"id": "bad-one", "category": "x", "name": "x", "what": "x", "cmd": cmd}]}
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(kit.KitError):
        kit.load(p)


def test_unknown_placeholder_and_domain_without_host_rejected(tmp_path):
    for cmd in ("echo {nope}", "dig {domain}"):
        p = tmp_path / "b.json"
        p.write_text(json.dumps({"recipes": [{"id": "x1", "category": "x", "name": "x", "what": "x", "cmd": cmd}]}))
        with pytest.raises(kit.KitError):
            kit.load(p)


# ---------------------------------------------------------------- value checks

@pytest.mark.parametrize("name,value", [
    ("target", "8.8.8.0/24"), ("target", "192.168.1.5"), ("target", "web.lab"), ("host", "10.30.0.1"),
    ("url", "http://8.8.8.8/"), ("url", "http://evil.com/"), ("url", "http://10.20.0.5/$(id)"),
    ("url", "ftp://10.20.0.5"), ("iface", "eth9"), ("iface", "eth0;id"), ("ports", "80;id"),
    ("port", "70000"), ("channel", "0"), ("bdaddr", "zz"), ("hci", "hci0;x"), ("freq", "5000"),
    ("seconds", "-1"), ("domain", "a b"), ("wordlist", "/etc/shadow"), ("domain", "-f"),
    ("ports", "1-99999"), ("host", "fd00::1%eth0"), ("url", "http://10.20.0.5/?a=b"),
    ("wordlist", "/usr/share/wordlists/../../etc/passwd"),
])
def test_bad_values_refused(name, value):
    with pytest.raises(kit.KitError):
        kit.check_value(name, value, ctx())


def test_good_values_and_hostname_url_in_scope():
    c = ctx()
    assert kit.check_value("target", "10.20.0.9/32", c) == "10.20.0.9"
    assert kit.check_value("url", "https://web.lab:8443/app", c) == "https://web.lab:8443/app"
    assert kit.check_value("bdaddr", "aa:bb:cc:dd:ee:ff", c, "probe") == "AA:BB:CC:DD:EE:FF"


def test_probe_bluetooth_needs_mine():
    with pytest.raises(kit.KitError, match="Mine"):
        kit.check_value("bdaddr", "11:22:33:44:55:66", ctx(), "probe")
    assert kit.check_value("bdaddr", "11:22:33:44:55:66", ctx(), "discovery")


# ---------------------------------------------------------------- rendering and running

def test_render_quotes_and_adds_never_list(cat):
    p = kit.plan(cat, "ping-sweep", {"target": "10.20.0.0/24"}, ctx())
    cmd = p.commands[0][1]
    assert cmd.startswith(f"nmap --exclude {NEVER} -sn 10.20.0.0/24")
    assert str(p.outdir) in cmd


def test_chain_collects_params_and_writes_logged_scripts(cat):
    assert cat.chain_params("first-look") == ["target", "url"]
    p = kit.plan(cat, "first-look", {"target": "10.20.0.0/24", "url": "http://10.20.0.5/"}, ctx())
    assert len(p.commands) == 2
    run = kit.write(p)
    body = (p.outdir / "body.sh").read_text()
    assert "tee -a output.log" in body and "step 2/2" in body
    assert (p.outdir / "command.txt").read_text().count("\n") == 2
    assert "Press Enter" in run.read_text()
    assert str(p.outdir) in (kit.kit_dir() / "history.log").read_text()


def test_root_recipes_use_sudo_when_not_root(cat, monkeypatch):
    monkeypatch.setattr(kit.os, "geteuid", lambda: 1000)
    p = kit.plan(cat, "ping-sweep", {"target": "10.20.0.0/24"}, ctx())
    assert p.root and "sudo bash -c" in p.body() and "chown" in p.body()


def test_domain_recipe_requires_in_scope_server(cat):
    with pytest.raises(kit.KitError):
        kit.plan(cat, "dns-axfr", {"domain": "corp.lab", "host": "8.8.8.8"}, ctx())


def test_no_engagement_refuses_network_recipes(cat):
    empty = Scope({"networks": {"include": [], "exclude": [NEVER]}})
    with pytest.raises(kit.KitError, match="out of scope"):
        kit.plan(cat, "ping-sweep", {"target": "10.20.0.0/24"}, kit.Context(scope=empty, ifaces=[]))


# ---------------------------------------------------------------- local web GUI

def test_web_guard_and_preview(cat):
    from starlette.testclient import TestClient
    from havokbox import kitweb
    launched = []
    app = kitweb.build_app(cat, lambda: ctx(), "tok", {}, launcher=launched.append)
    c = TestClient(app, base_url="http://127.0.0.1:5000")
    assert c.get("/api/recipes").status_code == 403                       # no token
    assert c.get("/api/recipes?t=tok", headers={"host": "evil.com"}).status_code == 403   # rebinding
    assert c.get("/api/recipes?t=tok").json()["recipes"][0]["params"] == ["target"]
    assert c.get("/static/kit.js").status_code == 200
    assert c.get("/static/../server.py").status_code == 404
    r = c.post("/api/preview?t=tok", json={"id": "ping-sweep", "values": {"target": "8.8.8.0/24"}}).json()
    assert not r["ok"] and "out of scope" in r["error"]
    r = c.post("/api/run?t=tok", json={"id": "ping-sweep", "values": {"target": "10.20.0.0/24"}}).json()
    assert r["ok"] and launched and launched[0].name == "run.sh"
    r = c.post("/api/run?t=tok", json={"id": "nope", "values": {}}).json()
    assert not r["ok"]


def test_non_nmap_tool_refuses_range_containing_never_list(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"recipes": [{"id": "arp", "category": "x", "name": "ARP", "what": "x",
                                          "cmd": "arp-scan {target}"}]}))
    wide = Scope({"networks": {"include": ["192.168.0.0/16"], "exclude": [NEVER]}})
    c = kit.load(p)
    with pytest.raises(kit.KitError, match="never-list"):
        kit.plan(c, "arp", {"target": "192.168.0.0/16"}, kit.Context(scope=wide, ifaces=[]))
    assert kit.plan(c, "arp", {"target": "192.168.2.0/24"}, kit.Context(scope=wide, ifaces=[]))


def test_monitor_iface_created_by_chain_is_accepted():
    c = ctx(ifaces=["wlan1"])
    assert kit.check_value("mon", "wlan1mon", c) == "wlan1mon"
    with pytest.raises(kit.KitError):
        kit.check_value("mon", "eth7mon", c)


def test_hb_kit_cli(tmp_path, monkeypatch, capsys):
    from havokbox import hbcli
    sc = tmp_path / "scope.yaml"
    sc.write_text("networks:\n  include: [10.20.0.0/24]\n  exclude: [192.168.1.0/24]\n")
    assert hbcli.main(["--scope", str(sc), "kit", "list"]) == 0
    assert "Bluetooth" in capsys.readouterr().out
    assert hbcli.main(["--scope", str(sc), "kit", "run", "ports-quick", "target=10.20.0.0/24", "-n"]) == 0
    assert "nmap --exclude 192.168.1.0/24 -F" in capsys.readouterr().err
    assert hbcli.main(["--scope", str(sc), "kit", "run", "ports-quick", "target=8.8.8.8", "-n"]) == 2


def test_same_second_runs_get_separate_folders(cat):
    import datetime as dt
    t = dt.datetime(2026, 11, 25, 12, 0, 0)
    a = kit.plan(cat, "web-head", {"url": "http://10.20.0.5/"}, ctx(), when=t)
    kit.write(a)
    b = kit.plan(cat, "web-head", {"url": "http://10.20.0.5/"}, ctx(), when=t)
    assert a.outdir != b.outdir and b.outdir.name.endswith("-2")


def test_web_rejects_odd_tokens_and_bodies(cat):
    from starlette.testclient import TestClient
    from havokbox import kitweb
    c = TestClient(kitweb.build_app(cat, lambda: ctx(), "tok", {}, launcher=lambda p: None),
                   base_url="http://127.0.0.1:5000")
    assert c.get("/api/recipes?t=%C3%A9").status_code == 403
    assert c.post("/api/preview?t=tok", json=[1, 2]).json()["ok"] is False
