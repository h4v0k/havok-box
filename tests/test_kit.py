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
    kw.setdefault("dev_exists", lambda p: p in ("/dev/ttyACM0", "/dev/ttyUSB0"))
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
        if re.search(r"\bnmap\b", r.cmd) and "http-default-accounts" not in r.cmd:
            assert "{outdir}" in r.cmd, f"{r.id}: nmap output should be saved"
    cats = c.categories()
    for need in ("Bluetooth", "Port"):
        assert any(need.lower() in x.lower() for x in cats), need


SAMPLE = {"target": "10.20.0.0/24", "host": "10.20.0.5", "port": "80", "ports": "22,80",
          "url": "http://10.20.0.5/", "domain": "corp.lab", "iface": "eth0", "wlan": "wlan1",
          "mon": "wlan1mon", "channel": "6", "bdaddr": "AA:BB:CC:DD:EE:FF", "hci": "hci0",
          "wordlist": "/usr/share/wordlists/dirb/common.txt", "freq": "433.92", "seconds": "30",
          "tty": "/dev/ttyACM0", "sdr": "0", "freqs": "315,433.92", "fmin": "400", "fmax": "470",
          "demod": "fm", "mod": "ook", "baud": "4800"}


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
    with pytest.raises(kit.KitError, match="Known devices"):
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


def test_default_login_checks_need_typed_yes(tmp_path):
    from starlette.testclient import TestClient
    from havokbox import kitweb
    c = kit.load()
    assert "creds-ssh" in c.recipes and c.recipes["creds-ssh"].risk == "active"
    launched = []
    cl = TestClient(kitweb.build_app(c, lambda: ctx(), "tok", {}, launcher=launched.append),
                    base_url="http://127.0.0.1:5000")
    body = {"id": "creds-ssh", "values": {"host": "10.20.0.5"}}
    r = cl.post("/api/run?t=tok", json=body).json()
    assert not r["ok"] and r["need_confirm"] and not launched
    r = cl.post("/api/run?t=tok", json={**body, "confirm": "YES "}).json()
    assert r["ok"] and launched
    assert "ACTIVE" in (kit.kit_dir() / "history.log").read_text()
    with pytest.raises(kit.KitError):    # out of scope still refused
        kit.plan(c, "creds-ssh", {"host": "8.8.8.8"}, ctx())


@pytest.mark.parametrize("cmd", [
    "hydra -C /opt/havokbox/default-creds.txt {host} ssh",                         # no throttling
    "hydra -C {wordlist} -t 1 -W 1 -f {host} ssh",                                 # user wordlist
    "hydra -P /usr/share/wordlists/rockyou.txt -t 1 -W 1 -f -l root {host} ssh",   # big list
    "L=/opt/havokbox/../../usr/share/wordlists/rockyou.txt; hydra -C \"$L\" -t 1 -W 1 -f {host} ssh",
    "hydra -P/tmp/rockyou.txt -C /opt/havokbox/default-creds.txt -t 1 -W 1 -f {host} ssh",
    "hydra -x 4:8:a1 -C /opt/havokbox/default-creds.txt -t 1 -W 1 -f {host} ssh",
    "hydra -M /tmp/hosts.txt -C /opt/havokbox/default-creds.txt -t 1 -W 1 -f ssh",
])
def test_hydra_only_as_gentle_default_check(tmp_path, cmd):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"recipes": [{"id": "h1", "category": "x", "name": "x", "what": "x",
                                          "cmd": cmd, "risk": "active"}]}))
    with pytest.raises(kit.KitError):
        kit.load(p)


def test_cli_requires_confirm_for_default_logins(tmp_path, monkeypatch):
    from havokbox import hbcli
    sc = tmp_path / "scope.yaml"
    sc.write_text("networks:\n  include: [10.20.0.0/24]\n  exclude: []\n")
    monkeypatch.setattr(hbcli.sys.stdin, "isatty", lambda: False)
    assert hbcli.main(["--scope", str(sc), "kit", "run", "creds-ssh", "host=10.20.0.5"]) == 2


def test_kit_web_defaults_skips_never_list_and_hydra_hides_passwords():
    c = kit.load()
    wide = Scope({"networks": {"include": ["192.168.0.0/16"], "exclude": [NEVER]}})
    p = kit.plan(c, "creds-web-defaults", {"target": "192.168.0.0/16"}, kit.Context(scope=wide, ifaces=[]))
    assert f"--exclude {NEVER}" in p.commands[0][1] and "--max-parallelism 1" in p.commands[0][1]
    p = kit.plan(c, "creds-ssh", {"host": "10.20.0.5"}, ctx())
    assert "(hidden)" in p.commands[0][1] and "-o " not in p.commands[0][1]


# ---------------------------------------------------------------- every piece of kit is covered

def test_catalog_covers_every_radio_and_gadget():
    c = kit.load()
    cmds = " ".join(r.cmd for r in c.recipes.values())
    for tool in ("airodump-ng", "kismet", "bluetoothctl", "sniff_receiver", "rtl_433", "rtl_power",
                 "readsb", "yardstick scan", "yardstick info", "yardstick rssi", "yardstick captures",
                 "marauder scan", "radio bands", "rtl_sdr ", "rtl_tcp", "rtl_eeprom", "sweep picture",
                 "radio aprs", "meshbridge nodes", "gpspipe", "p0f", "netdiscover -p",
                 "atk6-detect-new-ip6", "nuclei", "tcpdump", "tshark", "nmap", "netexec",
                 "gqrx", "urh", "wireshark", "chirp"):
        assert tool in cmds, f"no toolbox recipe uses {tool}"


HELPER_OK = ("yardstick scan", "yardstick info", "yardstick rssi", "yardstick captures", "marauder scan",
             "radio bands", "radio aprs", "meshbridge nodes", "sweep picture")


def test_hb_helper_wrapper_allows_only_the_receive_list():
    import pathlib
    setup = pathlib.Path("scripts/kali-setup.sh").read_text()
    line = next(l for l in setup.splitlines() if '"yardstick scan"' in l and l.rstrip().endswith(";;"))
    case = line.strip()[:-2].strip().rstrip(")")
    allowed = {x.strip('"') for x in case.split("|")}
    assert allowed == set(HELPER_OK) | {"marauder stop"}
    assert not any(w in case for w in ("replay", "deauth", "flipper"))


def test_rtl_tcp_bound_to_localhost_and_eeprom_read_only(tmp_path):
    for r in kit.load().recipes.values():
        if "rtl_tcp" in r.cmd:
            assert "-a 127.0.0.1" in r.cmd, r.id
    for cmd in ("rtl_eeprom -d {sdr} -s HBSDR9", "rtl_eeprom -d {sdr} -w {outdir}/x.bin"):
        p = tmp_path / "b.json"
        p.write_text(json.dumps({"recipes": [{"id": "bad-ee", "category": "x", "name": "x", "what": "x", "cmd": cmd}]}))
        with pytest.raises(kit.KitError):
            kit.load(p)


def test_new_sdr_fields_checked():
    c = ctx()
    assert kit.check_value("freqs", "315, 433.92", c) == "315,433.92"
    assert kit.check_value("demod", "AM", c) == "am" and kit.check_value("sdr", "1", c) == "1"
    for name, bad in (("freqs", "433;rm"), ("freqs", ",".join(["433"] * 17)), ("sdr", "4"),
                      ("demod", "wbfm -x"), ("mod", "ask"), ("baud", "1"), ("fmin", "5")):
        with pytest.raises(kit.KitError):
            kit.check_value(name, bad, c)


def test_helpers_are_receive_only_in_the_kit():
    for r in kit.load().recipes.values():
        if "hb-helper" in r.cmd:
            sub = r.cmd.split("hb-helper", 1)[1].split()[:2]
            assert " ".join(sub) in HELPER_OK, r.id
            assert r.risk == "passive", r.id


@pytest.mark.parametrize("cmd", ["hb-helper yardstick replay --id x --freq-mhz 433.92 --work-dir {outdir}",
                                 "hb-helper marauder deauth --port {tty}",
                                 "python3 -c 'import rflib; d.RFxmit(b)'"])
def test_transmit_helpers_rejected(tmp_path, cmd):
    bad = {"recipes": [{"id": "bad-tx", "category": "x", "name": "x", "what": "x", "cmd": cmd}]}
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(kit.KitError):
        kit.load(p)


def test_tty_field_checked():
    c = ctx()
    assert kit.check_value("tty", "/dev/ttyACM0", c) == "/dev/ttyACM0"
    for bad in ("/dev/ttyACM9", "/dev/sda", "/etc/passwd", "/dev/ttyACM0; rm -rf ~", "../dev/ttyUSB0"):
        with pytest.raises(kit.KitError):
            kit.check_value("tty", bad, c)
