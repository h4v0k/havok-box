import pytest

from havokbox import hbcli
from havokbox.scope import Scope

SCOPE = Scope({"networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"]}})

XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.10.0.20" addrtype="ipv4"/>
 <address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Raspberry Pi"/>
 <hostnames><hostname name="pi.lab"/></hostnames>
 <ports>
  <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
  <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
  <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
 </ports></host>
<host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/>
 <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port></ports></host>
<host><status state="down"/><address addr="10.10.0.9" addrtype="ipv4"/></host>
</nmaprun>"""


def test_scope_refuses_out_of_scope_hostname_and_excluded():
    assert hbcli.check_targets(SCOPE, ["10.10.0.0/24", "10.10.0.7"]) == ["10.10.0.0/24", "10.10.0.7"]
    for bad in (["192.168.1.0/24"], ["lab.example.com"], ["10.10.0.1"], ["10.0.0.0/8"]):
        with pytest.raises(hbcli.ScopeError):
            hbcli.check_targets(SCOPE, bad)


def test_build_cmd_profiles_excludes_and_port_override():
    cmd = hbcli.build_cmd("quiet", ["10.10.0.0/24"], "/tmp/x/scan", ["10.10.0.1/32"])
    assert cmd[:3] == ["nmap", "-sS", "-T2"]
    assert cmd[cmd.index("--exclude") + 1] == "10.10.0.1/32"
    assert cmd[-3:] == ["-oA", "/tmp/x/scan", "10.10.0.0/24"] and "--top-ports" in cmd
    r = hbcli.build_cmd("robust", ["10.10.0.5"], "/o", [], ports="22,80")
    assert "-p-" not in r and r[r.index("-p") + 1] == "22,80"
    with pytest.raises(ValueError):
        hbcli.build_cmd("standard", ["10.10.0.5"], "/o", [], ports="22; rm -rf /")
    with pytest.raises(ValueError):
        hbcli.build_cmd("nope", ["10.10.0.5"], "/o", [])


def test_parse_and_filters():
    hosts = hbcli.parse(XML)
    assert [h["ip"] for h in hosts] == ["10.10.0.20", "10.10.0.5"]
    pi = hosts[0]
    assert pi["vendor"] == "Raspberry Pi" and pi["hostname"] == "pi.lab"
    assert [p["port"] for p in pi["ports"]] == [22, 445]  # closed 80 dropped
    assert pi["ports"][0]["version"] == "OpenSSH 9.6"
    assert [h["ip"] for h in hbcli.filter_hosts(hosts, port=445)] == ["10.10.0.20"]
    assert [h["ip"] for h in hbcli.filter_hosts(hosts, service="http")] == ["10.10.0.5"]


def test_parse_files_merges_and_sorts(tmp_path):
    a = tmp_path / "a.xml"
    a.write_text(XML)
    b = tmp_path / "b.xml"
    b.write_text(XML.replace('portid="445"', 'portid="139"'))
    hosts = hbcli.parse_files([str(a), str(b)])
    assert [h["ip"] for h in hosts] == ["10.10.0.5", "10.10.0.20"]
    assert sorted(p["port"] for p in hosts[1]["ports"]) == [22, 139, 445]


def test_diff():
    old = hbcli.parse(XML)
    new = hbcli.parse(XML.replace('portid="445"', 'portid="3389"').replace("10.10.0.5", "10.10.0.6"))
    d = hbcli.diff(old, new)
    assert d["new_hosts"] == ["10.10.0.6"] and d["gone_hosts"] == ["10.10.0.5"]
    assert d["changed"]["10.10.0.20"] == {"opened": [(3389, "tcp")], "closed": [(445, "tcp")]}


def test_cli_hosts_ports_and_dry_run_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HB_SCANS_DIR", str(tmp_path / "scans"))
    x = tmp_path / "s.xml"
    x.write_text(XML)
    assert hbcli.main(["hosts", str(x), "--port", "22"]) == 0
    assert capsys.readouterr().out.split() == ["10.10.0.20"]
    assert hbcli.main(["ports", str(x), "-f", "targets"]) == 0
    assert "10.10.0.5:80" in capsys.readouterr().out
    scope = tmp_path / "scope.yaml"
    scope.write_text("networks:\n  include: [10.10.0.0/24]\n  exclude: [10.10.0.1/32]\n")
    assert hbcli.main(["--scope", str(scope), "scan", "10.10.0.0/24", "-p", "quiet", "-n"]) == 0
    err = capsys.readouterr().err
    assert "--exclude 10.10.0.1/32" in err and "-oA" in err
    assert hbcli.main(["--scope", str(scope), "scan", "8.8.8.8", "-n"]) == 2
    assert hbcli.main(["--scope", str(tmp_path / "missing.yaml"), "scan", "10.10.0.5", "-n"]) == 2


def test_report_md_lists_services():
    md = hbcli.report_md(hbcli.parse(XML), "t", [["nmap", "-sn", "10.10.0.0/24"]])
    assert "| 10.10.0.20 | pi.lab / Raspberry Pi | 22/tcp ssh, 445/tcp microsoft-ds |" in md
    assert "10.10.0.20:22/tcp — ssh (OpenSSH 9.6)" in md


def _fake_nmap(xml):
    def run(cmd, dry):
        out = cmd[cmd.index("-oA") + 1]
        open(out + ".xml", "w").write(xml)
        return 0
    return run


def test_menu_scan_then_find_by_port(tmp_path, monkeypatch, capsys):
    from havokbox import hbmenu
    monkeypatch.setenv("HB_SCANS_DIR", str(tmp_path / "scans"))
    monkeypatch.setattr(hbcli, "run_nmap", _fake_nmap(XML))
    monkeypatch.setattr(hbcli, "privilege_prefix", lambda p: ([], []))
    scope = tmp_path / "scope.yaml"
    scope.write_text("networks:\n  include: [10.10.0.0/24]\n  exclude: [10.10.0.1/32]\n")
    answers = iter([
        "2", "1", "2", "y", "",          # scan -> whole 10.10.0.0/24 -> quiet -> run -> continue
        "6", "1", "445", "",             # find -> latest scan -> port 445 -> continue
        "2", "3", "8.8.8.8", "0", "0",   # scan -> typed out-of-scope IP is refused -> back -> quit
    ])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    assert hbmenu.run(str(scope)) == 0
    out = capsys.readouterr().out
    assert "10.10.0.20" in out and "Hosts with 445" in out
    assert "out of scope" in out
    assert len(list((tmp_path / "scans").iterdir())) == 1


def test_plain_hb_opens_menu(monkeypatch):
    from havokbox import hbmenu
    seen = {}
    monkeypatch.setattr(hbmenu, "run", lambda scope, gui=False: seen.update(gui=gui) or 0)
    assert hbcli.main(["--scope", "x.yaml"]) == 0 and seen == {"gui": False}
    seen.clear()
    assert hbcli.main(["gui"]) == 0 and seen == {"gui": True}


def test_privilege_prefix(monkeypatch):
    monkeypatch.setattr(hbcli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(hbcli, "nmap_has_caps", lambda: True)
    assert hbcli.privilege_prefix("quiet") == ([], ["--privileged"])
    assert hbcli.privilege_prefix("discover") == ([], [])
    monkeypatch.setattr(hbcli, "nmap_has_caps", lambda: False)
    assert hbcli.privilege_prefix("robust") == (["sudo"], [])
