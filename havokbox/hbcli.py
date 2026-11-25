"""`hb` — command-line nmap helpers for the Kali side of havok-box (Console, SSH, Desktop).

Standard nmap only, lab only. Every scan target is checked against config/scope.yaml first
(fail-closed: no scope file, a hostname, or an out-of-scope address means no scan), and the
scope's exclude list is always passed to nmap as --exclude.

    hb scan 10.10.0.0/24 -p quiet          # profiles: discover quiet standard robust udp web
    hb hosts                               # live IPs from the last scan, one per line
    hb hosts --port 445                    # only hosts with 445 open (pipe into other tools)
    hb ports --format csv                  # every open port with service/version
    hb flow 10.10.0.0/24 --profile robust  # discover -> scan live hosts -> report.md
    hb diff old.xml new.xml                # new/gone hosts and ports between two scans
    hb last                                # folder of the most recent scan
    hb find                                # which networks is the box on? (nothing is sent)
    hb find 10.20.0.0/24                   # who's up there (ARP sweep; asks first if not attached)
    hb engage start 10.20.0.0/24 --name lab-a   # make it the engagement (12 h default)
    hb engage                              # what's the engagement and how long is left
    hb engage end                          # stop; lab scans are refused again

Scans are written with -oA to ~/havok/scans/<time>_<profile>_<target>/ (override: HB_SCANS_DIR).
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# name -> (description, nmap flags). Targets/excludes/output flags are added by build_cmd.
PROFILES: dict[str, tuple[str, list[str]]] = {
    "discover": ("Who's up (ARP on the local segment, ping elsewhere). No port scan.",
                 ["-sn", "-n"]),
    "quiet": ("Stealthy: SYN scan, top 100 ports, slow timing, one retry, random host order.",
              ["-sS", "-T2", "--top-ports", "100", "--max-retries", "1", "--scan-delay", "300ms",
               "--randomize-hosts", "-n"]),
    "standard": ("Balanced: SYN scan, top 1000 ports, service versions.",
                 ["-sS", "-sV", "-T3", "--top-ports", "1000", "-n"]),
    "robust": ("Everything: all 65535 TCP ports, versions, default scripts, OS guess.",
               ["-sS", "-sV", "-sC", "-O", "-p-", "-T4", "--min-rate", "500", "--reason", "-n"]),
    "udp": ("Top 50 UDP ports with light version detection (slow by nature).",
            ["-sU", "--top-ports", "50", "-sV", "--version-light", "-T3", "-n"]),
    "web": ("Common web ports with title, headers and TLS cert.",
            ["-sS", "-sV", "-p", "80,443,8000,8008,8080,8443,8888",
             "--script", "http-title,http-headers,ssl-cert", "-n"]),
}
NEEDS_ROOT = {"quiet", "standard", "robust", "udp", "web"}


# ---------------------------------------------------------------- scope

class ScopeError(Exception):
    pass


def load_scope(path: str):
    from .scope import load_scope as _load
    if not os.path.exists(path):
        raise ScopeError(f"no scope file at {path} - copy config/scope.example.yaml and edit it")
    return _load(path, engagement_path=engagement_path())


def engagement_path() -> str:
    return os.environ.get("HB_ENGAGEMENT", "/data/havokbox/engagement.json")


def check_targets(scope, targets: list[str]) -> list[str]:
    """Return the normalised targets, or raise if any is not an in-scope IP/CIDR."""
    out = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise ScopeError(f"{t!r} is not an IP or CIDR (hostnames are refused - scope is by address)")
        ok = scope.ip_in_scope(str(net.network_address)) if net.num_addresses == 1 \
            else scope.network_in_scope(str(net))
        if not ok:
            raise ScopeError(f"{t} is out of scope (not in the engagement, or on the never list; see hb engage)")
        out.append(str(net) if net.num_addresses > 1 else str(net.network_address))
    if not out:
        raise ScopeError("no targets")
    return out


def excludes(scope) -> list[str]:
    return [str(e) for e in scope.exclude]


# ---------------------------------------------------------------- commands

def build_cmd(profile: str, targets: list[str], out_base: str, excl: list[str],
              ports: str | None = None) -> list[str]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile}")
    flags = list(PROFILES[profile][1])
    if ports:
        if not re.fullmatch(r"[0-9,\-TU:]+", ports):
            raise ValueError("ports must look like 22,80,443 or 1-1024")
        # replace any port selection in the profile with the user's
        for opt in ("--top-ports", "-p"):
            if opt in flags:
                i = flags.index(opt)
                del flags[i:i + 2]
        flags = [f for f in flags if f != "-p-"] + ["-p", ports]
    cmd = ["nmap", *flags]
    if excl:
        cmd += ["--exclude", ",".join(excl)]
    cmd += ["-oA", out_base, *targets]
    return cmd


def scans_dir() -> Path:
    return Path(os.environ.get("HB_SCANS_DIR", Path.home() / "havok" / "scans"))


def new_scan_dir(profile: str, targets: list[str], create: bool = True) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    label = re.sub(r"[^0-9A-Za-z.]+", "-", targets[0])[:40] + ("-plus" if len(targets) > 1 else "")
    d = scans_dir() / f"{stamp}_{profile}_{label}"
    if create:
        d.mkdir(parents=True, exist_ok=False)
    return d


def latest_xml() -> Path:
    xs = sorted(scans_dir().glob("*/scan.xml"), key=lambda p: p.stat().st_mtime)
    if not xs:
        raise FileNotFoundError(f"no scans yet in {scans_dir()}")
    return xs[-1]


# ---------------------------------------------------------------- parsing

def parse(xml_text: str) -> list[dict]:
    """Hosts that are up, with addresses, names and open ports."""
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        host = {"ip": None, "mac": None, "vendor": None, "hostname": None, "os": None, "ports": []}
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and not host["ip"]:
                host["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                host["mac"], host["vendor"] = a.get("addr"), a.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            host["hostname"] = hn.get("name")
        osm = h.find("os/osmatch")
        if osm is not None:
            host["os"] = osm.get("name")
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or s.get("state") not in ("open", "open|filtered"):
                continue
            svc = p.find("service")
            g = (lambda k: svc.get(k) if svc is not None else None)
            version = " ".join(x for x in (g("product"), g("version"), g("extrainfo")) if x) or None
            host["ports"].append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                                  "state": s.get("state"), "service": g("name"), "version": version})
        if host["ip"]:
            hosts.append(host)
    return hosts


def parse_files(paths: list[str]) -> list[dict]:
    merged: dict[str, dict] = {}
    for p in paths:
        for h in parse(Path(p).read_text()):
            cur = merged.setdefault(h["ip"], h)
            if cur is not h:
                for k in ("mac", "vendor", "hostname", "os"):
                    cur[k] = cur[k] or h[k]
                seen = {(x["port"], x["proto"]) for x in cur["ports"]}
                cur["ports"] += [x for x in h["ports"] if (x["port"], x["proto"]) not in seen]
    return sorted(merged.values(), key=lambda h: _ipkey(h["ip"]))


def _ipkey(ip: str):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def filter_hosts(hosts: list[dict], port: int | None = None, service: str | None = None) -> list[dict]:
    out = []
    for h in hosts:
        ps = h["ports"]
        if port is not None:
            ps = [p for p in ps if p["port"] == port]
        if service:
            ps = [p for p in ps if p["service"] and service.lower() in p["service"].lower()]
        if (port is None and not service) or ps:
            out.append({**h, "ports": ps if (port is not None or service) else h["ports"]})
    return out


def diff(old: list[dict], new: list[dict]) -> dict:
    o = {h["ip"]: h for h in old}
    n = {h["ip"]: h for h in new}
    pset = lambda h: {(p["port"], p["proto"]) for p in h["ports"]}  # noqa: E731
    changed = {}
    for ip in sorted(set(o) & set(n), key=_ipkey):
        opened, closed = pset(n[ip]) - pset(o[ip]), pset(o[ip]) - pset(n[ip])
        if opened or closed:
            changed[ip] = {"opened": sorted(opened), "closed": sorted(closed)}
    return {"new_hosts": sorted(set(n) - set(o), key=_ipkey),
            "gone_hosts": sorted(set(o) - set(n), key=_ipkey),
            "changed": changed}


def report_md(hosts: list[dict], title: str, cmds: list[list[str]]) -> str:
    lines = [f"# {title}", "", f"_{dt.datetime.now():%Y-%m-%d %H:%M}_ — {len(hosts)} host(s) up", ""]
    lines += ["| Host | Name / vendor | Open ports |", "|---|---|---|"]
    for h in hosts:
        name = " / ".join(x for x in (h["hostname"], h["vendor"]) if x) or ""
        ports = ", ".join(f"{p['port']}/{p['proto']} {p['service'] or ''}".strip() for p in h["ports"]) or "-"
        lines.append(f"| {h['ip']} | {name} | {ports} |")
    lines += ["", "## Services", ""]
    for h in hosts:
        for p in h["ports"]:
            lines.append(f"- {h['ip']}:{p['port']}/{p['proto']} — {p['service'] or '?'}"
                         + (f" ({p['version']})" if p["version"] else ""))
    lines += ["", "## Commands run", ""] + [f"    {' '.join(c)}" for c in cmds] + [""]
    return "\n".join(lines)


# ---------------------------------------------------------------- output

def emit_hosts(hosts: list[dict], fmt: str, fh=None) -> None:
    fh = fh or sys.stdout
    if fmt == "ips":
        for h in hosts:
            print(h["ip"], file=fh)
    elif fmt == "json":
        json.dump(hosts, fh, indent=2)
        print(file=fh)
    elif fmt == "csv":
        w = csv.writer(fh)
        w.writerow(["ip", "hostname", "mac", "vendor", "os", "open_ports"])
        for h in hosts:
            w.writerow([h["ip"], h["hostname"] or "", h["mac"] or "", h["vendor"] or "", h["os"] or "",
                        " ".join(f"{p['port']}/{p['proto']}" for p in h["ports"])])
    else:  # table
        for h in hosts:
            extra = " ".join(x for x in (h["hostname"], h["vendor"]) if x)
            ports = ",".join(str(p["port"]) for p in h["ports"])
            print(f"{h['ip']:<16} {ports:<30} {extra}", file=fh)


def emit_ports(hosts: list[dict], fmt: str, fh=None) -> None:
    fh = fh or sys.stdout
    rows = [(h["ip"], p["port"], p["proto"], p["service"] or "", p["version"] or "")
            for h in hosts for p in h["ports"]]
    if fmt == "json":
        json.dump([dict(zip(("ip", "port", "proto", "service", "version"), r)) for r in rows], fh, indent=2)
        print(file=fh)
    elif fmt == "csv":
        w = csv.writer(fh)
        w.writerow(["ip", "port", "proto", "service", "version"])
        w.writerows(rows)
    elif fmt == "targets":  # ip:port, handy for other tools
        for r in rows:
            print(f"{r[0]}:{r[1]}", file=fh)
    else:
        for r in rows:
            print(f"{r[0]:<16} {str(r[1]) + '/' + r[2]:<10} {r[3]:<14} {r[4]}", file=fh)


# ---------------------------------------------------------------- run

def run_nmap(cmd: list[str], dry: bool) -> int:
    print("+ " + " ".join(cmd), file=sys.stderr)
    if dry:
        return 0
    if not shutil.which("nmap"):
        print("nmap is not installed", file=sys.stderr)
        return 127
    return subprocess.call(cmd)


def nmap_has_caps() -> bool:
    """True if nmap carries raw-socket capabilities (set by kali-setup.sh), so no sudo is needed."""
    path = shutil.which("nmap")
    if not path or not shutil.which("getcap"):
        return False
    out = subprocess.run(["getcap", path], capture_output=True, text=True).stdout
    return "cap_net_raw" in out


def privilege_prefix(profile: str) -> tuple[list[str], list[str]]:
    """(command prefix, extra nmap flags) needed to run this profile as the current user."""
    if profile not in NEEDS_ROOT or os.geteuid() == 0:
        return [], []
    if nmap_has_caps():
        return [], ["--privileged"]
    return ["sudo"], []


def do_scan(scope, profile: str, targets: list[str], ports: str | None, dry: bool,
            runner=None) -> tuple[int, Path, list[str]]:
    d = new_scan_dir(profile, targets, create=not dry)
    cmd = build_cmd(profile, targets, str(d / "scan"), excludes(scope), ports)
    pre, extra = ([], []) if dry else privilege_prefix(profile)
    cmd = pre + cmd[:1] + extra + cmd[1:]
    if not dry:
        (d / "command.txt").write_text(" ".join(cmd) + "\n")
        eng = scope.engagement() if hasattr(scope, "engagement") else None
        if eng:
            (d / "engagement.txt").write_text(eng["name"] + "\n")
    return (runner or run_nmap)(cmd, dry), d, cmd


# ---------------------------------------------------------------- engagements

def _never(scope_path: str) -> list:
    """The never list, read from the scope file without needing an engagement."""
    scope = load_scope(scope_path)
    return list(scope.exclude)


def cmd_engage(a) -> int:
    from . import engagement as E
    path = engagement_path()
    if a.action == "end":
        print("engagement ended" if E.end(path) else "no engagement was running")
        return 0
    if a.action == "start":
        if not a.networks:
            raise ScopeError("give the lab range(s): hb engage start 10.20.0.0/24 --name lab-a")
        eng = E.start(path, a.name, a.networks, _never(a.scope), hours=a.hours, by="hb")
        print(f"engagement {eng['name']}: {', '.join(eng['networks'])} for {E.time_left(eng)}")
        return 0
    eng = E.read(path)
    if not eng:
        print("no engagement. find the lab with 'hb find', then 'hb engage start <cidr>'")
        return 1
    print(f"engagement {eng['name']}: {', '.join(eng['networks'])} — {E.time_left(eng)} left")
    return 0


def _ip_json(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return "[]"


def cmd_find(a, runner=None, ask=input, interactive: bool | None = None) -> int:
    from .engagement import EngagementError, validate_networks
    from .tools import net
    never = _never(a.scope)
    addrs = net.parse_addrs(_ip_json(["ip", "-j", "-4", "addr"]))
    if not a.network:
        rows = net.candidates(addrs, never)
        if not rows:
            print("the box isn't on any network right now")
            return 1
        for r in rows:
            note = "usable" if r["usable"] else f"can't use: {r['why_not']}"
            print(f"{r['network']:<18} on {r['iface']:<8} box is {r['box_ip']:<15} {note}")
        print("\nnext: hb find <network>   then   hb engage start <network> --name <lab>")
        return 0
    try:
        netw = validate_networks([a.network], never)[0]
    except EngagementError as e:
        raise ScopeError(str(e))
    target = ipaddress.ip_network(netw)
    hit = next((x for x in addrs if target.subnet_of(ipaddress.ip_network(x["network"]))), None)
    overlaps_never = any(target.overlaps(n) for n in never if n.version == target.version)
    if hit and not overlaps_never:   # arp-scan can't skip addresses, so never-list overlap -> nmap
        cmd = ["arp-scan", "--interface", hit["iface"], "--retry", "2", "--plain", netw]
        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd
    else:
        if not hit and not (sys.stdin.isatty() if interactive is None else interactive):
            raise ScopeError(f"{netw} isn't attached to the box; run this yourself to confirm the sweep")
        if not hit and ask(f"{netw} isn't attached to the box. Ping-sweep it (no ports)? type yes: ").strip() != "yes":
            print("cancelled")
            return 1
        cmd = ["nmap", "-sn", "-n"]
        if never:
            cmd += ["--exclude", ",".join(str(n) for n in never)]
        cmd += [netw]
    print("+ " + " ".join(cmd), file=sys.stderr)
    if a.dry_run:
        return 0
    if runner is not None:
        return runner(cmd)
    if not shutil.which(cmd[1] if cmd[0] == "sudo" else cmd[0]):
        print(f"{cmd[1] if cmd[0] == 'sudo' else cmd[0]} is not installed", file=sys.stderr)
        return 127
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    if cmd[-1] == netw and "arp-scan" in cmd:
        hosts = [h for h in net.parse_arp_scan(out)
                 if not any(ipaddress.ip_address(h["ip"]) in n for n in never)]
        for h in hosts:
            print(f"{h['ip']:<16} {h['mac']}  {h['vendor'] or ''}")
        print(f"{len(hosts)} host(s) up on {netw}", file=sys.stderr)
    else:
        print(out, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hb", description=__doc__.split("\n\n")[0])
    ap.add_argument("--scope", default=os.environ.get("HB_SCOPE", "config/scope.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run an nmap profile against in-scope targets")
    s.add_argument("targets", nargs="+")
    s.add_argument("-p", "--profile", default="standard", choices=PROFILES)
    s.add_argument("--ports", help="override the profile's ports, e.g. 22,80,443 or 1-1024")
    s.add_argument("-n", "--dry-run", action="store_true", help="print the nmap command only")

    f = sub.add_parser("flow", help="discover, then scan only the live hosts, then write report.md")
    f.add_argument("targets", nargs="+")
    f.add_argument("-p", "--profile", default="standard", choices=[p for p in PROFILES if p != "discover"])
    f.add_argument("-n", "--dry-run", action="store_true")

    for name, helptext in (("hosts", "list live hosts from scan XML"), ("ports", "list open ports")):
        x = sub.add_parser(name, help=helptext)
        x.add_argument("xml", nargs="*", help="nmap XML file(s); default: the last scan")
        x.add_argument("--port", type=int)
        x.add_argument("--service", help="substring of the service name, e.g. http, smb, ssh")
        x.add_argument("-f", "--format", default="ips" if name == "hosts" else "table",
                       choices=["ips", "table", "csv", "json"] if name == "hosts"
                       else ["table", "csv", "json", "targets"])

    d = sub.add_parser("diff", help="compare two scans")
    d.add_argument("old")
    d.add_argument("new")

    sub.add_parser("last", help="print the folder of the most recent scan")
    sub.add_parser("profiles", help="describe the scan profiles")
    sub.add_parser("hw", help="check every board: plugged in? software answering?")
    e = sub.add_parser("engage", help="show, start or end the engagement (the lab ranges in scope)")
    e.add_argument("action", nargs="?", default="status", choices=["status", "start", "end"])
    e.add_argument("networks", nargs="*")
    e.add_argument("--name", default="lab")
    e.add_argument("--hours", type=float, default=12)
    fd = sub.add_parser("find", help="which networks is the box on? / who's up on one (no ports)")
    fd.add_argument("network", nargs="?")
    fd.add_argument("-n", "--dry-run", action="store_true")
    sub.add_parser("menu", help="numbered menus in the terminal (also what plain 'hb' does)")
    sub.add_parser("gui", help="point-and-click windows on the Kali desktop")

    argv = sys.argv[1:] if argv is None else argv
    subs = {"scan", "flow", "hosts", "ports", "diff", "last", "profiles", "menu", "gui", "hw", "engage", "find"}
    if not subs & set(argv) and not {"-h", "--help"} & set(argv):
        argv = [*argv, "menu"]  # plain 'hb' opens the menus
    a = ap.parse_args(argv)
    if a.cmd in ("menu", "gui"):
        from . import hbmenu
        return hbmenu.run(a.scope, gui=(a.cmd == "gui"))
    try:
        if a.cmd == "profiles":
            for k, (desc, flags) in PROFILES.items():
                print(f"{k:<9} {desc}\n          nmap {' '.join(flags)}")
            return 0
        if a.cmd == "hw":
            from . import hwcheck
            print(hwcheck.render(hwcheck.check(missing_tools=hwcheck.missing_from_registry())))
            return 0
        if a.cmd == "engage":
            return cmd_engage(a)
        if a.cmd == "find":
            return cmd_find(a)
        if a.cmd == "last":
            print(latest_xml().parent)
            return 0
        if a.cmd in ("hosts", "ports"):
            hosts = filter_hosts(parse_files(a.xml or [str(latest_xml())]), a.port, a.service)
            (emit_hosts if a.cmd == "hosts" else emit_ports)(hosts, a.format)
            return 0
        if a.cmd == "diff":
            json.dump(diff(parse_files([a.old]), parse_files([a.new])), sys.stdout, indent=2)
            print()
            return 0

        scope = load_scope(a.scope)
        targets = check_targets(scope, a.targets)
        if a.cmd == "scan":
            rc, folder, _ = do_scan(scope, a.profile, targets, a.ports, a.dry_run)
            print(folder)
            return rc
        # flow
        rc, d1, c1 = do_scan(scope, "discover", targets, None, a.dry_run)
        if rc != 0:
            return rc
        if a.dry_run:
            print("(dry run: the live hosts from discovery would be scanned next)", file=sys.stderr)
            return 0
        live = [h["ip"] for h in parse_files([str(d1 / "scan.xml")])]
        live = [ip for ip in live if scope.ip_in_scope(ip)]
        if not live:
            print("no live in-scope hosts found", file=sys.stderr)
            return 0
        rc, d2, c2 = do_scan(scope, a.profile, live, None, False)
        hosts = parse_files([str(d2 / "scan.xml")])
        rep = d2 / "report.md"
        rep.write_text(report_md(hosts, f"havok-box flow: {', '.join(targets)} ({a.profile})", [c1, c2]))
        emit_hosts(hosts, "table")
        print(rep)
        return rc
    except (ScopeError, FileNotFoundError, ValueError) as e:
        print(f"hb: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
