"""Menus for `hb`: pick-a-number in the terminal, or point-and-click windows on the Kali desktop.

Same engine as the hb commands (hbcli): every target is scope-checked, excludes are always
skipped, and scans land in the usual scans folder. The GUI uses zenity, which ships with Kali.
"""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from . import hbcli


# ---------------------------------------------------------------- UIs

class TermUI:
    def choose(self, title: str, options: list[str], back: str = "Back") -> int | None:
        while True:
            print(f"\n== {title} ==")
            for i, o in enumerate(options, 1):
                print(f"  {i}) {o}")
            print(f"  0) {back}")
            raw = input("Pick a number: ").strip()
            if raw == "0" or raw.lower() in ("q", "b"):
                return None
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return int(raw) - 1
            print("  Not a choice, try again.")

    def ask(self, prompt: str, default: str = "") -> str | None:
        raw = input(f"{prompt}{f' [{default}]' if default else ''} (blank to go back): ").strip()
        return raw or (default or None)

    def confirm(self, text: str) -> bool:
        return input(f"\n{text}\nRun it? [Y/n] ").strip().lower() in ("", "y", "yes")

    def show(self, title: str, text: str) -> None:
        print(f"\n== {title} ==\n{text or '(nothing)'}")
        input("\nPress Enter to continue...")

    def error(self, text: str) -> None:
        print(f"\n!! {text}")

    def run(self, cmd: list[str], dry: bool = False) -> int:
        return hbcli.run_nmap(cmd, dry)


class ZenityUI:
    def __init__(self):
        if not shutil.which("zenity"):
            raise SystemExit("zenity is not installed (sudo apt install zenity)")

    def _z(self, *args: str) -> tuple[int, str]:
        p = subprocess.run(["zenity", "--width=640", *args], capture_output=True, text=True)
        return p.returncode, p.stdout.strip()

    def choose(self, title: str, options: list[str], back: str = "Back") -> int | None:
        rows = [x for i, o in enumerate(options, 1) for x in (str(i), o)]
        rc, out = self._z("--list", "--title=havok-box", f"--text={title}", "--height=480",
                          "--column=#", "--column=Choice", "--hide-header", "--print-column=1",
                          f"--cancel-label={back}", *rows)
        if rc != 0 or not out:
            return None
        return int(out.split("|")[0]) - 1

    def ask(self, prompt: str, default: str = "") -> str | None:
        rc, out = self._z("--entry", "--title=havok-box", f"--text={prompt}", f"--entry-text={default}")
        return out if rc == 0 and out else None

    def confirm(self, text: str) -> bool:
        return self._z("--question", "--title=havok-box", "--ok-label=Run", "--cancel-label=Back",
                       f"--text={text}", "--no-markup")[0] == 0

    def show(self, title: str, text: str) -> None:
        subprocess.run(["zenity", "--text-info", "--title=" + title, "--width=900", "--height=600",
                        "--font=monospace"], input=text or "(nothing)", text=True)

    def error(self, text: str) -> None:
        self._z("--error", "--title=havok-box", f"--text={text}", "--no-markup")

    def run(self, cmd: list[str], dry: bool = False) -> int:
        if dry:
            return 0
        if cmd[0] == "sudo":
            self.error("This scan needs raw-packet rights. Re-run scripts/kali-setup.sh "
                       "(it gives nmap those rights), or use 'hb' in a terminal.")
            return 1
        nm = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        bar = subprocess.Popen(["zenity", "--progress", "--pulsate", "--auto-close", "--title=havok-box",
                                "--text=Scanning... (Cancel stops the scan)", "--width=420"],
                               stdin=subprocess.PIPE, text=True)
        while nm.poll() is None:
            if bar.poll() is not None:  # user pressed Cancel
                nm.terminate()
                nm.wait()
                return 130
            try:
                nm.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        try:
            bar.communicate("100\n", timeout=2)
        except Exception:
            bar.kill()
        if nm.returncode != 0:
            self.error("nmap failed:\n" + (nm.stderr.read() if nm.stderr else "")[-800:])
        return nm.returncode


# ---------------------------------------------------------------- helpers

def capture(fn, *args) -> str:
    buf = io.StringIO()
    fn(*args, fh=buf)
    return buf.getvalue()


def recent_scans(limit: int = 15) -> list[Path]:
    d = hbcli.scans_dir()
    xs = sorted(d.glob("*/scan.xml"), key=lambda p: p.stat().st_mtime, reverse=True) if d.exists() else []
    return xs[:limit]


def scan_label(p: Path) -> str:
    stamp, _, rest = p.parent.name.partition("_")
    when = f"{stamp[4:6]}/{stamp[6:8]} {stamp[9:11]}:{stamp[11:13]}" if len(stamp) >= 13 else stamp
    try:
        n = len(hbcli.parse(p.read_text()))
    except Exception:
        n = "?"
    return f"{when}  {rest.replace('_', '  ')}  ({n} hosts)"


def pick_scan(ui, title: str) -> Path | None:
    scans = recent_scans()
    if not scans:
        ui.error("No scans yet. Run a scan first.")
        return None
    i = ui.choose(title, [scan_label(p) for p in scans])
    return None if i is None else scans[i]


def pick_targets(ui, scope) -> list[str] | None:
    nets = [str(n) for n in scope.include]
    if not nets:
        ui.error("No engagement yet. Pick the lab first: 'Engagement: find and pick the lab'.")
        return None
    opts = [f"{n}  (whole network)" for n in nets] + ["A host from my last scan", "Type an IP or range"]
    while True:
        i = ui.choose("What do you want to scan?", opts)
        if i is None:
            return None
        if i < len(nets):
            raw = nets[i]
        elif i == len(nets):
            scans = recent_scans(1)
            hosts = hbcli.parse(scans[0].read_text()) if scans else []
            if not hosts:
                ui.error("No hosts in the last scan.")
                continue
            j = ui.choose("Pick a host", [_host_line(h) for h in hosts])
            if j is None:
                continue
            raw = hosts[j]["ip"]
        else:
            raw = ui.ask("IP or range (e.g. 10.10.0.20 or 10.10.0.0/24). Separate several with spaces")
            if not raw:
                continue
        try:
            return hbcli.check_targets(scope, raw.split())
        except hbcli.ScopeError as e:
            ui.error(str(e))


def pick_profile(ui, skip_discover: bool = False) -> str | None:
    names = [k for k in hbcli.PROFILES if not (skip_discover and k == "discover")]
    i = ui.choose("How hard should it look?", [f"{k:<9} {hbcli.PROFILES[k][0]}" for k in names])
    return None if i is None else names[i]


def _host_line(h: dict) -> str:
    extra = " ".join(x for x in (h["hostname"], h["vendor"]) if x)
    ports = ",".join(str(p["port"]) for p in h["ports"])
    return f"{h['ip']:<16} {extra:<28} {ports}"


# ---------------------------------------------------------------- actions

def act_scan(ui, scope, flow: bool = False) -> None:
    targets = pick_targets(ui, scope)
    if not targets:
        return
    profile = pick_profile(ui, skip_discover=flow)
    if not profile:
        return
    if flow:
        if not ui.confirm(f"1) Find live hosts in {', '.join(targets)}\n2) Scan them with '{profile}'"
                          "\n3) Write a report"):
            return
        rc, d1, c1 = hbcli.do_scan(scope, "discover", targets, None, False, runner=ui.run)
        if rc != 0:
            return
        live = [h["ip"] for h in hbcli.parse_files([str(d1 / "scan.xml")]) if scope.ip_in_scope(h["ip"])]
        if not live:
            ui.show("Result", "No live in-scope hosts found.")
            return
        rc, d2, c2 = hbcli.do_scan(scope, profile, live, None, False, runner=ui.run)
        if rc != 0:
            return
        hosts = hbcli.parse_files([str(d2 / "scan.xml")])
        rep = hbcli.report_md(hosts, f"havok-box flow: {', '.join(targets)} ({profile})", [c1, c2])
        (d2 / "report.md").write_text(rep)
        ui.show("Report", rep + f"\nSaved: {d2 / 'report.md'}")
        return
    preview = hbcli.build_cmd(profile, targets, "<scan folder>/scan", hbcli.excludes(scope))
    if not ui.confirm(" ".join(preview)):
        return
    rc, d, _ = hbcli.do_scan(scope, profile, targets, None, False, runner=ui.run)
    if rc == 0:
        hosts = hbcli.parse_files([str(d / "scan.xml")])
        body = capture(hbcli.emit_ports if profile != "discover" else hbcli.emit_hosts, hosts, "table")
        ui.show(f"Results ({len(hosts)} hosts up)", body + f"\nSaved in {d}")


def act_hosts(ui, fmt: str = "table") -> None:
    p = pick_scan(ui, "Which scan?")
    if p:
        hosts = hbcli.parse_files([str(p)])
        i = ui.choose("Show as", ["Table (IP, ports, name)", "Just IPs (to copy)", "CSV (IP, name, MAC, vendor)"])
        if i is not None:
            ui.show(f"Devices: {p.parent.name}", capture(hbcli.emit_hosts, hosts, ("table", "ips", "csv")[i]))


def act_ports(ui) -> None:
    p = pick_scan(ui, "Which scan?")
    if p:
        ui.show(f"Open ports: {p.parent.name}", capture(hbcli.emit_ports, hbcli.parse_files([str(p)]), "table"))


def act_find(ui) -> None:
    p = pick_scan(ui, "Search which scan?")
    if not p:
        return
    q = ui.ask("Port number or service name (e.g. 445, 22, http, ssh, smb)")
    if not q:
        return
    hosts = hbcli.parse_files([str(p)])
    found = hbcli.filter_hosts(hosts, port=int(q)) if q.isdigit() else hbcli.filter_hosts(hosts, service=q)
    ui.show(f"Hosts with {q}", capture(hbcli.emit_hosts, found, "table"))


def act_diff(ui) -> None:
    old = pick_scan(ui, "Pick the OLDER scan")
    new = old and pick_scan(ui, "Pick the NEWER scan")
    if old and new:
        d = hbcli.diff(hbcli.parse_files([str(old)]), hbcli.parse_files([str(new)]))
        lines = [f"New hosts:  {', '.join(d['new_hosts']) or 'none'}",
                 f"Gone hosts: {', '.join(d['gone_hosts']) or 'none'}", ""]
        for ip, c in d["changed"].items():
            fmt = lambda xs: ", ".join(f"{p}/{pr}" for p, pr in xs) or "-"  # noqa: E731
            lines.append(f"{ip}: opened {fmt(c['opened'])}; closed {fmt(c['closed'])}")
        ui.show("What changed", "\n".join(lines) if d["changed"] or d["new_hosts"] or d["gone_hosts"]
                else "No changes.")


def act_past(ui, gui: bool) -> None:
    p = pick_scan(ui, "Past scans (newest first)")
    if not p:
        return
    opts = ["View report / results", "Show the nmap command used"] + (["Open the folder"] if gui else [])
    i = ui.choose(p.parent.name, opts)
    if i == 0:
        rep = p.parent / "report.md"
        ui.show(p.parent.name, rep.read_text() if rep.exists()
                else capture(hbcli.emit_ports, hbcli.parse_files([str(p)]), "table"))
    elif i == 1:
        cmd = p.parent / "command.txt"
        ui.show("Command", cmd.read_text() if cmd.exists() else "(not recorded)")
    elif i == 2:
        subprocess.Popen(["xdg-open", str(p.parent)])


def _ns(**kw):
    import argparse
    return argparse.Namespace(**kw)


def act_engage(ui, scope_path: str) -> None:
    from . import engagement as E
    from .tools import net
    path = hbcli.engagement_path()
    eng = E.read(path)
    if eng:
        i = ui.choose(f"Engagement {eng['name']}: {', '.join(eng['networks'])} ({E.time_left(eng)} left)",
                      ["Keep going", "End the engagement"])
        if i == 1 and ui.confirm("End it? Lab scans will be refused until you pick a lab again."):
            E.end(path)
            ui.show("Engagement", "Ended.")
        return
    never = hbcli._never(scope_path)
    rows = net.candidates(net.parse_addrs(hbcli._ip_json(["ip", "-j", "-4", "addr"])), never)
    usable = [r for r in rows if r["usable"]]
    opts = [f"{r['network']:<18} on {r['iface']} (box is {r['box_ip']})" for r in usable] + ["Type a range"]
    i = ui.choose("Which network is the lab?", opts)
    if i is None:
        return
    if i < len(usable):
        network = usable[i]["network"]
    else:
        network = ui.ask("Lab range (e.g. 10.20.0.0/24)")
        if not network:
            return
    j = ui.choose(network, ["See who's up first (no ports)", "Use it as the engagement now"])
    if j is None:
        return
    if j == 0:
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            # Choosing the range in this menu is the owner's confirmation for the sweep.
            hbcli.cmd_find(_ns(scope=scope_path, network=network, dry_run=False),
                           ask=lambda _q: "yes", interactive=True)
        out = buf.getvalue()
        ui.show(f"Who's up on {network}", out or "(nothing answered)")
        if not ui.confirm(f"Use {network} as the engagement?"):
            return
    name = ui.ask("Engagement name (letters, numbers, - _)") or "lab"
    k = ui.choose("How long?", ["12 hours", "4 hours", "8 hours", "24 hours", "72 hours"])
    hours = (12, 4, 8, 24, 72)[k or 0]
    eng = E.start(path, name, [network], never, hours=hours, by="hb")
    ui.show("Engagement", f"{eng['name']}: {', '.join(eng['networks'])} for {E.time_left(eng)}.\n"
                          "Scans now reach only this range (never the never list).")


def act_hw(ui) -> None:
    from . import hwcheck
    ui.show("Hardware check", hwcheck.render(hwcheck.check(missing_tools=hwcheck.missing_from_registry())))


MAIN = ["Engagement: find and pick the lab",
        "Scan a network or a host",
        "Quick workflow: find live hosts, scan them, write a report",
        "Show devices from a scan",
        "Show open ports from a scan",
        "Find hosts running a port or service",
        "Compare two scans (what changed)",
        "Past scans",
        "Check my hardware"]


def run(scope_path: str, gui: bool = False) -> int:
    ui = ZenityUI() if gui else TermUI()
    try:
        scope = hbcli.load_scope(scope_path)
    except hbcli.ScopeError as e:
        ui.error(str(e))
        return 2
    try:
        while True:
            i = ui.choose("havok-box: what do you want to do?", MAIN, back="Quit")
            if i is None:
                return 0
            try:
                if i == 0:
                    act_engage(ui, scope_path)
                    scope = hbcli.load_scope(scope_path)   # pick up the new engagement
                    continue
                i -= 1
                (lambda: act_scan(ui, scope), lambda: act_scan(ui, scope, flow=True), lambda: act_hosts(ui),
                 lambda: act_ports(ui), lambda: act_find(ui), lambda: act_diff(ui),
                 lambda: act_past(ui, gui), lambda: act_hw(ui))[i]()
            except (ValueError, OSError, json.JSONDecodeError, ET.ParseError, hbcli.ScopeError) as e:
                ui.error(str(e))
    except (KeyboardInterrupt, EOFError):
        print()
        return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else "config/scope.yaml", gui="--gui" in sys.argv))
