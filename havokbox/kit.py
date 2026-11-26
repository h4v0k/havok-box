"""Command toolbox ("hb kit"): a catalog of common, repeatable recon/enumeration commands.

Recipes live in havokbox/kit_recipes.json (shipped with the code, never edited at runtime). Each
recipe is a command template with {placeholders}. Filling a recipe is the only way to build a
command here - there is no free-form command box - and every placeholder is validated:

  {target} {host} {url}   must be inside the current engagement and off the never list
  {domain}                hostname syntax; only allowed in recipes that also query a {host}
  {bdaddr}                MAC syntax; "probe" recipes also require it on the Mine tab
  {iface} {wlan} {mon}    must be an interface that exists on the box
  {wordlist}              must be a file under the standard wordlist folders
  everything else         strict format (numbers, port lists, channel, hci, seconds, MHz)

nmap commands automatically get --exclude <never list>. Each run gets its own folder
(~/havok/kit/<time>_<id>/) holding command.txt, run.sh and output.log, so every action is logged.
Exploitation, credential attacks, poisoning, deauth and RF transmit are not in the catalog, and
tests/test_kit.py fails if a recipe for any of them is added.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

RECIPES_PATH = Path(__file__).with_name("kit_recipes.json")
PLACEHOLDER = re.compile(r"\{([a-z]+)\}")
KNOWN = {"target", "host", "port", "ports", "url", "domain", "iface", "wlan", "mon", "channel",
         "bdaddr", "hci", "outdir", "wordlist", "freq", "seconds"}
RISKS = ("passive", "discovery", "probe", "active")
CRED_DIRS = ("/usr/share/seclists/Passwords/Default-Credentials/", "/opt/havokbox/")
WORDLIST_ROOTS = ("/usr/share/wordlists", "/usr/share/seclists", "/usr/share/dirb",
                  "/usr/share/dirbuster", str(Path.home() / "havok" / "wordlists"))
# Never allowed in a recipe (lab rules: no exploitation, cred attacks, poisoning, deauth, transmit).
FORBIDDEN = re.compile(
    r"\b(medusa|ncrack|patator|crackmapexec\s+\S+\s+\S+\s+-p|responder|mitm6|bettercap|"
    r"arpspoof|ettercap|aireplay-ng|mdk3|mdk4|wifite|reaver|bully|metasploit|msfconsole|"
    r"msfvenom|sqlmap|searchsploit|-t\s*xmit|rf\.RFxmit|RFxmit|hcitool\s+cc|l2ping\s+-f)\b",
    re.I)

LABELS = {
    "target": "Target (IP or CIDR in the engagement)", "host": "Host (one IP)", "port": "Port",
    "ports": "Ports (e.g. 22,80,443 or 1-1024)", "url": "URL (http://10.20.0.5:8080/)",
    "domain": "Domain (lab DNS name)", "iface": "Network interface", "wlan": "Wi-Fi interface",
    "mon": "Monitor-mode interface", "channel": "Wi-Fi channel", "bdaddr": "Bluetooth address",
    "hci": "Bluetooth adapter", "wordlist": "Wordlist", "freq": "Frequency (MHz)",
    "seconds": "Duration (seconds)",
}
DEFAULTS = {"hci": "hci0", "seconds": "30", "channel": "6", "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "freq": "433.92"}


class KitError(ValueError):
    pass


@dataclass
class Recipe:
    id: str
    category: str
    name: str
    what: str
    cmd: str
    risk: str = "discovery"
    root: bool = False
    when: str = ""
    needs: list = field(default_factory=list)
    est: str = ""
    notes: str = ""
    source: str = ""

    @property
    def params(self) -> list[str]:
        seen = []
        for p in PLACEHOLDER.findall(self.cmd):
            if p != "outdir" and p not in seen:
                seen.append(p)
        return seen


@dataclass
class Chain:
    id: str
    name: str
    what: str
    steps: list


@dataclass
class Catalog:
    recipes: dict
    chains: dict

    def categories(self) -> list[str]:
        out = []
        for r in self.recipes.values():
            if r.category not in out:
                out.append(r.category)
        return out

    def in_category(self, cat: str) -> list[Recipe]:
        return [r for r in self.recipes.values() if r.category == cat]

    def search(self, q: str) -> list[Recipe]:
        q = q.lower().strip()
        return [r for r in self.recipes.values()
                if q in " ".join([r.id, r.name, r.what, r.category, r.cmd, r.notes]).lower()]

    def chain_params(self, chain_id: str) -> list[str]:
        out = []
        for sid in self.chains[chain_id].steps:
            for p in self.recipes[sid].params:
                if p not in out:
                    out.append(p)
        return out


def validate_recipe(r: Recipe) -> None:
    bad = set(PLACEHOLDER.findall(r.cmd)) - KNOWN
    if bad:
        raise KitError(f"{r.id}: unknown placeholder(s) {sorted(bad)}")
    if r.risk not in RISKS:
        raise KitError(f"{r.id}: risk must be one of {RISKS}")
    if FORBIDDEN.search(r.cmd):
        raise KitError(f"{r.id}: command uses a tool or mode that's not allowed on this box")
    if re.search(r"\bhydra\b", r.cmd):
        # Default-login checks only: typed confirmation, one connection at a time with a pause,
        # stop at the first hit, and only the factory-default lists - never a user wordlist.
        if r.risk != "active" or "{wordlist}" in r.cmd or not all(
                f in r.cmd for f in (" -t 1 ", " -W 1 ", " -f ")):
            raise KitError(f"{r.id}: hydra is only allowed as a gentle default-login check (risk active, -t 1 -W 1 -f)")
        if re.search(r"\s-(x|p|M|L|l)\s|\s-[CPMxLp]\S", r.cmd):
            raise KitError(f"{r.id}: hydra may not use generated passwords, extra lists or target files")
        if not (re.search(r"\s-t 1\s", r.cmd) and re.search(r"\s-W 1\s", r.cmd)):
            raise KitError(f"{r.id}: hydra must run with -t 1 -W 1")
        lists = re.findall(r"\bL=([^;\s]+)", r.cmd) + \
            [x.strip('"') for x in re.findall(r"\s-[CP]\s+(\S+)", r.cmd) if x.strip('"') != "$L"]
        real = [os.path.realpath(x) for x in lists]
        if not real or not all(any(x.startswith(d) for d in CRED_DIRS) for x in real):
            raise KitError(f"{r.id}: hydra may only use the default-credential lists")
    if "http-default-accounts" in r.cmd and (r.risk != "active" or not all(
            f in r.cmd for f in ("--max-parallelism 1", "--max-hostgroup 1", "--scan-delay 1s"))):
        raise KitError(f"{r.id}: web default-login checks must run one at a time (--max-parallelism 1 "
                       "--max-hostgroup 1 --scan-delay 1s) and be marked active")
    if "http-default-accounts" in r.cmd and re.search(r"\s-o[ANXGS]\s", r.cmd):
        raise KitError(f"{r.id}: web default-login output can't be saved to files (it holds passwords)")
    if re.search(r"\bonesixtyone\b", r.cmd) and (r.risk != "active" or "-w " not in r.cmd
                                                  or "-c /opt/havokbox/" not in r.cmd):
        raise KitError(f"{r.id}: SNMP community checks must be active, paced (-w) and use the box's list")
    if "{domain}" in r.cmd and "{host}" not in r.cmd:
        raise KitError(f"{r.id}: a {{domain}} recipe must query an in-scope {{host}} server")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,60}", r.id):
        raise KitError(f"bad recipe id {r.id!r}")


def load(path: Path | str = RECIPES_PATH) -> Catalog:
    data = json.loads(Path(path).read_text())
    recipes = {}
    for d in data.get("recipes", []):
        r = Recipe(**{k: v for k, v in d.items() if k in Recipe.__dataclass_fields__})
        validate_recipe(r)
        if r.id in recipes:
            raise KitError(f"duplicate recipe id {r.id}")
        recipes[r.id] = r
    chains = {}
    for d in data.get("chains", []):
        c = Chain(id=d["id"], name=d["name"], what=d.get("what", ""), steps=list(d["steps"]))
        missing = [s for s in c.steps if s not in recipes]
        if missing:
            raise KitError(f"chain {c.id}: unknown step(s) {missing}")
        chains[c.id] = c
    return Catalog(recipes, chains)


# ---------------------------------------------------------------- validation of filled values

def _ifaces() -> list[str]:
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


@dataclass
class Context:
    """Everything validation needs from the box; injectable for tests."""
    scope: object
    ifaces: list = field(default_factory=_ifaces)
    resolve: object = None          # host -> list of IPs
    file_exists: object = os.path.isfile

    def resolver(self, host: str) -> list[str]:
        if self.resolve:
            return self.resolve(host)
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except OSError:
            return []


def _in_scope_ip(ctx: Context, ip: str) -> bool:
    return ctx.scope.ip_in_scope(ip)


def check_value(name: str, value: str, ctx: Context, risk: str = "discovery") -> str:
    v = (value or "").strip()
    if not v:
        raise KitError(f"{LABELS.get(name, name)} is required")
    if name == "target":
        try:
            net = ipaddress.IPv4Network(v, strict=False)
        except ValueError:
            raise KitError(f"{v!r} isn't an IPv4 address or CIDR (hostnames are refused; scope is by address)")
        ok = ctx.scope.ip_in_scope(str(net.network_address)) if net.num_addresses == 1 \
            else ctx.scope.network_in_scope(str(net))
        if not ok:
            raise KitError(f"{v} is out of scope (not in the engagement, or on the never list)")
        return str(net) if net.num_addresses > 1 else str(net.network_address)
    if name == "host":
        try:
            ip = ipaddress.IPv4Address(v)
        except ValueError:
            raise KitError(f"{v!r} isn't an IPv4 address")
        if not _in_scope_ip(ctx, str(ip)):
            raise KitError(f"{v} is out of scope (not in the engagement, or on the never list)")
        return str(ip)
    if name == "port":
        if not v.isdigit() or not 1 <= int(v) <= 65535:
            raise KitError("port must be 1-65535")
        return str(int(v))
    if name == "ports":
        if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", v) or \
                any(not 1 <= int(n) <= 65535 for n in re.split(r"[,-]", v)):
            raise KitError("ports must look like 22,80,443 or 1-1024 (each 1-65535)")
        return v
    if name == "url":
        u = urlsplit(v)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise KitError("URL must start with http:// or https://")
        if re.search(r"[\s'\"`$\\<>|;?#&]", v):
            raise KitError("URL has characters that aren't allowed (no query strings)")
        if u.hostname and ":" in u.hostname:
            raise KitError("IPv6 URLs aren't supported here")
        host = u.hostname
        try:
            ips = [str(ipaddress.ip_address(host))]
        except ValueError:
            ips = ctx.resolver(host)
            if not ips:
                raise KitError(f"{host} doesn't resolve")
        if not all(_in_scope_ip(ctx, ip) for ip in ips):
            raise KitError(f"{host} is out of scope (every address it resolves to must be in the engagement)")
        return v
    if name == "domain":
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}\.?", v):
            raise KitError("domain must be a DNS name like corp.lab")
        return v
    if name == "mon" and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", v) and v not in ctx.ifaces \
            and any(v == i + "mon" for i in ctx.ifaces):
        return v      # created by "Start monitor mode" earlier in the same chain
    if name in ("iface", "wlan", "mon"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", v) or v not in ctx.ifaces:
            raise KitError(f"{v!r} isn't an interface on this box ({', '.join(ctx.ifaces) or 'none'})")
        return v
    if name == "channel":
        if not v.isdigit() or not 1 <= int(v) <= 196:
            raise KitError("channel must be 1-196")
        return str(int(v))
    if name == "bdaddr":
        if not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", v):
            raise KitError("Bluetooth address must look like AA:BB:CC:DD:EE:FF")
        if risk == "probe" and v.lower() not in {b.lower() for b in ctx.scope.ble}:
            raise KitError(f"{v} isn't on the Mine tab; mark the device as yours before probing it")
        return v.upper()
    if name == "hci":
        if not re.fullmatch(r"hci\d", v):
            raise KitError("adapter must look like hci0")
        return v
    if name == "wordlist":
        p = os.path.realpath(v)
        if not any(p.startswith(os.path.realpath(r) + os.sep) for r in WORDLIST_ROOTS) or not ctx.file_exists(p):
            raise KitError("wordlist must be an existing file under /usr/share/wordlists or /usr/share/seclists")
        return p
    if name == "freq":
        try:
            f = float(v)
        except ValueError:
            raise KitError("frequency must be a number in MHz, e.g. 433.92")
        if not 24 <= f <= 1766:
            raise KitError("frequency must be 24-1766 MHz (RTL-SDR range)")
        return f"{f:g}"
    if name == "seconds":
        if not v.isdigit() or not 1 <= int(v) <= 86400:
            raise KitError("seconds must be 1-86400")
        return str(int(v))
    raise KitError(f"unknown field {name}")


# ---------------------------------------------------------------- building commands

def kit_dir() -> Path:
    return Path(os.environ.get("HB_KIT_DIR", Path.home() / "havok" / "kit"))


def render(r: Recipe, values: dict, ctx: Context, outdir: str) -> str:
    clean = {p: check_value(p, values.get(p, ""), ctx, r.risk) for p in r.params}
    clean["outdir"] = outdir
    cmd = PLACEHOLDER.sub(lambda m: shlex.quote(clean[m.group(1)]), r.cmd)
    never = [str(n) for n in ctx.scope.exclude]
    uses_nmap = re.search(r"(^|[\s;|&(])nmap\s", cmd) is not None
    if "target" in clean and not uses_nmap:
        net = ipaddress.ip_network(clean["target"], strict=False)
        if any(net.overlaps(ipaddress.ip_network(n)) for n in never):
            raise KitError(f"{r.name} can't skip never-list addresses inside {net}; "
                           "pick a range that doesn't include them")
    if never and re.search(r"(^|[\s;|&(])nmap\s", cmd) and "--exclude" not in cmd:
        cmd = re.sub(r"(^|[\s;|&(])nmap\s", lambda m: f"{m.group(1)}nmap --exclude {shlex.quote(','.join(never))} ",
                     cmd, count=1)
    return cmd


@dataclass
class Plan:
    """What will run: the exact commands, where output goes, and the scripts to execute."""
    label: str
    outdir: Path
    commands: list          # (name, command, needs_root)
    active: bool = False    # includes a default-login check: needs a typed "yes" to run

    @property
    def root(self) -> bool:
        return any(r for _, _, r in self.commands)

    def body(self) -> str:
        d = shlex.quote(str(self.outdir))
        lines = ["#!/bin/bash", "set -o pipefail", f"cd {d}"]
        for i, (name, cmd, root) in enumerate(self.commands, 1):
            hdr = f"== step {i}/{len(self.commands)}: {name}" if len(self.commands) > 1 else f"== {name}"
            run = f"sudo bash -c {shlex.quote(cmd)}" if root else cmd
            lines += [f"echo {shlex.quote(hdr)} | tee -a output.log",
                      f"echo {shlex.quote('+ ' + cmd)} | tee -a output.log",
                      f"( {run} ) 2>&1 | tee -a output.log",
                      'echo "== exit code $?" | tee -a output.log']
        if self.root:   # files written by sudo steps go back to you
            lines.append(f'sudo -n chown -R "$(id -u):$(id -g)" {d} 2>/dev/null || true')
        return "\n".join(lines) + "\n"

    def runner(self) -> str:
        body = shlex.quote(str(self.outdir / "body.sh"))
        return ("#!/bin/bash\n" + f"bash {body}\n"
                f'echo; echo "Output saved in {self.outdir}"; read -rp "Press Enter to close " _\n')


def plan(cat: Catalog, item_id: str, values: dict, ctx: Context, when: dt.datetime | None = None) -> Plan:
    if item_id in cat.chains:
        steps = [cat.recipes[s] for s in cat.chains[item_id].steps]
        label = cat.chains[item_id].name
    elif item_id in cat.recipes:
        steps = [cat.recipes[item_id]]
        label = steps[0].name
    else:
        raise KitError(f"no recipe or chain called {item_id!r}")
    stamp = (when or dt.datetime.now()).strftime("%Y%m%d-%H%M%S")
    outdir = kit_dir() / f"{stamp}_{item_id}"
    n = 2
    while outdir.exists():          # two runs in the same second
        outdir = kit_dir() / f"{stamp}_{item_id}-{n}"
        n += 1
    as_root = os.geteuid() == 0
    cmds = [(r.name, render(r, values, ctx, str(outdir)), r.root and not as_root) for r in steps]
    return Plan(label=label, outdir=outdir, commands=cmds, active=any(r.risk == "active" for r in steps))


CONFIRM_WORD = "yes"


def confirmed(p: Plan, typed: str | None) -> bool:
    return not p.active or (typed or "").strip().lower() == CONFIRM_WORD


def write(p: Plan) -> Path:
    kit_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    p.outdir.mkdir(mode=0o700, exist_ok=False)
    (p.outdir / "command.txt").write_text("\n".join(c for _, c, _ in p.commands) + "\n")
    body = p.outdir / "body.sh"
    body.write_text(p.body())
    body.chmod(0o400)               # read-only once written; it's what sudo runs
    run = p.outdir / "run.sh"
    run.write_text(p.runner())
    run.chmod(0o500)
    with open(kit_dir() / "history.log", "a") as fh:
        tag = "ACTIVE\t" if p.active else ""
        fh.write(f"{dt.datetime.now().isoformat(timespec='seconds')}\t{tag}{p.label}\t{p.outdir}\n")
    return run


def launch_terminal(run: Path) -> None:
    """Open a terminal window on the desktop that runs the recipe (sudo prompts work there)."""
    for term in (["x-terminal-emulator", "-e"], ["qterminal", "-e"], ["xfce4-terminal", "-x"],
                 ["gnome-terminal", "--"]):
        try:
            subprocess.Popen(term + [str(run)], start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except FileNotFoundError:
            continue
    raise KitError("no terminal program found to run it in; run it with: bash " + str(run))
