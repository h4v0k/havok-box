"""Recon/Enumerate pack (design-kali-pack.md section 3): passive listeners + detection-only active probes.

Lab-only wrappers around standard installed Kali tools. Each tool has a deterministic build_<x>
(the exact argv), a pure parse_<x> (tolerant of empty/garbage output) and an fn that runs build's
argv through ctx.runner and parses. Nothing here sends exploits, payloads, or credentials, and
nothing extracts credentials from traffic.

Binaries (for ToolSpec.binary): responder, p0f, tshark, atk6-detect-new-ip6, nuclei, testssl,
feroxbuster, netexec, ldapsearch, onesixtyone, searchsploit.
"""
from __future__ import annotations

import json
import re

from ..store import new_id

CAP = 64

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_IP4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


def _int(v, lo, hi, default):
    try:
        if v is None or v == "" or isinstance(v, bool):
            return default
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _clean(text) -> list[str]:
    if not isinstance(text, str):
        return []
    return _ANSI.sub("", text).splitlines()


def _iface(hw: dict) -> str:
    return (hw or {}).get("wired_iface", "eth0")


def _run(argvs, ctx) -> str:
    out = ctx.runner(argvs[0])
    return out if isinstance(out, str) else ""


def _result(space, kind, summary, data):
    return {"result_id": new_id(), "space": space, "kind": kind, "summary": summary, "data": data}


# ---------------------------------------------------------------- responder.analyze

_RESP = re.compile(
    rf"\[Analyze mode(?::\s*([A-Za-z0-9_\- ]+?))?\]\s*(?:\[[^\]]*\]\s*)?Request by ({_IP4}) for (\S+?)(?:,|\s|$)",
    re.I)
_RESP_ALT = re.compile(rf"\[([A-Za-z0-9_\-]+)\]\s*Request by ({_IP4}) for (\S+?)(?:,|\s|$)", re.I)


def build_responder(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = _int((target or {}).get("seconds"), 10, 600, 120)
    # -A = analyze only: listens, never answers/poisons.
    return [["timeout", str(seconds), "responder", "-I", _iface(hw), "-A"]]


def parse_responder(stdout: str) -> list[dict]:
    seen, out = set(), []
    for line in _clean(stdout):
        m = _RESP.search(line) or (_RESP_ALT.search(line) if "analyze" in line.lower() else None)
        if not m:
            continue
        proto = (m.group(1) or "unknown").strip().upper()
        name, ip = m.group(3).strip(), m.group(2)
        key = (name.lower(), proto, ip)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "proto": proto, "ip": ip})
    return out[:CAP]


def responder_analyze(task: dict, ctx) -> dict:
    argvs = build_responder(task.get("target") or {}, ctx.mode, ctx.scope, ctx.hw)
    names = parse_responder(_run(argvs, ctx))
    return _result("wired", "net_names", f"{len(names)} name-resolution request(s) heard (analyze only)",
                   {"names": names})


# ---------------------------------------------------------------- p0f.listen

def build_p0f(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = _int((target or {}).get("seconds"), 10, 600, 120)
    return [["timeout", str(seconds), "p0f", "-i", _iface(hw), "-o", "/dev/stdout"]]


def parse_p0f(stdout: str) -> list[dict]:
    hosts: dict[str, dict] = {}
    for line in _clean(stdout):
        if "|" not in line or "mod=" not in line:
            continue
        kv = {}
        for part in line.split("|"):
            k, sep, v = part.partition("=")
            if sep:
                kv[k.split("]")[-1].strip()] = v.strip()
        subj = kv.get("subj", "cli")
        ep = kv.get("srv" if subj == "srv" else "cli", "")
        ip = ep.rsplit("/", 1)[0]
        if not re.fullmatch(_IP4, ip) and ":" not in ip:
            continue
        if not ip:
            continue
        h = hosts.setdefault(ip, {"ip": ip, "os": None, "link": None, "distance": None})
        os_ = kv.get("os")
        if os_ and os_ != "???":
            h["os"] = os_
        if kv.get("mod") == "mtu" and kv.get("link") and kv["link"] != "???":
            h["link"] = kv["link"]
        d = kv.get("dist")
        if d is not None and d.isdigit():
            h["distance"] = int(d)
    return list(hosts.values())[:CAP]


def p0f_listen(task: dict, ctx) -> dict:
    argvs = build_p0f(task.get("target") or {}, ctx.mode, ctx.scope, ctx.hw)
    hosts = parse_p0f(_run(argvs, ctx))
    return _result("wired", "os_fingerprint", f"{len(hosts)} host(s) fingerprinted passively",
                   {"hosts": hosts})


# ---------------------------------------------------------------- cleartext.find

# PRESENCE only: frame.protocols + addresses. No credential/payload fields are ever requested.
CLEARTEXT_FILTER = "telnet || ftp || http.authbasic || snmp.version==0 || pop || imap"
_CLEAR_PROTOS = ("telnet", "ftp", "http", "snmp", "pop", "imap")


def build_cleartext(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = _int((target or {}).get("seconds"), 10, 300, 120)
    return [["timeout", str(seconds), "tshark", "-i", _iface(hw), "-l", "-n", "-Y", CLEARTEXT_FILTER,
             "-T", "fields", "-e", "frame.protocols", "-e", "ip.src", "-e", "ip.dst"]]


def parse_cleartext(stdout: str) -> list[dict]:
    seen, out = set(), []
    for line in _clean(stdout):
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        # Only the first three columns are ever read; anything extra is dropped unread.
        protos = [p.lower() for p in cols[0].split(":")]
        src, dst = cols[1].strip(), cols[2].strip()
        if not src or not dst:
            continue
        hit = next((p for p in _CLEAR_PROTOS if p in protos), None)
        if hit is None:
            continue
        key = (hit, src, dst)
        if key in seen:
            continue
        seen.add(key)
        out.append({"protocol": hit, "src": src, "dst": dst})
    return out[:CAP]


def cleartext_find(task: dict, ctx) -> dict:
    argvs = build_cleartext(task.get("target") or {}, ctx.mode, ctx.scope, ctx.hw)
    svc = parse_cleartext(_run(argvs, ctx))
    protos = sorted({s["protocol"] for s in svc})
    return _result("wired", "cleartext_services",
                   f"{len(svc)} cleartext flow(s) seen ({', '.join(protos) or 'none'}); presence only",
                   {"services": svc})


# ---------------------------------------------------------------- ipv6.listen

_V6 = re.compile(r"Detected.*?\b((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})", re.I)
_V6MAC = re.compile(_MAC)


def build_ipv6(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = _int((target or {}).get("seconds"), 10, 300, 120)
    return [["timeout", str(seconds), "atk6-detect-new-ip6", _iface(hw)]]


def parse_ipv6(stdout: str) -> list[dict]:
    seen, out = set(), []
    for line in _clean(stdout):
        if "detected" not in line.lower():
            continue
        m = _V6.search(line)
        if not m:
            continue
        addr = m.group(1).lower()
        if addr in seen:
            continue
        seen.add(addr)
        mac = _V6MAC.search(line)
        out.append({"ip6": addr, "mac": mac.group(0).lower() if mac else None})
    return out[:CAP]


def ipv6_listen(task: dict, ctx) -> dict:
    argvs = build_ipv6(task.get("target") or {}, ctx.mode, ctx.scope, ctx.hw)
    hosts = parse_ipv6(_run(argvs, ctx))
    return _result("wired", "ipv6_hosts", f"{len(hosts)} new IPv6 address(es) detected", {"hosts": hosts})


# ---------------------------------------------------------------- nuclei.scan

NUCLEI_TAGS = "exposure,misconfiguration,tech,default-login"
NUCLEI_EXCLUDE = "intrusive,dos,fuzz"


def build_nuclei(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    # Scheme is always http (documented choice): a plain-HTTP probe of the port-80 service; TLS
    # services are covered by tls.scan. Detection only: allowlisted tags, intrusive/dos/fuzz excluded,
    # rate limited, no update check, no interactsh (no out-of-band callbacks).
    return [["nuclei", "-u", f"http://{target['ip']}", "-jsonl", "-silent", "-disable-update-check",
             "-no-interactsh", "-rate-limit", "20", "-tags", NUCLEI_TAGS, "-exclude-tags", NUCLEI_EXCLUDE]]


def _jsonl(stdout: str):
    for line in _clean(stdout):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            yield obj


def parse_nuclei(stdout: str) -> list[dict]:
    out = []
    for o in _jsonl(stdout):
        tid = o.get("template-id") or o.get("template_id")
        if not tid:
            continue
        info = o.get("info") if isinstance(o.get("info"), dict) else {}
        out.append({"template_id": str(tid), "name": str(info.get("name") or ""),
                    "severity": str(info.get("severity") or "info").lower(),
                    "matched_at": str(o.get("matched-at") or o.get("matched") or "")})
    return out[:CAP]


def nuclei_scan(task: dict, ctx) -> dict:
    argvs = build_nuclei(task["target"], ctx.mode, ctx.scope, ctx.hw)
    f = parse_nuclei(_run(argvs, ctx))
    return _result("wired", "nuclei", f"{len(f)} nuclei detection(s)", {"ip": task["target"]["ip"], "findings": f})


# ---------------------------------------------------------------- tls.scan

def build_tls(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    argv = ["testssl"]
    if mode == "stealth":
        argv.append("--fast")
    argv += ["--quiet", "--jsonfile", "/dev/stdout", target["ip"]]
    return [argv]


_PROTO_IDS = {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}


def _testssl_items(stdout: str) -> list[dict]:
    text = "\n".join(_clean(stdout))
    items: list = []
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("scanResult") or []
            if data and isinstance(data[0], dict) and "serverDefaults" in data[0]:
                data = [i for r in data for k in ("protocols", "vulnerabilities", "serverDefaults")
                        for i in (r.get(k) or [])]
        items = data if isinstance(data, list) else []
    except (ValueError, TypeError):
        items = list(_jsonl(stdout))
    return [i for i in items if isinstance(i, dict)]


def parse_tls(stdout: str) -> dict:
    protocols, vulns, seen = [], [], set()
    for i in _testssl_items(stdout):
        id_, sev, fnd = str(i.get("id") or ""), str(i.get("severity") or "").upper(), str(i.get("finding") or "")
        if id_ in _PROTO_IDS and id_ not in seen:
            seen.add(id_)
            protocols.append({"id": id_, "offered": fnd.lower().startswith("offered")})
        elif sev in ("HIGH", "CRITICAL") and id_:
            vulns.append({"id": id_, "severity": sev, "finding": fnd[:200]})
    return {"protocols": protocols[:CAP], "vulns": vulns[:CAP]}


def tls_scan(task: dict, ctx) -> dict:
    argvs = build_tls(task["target"], ctx.mode, ctx.scope, ctx.hw)
    p = parse_tls(_run(argvs, ctx))
    return _result("wired", "tls", f"{len(p['protocols'])} protocol(s) checked, {len(p['vulns'])} high/critical issue(s)",
                   {"ip": task["target"]["ip"], **p})


# ---------------------------------------------------------------- web.content

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


def build_web_content(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [["feroxbuster", "-u", f"http://{target['ip']}/", "-q", "--json", "--depth", "1",
             "--rate-limit", "50", "-w", (hw or {}).get("wordlist", DEFAULT_WORDLIST)]]


def parse_web_content(stdout: str) -> list[dict]:
    seen, out = set(), []
    for o in _jsonl(stdout):
        if o.get("type") not in (None, "response"):
            continue
        url = str(o.get("url") or "")
        path = o.get("path") or re.sub(r"^\w+://[^/]+", "", url)
        status = o.get("status")
        if not path or not isinstance(status, int) or path in seen:
            continue
        seen.add(path)
        size = o.get("content_length")
        out.append({"path": str(path), "status": status, "size": size if isinstance(size, int) else None})
    return out[:CAP]


def web_content(task: dict, ctx) -> dict:
    argvs = build_web_content(task["target"], ctx.mode, ctx.scope, ctx.hw)
    paths = parse_web_content(_run(argvs, ctx))
    return _result("wired", "web_content", f"{len(paths)} path(s) found", {"ip": task["target"]["ip"], "paths": paths})


# ---------------------------------------------------------------- smb.nxc

def build_smb_nxc(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    # NULL session only: empty user, empty password. No credential guessing.
    return [["netexec", "smb", target["ip"], "-u", "", "-p", "", "--shares"]]


_NXC_PFX = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(.*)$")
_NXC_ROW = re.compile(r"^(\S+)\s+(NO ACCESS|READ,WRITE|READ|WRITE)?\s*(.*)$")


def parse_smb_nxc(stdout: str) -> dict:
    os_banner = signing = None
    shares: list[dict] = []
    in_shares = False
    for line in _clean(stdout):
        m = _NXC_PFX.match(line.strip())
        if not m:
            continue
        body = m.group(1).strip()
        if body.startswith("[*]") and "(signing:" in body:
            sm = re.search(r"\(signing:(\w+)\)", body)
            signing = (sm.group(1).lower() == "true") if sm else None
            os_banner = re.sub(r"\s*\(.*$", "", body[3:]).strip() or None
            continue
        if re.match(r"Share\s+Permissions", body):
            in_shares = True
            continue
        if not in_shares or body.startswith(("-----", "[")):
            continue
        r = _NXC_ROW.match(body)
        if r:
            shares.append({"name": r.group(1), "access": r.group(2) or "", "remark": r.group(3).strip()})
    return {"os": os_banner, "signing": signing, "shares": shares[:CAP]}


def smb_nxc(task: dict, ctx) -> dict:
    argvs = build_smb_nxc(task["target"], ctx.mode, ctx.scope, ctx.hw)
    p = parse_smb_nxc(_run(argvs, ctx))
    return _result("wired", "smb_nxc", f"{len(p['shares'])} share(s) listed via null session",
                   {"ip": task["target"]["ip"], **p})


# ---------------------------------------------------------------- ldap.anon

def build_ldap(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [["ldapsearch", "-x", "-H", f"ldap://{target['ip']}", "-s", "base", "-b", "", "+"]]


def parse_ldap(stdout: str) -> dict:
    naming, default, extra = [], None, {}
    for line in _clean(stdout):
        k, sep, v = line.partition(":")
        if not sep or line.startswith("#"):
            continue
        k, v = k.strip(), v.strip()
        kl = k.lower()
        if kl == "namingcontexts" and v and v not in naming:
            naming.append(v)
        elif kl == "defaultnamingcontext" and v:
            default = v
        elif kl in ("dnshostname", "servername", "domainfunctionality", "forestfunctionality") and v:
            extra[k] = v
    return {"naming_contexts": naming[:CAP], "default_naming_context": default, "info": extra}


def ldap_anon(task: dict, ctx) -> dict:
    argvs = build_ldap(task["target"], ctx.mode, ctx.scope, ctx.hw)
    p = parse_ldap(_run(argvs, ctx))
    return _result("wired", "ldap", f"{len(p['naming_contexts'])} naming context(s) via anonymous bind",
                   {"ip": task["target"]["ip"], **p})


# ---------------------------------------------------------------- snmp.enum

def build_snmp(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    # One step: onesixtyone against ONLY "public" and "private". snmpwalk is a follow-up recipe
    # step (recipe-defined, per-community) and is deliberately not run by this tool.
    return [["onesixtyone", target["ip"], "public", "private"]]


_SNMP = re.compile(rf"^({_IP4})\s+\[([^\]]*)\]\s*(.*)$")


def parse_snmp(stdout: str) -> list[dict]:
    out, seen = [], set()
    for line in _clean(stdout):
        m = _SNMP.match(line.strip())
        if not m or m.group(2) not in ("public", "private") or (m.group(1), m.group(2)) in seen:
            continue
        seen.add((m.group(1), m.group(2)))
        out.append({"ip": m.group(1), "community": m.group(2), "sysdescr": m.group(3).strip()[:200]})
    return out[:CAP]


def snmp_enum(task: dict, ctx) -> dict:
    argvs = build_snmp(task["target"], ctx.mode, ctx.scope, ctx.hw)
    c = parse_snmp(_run(argvs, ctx))
    return _result("wired", "snmp", f"{len(c)} SNMP community string(s) responded",
                   {"ip": task["target"]["ip"], "communities": c})


# ---------------------------------------------------------------- exploit.lookup

def build_exploit_lookup(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    # Offline Exploit-DB title search. No target, no network. Leading dashes stripped so the
    # query can never be read as a searchsploit option.
    q = str((target or {}).get("query", "")).strip().lstrip("-")
    return [["searchsploit", "--color=never", "-w", q]]


_EDB = re.compile(r"https?://\S*exploit-db\.com/\S+")


def parse_exploit_lookup(stdout: str) -> list[dict]:
    out, seen = [], set()
    for line in _clean(stdout):
        u = _EDB.search(line)
        if not u or "|" not in line:
            continue
        url = u.group(0)
        title = line.rsplit("|", 1)[0].strip()
        if not title or title.lower().startswith("exploit title") or url in seen:
            continue
        seen.add(url)
        out.append({"title": title, "url": url})
    return out[:CAP]


def exploit_lookup(task: dict, ctx) -> dict:
    argvs = build_exploit_lookup(task.get("target") or {}, ctx.mode, ctx.scope, ctx.hw)
    refs = parse_exploit_lookup(_run(argvs, ctx))
    return _result("report", "exploit_refs", f"{len(refs)} Exploit-DB reference(s) (offline lookup)",
                   {"query": argvs[0][-1], "refs": refs})
