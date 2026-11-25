import json
import unittest
from types import SimpleNamespace

from havokbox.tools import kali_recon as k

HW = {"wired_iface": "eth9"}


class Rec:
    def __init__(self, out=""):
        self.cmds, self.out = [], out

    def __call__(self, argv):
        self.cmds.append(argv)
        return self.out


def ctx(out="", mode="standard", hw=HW):
    r = Rec(out)
    return SimpleNamespace(runner=r, mode=mode, scope=None, hw=hw), r


RESP = """\x1b[1;34m[Analyze mode: LLMNR]\x1b[0m Request by 10.0.0.5 for fileserv, ignoring
[Analyze mode: NBT-NS] Request by 10.0.0.5 for WPAD, ignoring
[Analyze mode: MDNS] Request by 10.0.0.7 for printer.local, ignoring
[Analyze mode: LLMNR] Request by 10.0.0.5 for fileserv, ignoring
random noise
"""
P0F = """[2026/01/01 10:00:00] mod=syn|cli=10.0.0.5/51234|srv=10.0.0.1/80|subj=cli|os=Linux 3.x|dist=0|params=none|raw_sig=4:64+0
[2026/01/01 10:00:01] mod=mtu|cli=10.0.0.5/51234|srv=10.0.0.1/80|subj=cli|link=Ethernet or modem|raw_mtu=1500
[2026/01/01 10:00:02] mod=syn+ack|cli=10.0.0.5/51234|srv=10.0.0.1/80|subj=srv|os=Windows 10|dist=2|params=none
"""
TSHARK = ("eth:ethertype:ip:tcp:telnet\t10.0.0.5\t10.0.0.9\n"
          "eth:ethertype:ip:tcp:ftp\t10.0.0.5\t10.0.0.9\n"
          "eth:ethertype:ip:tcp:telnet\t10.0.0.5\t10.0.0.9\n"
          "eth:ethertype:ip:udp:snmp\t10.0.0.6\t10.0.0.9\n"
          "garbage\n")
V6 = ("Started detect-new-ip6\nDetected new ip6 address: fe80::a00:27ff:fe12:3456 (MAC 08:00:27:12:34:56)\n"
      "Detected new ip6 address: 2001:db8::5\n")
NUC = (json.dumps({"template-id": "git-config", "info": {"name": "Git Config", "severity": "medium"},
                   "matched-at": "http://10.0.0.5/.git/config"}) + "\nnot json\n{broken\n")
TLS = json.dumps([
    {"id": "SSLv3", "severity": "OK", "finding": "not offered"},
    {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
    {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE"},
    {"id": "BEAST", "severity": "LOW", "finding": "x"},
])
FEROX = "\n".join([
    json.dumps({"type": "response", "url": "http://10.0.0.5/admin", "path": "/admin", "status": 301, "content_length": 169}),
    json.dumps({"type": "statistics", "total": 3}),
    "junk",
])
NXC = """SMB   10.0.0.5  445  FS01  [*] Windows Server 2019 Build 17763 x64 (name:FS01) (domain:LAB) (signing:False) (SMBv1:False)
SMB   10.0.0.5  445  FS01  [+] LAB\\: 
SMB   10.0.0.5  445  FS01  [*] Enumerated shares
SMB   10.0.0.5  445  FS01  Share           Permissions     Remark
SMB   10.0.0.5  445  FS01  -----           -----------     ------
SMB   10.0.0.5  445  FS01  ADMIN$                          Remote Admin
SMB   10.0.0.5  445  FS01  public          READ            Public files
"""
LDAP = """# extended LDIF
dn:
namingContexts: DC=lab,DC=local
namingContexts: CN=Configuration,DC=lab,DC=local
defaultNamingContext: DC=lab,DC=local
dnsHostName: dc01.lab.local
"""
SNMP = """Scanning 1 hosts, 2 communities
10.0.0.5 [public] Linux fs01 5.10 #1 SMP x86_64
10.0.0.5 [secret] Evil
"""
SEARCH = """------------------------------------------------ ---------------------------------
 Exploit Title                                  |  URL
------------------------------------------------ ---------------------------------
Apache 2.4.49 - Path Traversal                  | https://www.exploit-db.com/exploits/50383
Apache HTTP Server 2.4.50 - RCE                 | https://www.exploit-db.com/exploits/50406
------------------------------------------------ ---------------------------------
"""


class Parsers(unittest.TestCase):
    def test_responder(self):
        n = k.parse_responder(RESP)
        self.assertEqual(len(n), 3)
        self.assertIn({"name": "fileserv", "proto": "LLMNR", "ip": "10.0.0.5"}, n)
        self.assertIn({"name": "printer.local", "proto": "MDNS", "ip": "10.0.0.7"}, n)

    def test_p0f(self):
        h = {x["ip"]: x for x in k.parse_p0f(P0F)}
        self.assertEqual(h["10.0.0.5"], {"ip": "10.0.0.5", "os": "Linux 3.x", "link": "Ethernet or modem", "distance": 0})
        self.assertEqual(h["10.0.0.1"]["os"], "Windows 10")
        self.assertEqual(h["10.0.0.1"]["distance"], 2)

    def test_cleartext(self):
        s = k.parse_cleartext(TSHARK)
        self.assertEqual(len(s), 3)
        self.assertIn({"protocol": "snmp", "src": "10.0.0.6", "dst": "10.0.0.9"}, s)

    def test_cleartext_ignores_extra_columns(self):
        s = k.parse_cleartext("eth:ip:tcp:ftp\t1.1.1.1\t2.2.2.2\tUSER admin PASS hunter2\n")
        self.assertEqual(s, [{"protocol": "ftp", "src": "1.1.1.1", "dst": "2.2.2.2"}])
        self.assertNotIn("hunter2", json.dumps(s))

    def test_ipv6(self):
        h = k.parse_ipv6(V6)
        self.assertEqual(h[0], {"ip6": "fe80::a00:27ff:fe12:3456", "mac": "08:00:27:12:34:56"})
        self.assertEqual(h[1]["ip6"], "2001:db8::5")

    def test_nuclei(self):
        f = k.parse_nuclei(NUC)
        self.assertEqual(f, [{"template_id": "git-config", "name": "Git Config", "severity": "medium",
                              "matched_at": "http://10.0.0.5/.git/config"}])

    def test_tls(self):
        p = k.parse_tls(TLS)
        self.assertEqual({x["id"]: x["offered"] for x in p["protocols"]},
                         {"SSLv3": False, "TLS1_2": True, "TLS1": True})
        self.assertEqual([v["id"] for v in p["vulns"]], ["heartbleed"])

    def test_tls_jsonl_fallback(self):
        line = json.dumps({"id": "ROBOT", "severity": "HIGH", "finding": "VULNERABLE"})
        self.assertEqual(k.parse_tls(line + "\nnoise")["vulns"][0]["id"], "ROBOT")

    def test_web(self):
        self.assertEqual(k.parse_web_content(FEROX), [{"path": "/admin", "status": 301, "size": 169}])

    def test_smb(self):
        p = k.parse_smb_nxc(NXC)
        self.assertEqual(p["os"], "Windows Server 2019 Build 17763 x64")
        self.assertIs(p["signing"], False)
        self.assertEqual([s["name"] for s in p["shares"]], ["ADMIN$", "public"])
        self.assertEqual(p["shares"][1]["access"], "READ")

    def test_ldap(self):
        p = k.parse_ldap(LDAP)
        self.assertEqual(p["default_naming_context"], "DC=lab,DC=local")
        self.assertEqual(len(p["naming_contexts"]), 2)

    def test_snmp_only_allowed_communities(self):
        c = k.parse_snmp(SNMP)
        self.assertEqual([x["community"] for x in c], ["public"])

    def test_exploit(self):
        r = k.parse_exploit_lookup(SEARCH)
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0], {"title": "Apache 2.4.49 - Path Traversal",
                                "url": "https://www.exploit-db.com/exploits/50383"})

    def test_garbage_and_empty(self):
        for p in (k.parse_responder, k.parse_p0f, k.parse_cleartext, k.parse_ipv6, k.parse_nuclei,
                  k.parse_web_content, k.parse_snmp, k.parse_exploit_lookup):
            for junk in ("", None, "\x00\xff garbage {[", "a|b|c\n\t\t\n"):
                self.assertEqual(p(junk), [], p.__name__)
        for p in (k.parse_tls, k.parse_smb_nxc, k.parse_ldap):
            for junk in ("", None, "{{{ nonsense", "[1,2]"):
                p(junk)

    def test_caps(self):
        many = "\n".join(f"[Analyze mode: LLMNR] Request by 10.0.0.{i % 250 + 1} for h{i}, ignoring" for i in range(200))
        self.assertEqual(len(k.parse_responder(many)), k.CAP)


class Builds(unittest.TestCase):
    def test_timeouts_and_clamps(self):
        self.assertEqual(k.build_responder({}, "standard", None, HW)[0],
                         ["timeout", "120", "responder", "-I", "eth9", "-A"])
        self.assertEqual(k.build_responder({"seconds": 5000}, "x", None, {})[0][:2], ["timeout", "600"])
        self.assertEqual(k.build_p0f({"seconds": 1}, "x", None, HW)[0],
                         ["timeout", "10", "p0f", "-i", "eth9", "-o", "/dev/stdout"])
        self.assertEqual(k.build_ipv6({"seconds": 999}, "x", None, HW)[0],
                         ["timeout", "300", "atk6-detect-new-ip6", "eth9"])
        self.assertEqual(k.build_cleartext({"seconds": "bad"}, "x", None, HW)[0][:2], ["timeout", "120"])

    def test_cleartext_never_credentials(self):
        argv = k.build_cleartext({}, "standard", None, HW)[0]
        fields = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
        self.assertEqual(fields, ["frame.protocols", "ip.src", "ip.dst"])
        blob = " ".join(argv).lower()
        for bad in ("password", "passwd", "username", "user", "credential", "auth.", "-w"):
            if bad == "auth.":
                self.assertNotIn("authbasic.", blob)
            else:
                self.assertNotIn(f" {bad}", blob.replace("http.authbasic", ""))
        out = json.dumps(k.parse_cleartext(TSHARK)).lower()
        for bad in ("password", "credential", "passwd"):
            self.assertNotIn(bad, out)

    def test_nuclei_detection_only(self):
        a = k.build_nuclei({"ip": "10.0.0.5"}, "standard", None, HW)[0]
        self.assertEqual(a[a.index("-exclude-tags") + 1], "intrusive,dos,fuzz")
        self.assertEqual(a[a.index("-tags") + 1], "exposure,misconfiguration,tech,default-login")
        self.assertIn("-no-interactsh", a)
        self.assertIn("-disable-update-check", a)
        self.assertFalse(any("interactsh" in x and x != "-no-interactsh" for x in a))
        self.assertEqual(a[a.index("-rate-limit") + 1], "20")
        self.assertEqual(a[:3], ["nuclei", "-u", "http://10.0.0.5"])
        self.assertEqual(a, k.build_nuclei({"ip": "10.0.0.5"}, "stealth", None, HW)[0])

    def test_tls_stealth_vs_standard(self):
        s = k.build_tls({"ip": "10.0.0.5"}, "stealth", None, HW)[0]
        d = k.build_tls({"ip": "10.0.0.5"}, "standard", None, HW)[0]
        self.assertEqual(s, ["testssl", "--fast", "--quiet", "--jsonfile", "/dev/stdout", "10.0.0.5"])
        self.assertEqual(d, ["testssl", "--quiet", "--jsonfile", "/dev/stdout", "10.0.0.5"])

    def test_misc_argv(self):
        t = {"ip": "10.0.0.5"}
        w = k.build_web_content(t, "standard", None, {})[0]
        self.assertEqual(w, ["feroxbuster", "-u", "http://10.0.0.5/", "-q", "--json", "--depth", "1",
                             "--rate-limit", "50", "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt"])
        self.assertEqual(k.build_web_content(t, "x", None, {"wordlist": "/w.txt"})[0][-1], "/w.txt")
        self.assertEqual(k.build_smb_nxc(t, "x", None, HW)[0],
                         ["netexec", "smb", "10.0.0.5", "-u", "", "-p", "", "--shares"])
        self.assertEqual(k.build_ldap(t, "x", None, HW)[0],
                         ["ldapsearch", "-x", "-H", "ldap://10.0.0.5", "-s", "base", "-b", "", "+"])
        self.assertEqual(k.build_snmp(t, "x", None, HW), [["onesixtyone", "10.0.0.5", "public", "private"]])
        self.assertEqual(k.build_exploit_lookup({"query": "apache 2.4"}, "x", None, HW)[0],
                         ["searchsploit", "--color=never", "-w", "apache 2.4"])
        self.assertEqual(k.build_exploit_lookup({"query": "--update"}, "x", None, HW)[0][-1], "update")


class Fns(unittest.TestCase):
    CASES = [
        (k.responder_analyze, k.build_responder, {"seconds": 30}, RESP, "net_names", "wired"),
        (k.p0f_listen, k.build_p0f, {"seconds": 30}, P0F, "os_fingerprint", "wired"),
        (k.cleartext_find, k.build_cleartext, {"seconds": 30}, TSHARK, "cleartext_services", "wired"),
        (k.ipv6_listen, k.build_ipv6, {"seconds": 30}, V6, "ipv6_hosts", "wired"),
        (k.nuclei_scan, k.build_nuclei, {"ip": "10.0.0.5"}, NUC, "nuclei", "wired"),
        (k.tls_scan, k.build_tls, {"ip": "10.0.0.5"}, TLS, "tls", "wired"),
        (k.web_content, k.build_web_content, {"ip": "10.0.0.5"}, FEROX, "web_content", "wired"),
        (k.smb_nxc, k.build_smb_nxc, {"ip": "10.0.0.5"}, NXC, "smb_nxc", "wired"),
        (k.ldap_anon, k.build_ldap, {"ip": "10.0.0.5"}, LDAP, "ldap", "wired"),
        (k.snmp_enum, k.build_snmp, {"ip": "10.0.0.5"}, SNMP, "snmp", "wired"),
        (k.exploit_lookup, k.build_exploit_lookup, {"query": "apache"}, SEARCH, "exploit_refs", "report"),
    ]

    def test_fn_runs_exactly_build_argv(self):
        for fn, build, target, out, kind, space in self.CASES:
            for mode in ("stealth", "standard"):
                c, rec = ctx(out, mode)
                res = fn({"target": target}, c)
                self.assertEqual(rec.cmds, build(target, mode, None, HW), fn.__name__)
                self.assertEqual((res["kind"], res["space"]), (kind, space), fn.__name__)
                self.assertTrue(res["result_id"] and res["summary"])

    def test_fn_tolerates_empty_output(self):
        for fn, _b, target, _o, kind, _s in self.CASES:
            c, _ = ctx("")
            self.assertEqual(fn({"target": target}, c)["kind"], kind)

    def test_data_shapes(self):
        c, _ = ctx(RESP)
        self.assertEqual(len(k.responder_analyze({"target": {}}, c)["data"]["names"]), 3)
        c, _ = ctx(TSHARK)
        self.assertEqual(len(k.cleartext_find({"target": {}}, c)["data"]["services"]), 3)


if __name__ == "__main__":
    unittest.main()
