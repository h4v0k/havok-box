import json
import unittest
from types import SimpleNamespace

from havokbox.tools import DEFAULT_HW, wired

HW = dict(DEFAULT_HW)

LISTEN = """\
12:00:01.100000 aa:bb:cc:00:00:50 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Request who-has 192.168.1.1 tell 192.168.1.50, length 28
12:00:01.101000 aa:bb:cc:00:00:01 > aa:bb:cc:00:00:50, ethertype ARP (0x0806), length 42: Reply 192.168.1.1 is-at aa:bb:cc:00:00:01, length 28
12:00:02.000000 aa:bb:cc:00:00:60 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Request who-has 192.168.1.1 tell 192.168.1.60, length 28
12:00:03.000000 aa:bb:cc:00:00:99 > aa:bb:cc:00:00:60, ethertype ARP (0x0806), length 42: Reply 192.168.1.1 is-at aa:bb:cc:00:00:99, length 28
12:00:04.000000 aa:bb:cc:00:00:01 > aa:bb:cc:00:00:70, ethertype IPv4 (0x0800), length 342: 192.168.1.1.67 > 192.168.1.70.68: BOOTP/DHCP, Reply, length 300
12:00:04.500000 aa:bb:cc:00:00:ee > aa:bb:cc:00:00:70, ethertype IPv4 (0x0800), length 342: 192.168.1.250.67 > 192.168.1.70.68: BOOTP/DHCP, Reply, length 300
12:00:05.000000 aa:bb:cc:00:00:70 > 01:00:5e:00:00:fb, ethertype IPv4 (0x0800), length 80: 192.168.1.70.5353 > 224.0.0.251.5353: 0 PTR? printer.local. (38)
12:00:06.000000 aa:bb:cc:00:00:80 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Request who-has 192.168.1.1 (ff:ff:ff:ff:ff:ff) tell 0.0.0.0, length 28
"""

VULN_XML = """<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/>
<script id="smb-vuln-ms17-010" output="&#10;  VULNERABLE:&#10;  Remote Code Execution vulnerability in Microsoft SMBv1&#10;    IDs:  CVE:CVE-2017-0143&#10;"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
<script id="http-csrf" output="Couldn't find any CSRF vulnerabilities."/>
<script id="http-vuln-cve2014-3704" output="VULNERABLE: Drupal SQLi CVE-2014-3704 and cve-2014-3704"/></port>
</ports>
<hostscript><script id="smb-vuln-ms08-067" output="VULNERABLE: MS08-067 CVE-2008-4250"/>
<script id="smb-vuln-x" output="NOT VULNERABLE"/></hostscript></host></nmaprun>"""

SMB = """\
Anonymous login successful
Disk|public|Public share
Disk|backup$|
IPC|IPC$|IPC Service (Samba)
Printer|hp1|HP LaserJet
"""

WHATWEB_ONE = json.dumps({"target": "http://10.0.0.5:80/", "http_status": 200, "plugins": {
    "Title": {"string": ["Welcome"]}, "Apache": {"version": ["2.4.41"]},
    "HTTPServer": {"string": ["Ubuntu Linux"]}, "PHP": {"version": ["7.4.3"]}}})


class TestListen(unittest.TestCase):
    def test_build(self):
        argv = wired.build_listen({"seconds": 30}, "stealth", None, HW)
        self.assertEqual(argv, [["timeout", "30", "tcpdump", "-i", "eth0", "-nn", "-e", "-l",
                                 "arp or udp port 67 or udp port 68 or udp port 5353"]])
        self.assertEqual(wired.build_listen({}, "standard", None, HW)[0][1], "60")

    def test_parse(self):
        p = wired.parse_listen(LISTEN)
        ips = {h["ip"]: h["mac"] for h in p["hosts"]}
        self.assertEqual(ips["192.168.1.50"], "aa:bb:cc:00:00:50")
        self.assertEqual(ips["192.168.1.1"], "aa:bb:cc:00:00:01")
        self.assertNotIn("0.0.0.0", ips)
        types = {a["type"] for a in p["anomalies"]}
        self.assertEqual(types, {"arp_conflict", "multiple_dhcp_servers"})
        conflict = [a for a in p["anomalies"] if a["type"] == "arp_conflict"][0]
        self.assertEqual(conflict["ip"], "192.168.1.1")
        self.assertEqual(len(p["dhcp_servers"]), 2)
        self.assertIn("printer.local", p["mdns_names"])

    def test_empty_garbage(self):
        for s in ("", "junk\nlines", None):
            p = wired.parse_listen(s)
            self.assertEqual((p["hosts"], p["anomalies"]), ([], []))

    def test_fn(self):
        calls = []
        ctx = SimpleNamespace(runner=lambda a: calls.append(a) or LISTEN, mode="stealth", scope=None, hw=HW)
        task = {"target": {"seconds": 20}}
        r = wired.listen(task, ctx)
        self.assertEqual(calls, wired.build_listen(task["target"], "stealth", None, HW))
        self.assertEqual((r["space"], r["kind"]), ("wired", "hosts"))
        self.assertIsNone(r["data"]["network"])
        self.assertIn("2 anomalies", r["summary"])


class TestVuln(unittest.TestCase):
    def test_build(self):
        self.assertEqual(wired.build_vuln({"ip": "10.0.0.5"}, "standard", None, HW),
                         [["nmap", "-sV", "--script", "vuln", "-T4", "--host-timeout", "800s", "-oX", "-", "10.0.0.5"]])
        self.assertEqual(wired.build_vuln({"ip": "10.0.0.5"}, "stealth", None, HW),
                         [["nmap", "-sS", "-T2", "--top-ports", "100", "--script", "vuln", "--host-timeout", "800s", "-oX", "-", "10.0.0.5"]])

    def test_parse(self):
        f = wired.parse_vuln(VULN_XML)
        self.assertEqual([x["id"] for x in f],
                         ["smb-vuln-ms17-010", "http-vuln-cve2014-3704", "smb-vuln-ms08-067"])
        self.assertEqual(f[0]["port"], 445)
        self.assertEqual(f[0]["cves"], ["CVE-2017-0143"])
        self.assertEqual(f[1]["cves"], ["CVE-2014-3704"])
        self.assertIsNone(f[2]["port"])
        self.assertLessEqual(len(f[0]["output"]), 200)

    def test_empty_garbage(self):
        for s in ("", "not xml", None, "<nmaprun/>"):
            self.assertEqual(wired.parse_vuln(s), [])

    def test_fn(self):
        calls = []
        ctx = SimpleNamespace(runner=lambda a: calls.append(a) or VULN_XML, mode="standard", scope=None, hw=HW)
        task = {"target": {"ip": "10.0.0.5"}}
        r = wired.vuln(task, ctx)
        self.assertEqual(calls, wired.build_vuln(task["target"], "standard", None, HW))
        self.assertEqual(r["kind"], "vulns")
        self.assertEqual(len(r["data"]["findings"]), 3)


class TestSmb(unittest.TestCase):
    def test_build(self):
        self.assertEqual(wired.build_smb({"ip": "10.0.0.5"}, "standard", None, HW),
                         [["smbclient", "-N", "-g", "-L", "//10.0.0.5"]])

    def test_parse(self):
        p = wired.parse_smb(SMB)
        self.assertTrue(p["anonymous"])
        self.assertEqual([s["name"] for s in p["shares"]], ["public", "backup$", "IPC$", "hp1"])
        self.assertEqual(p["shares"][0]["comment"], "Public share")

    def test_denied(self):
        p = wired.parse_smb("session setup failed: NT_STATUS_ACCESS_DENIED\n")
        self.assertEqual((p["shares"], p["anonymous"], p["errors"]), ([], False, ["NT_STATUS_ACCESS_DENIED"]))

    def test_empty_garbage(self):
        for s in ("", "???|||", None):
            self.assertEqual(wired.parse_smb(s)["shares"], [])

    def test_fn(self):
        calls = []
        ctx = SimpleNamespace(runner=lambda a: calls.append(a) or SMB, mode="standard", scope=None, hw=HW)
        task = {"target": {"ip": "10.0.0.5"}}
        r = wired.smb_enum(task, ctx)
        self.assertEqual(calls, wired.build_smb(task["target"], "standard", None, HW))
        self.assertEqual(r["kind"], "smb_shares")
        self.assertEqual(len(r["data"]["shares"]), 4)


class TestWeb(unittest.TestCase):
    def test_build(self):
        std = wired.build_web({"ip": "10.0.0.5"}, "standard", None, HW)
        self.assertEqual(std, [["whatweb", "-q", "--color=never", "--no-errors", "--follow-redirect=never",
                                "-a", "3", "--log-json=/dev/stdout", "http://10.0.0.5:80/"]])
        st = wired.build_web({"ip": "10.0.0.5", "port": 8443}, "stealth", None, HW)
        self.assertEqual(st[0][st[0].index("-a") + 1], "1")
        self.assertEqual(st[0][-1], "https://10.0.0.5:8443/")
        self.assertTrue(wired.build_web({"ip": "1.2.3.4", "port": 443}, "standard", None, HW)[0][-1].startswith("https"))
        self.assertTrue(wired.build_web({"ip": "1.2.3.4", "port": 8080}, "standard", None, HW)[0][-1].startswith("http:"))

    def test_parse_object_array_lines_junk(self):
        for text in (WHATWEB_ONE, "[" + WHATWEB_ONE + "]", "junk\n" + WHATWEB_ONE + "\n"):
            r = wired.parse_web(text)
            self.assertEqual(len(r), 1)
            self.assertEqual(r[0]["status"], 200)
            self.assertEqual(r[0]["title"], "Welcome")
            self.assertIn("Apache 2.4.41", r[0]["technologies"])
            self.assertIn("HTTPServer", r[0]["technologies"])

    def test_empty_garbage(self):
        for s in ("", "garbage", "[", None, "[1,2]"):
            self.assertEqual(wired.parse_web(s), [])

    def test_fn(self):
        calls = []
        ctx = SimpleNamespace(runner=lambda a: calls.append(a) or WHATWEB_ONE, mode="stealth", scope=None, hw=HW)
        task = {"target": {"ip": "10.0.0.5"}}
        r = wired.web_scan(task, ctx)
        self.assertEqual(calls, wired.build_web(task["target"], "stealth", None, HW))
        self.assertEqual(r["kind"], "web")
        self.assertEqual(r["data"]["title"], "Welcome")
        r2 = wired.web_scan(task, SimpleNamespace(runner=lambda a: "", mode="standard", scope=None, hw=HW))
        self.assertEqual(r2["data"]["technologies"], [])


if __name__ == "__main__":
    unittest.main()
