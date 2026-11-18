import unittest

from havokbox.scope import Scope
from havokbox.tools import ToolCtx, nmap

DISCOVERY_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.10.0.50" addrtype="ipv4"/>
<address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host>
<host><status state="down"/><address addr="10.10.0.99" addrtype="ipv4"/></host>
</nmaprun>"""

SERVICES_XML = """<?xml version="1.0"?><nmaprun>
<host><address addr="10.10.0.50" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
</ports></host></nmaprun>"""


class NmapTest(unittest.TestCase):
    def test_parse_discovery_only_up_hosts(self):
        hosts = nmap.parse_discovery(DISCOVERY_XML)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], "10.10.0.50")
        self.assertEqual(hosts[0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_parse_services_only_open(self):
        svcs = nmap.parse_services(SERVICES_XML)
        self.assertEqual({s["port"] for s in svcs}, {22, 80})

    def test_services_cmd_modes_differ(self):
        self.assertIn("-sS", nmap.build_services_cmd("10.10.0.50", "stealth"))
        self.assertIn("-T1", nmap.build_services_cmd("10.10.0.50", "stealth"))
        self.assertIn("-sV", nmap.build_services_cmd("10.10.0.50", "standard"))

    def test_discovery_cmd_excludes_hosts(self):
        cmd = nmap.build_discovery_cmd("10.10.0.0/24", ["10.10.0.1/32"])
        self.assertIn("--exclude", cmd)
        self.assertIn("10.10.0.1", cmd)

    def test_discovery_tool_summary(self):
        scope = Scope({"name": "t", "networks": {"include": ["10.10.0.0/24"]},
                       "auto_allow": [], "approval_required": []})
        ctx = ToolCtx(runner=lambda cmd: DISCOVERY_XML, mode="standard", scope=scope)
        res = nmap.discovery({"target": {"network": "10.10.0.0/24"}}, ctx)
        self.assertEqual(res["space"], "wired")
        self.assertIn("1 host", res["summary"])


if __name__ == "__main__":
    unittest.main()
