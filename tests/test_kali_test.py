import json
import os
import tempfile
import unittest

from havokbox.helpers import poison
from havokbox.scope import Scope
from havokbox.tools import DEFAULT_HW, ToolCtx, kali_test as kt

HW = dict(DEFAULT_HW)
SCOPE = Scope({"name": "t", "auto_allow": [], "approval_required": []})

FAKE_HASH = "user::DOMAIN:1122334455667788:aabbccddeeff00112233445566778899:1122334455667788aabbccdd"
HYDRA_SUCCESS = (
    "Hydra v9.5 starting\n"
    f"[22][ssh] host: 10.10.0.5   login: admin   password: admin123\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)
HYDRA_FAIL = "Hydra v9.5 starting\n0 of 1 target successfully completed, 0 valid passwords found\n"


class Recorder:
    def __init__(self, out=""):
        self.calls, self.out = [], out

    def __call__(self, argv):
        self.calls.append(argv)
        return self.out


# ---------------------------------------------------------------- creds.default

class CredsDefaultTest(unittest.TestCase):
    def test_build_argv_hydra(self):
        argv, = kt.build_creds_default({"ip": "10.10.0.5", "service": "ssh"}, "stealth", SCOPE, HW)
        self.assertEqual(argv[0], "hydra")
        self.assertIn("-C", argv)
        self.assertIn("-t", argv)
        self.assertEqual(argv[argv.index("-t") + 1], "1")
        self.assertIn("-f", argv)
        self.assertEqual(argv[argv.index("-W") + 1], "1")   # 1 s between connections
        self.assertEqual(argv[-2:], ["10.10.0.5", "ssh"])

    def test_build_uses_bundled_creds_file_default(self):
        argv, = kt.build_creds_default({"ip": "10.10.0.5"}, "stealth", SCOPE, HW)
        creds_path = argv[argv.index("-C") + 1]
        self.assertEqual(creds_path, "/opt/havokbox/default-creds.txt")

    def test_build_honors_hw_override(self):
        hw = dict(HW, default_creds="/opt/havokbox/custom.txt")
        argv, = kt.build_creds_default({"ip": "10.10.0.5"}, "stealth", SCOPE, hw)
        self.assertEqual(argv[argv.index("-C") + 1], "/opt/havokbox/custom.txt")

    def test_parse_creds_found_never_returns_credential(self):
        data = kt.parse_creds(HYDRA_SUCCESS, "10.10.0.5", "ssh")
        self.assertEqual(data, {"found": True, "service": "ssh", "ip": "10.10.0.5", "accounts": ["admin"]})
        self.assertNotIn("admin123", json.dumps(data))   # the account name, never the password

    def test_parse_creds_not_found(self):
        data = kt.parse_creds(HYDRA_FAIL, "10.10.0.5", "ssh")
        self.assertEqual(data["found"], False)

    def test_parse_creds_tolerant_of_junk(self):
        self.assertEqual(kt.parse_creds("", "1.2.3.4", "ftp")["found"], False)
        self.assertEqual(kt.parse_creds("garbage \x00 output", "1.2.3.4", "ftp")["found"], False)

    def test_fn_runs_exactly_build_argv_and_never_returns_credential(self):
        rec = Recorder(HYDRA_SUCCESS)
        ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
        task = {"target": {"ip": "10.10.0.5", "service": "ssh"}}
        expected, = kt.build_creds_default(task["target"], ctx.mode, ctx.scope, ctx.hw)
        result = kt.creds_default(task, ctx)
        self.assertEqual(rec.calls, [expected])
        self.assertEqual(result["kind"], "creds_default")
        self.assertTrue(result["data"]["found"])
        dumped = json.dumps(result)
        self.assertNotIn("admin123", dumped)

    def test_fn_default_service_is_ssh(self):
        rec = Recorder(HYDRA_FAIL)
        ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
        result = kt.creds_default({"target": {"ip": "10.10.0.5"}}, ctx)
        self.assertEqual(result["data"]["service"], "ssh")
        self.assertEqual(rec.calls[0][-1], "ssh")


# ---------------------------------------------------------------- net.poison.responder / mitm6 / rogue_ap (tool layer)

class PoisonToolBuildTest(unittest.TestCase):
    def test_build_responder_wraps_helper_with_iface_and_seconds(self):
        argv, = kt.build_net_poison_responder({"network": "10.20.0.0/24"}, "stealth", SCOPE, HW)
        self.assertEqual(argv[:3], ["python3", "-m", "havokbox.helpers.poison"])
        self.assertIn("responder", argv)
        self.assertEqual(argv[argv.index("--iface") + 1], HW["wired_iface"])
        self.assertEqual(argv[argv.index("--seconds") + 1], "120")

    def test_build_responder_clamps_seconds(self):
        argv, = kt.build_net_poison_responder({"seconds": 999}, "stealth", SCOPE, HW)
        self.assertEqual(argv[argv.index("--seconds") + 1], "300")
        argv, = kt.build_net_poison_responder({"seconds": 1}, "stealth", SCOPE, HW)
        self.assertEqual(argv[argv.index("--seconds") + 1], "30")

    def test_build_mitm6_includes_domain(self):
        argv, = kt.build_net_poison_mitm6({"domain": "lab.local", "seconds": 60}, "stealth", SCOPE, HW)
        self.assertIn("mitm6", argv)
        self.assertEqual(argv[argv.index("--domain") + 1], "lab.local")
        self.assertEqual(argv[argv.index("--seconds") + 1], "60")

    def test_build_rogue_ap_uses_wifi_mon_iface(self):
        argv, = kt.build_wifi_rogue_ap({"ssid": "LAB-NET"}, "stealth", SCOPE, HW)
        self.assertIn("rogue_ap", argv)
        self.assertEqual(argv[argv.index("--iface") + 1], HW["wifi_mon_iface"])
        self.assertEqual(argv[argv.index("--ssid") + 1], "LAB-NET")

    def test_fn_runs_exactly_build_argv(self):
        for builder, fn, target in (
            (kt.build_net_poison_responder, kt.net_poison_responder, {"network": "10.20.0.0/24"}),
            (kt.build_net_poison_mitm6, kt.net_poison_mitm6, {"domain": "lab.local"}),
            (kt.build_wifi_rogue_ap, kt.wifi_rogue_ap, {"ssid": "LAB-NET"}),
        ):
            rec = Recorder(json.dumps({"status": "ok"}))
            ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
            expected, = builder(target, ctx.mode, ctx.scope, ctx.hw)
            fn({"target": target}, ctx)
            self.assertEqual(rec.calls, [expected])

    def test_responder_never_returns_hash_material(self):
        rec = Recorder(json.dumps({"status": "ok", "hashes_captured": 2, "file": "/data/havokbox/work/x/cap.txt"}))
        ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
        result = kt.net_poison_responder({"target": {"network": "10.20.0.0/24"}}, ctx)
        self.assertEqual(result["data"]["hashes_captured"], 2)
        dumped = json.dumps(result)
        self.assertNotIn(FAKE_HASH, dumped)
        self.assertNotIn("DOMAIN:1122334455667788", dumped)

    def test_responder_handles_garbage_helper_output(self):
        rec = Recorder("not json")
        ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
        result = kt.net_poison_responder({"target": {"network": "10.20.0.0/24"}}, ctx)
        self.assertEqual(result["data"]["hashes_captured"], 0)

    def test_mitm6_note_only_no_credentials(self):
        rec = Recorder(json.dumps({"status": "ok", "note": "mitm6 ran for 60 s"}))
        ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
        result = kt.net_poison_mitm6({"target": {"domain": "lab.local", "seconds": 60}}, ctx)
        self.assertEqual(result["data"]["note"], "mitm6 ran for 60 s")
        self.assertEqual(result["kind"], "poison")

    def test_rogue_ap_counts_only(self):
        rec = Recorder(json.dumps({"status": "ok", "ssid": "LAB-NET", "clients_seen": 3}))
        ctx = ToolCtx(runner=rec, mode="stealth", scope=SCOPE, hw=HW)
        result = kt.wifi_rogue_ap({"target": {"ssid": "LAB-NET"}}, ctx)
        self.assertEqual(result["data"], {"ssid": "LAB-NET", "clients_seen": 3})
        self.assertEqual(result["kind"], "rogue_ap")


# ---------------------------------------------------------------- helpers/poison.py argv builders

class PoisonHelperArgvTest(unittest.TestCase):
    def test_responder_argv_no_dash_a_and_timeout_wrapped(self):
        argv = poison.responder_argv("eth0", 120)
        self.assertEqual(argv, ["timeout", "120", "responder", "-I", "eth0"])
        self.assertNotIn("-A", argv)

    def test_mitm6_argv_timeout_wrapped(self):
        argv = poison.mitm6_argv("eth0", "lab.local", 60)
        self.assertEqual(argv, ["timeout", "60", "mitm6", "-i", "eth0", "-d", "lab.local"])

    def test_rogue_ap_argv_timeout_wrapped(self):
        argv = poison.rogue_ap_argv("wlan1mon", "LAB-NET", 90)
        self.assertEqual(argv[:2], ["timeout", "90"])
        self.assertIn("LAB-NET", argv)
        self.assertIn("wlan1mon", argv)


class PoisonHelperValidationTest(unittest.TestCase):
    def test_bad_iface_refused(self):
        with self.assertRaises(poison.HelperError):
            poison.validate_iface("eth0; rm -rf /")
        with self.assertRaises(poison.HelperError):
            poison.validate_iface("")
        with self.assertRaises(poison.HelperError):
            poison.validate_iface("a" * 20)
        self.assertEqual(poison.validate_iface("eth0"), "eth0")
        self.assertEqual(poison.validate_iface("wlan1mon"), "wlan1mon")

    def test_bad_domain_refused(self):
        with self.assertRaises(poison.HelperError):
            poison.validate_domain("not a domain; rm -rf")
        with self.assertRaises(poison.HelperError):
            poison.validate_domain("")
        self.assertEqual(poison.validate_domain("Lab.Local"), "lab.local")

    def test_bad_ssid_name_refused(self):
        with self.assertRaises(poison.HelperError):
            poison.validate_name("not valid; whoami")
        with self.assertRaises(poison.HelperError):
            poison.validate_name("has spaces")
        self.assertEqual(poison.validate_name("LAB-NET"), "LAB-NET")

    def test_seconds_bounds(self):
        with self.assertRaises(poison.HelperError):
            poison.validate_seconds(29)
        with self.assertRaises(poison.HelperError):
            poison.validate_seconds(301)
        with self.assertRaises(poison.HelperError):
            poison.validate_seconds(True)
        self.assertEqual(poison.validate_seconds(30), 30)
        self.assertEqual(poison.validate_seconds(300), 300)


class PoisonHelperDoResponderTest(unittest.TestCase):
    def test_writes_0600_and_prints_count_only(self):
        calls = []

        def runner(argv, timeout):
            calls.append((argv, timeout))
            # simulate responder having written a capture file with real hash material
            session_dirs = [d for d in os.listdir(work) if d.startswith("poison-responder-")]
            cap_path = os.path.join(work, session_dirs[0], "capture.txt")
            os.makedirs(os.path.dirname(cap_path), exist_ok=True)
            with open(cap_path, "w") as f:
                f.write(FAKE_HASH + "\n")
            return "responder output, 1 hashes captured\n"

        with tempfile.TemporaryDirectory() as work:
            result = poison.do_responder("eth0", 60, work, runner=runner)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["hashes_captured"], 1)
            self.assertIsNotNone(result["file"])
            mode = os.stat(result["file"]).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        self.assertEqual(calls[0][1], 65)  # seconds + 5
        dumped = json.dumps(result)
        self.assertNotIn(FAKE_HASH, dumped)

    def test_no_capture_file_count_zero(self):
        with tempfile.TemporaryDirectory() as work:
            result = poison.do_responder("eth0", 60, work, runner=lambda a, t: "nothing happened\n")
            self.assertEqual(result["hashes_captured"], 0)
            self.assertIsNone(result["file"])

    def test_bad_iface_rejected_with_error_status(self):
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaises(poison.HelperError):
                poison.do_responder("eth0 && whoami", 60, work, runner=lambda a, t: "")


class PoisonHelperDoMitm6Test(unittest.TestCase):
    def test_runs_with_timeout_wrapped_argv_and_no_capture_claim(self):
        calls = []

        def runner(argv, timeout):
            calls.append((argv, timeout))
            return ""

        with tempfile.TemporaryDirectory() as work:
            result = poison.do_mitm6("eth0", "lab.local", 90, work, runner=runner)
        self.assertEqual(result, {"status": "ok", "note": "mitm6 ran for 90 s"})
        self.assertEqual(calls[0][0][:2], ["timeout", "90"])

    def test_bad_domain_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaises(poison.HelperError):
                poison.do_mitm6("eth0", "not a domain!", 60, work, runner=lambda a, t: "")


class PoisonHelperDoRogueApTest(unittest.TestCase):
    def test_counts_clients_only(self):
        def runner(argv, timeout):
            return "client connect from aa:bb:cc:dd:ee:ff\nclient connect from 11:22:33:44:55:66\n"

        with tempfile.TemporaryDirectory() as work:
            result = poison.do_rogue_ap("wlan1mon", "LAB-NET", 60, work, runner=runner)
        self.assertEqual(result, {"status": "ok", "ssid": "LAB-NET", "clients_seen": 2})

    def test_bad_ssid_rejected(self):
        # a real SSID with a space/'!' is fine (the gate confines it to wifi.ssids); control chars
        # and over-length are the real guard
        with tempfile.TemporaryDirectory() as work:
            poison.do_rogue_ap("wlan1mon", "My Lab AP!", 60, work, runner=lambda a, t: "")   # ok
            for bad in ("has\x00null", "x" * 33, "line\nbreak"):
                with self.assertRaises(poison.HelperError):
                    poison.do_rogue_ap("wlan1mon", bad, 60, work, runner=lambda a, t: "")


class PoisonHelperCliMainTest(unittest.TestCase):
    def test_main_bad_iface_prints_error_json_and_exits_nonzero(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = poison.main(["responder", "--iface", "bad;iface", "--seconds", "60",
                                 "--work-dir", "/tmp"])
        self.assertEqual(code, 1)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["status"], "error")


if __name__ == "__main__":
    unittest.main()


class CredsRangeAndWebTest(unittest.TestCase):
    NMAP = ('<nmaprun><host><address addr="10.10.0.7" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/></port>'
            '<port protocol="tcp" portid="3306"><state state="open"/></port></ports></host></nmaprun>')
    WEB = ('<nmaprun><host><address addr="10.10.0.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
           '<state state="open"/><script id="http-default-accounts" output="&#xa;  [Cisco router] at /&#xa;'
           '    admin:cisco123&#xa;"/></port></ports></host></nmaprun>')

    def test_range_checks_only_open_services_and_hides_passwords(self):
        class R:
            calls = []
            def __call__(s, argv):
                s.calls.append(argv)
                if argv[0] == "nmap":
                    return CredsRangeAndWebTest.NMAP
                return HYDRA_SUCCESS.replace("10.10.0.5", argv[-2]) if argv[-1] == "ssh" else HYDRA_FAIL
        rec = R()
        lab = Scope({"networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.99/32"]}})
        ctx = ToolCtx(runner=rec, mode="stealth", scope=lab, hw=HW)
        res = kt.creds_default({"target": {"network": "10.10.0.0/24", "service": "common"}}, ctx)
        hydras = [c for c in rec.calls if c[0] == "hydra"]
        self.assertEqual(sorted(c[-1] for c in hydras), ["mysql", "ssh"])
        self.assertIn("--exclude", rec.calls[0])
        # a never-list host that slips into the port-check output is still skipped
        rec.calls.clear()
        CredsRangeAndWebTest.NMAP, saved = self.NMAP.replace("10.10.0.7", "10.10.0.99"), self.NMAP
        try:
            kt.creds_default({"target": {"network": "10.10.0.0/24", "service": "common"}}, ctx)
        finally:
            CredsRangeAndWebTest.NMAP = saved
        self.assertEqual([c for c in rec.calls if c[0] == "hydra"], [])
        rec.calls.clear()
        res = kt.creds_default({"target": {"network": "10.10.0.0/24", "service": "common"}}, ctx)
        self.assertEqual(res["data"]["checked"], 2)
        self.assertEqual(res["data"]["hits"][0]["accounts"], ["admin"])
        self.assertNotIn("admin123", json.dumps(res))

    def test_needs_exactly_one_of_ip_or_network(self):
        with self.assertRaises(ValueError):
            kt.build_creds_default({"service": "ssh"}, "stealth", SCOPE, HW)
        with self.assertRaises(ValueError):
            kt.build_creds_default({"ip": "10.10.0.5", "network": "10.10.0.0/24"}, "stealth", SCOPE, HW)

    def test_web_defaults_report_account_not_password(self):
        hits = kt.parse_web_defaults(self.WEB)
        self.assertEqual(hits, [{"ip": "10.10.0.9", "port": 80, "product": "Cisco router", "path": "/",
                                 "account": "admin"}])
        argv, = kt.build_creds_web_defaults({"network": "10.10.0.0/24"}, "stealth", SCOPE, HW)
        self.assertIn("http-default-accounts", argv)
        for f in ("--max-parallelism", "--max-hostgroup", "--scan-delay"):
            self.assertIn(f, argv)
        with self.assertRaises(ValueError):
            kt.build_creds_web_defaults({"ip": "10.10.0.5", "network": "8.8.8.0/24"}, "stealth", SCOPE, HW)

    def test_gate_allows_in_scope_range_with_approval_only(self):
        from havokbox.scope import Gate
        g = Gate(Scope({"networks": {"include": ["10.10.0.0/24"], "exclude": []}}))
        ok = g.evaluate({"category": "auth.attempt", "target": {"network": "10.10.0.0/24"}})
        self.assertTrue(ok.allowed and ok.needs_approval)
        self.assertFalse(g.evaluate({"category": "auth.attempt", "target": {"network": "8.8.8.0/24"}}).allowed)
        both = {"ip": "10.10.0.5", "network": "8.8.8.0/24"}
        self.assertFalse(g.evaluate({"category": "auth.attempt", "target": both}).allowed)


class CredsRound2Test(unittest.TestCase):
    def test_proposal_refuses_ip_and_network_together(self):
        from havokbox.tasks import TaskError, make_task
        from havokbox.tools.registry import default_registry
        reg = default_registry()
        for tool in ("creds.default", "creds.web_defaults"):
            with self.assertRaises(TaskError):
                make_task(reg, tool, {"ip": "10.10.0.5", "network": "8.8.8.0/24"}, "stealth", "r")

    def test_common_leaves_out_lockout_prone_services(self):
        self.assertNotIn("smb", kt.COMMON)
        self.assertNotIn("rdp", kt.COMMON)

    def test_ipv6_refused(self):
        with self.assertRaises(ValueError):
            kt.build_creds_default({"ip": "fe80::1", "service": "common"}, "stealth", SCOPE, HW)

    def test_many_open_services_are_capped_and_reported(self):
        hosts = "".join(f'<host><address addr="10.10.0.{i}" addrtype="ipv4"/><ports>'
                        f'<port protocol="tcp" portid="22"><state state="open"/></port>'
                        f'<port protocol="tcp" portid="abc"><state state="open"/></port></ports></host>'
                        for i in range(1, 71))
        lab = Scope({"networks": {"include": ["10.10.0.0/24"], "exclude": []}})
        rec = Recorder("")
        rec.out = f"<nmaprun>{hosts}</nmaprun>"
        ctx = ToolCtx(runner=rec, mode="stealth", scope=lab, hw=HW)
        res = kt.creds_default({"target": {"network": "10.10.0.0/24", "service": "common"}}, ctx)
        self.assertEqual(res["data"]["checked"], kt.MAX_CHECKS)
        self.assertEqual(res["data"]["skipped"], 70 - kt.MAX_CHECKS)
        self.assertIn("skipped", res["summary"])

    def test_https_and_port(self):
        argv = kt.hydra_argv("10.10.0.5", "https", HW, port_override=8443)
        self.assertEqual(argv[-4:], ["8443", "10.10.0.5", "https-get", "/"])


class CredsPortTest(unittest.TestCase):
    def test_port_used_for_check_and_login(self):
        scan, hyd = kt.build_creds_default({"network": "10.10.0.0/24", "service": "http", "port": 8080},
                                           "stealth", SCOPE, HW)
        self.assertEqual(scan[scan.index("-p") + 1], "T:8080")
        self.assertIn("-s", hyd)
        argv, = kt.build_creds_default({"ip": "10.10.0.5", "service": "ssh", "port": 2222}, "stealth", SCOPE, HW)
        self.assertEqual(argv[argv.index("-s") + 1], "2222")
