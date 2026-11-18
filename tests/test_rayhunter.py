import json
import unittest

from havokbox import rayhunter as R

MANIFEST = json.dumps({"entries": [{"name": "1700000000"}], "current_entry": {"name": "1700000099"}, "version": "0.2.5"})
META = {"analyzers": [{"name": "IMSI Requested", "description": "d"}, {"name": "Null Cipher", "description": "d"}],
        "report_version": 2}
ROWS = [
    {"packet_timestamp": "2026-01-01T10:00:00+00:00", "skipped_message_reasons": [],
     "events": [None, {"event_type": {"type": "QualitativeWarning", "severity": "High"}, "message": "x" * 300}]},
    {"packet_timestamp": "2026-01-01T10:00:05+00:00",
     "events": [{"event_type": {"type": "Informational", "severity": "Informational"}, "message": "note"}, None]},
    {"packet_timestamp": "2026-01-01T10:00:09+00:00", "events": [None, None]},
]


def nd(meta=META, rows=ROWS):
    return "\n".join(json.dumps(x) for x in [meta] + rows)


def transport(routes, calls=None):
    def t(url, timeout, max_bytes):
        if calls is not None:
            calls.append(url)
        v = routes.get(url.split(":", 2)[2].split("/", 1)[1] and "/" + url.split(":", 2)[2].split("/", 1)[1])
        if isinstance(v, Exception):
            raise v
        if v is None:
            return 404, b""
        if isinstance(v, tuple):
            return v
        return 200, v.encode()
    return t


URL = "http://192.168.1.1:8080"
ROUTES = {"/api/qmdl-manifest": MANIFEST, "/api/analysis-report/1700000099": nd()}


class TestUrl(unittest.TestCase):
    def test_ok(self):
        for u in ("http://192.168.1.1:8080", "http://10.1.2.3:80", "http://172.16.0.9:1"):
            self.assertEqual(R.validate_url(u), u)

    def test_bad(self):
        for u in ("https://192.168.1.1:8080", "http://8.8.8.8:80", "http://192.168.1.1", "http://172.32.0.1:80",
                  "http://192.168.1.1:80/", "http://192.168.1.1:80/x", "http://u:p@192.168.1.1:80",
                  "http://192.168.1.1:80?a=1", "http://orbic.lan:80", "http://169.254.1.1:80", "http://[::1]:80", ""):
            with self.assertRaises(ValueError, msg=u):
                R.validate_url(u)


class TestClient(unittest.TestCase):
    def test_get_allowlist(self):
        calls = []
        c = R.RayhunterClient(URL, transport(ROUTES, calls))
        c.manifest()
        c.report("1700000099")
        self.assertEqual(calls, [URL + "/api/qmdl-manifest", URL + "/api/analysis-report/1700000099"])

    def test_bad_entry(self):
        c = R.RayhunterClient(URL, transport(ROUTES))
        for e in ("../etc", "a/b", "", "x" * 129, "a b", "a?b"):
            with self.assertRaises(R.RayhunterError):
                c.report(e)

    def test_redirect_and_errors(self):
        for st in (301, 302, 307, 404, 500):
            c = R.RayhunterClient(URL, lambda u, t, m, st=st: (st, b""))
            with self.assertRaises(R.RayhunterError):
                c.manifest()

    def test_cap(self):
        c = R.RayhunterClient(URL, lambda u, t, m: (200, b"x" * (m + 1)), max_bytes=100)
        with self.assertRaises(R.RayhunterError):
            c.manifest()

    def test_default_transport_does_not_follow(self):
        import http.server, threading

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        st, body = R.default_transport(f"http://127.0.0.1:{srv.server_port}/x", 2, 100)
        srv.server_close()
        self.assertEqual((st, body), (302, b""))


class TestParse(unittest.TestCase):
    def test_manifest_shapes(self):
        self.assertEqual(R.parse_manifest(MANIFEST), {"current_entry": "1700000099", "version": "0.2.5"})
        self.assertEqual(R.parse_manifest('{"current_entry":"abc"}')["current_entry"], "abc")
        for bad in ("", "[]", "nope", '{"current_entry":null}'):
            self.assertEqual(R.parse_manifest(bad)["current_entry"], None)

    def test_report(self):
        p = R.parse_report(nd())
        self.assertEqual(p["report_version"], "2")
        self.assertEqual(len(p["rows"]), 2)
        a, b = p["rows"]
        self.assertEqual((a["analyzer"], a["severity"], len(a["message"])), ("Null Cipher", "high", 200))
        self.assertEqual((b["analyzer"], b["severity"]), ("IMSI Requested", "medium"))

    def test_severity_map(self):
        rows = [{"packet_timestamp": "t%d" % i, "events": [{"event_type": {"severity": s}, "message": "m"}]}
                for i, s in enumerate(["High", "Medium", "Low", "Informational", "Weird", None])]
        sev = [r["severity"] for r in R.parse_report(nd(rows=rows))["rows"]]
        self.assertEqual(sev, ["high"] + ["medium"] * 5)

    def test_defensive(self):
        txt = "\n".join(["{}", "garbage", "[1]", '{"events":"no"}', '{"events":[1,"a",{}]}'])
        p = R.parse_report(txt)
        self.assertIsNone(p["report_version"])
        self.assertEqual(len(p["rows"]), 1)
        self.assertEqual(R.parse_report("")["rows"], [])


class TestPoller(unittest.TestCase):
    def poller(self, routes):
        return R.RayhunterPoller(R.RayhunterClient(URL, transport(routes)), clock=lambda: 42.0)

    def test_ok_and_dedupe(self):
        p = self.poller(ROUTES)
        self.assertIn("not been checked", p.status_text())
        r = p.poll()
        self.assertEqual((r["status"], r["version"], r["entry"], len(r["new"])), ("ok", "2", "1700000099", 2))
        self.assertEqual(p.poll()["new"], [])
        self.assertIn("2 warning", p.status_text())
        self.assertNotIn("all clear", p.status_text())

    def test_all_clear_only_when_ok_and_empty(self):
        p = self.poller({**ROUTES, "/api/analysis-report/1700000099": nd(rows=[ROWS[2]])})
        p.poll()
        self.assertIn("all clear", p.status_text())

    def test_new_entry_not_deduped(self):
        routes = dict(ROUTES)
        p = self.poller(routes)
        p.poll()
        routes["/api/qmdl-manifest"] = json.dumps({"current_entry": "1700000200"})
        routes["/api/analysis-report/1700000200"] = nd()
        self.assertEqual(len(p.poll()["new"]), 2)

    def test_unreachable(self):
        p = self.poller({"/api/qmdl-manifest": R.RayhunterError("down")})
        self.assertEqual(p.poll()["status"], "unreachable")
        self.assertNotIn("all clear", p.status_text())
        p = self.poller({})
        self.assertEqual(p.poll()["status"], "unreachable")

    def test_report_fetch_fails(self):
        p = self.poller({"/api/qmdl-manifest": MANIFEST})
        self.assertEqual(p.poll()["status"], "unreachable")

    def test_not_recording(self):
        p = self.poller({"/api/qmdl-manifest": '{"entries": [], "current_entry": null}'})
        r = p.poll()
        self.assertEqual((r["status"], r["new"]), ("not_recording", []))
        self.assertNotIn("all clear", p.status_text())

    def test_unknown_version_still_returns_rows(self):
        meta = dict(META, report_version=99)
        p = self.poller({**ROUTES, "/api/analysis-report/1700000099": nd(meta=meta)})
        r = p.poll()
        self.assertEqual((r["status"], len(r["new"])), ("unknown_version", 2))
        self.assertNotIn("all clear", p.status_text())


if __name__ == "__main__":
    unittest.main()
