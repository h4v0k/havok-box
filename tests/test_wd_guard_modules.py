import json
import os
import tempfile
import unittest

from havokbox.wardrive import alpr, notify, tpms


def jl(*recs):
    return "\n".join(json.dumps(r) for r in recs) + "\nnot json\n"


def t(model="Toyota", id="AB12", **kw):
    r = {"type": "TPMS", "model": model, "id": id, "pressure_kPa": 220, "temperature_C": 20,
         "rssi": -20.0}
    r.update(kw)
    return r


class TpmsTests(unittest.TestCase):
    def test_argv(self):
        a = tpms.window_argv("315M")
        self.assertEqual(a[0], "rtl_433")
        self.assertIn("315M", a)
        self.assertEqual(a[a.index("-T") + 1], "50")

    def test_parse_basic_and_drops(self):
        out = tpms.parse_window(jl(
            t(rssi=-30), t(rssi=-20), {"model": "Acurite", "id": 1, "type": "x"},
            {"model": "Acurite", "id": 1}, {"model": "Acurite", "id": 1},
            t(id="SOLO")))
        self.assertEqual(out, [{"model": "Toyota", "id": "ab12", "rssi": -20.0}])
        self.assertNotIn("pressure_kPa", out[0])

    def test_checksum_rule(self):
        unk = [t(model="Mystery", id="1"), t(model="Mystery", id="1")]
        self.assertEqual(tpms.parse_window(jl(*unk)), [])
        ok = [t(model="Mystery", id="1", mic="CRC")] * 2
        self.assertEqual(len(tpms.parse_window(jl(*ok))), 1)
        bad = [t(model="Mystery", id="1", mic="PARITY")] * 2
        self.assertEqual(tpms.parse_window(jl(*bad)), [])

    def test_freq_alternation(self):
        self.assertEqual([tpms.next_freq(i) for i in range(4)],
                         ["315M", "433.92M", "315M", "433.92M"])


BB = (27.55, -82.85, 28.45, -82.05)


def node(i, lat=28.0, lon=-82.5, **tags):
    return {"type": "node", "id": i, "lat": lat, "lon": lon, "tags": tags}


class AlprDataTests(unittest.TestCase):
    def test_query(self):
        self.assertEqual(alpr.query((1, 2, 3, 4)),
                         '[out:json][timeout:60];node["surveillance:type"="ALPR"](1,2,3,4);out body;')

    def test_fetch(self):
        seen = {}

        def tr(url, data, timeout):
            seen.update(url=url, data=data)
            return 200, b"{}"
        self.assertEqual(alpr.fetch(BB, tr), b"{}")
        self.assertEqual(seen["url"], alpr.OVERPASS_URL)
        with self.assertRaises(Exception):
            alpr.fetch(BB, lambda *a: (302, b""))
        with self.assertRaises(Exception):
            alpr.fetch(BB, lambda *a: (200, b"x" * (alpr.MAX_BYTES + 1)))

    def test_validate(self):
        els = [node(1, direction="NE"), node(2, 40.0, -82.5), node(3, lat="x"), "junk", None,
               node(4, **{"camera:direction": "90"}), node(5, direction="sideways"),
               node(6, direction="400"), node("7"), node(8, direction="270"),
               {"id": 9, "lat": 28.1, "lon": -82.4}]
        raw = json.dumps({"elements": els}).encode()
        out = {c["id"]: c for c in alpr.validate(raw, BB)}
        self.assertEqual(sorted(out), ["1", "4", "5", "6", "8", "9"])
        self.assertEqual(out["1"]["dir"], 45.0)
        self.assertEqual(out["4"]["dir"], 90.0)
        self.assertIsNone(out["5"]["dir"])
        self.assertIsNone(out["6"]["dir"])
        self.assertEqual(out["8"]["dir"], 270.0)
        self.assertEqual(alpr.validate(b"garbage", BB), [])
        self.assertEqual(alpr.validate(b"[1]", BB), [])

    def test_cap(self):
        raw = json.dumps({"elements": [node(i) for i in range(50)]}).encode()
        self.assertEqual(len(alpr.validate(raw, BB, cap=10)), 10)

    def test_save_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "alpr.json")
            self.assertEqual(alpr.load(p), [])
            cams = [{"id": "1", "lat": 28.0, "lon": -82.5, "dir": None}]
            alpr.save_atomic(p, cams)
            self.assertEqual(alpr.load(p), cams)
            self.assertFalse(os.path.exists(p + ".tmp"))
            with open(p, "w") as f:
                f.write("{corrupt")
            self.assertEqual(alpr.load(p), [])


def cam(i, lat, lon, d=None):
    return {"id": i, "lat": lat, "lon": lon, "dir": d}


LAT = 28.0
LON = -82.5
M = 1 / 111320.0  # degrees lat per metre


class IndexGeoTests(unittest.TestCase):
    def test_near(self):
        cams = [cam("a", LAT + 100 * M, LON), cam("b", LAT + 2500 * M, LON), cam("c", LAT, LON + 0.5)]
        idx = alpr.Index(cams)
        r = idx.near(LAT, LON, 300)
        self.assertEqual([c["id"] for c, _ in r], ["a"])
        self.assertAlmostEqual(r[0][1], 100, delta=1)
        self.assertEqual(len(idx.near(LAT, LON, 3000)), 2)

    def test_angles(self):
        self.assertAlmostEqual(alpr.bearing_deg(LAT, LON, LAT + 0.01, LON), 0, delta=0.1)
        self.assertAlmostEqual(alpr.bearing_deg(LAT, LON, LAT, LON + 0.01), 90, delta=0.1)
        self.assertEqual(alpr.angle_diff(350, 10), 20)
        self.assertEqual(alpr.angle_diff(0, 180), 180)


class WarnerTests(unittest.TestCase):
    """A warning needs two fixes with the distance shrinking (resolution #13), so each 'warns'
    case first primes the warner with a fix 10 m further back."""
    def w(self, cams, prime=True, **kw):
        w = alpr.Warner(alpr.Index(cams), **kw)
        if prime:
            w.update(-1, LAT - 10 * M, LON, 15, 0, [])
            w.passes = 0
        return w

    def test_first_sight_does_not_warn(self):
        w = self.w([cam("a", LAT + 200 * M, LON)], prime=False)
        self.assertIsNone(w.update(0, LAT, LON, 15, 0, []))
        self.assertIsNotNone(w.update(1, LAT + 10 * M, LON, 15, 0, []))

    def test_ahead_warns_behind_not(self):
        ahead = self.w([cam("a", LAT + 200 * M, LON)])
        r = ahead.update(0, LAT, LON, 15, 0, [])
        self.assertEqual(r["id"], "a")
        self.assertAlmostEqual(r["dist_m"], 200, delta=1)
        self.assertEqual(ahead.passes, 1)
        behind = self.w([cam("a", LAT - 200 * M, LON)])
        self.assertIsNone(behind.update(0, LAT, LON, 15, 0, []))
        self.assertEqual(behind.passes, 0)

    def test_outside_cone(self):
        w = self.w([cam("a", LAT + 100 * M, LON + 200 * M / 0.883)])
        self.assertIsNone(w.update(0, LAT, LON, 15, 0, []))

    def test_opening_no_warn(self):
        w = self.w([cam("a", LAT + 200 * M, LON)])
        self.assertIsNotNone(w.update(0, LAT, LON, 15, 0, []))
        w2 = self.w([cam("a", LAT + 200 * M, LON)], prime=False, repeat_s=0)
        w2.update(0, LAT, LON, 15, 0, [])
        # moving laterally-away while still "ahead" cone: distance grows
        self.assertIsNone(w2.update(1, LAT - 20 * M, LON, 15, 0, []))

    def test_repeat_suppression(self):
        w = self.w([cam("a", LAT + 250 * M, LON)])
        self.assertIsNotNone(w.update(0, LAT, LON, 15, 0, []))
        self.assertIsNone(w.update(10, LAT + 50 * M, LON, 15, 0, []))
        self.assertIsNotNone(w.update(700, LAT + 100 * M, LON, 15, 0, []))
        self.assertEqual(w.passes, 2)

    def test_low_speed_uses_bearing(self):
        w = self.w([cam("a", LAT + 200 * M, LON)], prime=False)
        pts = [(LAT - 80 * M, LON), (LAT - 30 * M, LON)]
        w.update(-1, LAT - 10 * M, LON, 2, 180, pts)
        self.assertIsNotNone(w.update(0, LAT, LON, 2, 180, pts))  # track ignored at low speed
        w2 = self.w([cam("a", LAT + 200 * M, LON)])
        self.assertIsNone(w2.update(0, LAT, LON, 2, 0, [(LAT - 10 * M, LON)]))  # not enough movement
        self.assertIsNone(w2.update(1, LAT, LON, 2, 0, None))

    def test_camera_facing(self):
        away = self.w([cam("a", LAT + 200 * M, LON, d=0)])   # faces north, away from car (south)
        self.assertIsNone(away.update(0, LAT, LON, 15, 0, []))
        toward = self.w([cam("a", LAT + 200 * M, LON, d=180)])
        self.assertIsNotNone(toward.update(0, LAT, LON, 15, 0, []))


URL = "https://discord.com/api/webhooks/123/SECRETTOKEN"


class Clock:
    def __init__(self, t=1700000000.0):
        self.t = t

    def __call__(self):
        return self.t


class Rec:
    def __init__(self, *resp):
        self.calls, self.resp = [], list(resp)

    def __call__(self, url, data, timeout):
        self.calls.append((url, json.loads(data)))
        r = self.resp.pop(0) if self.resp else (204, b"")
        if isinstance(r, Exception):
            raise r
        return r


class DiscordTests(unittest.TestCase):
    def mk(self, *resp, **kw):
        self.clock, self.tr = Clock(), Rec(*resp)
        return notify.Discord(URL, transport=self.tr, clock=self.clock, **kw)

    def test_bad_url(self):
        for u in (None, "", "http://discord.com/api/webhooks/1/x", "https://evil.com/api/webhooks/1/x"):
            d = notify.Discord(u, transport=Rec())
            self.assertFalse(d.enabled)
            self.assertFalse(d.send("k", "Car moved", "high", "x", 0))
            self.assertEqual(d.flush(), 0)

    def test_payload_and_no_map(self):
        d = self.mk()
        self.assertTrue(d.send("k", "Car moved", "high", "moved 90 m", self.clock.t, 28.0, -82.5))
        self.assertEqual(d.flush(), 1)
        url, body = self.tr.calls[0]
        self.assertEqual(url, URL)
        self.assertEqual(body["allowed_mentions"], {"parse": []})
        self.assertTrue(body["content"].startswith("[HIGH] Car moved — moved 90 m · "))
        self.assertNotIn("maps", body["content"])
        self.assertLessEqual(len(body["content"]), 300)

    def test_map_opt_in(self):
        d = self.mk(map_links=True)
        d.send("k", "Car moved", "high", "x" * 500, self.clock.t, 28.0, -82.5)
        d.flush()
        c = self.tr.calls[0][1]["content"]
        self.assertIn("maps.google.com/?q=28.00000,-82.50000", c)
        self.assertLessEqual(len(c), 300)

    def test_rate_limits(self):
        d = self.mk()
        self.assertTrue(d.send("k", "a", "high", "x", 0))
        self.assertFalse(d.send("k", "a", "high", "x", 0))
        self.clock.t += 601
        self.assertTrue(d.send("k", "a", "high", "x", 0))
        d = self.mk()
        ok = sum(d.send(f"k{i}", "a", "high", "x", 0) for i in range(30))
        self.assertEqual(ok, 20)
        self.clock.t += 3601
        self.assertTrue(d.send("new", "a", "high", "x", 0))

    def test_429_retry_after(self):
        d = self.mk((429, b'{"retry_after": 5.5}'))
        d.send("k", "a", "high", "x", 0)
        self.assertEqual(d.flush(), 0)
        self.assertEqual(len(self.tr.calls), 1)
        self.clock.t += 3
        self.assertEqual(d.flush(), 0)
        self.assertEqual(len(self.tr.calls), 1)  # still waiting
        self.clock.t += 3
        self.assertEqual(d.flush(), 1)

    def test_network_error_keeps_queue(self):
        d = self.mk(OSError("boom " + URL))
        d.send("k", "a", "high", "x", 0)
        self.assertEqual(d.flush(), 0)
        self.assertEqual(d.flush(), 1)

    def test_queue_age_and_size(self):
        d = self.mk()
        d.send("k", "a", "high", "x", 0)
        self.clock.t += 2 * 3600 + 1
        self.assertEqual(d.flush(), 0)
        self.assertEqual(self.tr.calls, [])
        d = self.mk()
        for i in range(20):
            d.send(f"k{i}", "a", "high", str(i), 0)
        self.assertEqual(d.flush(), 20)

    def test_url_not_exposed(self):
        d = self.mk()
        for s in (repr(d), str(d)):
            self.assertNotIn("SECRET", s)
        with self.assertRaises(TypeError) as cm:
            import pickle
            pickle.dumps(d)
        self.assertNotIn("SECRET", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
