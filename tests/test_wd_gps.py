import json
import signal
import unittest
from unittest import mock

from havokbox.wardrive import geo, gps


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def tpv(mode=3, lat=27.95, lon=-82.46, time_="2026-11-17T12:00:00.000Z"):
    return json.dumps({"class": "TPV", "mode": mode, "lat": lat, "lon": lon,
                       "time": time_, "speed": 12.5})


def sky(snrs, used=True):
    return json.dumps({"class": "SKY", "satellites": [
        {"PRN": i, "ss": s, "used": used} for i, s in enumerate(snrs)]})


class GeoTests(unittest.TestCase):
    def test_haversine(self):
        self.assertEqual(geo.haversine_m(10, 10, 10, 10), 0)
        d = geo.haversine_m(0, 0, 1, 0)
        self.assertAlmostEqual(d, 111195, delta=100)
        d = geo.haversine_m(51.5007, -0.1246, 48.8584, 2.2945)  # Big Ben -> Eiffel
        self.assertAlmostEqual(d / 1000, 340.9, delta=2)

    def test_cell_id(self):
        a = geo.cell_id(27.9500, -82.4600)
        self.assertEqual(a, geo.cell_id(27.9500, -82.4600))
        self.assertEqual(a, geo.cell_id(27.95001, -82.46001))
        self.assertNotEqual(a, geo.cell_id(27.9500 + 0.003, -82.4600))
        self.assertNotEqual(a, geo.cell_id(27.9500, -82.4600 + 0.004))
        self.assertRegex(a, r"^-?\d+:-?\d+$")

    def test_track_recorder(self):
        r = geo.TrackRecorder()
        self.assertIsNone(r.offer(0, None, None, 3))
        self.assertIsNotNone(r.offer(0, 27.95, -82.46, 3))  # first
        self.assertIsNone(r.offer(5, 27.95001, -82.46, 3))  # near, soon
        self.assertIsNotNone(r.offer(11, 27.95001, -82.46, 3))  # interval
        self.assertIsNotNone(r.offer(12, 27.9505, -82.46, 3))  # >25 m
        self.assertGreater(r.distance_m, 50)

    def test_glitch_ignored(self):
        r = geo.TrackRecorder()
        r.offer(0, 27.95, -82.46, 3)
        before = r.distance_m
        p = r.offer(1, 28.05, -82.46, 3)  # ~11 km in 1 s
        self.assertIsNotNone(p)
        self.assertEqual(r.distance_m, before)

    def test_find_stops(self):
        pts = []
        for i in range(0, 600, 30):  # stop A 10 min
            pts.append({"ts": i, "lat": 27.95 + (i % 3) * 1e-5, "lon": -82.46})
        for k in range(1, 7):  # drive ~3 km north, 30 s steps of ~500 m
            pts.append({"ts": 600 + k * 30, "lat": 27.95 + k * 0.0045, "lon": -82.46})
        t0 = 600 + 7 * 30
        for i in range(0, 600, 30):  # stop B
            pts.append({"ts": t0 + i, "lat": 27.95 + 0.027, "lon": -82.46})
        stops = geo.find_stops(pts)
        self.assertEqual(len(stops), 2)
        self.assertLess(stops[0]["end"], stops[1]["start"])
        self.assertGreater(geo.haversine_m(stops[0]["lat"], stops[0]["lon"],
                                           stops[1]["lat"], stops[1]["lon"]), 2000)
        self.assertEqual(geo.find_stops(pts[:3]), [])


class ParseTests(unittest.TestCase):
    def test_tpv(self):
        p = gps.parse_line(tpv())
        self.assertEqual(p["class"], "TPV")
        self.assertEqual(p["mode"], 3)
        self.assertAlmostEqual(p["ts"], 1794916800.0, delta=1)
        self.assertEqual(p["lat"], 27.95)
        self.assertEqual(p["speed"], 12.5)
        p = gps.parse_line(json.dumps({"class": "TPV", "mode": 1}))
        self.assertIsNone(p["ts"])
        self.assertIsNone(p["lat"])

    def test_sky(self):
        line = json.dumps({"class": "SKY", "satellites": [
            {"ss": 40, "used": True}, {"ss": 30, "used": True}, {"ss": 10, "used": False}]})
        p = gps.parse_line(line)
        self.assertEqual(p["used"], 2)
        self.assertEqual(p["snr_mean"], 35)
        p = gps.parse_line(json.dumps({"class": "SKY", "uSat": 7}))
        self.assertEqual(p["used"], 7)
        self.assertIsNone(p["snr_mean"])

    def test_garbage(self):
        for s in ["", "nope", "{", "[1]", "null", json.dumps({"class": "VERSION"}), None]:
            self.assertIsNone(gps.parse_line(s))


class StateTests(unittest.TestCase):
    def test_degraded(self):
        c = Clock()
        st = gps.GpsState(clock=c)
        st.update(gps.parse_line(tpv()))
        for _ in range(5):
            st.update(gps.parse_line(sky([40] * 8)))
            c.t += 5
        f = st.fix()
        self.assertFalse(f["degraded"])
        self.assertEqual(f["mode"], 3)
        st.update(gps.parse_line(sky([20] * 8)))
        self.assertTrue(st.fix()["degraded"])

    def test_degraded_few_sats_and_no_prior_fix(self):
        c = Clock()
        st = gps.GpsState(clock=c)
        st.update(gps.parse_line(sky([40])))
        self.assertFalse(st.fix()["degraded"])  # never had 3D
        st.update(gps.parse_line(tpv()))
        st.update(gps.parse_line(sky([40, 40])))
        self.assertTrue(st.fix()["degraded"])
        c.t += 120  # 3D fix too old
        self.assertFalse(st.fix()["degraded"])


class FakeProc:
    pid = 4242

    def __init__(self, lines):
        self.stdout = iter(lines)
        self.waited = False

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.waited = True
        return 0


class ReaderTests(unittest.TestCase):
    def test_reader(self):
        proc = FakeProc(["garbage\n", tpv() + "\n", "{bad", sky([35, 35, 35]) + "\n"])
        calls = []

        def popen(argv, **kw):
            calls.append((argv, kw))
            return proc

        st = gps.GpsState()
        rd = gps.GpsReader(st, popen=popen)
        with mock.patch("os.killpg") as kp:
            rd.start()
            rd._thread.join(2)
            self.assertEqual(calls[0][0], ["gpspipe", "-w"])
            self.assertTrue(calls[0][1]["start_new_session"])
            # process "exited": state marked no-fix
            self.assertEqual(st.fix()["mode"], 0)
            rd.stop()
            kp.assert_called_with(4242, signal.SIGTERM)
            self.assertTrue(proc.waited)

    def test_lines_consumed_into_state(self):
        st = gps.GpsState()
        st.update(gps.parse_line(tpv()))
        self.assertEqual(st.fix()["lat"], 27.95)
        rd = gps.GpsReader(st, popen=lambda *a, **k: FakeProc([]))
        rd._run(FakeProc([tpv() + "\n", "xx\n"]))
        self.assertEqual(st.fix()["mode"], 0)


if __name__ == "__main__":
    unittest.main()
