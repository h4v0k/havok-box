import struct
import unittest

from havokbox.wardrive.remoteid import DroneTracker, parse_service_data


def wrap(msg: bytes, prefix=True) -> str:
    assert len(msg) == 25
    return ("faff" if prefix else "") + "0d" + "07" + msg.hex()


def basic(uid=b"1581F4XYZ"):
    return wrap(bytes([0x02, 0x12]) + uid.ljust(20, b"\0") + b"\0\0\0")


def loc(lat=27.9, lon=-82.4, st=0x00, d=90, sp=40, vs=-6, ga=1200):
    m = bytes([0x12, st, d, sp, vs & 0xFF]) + struct.pack("<ii", int(lat * 1e7), int(lon * 1e7))
    m += struct.pack("<HHH", 0, ga, 0) + bytes(6)
    return wrap(m)


def system(lat=27.95, lon=-82.45):
    return wrap(bytes([0x42, 0]) + struct.pack("<ii", int(lat * 1e7), int(lon * 1e7)) + bytes(15))


class ParseTest(unittest.TestCase):
    def test_basic(self):
        r = parse_service_data(basic())
        self.assertEqual((r["type"], r["id_type"], r["ua_type"], r["ua_id"], r["version"]),
                         ("basic_id", 1, 2, "1581F4XYZ", 2))

    def test_location(self):
        r = parse_service_data(loc())
        self.assertAlmostEqual(r["lat"], 27.9, 6)
        self.assertAlmostEqual(r["lon"], -82.4, 6)
        self.assertEqual((r["direction"], r["speed"], r["vspeed"], r["alt"]), (90, 10.0, -3.0, -400.0))

    def test_location_flags(self):
        r = parse_service_data(loc(st=0x03, d=90, sp=40))
        self.assertEqual(r["direction"], 270)
        self.assertEqual(r["speed"], 40 * 0.75 + 63.75)

    def test_invalid(self):
        self.assertIsNone(parse_service_data(loc(lat=0, lon=0)))
        self.assertIsNone(parse_service_data(loc(ga=0))["alt"])

    def test_system_and_operator(self):
        r = parse_service_data(system())
        self.assertAlmostEqual(r["op_lat"], 27.95, 6)
        self.assertAlmostEqual(r["op_lon"], -82.45, 6)
        o = parse_service_data(wrap(bytes([0x52, 0]) + b"OP-123".ljust(20, b"\0") + b"\0\0\0"))
        self.assertEqual(o["operator_id"], "OP-123")

    def test_pack_and_junk(self):
        self.assertIsNone(parse_service_data(wrap(bytes([0xF2]) + bytes(24))))
        self.assertIsNone(parse_service_data(wrap(bytes([0x32]) + bytes(24))))
        for bad in ("", "zz", "faff0d07", "faff0e07" + "00" * 25, "abc"):
            self.assertIsNone(parse_service_data(bad))

    def test_prefix_optional(self):
        a = parse_service_data(basic())
        b = parse_service_data(wrap(bytes([0x02, 0x12]) + b"1581F4XYZ".ljust(20, b"\0") + b"\0\0\0", prefix=False))
        self.assertEqual(a, b)


class TrackerTest(unittest.TestCase):
    def feed(self, t, ts, addr="aa:bb:cc:dd:ee:ff", lat=27.9):
        msgs = [parse_service_data(x) for x in (basic(), loc(lat=lat), system())]
        t.update(addr, msgs, ts)

    def test_merge_and_operator_ttl(self):
        t = DroneTracker(ttl_s=600)
        self.feed(t, 1000)
        d = t.drones(1100)[0]
        self.assertEqual(d["ua_id"], "1581F4XYZ")
        self.assertAlmostEqual(d["op_lat"], 27.95, 6)
        # drone keeps beaconing location only; operator location ages out
        t.update("aa:bb:cc:dd:ee:ff", [parse_service_data(loc())], 1500)
        d = t.drones(1700)[0]
        self.assertIsNone(d["op_lat"])
        self.assertIsNone(d["op_lon"])
        self.assertEqual(d["ua_id"], "1581F4XYZ")
        self.assertEqual(t.drones(5000), [])

    def test_near_for(self):
        t = DroneTracker()
        self.feed(t, 100)
        self.assertEqual(t.near_for("aa:bb:cc:dd:ee:ff", 27.9, -82.4, 100), 0.0)
        self.assertEqual(t.near_for("aa:bb:cc:dd:ee:ff", 27.9, -82.4, 160), 60.0)
        self.assertEqual(t.near_for("aa:bb:cc:dd:ee:ff", 28.5, -82.4, 170), 0.0)   # far -> reset
        self.assertEqual(t.near_for("aa:bb:cc:dd:ee:ff", 27.9, -82.4, 200), 0.0)   # restarts
        self.assertEqual(t.near_for("nope", 27.9, -82.4, 200), 0.0)


if __name__ == "__main__":
    unittest.main()
