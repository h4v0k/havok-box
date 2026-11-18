import unittest

from havokbox import baseline as B

GW = "192.168.1.1"
M1, M2, M3, M4 = ("aa:00:00:00:00:0%d" % i for i in (1, 2, 3, 4))


def F(space, kind, data, created=1.0):
    return {"space": space, "kind": kind, "data": data, "created": created}


def hosts(*pairs, created=1.0):
    return F("wired", "hosts", {"hosts": [{"ip": ip, "mac": mac} for ip, mac in pairs]}, created)


def brow(space, key, **attrs):
    return {"space": space, "key": key, "label": key, "attrs": attrs, "rowid": 1}


BASE_HOSTS = [brow("wired", M1, ip=GW), brow("wired", M2, ip="192.168.1.20")]


def kinds(items):
    return sorted(i["kind"] for i in items)


class TestInventory(unittest.TestCase):
    def test_hosts_and_weak(self):
        inv = B.inventory([hosts(("1.1.1.1", "AA:00:00:00:00:01"), ("1.1.1.2", None))])
        self.assertEqual(inv["wired"][M1]["ip"], "1.1.1.1")
        self.assertTrue(inv["wired"]["ip:1.1.1.2"]["weak"])

    def test_latest_finding_wins(self):
        inv = B.inventory([hosts(("1.1.1.1", M1), created=1), hosts(("1.1.1.2", M2), created=2)])
        self.assertEqual(list(inv["wired"]), [M2])

    def test_ble_random_counted(self):
        f = F("ble", "ble_devices", {"devices": [{"addr": "AA:BB:CC:00:00:01", "random": False},
                                                  {"addr": "11:22:33:44:55:66", "random": True},
                                                  {"addr": "11:22:33:44:55:67"}]})
        inv = B.inventory([f])
        self.assertEqual(len(inv["ble"]), 2)
        self.assertEqual(inv["_meta"]["ble_random_count"], 1)

    def test_iot_subghz_ap(self):
        inv = B.inventory([
            F("sdr", "iot_devices", {"devices": [{"model": "Acurite", "id": 5, "channel": "A"}]}),
            F("subghz", "subghz", {"received": [{"protocol": "Princeton", "key": "0x1"}, {"protocol": "x"}]}),
            F("wifi", "wifi_survey", {"aps": [{"bssid": "AA:00:00:00:00:09", "ssid": "Lab", "channel": 6}]})])
        self.assertIn("Acurite:5:A", inv["sdr"])
        self.assertEqual(list(inv["subghz"]), ["Princeton:0x1"])
        self.assertEqual(inv["wifi"]["aa:00:00:00:00:09"]["channel"], 6)


class TestDrift(unittest.TestCase):
    def d(self, findings, base, **kw):
        return B.drift(B.inventory(findings), base, **kw)

    def test_new_host(self):
        r = self.d([hosts((GW, M1), ("192.168.1.99", M3))], BASE_HOSTS, gateway_ip=GW)
        self.assertEqual([(i["kind"], i["severity"], i["key"]) for i in r if i["kind"] != "gone"],
                         [("new_host", "medium", M3)])

    def test_dhcp_reassignment_is_info_only(self):
        # M2 moved IPs; M3 took M2's old address. Neither is the gateway/pinned.
        r = self.d([hosts((GW, M1), ("192.168.1.30", M2), ("192.168.1.20", M3))], BASE_HOSTS, gateway_ip=GW)
        self.assertNotIn("arp_spoof", kinds(r))
        self.assertIn("ip_reassigned", kinds(r))
        self.assertTrue(all(i["severity"] != "high" for i in r))

    def test_arp_spoof_gateway_mac_changed(self):
        r = self.d([hosts((GW, M3), ("192.168.1.20", M2))], BASE_HOSTS, gateway_ip=GW)
        sp = [i for i in r if i["kind"] == "arp_spoof"]
        self.assertEqual(len(sp), 1)
        self.assertEqual(sp[0]["severity"], "high")

    def test_arp_spoof_pinned_static(self):
        r = self.d([hosts((GW, M1), ("192.168.1.20", M3))], BASE_HOSTS, gateway_ip=GW,
                   pinned_static=("192.168.1.20",))
        self.assertIn("arp_spoof", kinds(r))

    def test_arp_spoof_one_mac_two_ips(self):
        r = self.d([hosts((GW, M3), ("192.168.1.20", M3))], BASE_HOSTS, gateway_ip=GW)
        self.assertEqual(kinds([i for i in r if i["kind"] == "arp_spoof"]), ["arp_spoof"])

    def test_weak_host_flagged(self):
        r = self.d([hosts(("192.168.1.50", None))], [])
        self.assertEqual(r[0]["kind"], "new_host")
        self.assertIn("weak", r[0]["detail"])

    def test_new_ap_and_evil_twin_and_channel(self):
        base = [brow("wifi", "aa:00:00:00:00:01", ssid="Lab", channel=6, kind="ap")]
        f = F("wifi", "wifi_survey", {"aps": [
            {"bssid": "aa:00:00:00:00:01", "ssid": "Lab", "channel": 11},
            {"bssid": "aa:00:00:00:00:02", "ssid": "Lab", "channel": 6},
            {"bssid": "aa:00:00:00:00:03", "ssid": "Cafe", "channel": 1}]})
        r = {i["kind"]: i for i in self.d([f], base)}
        self.assertEqual(r["ap_channel_change"]["severity"], "info")
        self.assertEqual(r["evil_twin_indicator"]["severity"], "high")
        self.assertEqual(r["evil_twin_indicator"]["key"], "aa:00:00:00:00:02")
        self.assertEqual(r["new_ap"]["severity"], "medium")
        self.assertEqual(r["new_ap"]["key"], "aa:00:00:00:00:03")

    def test_ble_random_never_new_ble(self):
        f = F("ble", "ble_devices", {"devices": [{"addr": "11:22:33:44:55:66", "random": True},
                                                  {"addr": "aa:bb:cc:dd:ee:ff", "random": False}]})
        r = self.d([f], [])
        self.assertEqual([i["key"] for i in r if i["kind"] == "new_ble"], ["aa:bb:cc:dd:ee:ff"])
        self.assertEqual(r[0]["severity"], "low")

    def test_new_iot_and_subghz(self):
        r = self.d([F("sdr", "iot_devices", {"devices": [{"model": "T", "id": 1, "channel": 2}]}),
                    F("subghz", "subghz", {"received": [{"protocol": "P", "key": "K"}]})], [])
        self.assertEqual(kinds(r), ["new_iot", "new_iot"])

    def test_gone_only_for_scanned_space(self):
        base = BASE_HOSTS + [brow("wifi", "aa:00:00:00:00:01", ssid="Lab")]
        r = self.d([hosts((GW, M1))], base, gateway_ip=GW)
        gone = [i for i in r if i["kind"] == "gone"]
        self.assertEqual([i["key"] for i in gone], [M2])
        self.assertEqual(gone[0]["severity"], "info")

    def test_spectrum_does_not_mark_sdr_scanned(self):
        r = self.d([F("sdr", "spectrum", {"top": []})], [brow("sdr", "T:1:2")])
        self.assertEqual(r, [])


class TestCache(unittest.TestCase):
    def test_hit_and_miss(self):
        c = B.DriftCache()
        fs = [hosts((GW, M1), created=5.0)]
        a = c.get(fs, BASE_HOSTS, gateway_ip=GW)
        b = c.get(fs, BASE_HOSTS, gateway_ip=GW)
        self.assertIs(a, b)
        self.assertEqual((c.hits, c.misses), (1, 1))
        c.get(fs + [hosts((GW, M1), ("9.9.9.9", M4), created=6.0)], BASE_HOSTS, gateway_ip=GW)
        self.assertEqual(c.misses, 2)
        rows = BASE_HOSTS + [dict(brow("wired", M4, ip="9.9.9.9"), rowid=7)]
        c.get(fs + [hosts((GW, M1), ("9.9.9.9", M4), created=6.0)], rows, gateway_ip=GW)
        self.assertEqual(c.misses, 3)


if __name__ == "__main__":
    unittest.main()
