import unittest

from havokbox.scope import Scope, Gate

SCOPE = {
    "name": "t",
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"]},
    "wifi": {"bssids": ["AA:BB:CC:DD:EE:FF"]},
    "rf": {"subghz_ids": ["fob1"], "tx_bands": [{"min_mhz": 433.05, "max_mhz": 434.79}]},
    "auto_allow": ["recon.passive"],
    "approval_required": ["recon.active", "wifi.deauth", "rf.transmit", "exploit.tool"],
}


class GateTest(unittest.TestCase):
    def setUp(self):
        self.g = Gate(Scope(SCOPE))

    def test_passive_auto_allowed(self):
        d = self.g.evaluate({"category": "recon.passive"})
        self.assertTrue(d.allowed)
        self.assertFalse(d.needs_approval)

    def test_passive_refused_when_not_allowed(self):
        g = Gate(Scope({**SCOPE, "auto_allow": []}))
        self.assertFalse(g.evaluate({"category": "recon.passive"}).allowed)

    def test_in_scope_active_needs_approval(self):
        d = self.g.evaluate({"category": "recon.active", "target": {"ip": "10.10.0.50"}})
        self.assertTrue(d.allowed)
        self.assertTrue(d.needs_approval)

    def test_excluded_ip_refused(self):
        self.assertFalse(
            self.g.evaluate({"category": "recon.active", "target": {"ip": "10.10.0.1"}}).allowed
        )

    def test_out_of_scope_ip_refused(self):
        self.assertFalse(
            self.g.evaluate({"category": "exploit.tool", "target": {"ip": "192.168.1.5"}}).allowed
        )

    def test_bssid_case_insensitive_match(self):
        d = self.g.evaluate({"category": "wifi.deauth", "target": {"bssid": "aa:bb:cc:dd:ee:ff"}})
        self.assertTrue(d.allowed and d.needs_approval)

    def test_bssid_not_in_scope_refused(self):
        self.assertFalse(
            self.g.evaluate({"category": "wifi.deauth", "target": {"bssid": "11:22:33:44:55:66"}}).allowed
        )

    def test_missing_bssid_fail_closed(self):
        self.assertFalse(self.g.evaluate({"category": "wifi.deauth", "target": {}}).allowed)

    def test_rf_tx_in_band(self):
        d = self.g.evaluate({"category": "rf.transmit", "target": {"id": "fob1", "freq_mhz": 433.9}})
        self.assertTrue(d.allowed and d.needs_approval)

    def test_rf_tx_out_of_band_refused(self):
        self.assertFalse(
            self.g.evaluate({"category": "rf.transmit", "target": {"id": "fob1", "freq_mhz": 915.0}}).allowed
        )

    def test_rf_tx_unknown_device_refused(self):
        self.assertFalse(
            self.g.evaluate({"category": "rf.transmit", "target": {"id": "nope", "freq_mhz": 433.9}}).allowed
        )

    def test_rf_tx_missing_bands_fail_closed(self):
        g = Gate(Scope({**SCOPE, "rf": {"subghz_ids": ["fob1"]}}))  # no tx_bands
        self.assertFalse(
            g.evaluate({"category": "rf.transmit", "target": {"id": "fob1", "freq_mhz": 433.9}}).allowed
        )

    def test_unknown_category_refused(self):
        self.assertFalse(self.g.evaluate({"category": "wifi.magic"}).allowed)


if __name__ == "__main__":
    unittest.main()
