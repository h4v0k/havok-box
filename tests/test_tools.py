import unittest

from havokbox.tools import ToolSpec, validate_params
from havokbox.tools.registry import default_registry


def spec(params):
    return ToolSpec(name="t", category="c", params=params, fn=lambda task, ctx: {})


class ValidateParamsTest(unittest.TestCase):
    def test_required_missing(self):
        ok, why = validate_params(spec({"network": {"type": "cidr", "required": True}}), {})
        self.assertFalse(ok)
        self.assertIn("network", why)

    def test_valid_cidr(self):
        ok, _ = validate_params(spec({"network": {"type": "cidr", "required": True}}),
                                {"network": "10.10.0.0/24"})
        self.assertTrue(ok)

    def test_bad_ip(self):
        ok, _ = validate_params(spec({"ip": {"type": "ip", "required": True}}), {"ip": "999.1.1.1"})
        self.assertFalse(ok)

    def test_bad_bssid(self):
        ok, _ = validate_params(spec({"bssid": {"type": "bssid", "required": True}}),
                                {"bssid": "nope"})
        self.assertFalse(ok)

    def test_optional_absent_ok(self):
        ok, _ = validate_params(spec({"ip": {"type": "ip"}}), {})
        self.assertTrue(ok)


class RegistryTest(unittest.TestCase):
    def test_every_tool_binds_a_category(self):
        for name, s in default_registry().items():
            self.assertTrue(s.category, f"{name} has no category")
            self.assertTrue(callable(s.fn))


if __name__ == "__main__":
    unittest.main()
