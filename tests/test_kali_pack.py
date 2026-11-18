"""Kali pack integration: recipes, inventory, the gated manual-tool path, Test-pack safety."""
import json
import unittest

from havokbox.inventory import Inventory
from havokbox.recipes import load_recipes
from havokbox.scope import KNOWN, Gate, Scope
from havokbox.tasks import make_task
from havokbox.tools.registry import default_registry
from tests.helpers import make

POISON_SCOPE = {
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"],
                 "poison_allowed": ["10.10.99.0/24"]},
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "domains": ["lab.local"], "auto_allow": ["recon.passive", "recon.discovery"],
}


def recipe_api():
    h, store, runner, scope, reg = make()
    h.api.scope = Scope(POISON_SCOPE)
    h.api.orch.scope = h.api.scope
    h.api.orch.gate = Gate(h.api.scope)
    return h, store, runner


class InventoryTest(unittest.TestCase):
    def test_missing_binary_hides_tool(self):
        reg = default_registry()
        inv = Inventory(reg, which=lambda b: "/usr/bin/x" if b in ("nmap", "tshark", "curl") else None)
        self.assertFalse(inv.has("nuclei.scan"))       # nuclei not "installed"
        self.assertTrue(inv.has("cleartext.find"))     # tshark installed
        self.assertIn("nuclei.scan", inv.missing)


class RecipeLoadTest(unittest.TestCase):
    def test_good_recipe_becomes_a_gated_tool(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "recipes.yaml")
        with open(path, "w") as fh:
            fh.write("""
- name: recipe.sslscan
  label: "TLS {ip}:{port}"
  space: wired
  phase: enumerate
  category: recon.active
  params:
    ip: {type: ip, required: true}
    port: {type: int, min: 1, max: 65535, default: 443}
  argv: ["sslscan", "--no-colour", "{ip}:{port}"]
- name: recipe.evil
  category: recon.active
  params: {ip: {type: ip, required: true}, c: {type: str}}
  argv: ["bash", "-c", "{c}"]
""")
        logs = []
        recs = load_recipes(path, KNOWN, log=lambda k, m: logs.append(m))
        self.assertIn("recipe.sslscan", recs)
        self.assertNotIn("recipe.evil", recs)          # shell argv0 + str param dropped
        self.assertTrue(any("evil" in m for m in logs))
        spec = recs["recipe.sslscan"]
        argv = spec.build({"ip": "10.10.0.5"}, "stealth", None, {})[0]
        self.assertEqual(argv, ["timeout", "300", "sslscan", "--no-colour", "10.10.0.5:443"])
        self.assertNotIn("bash", argv)


class ManualToolTest(unittest.TestCase):
    def test_gated_proposal_for_in_scope_target(self):
        h, store, runner = recipe_api()
        r = h.run_tool({"tool": "nuclei.scan", "target": {"ip": "10.10.0.50"}})
        self.assertEqual(r[0], 200)
        self.assertTrue(r[1]["needs_approval"])
        p = [p for p in h.state()[1]["proposals"] if p["tool"] == "nuclei.scan"][0]
        self.assertTrue(p["needs_approval"] and p["runnable"])
        store.close()

    def test_out_of_scope_refused(self):
        h, store, runner = recipe_api()
        self.assertEqual(h.run_tool({"tool": "nuclei.scan", "target": {"ip": "8.8.8.8"}})[0], 403)
        self.assertEqual(h.run_tool({"tool": "nope.tool", "target": {}})[0], 404)
        store.close()

    def test_poison_only_on_isolated_vlan_and_refused_during_wardrive(self):
        h, store, runner = recipe_api()
        self.assertEqual(h.run_tool({"tool": "net.poison.responder", "target": {"network": "10.10.0.0/24"}})[0], 403)
        r = h.run_tool({"tool": "net.poison.responder", "target": {"network": "10.10.99.0/24"}})
        self.assertEqual(r[0], 200)
        # during a drive, the orchestrator refuses any non-passive tool even once approved
        tid = r[1]["task_id"]
        h.approve({"task_id": [p for p in h.state()[1]["proposals"] if p["task_id"] == tid][0]["task_id"],
                   "digest": [p for p in h.state()[1]["proposals"] if p["task_id"] == tid][0]["digest"]})
        h.api.orch.passive_only = True
        self.assertEqual(h.api.run(tid)["status"], "refused")
        store.close()

    def test_rogue_ap_only_own_ssid(self):
        h, store, runner = recipe_api()
        self.assertEqual(h.run_tool({"tool": "wifi.rogue_ap", "target": {"ssid": "LAB-NET"}})[0], 200)
        self.assertEqual(h.run_tool({"tool": "wifi.rogue_ap", "target": {"ssid": "Starbucks"}})[0], 403)
        store.close()


class CaptureStaysOnBoxTest(unittest.TestCase):
    def test_creds_result_never_contains_the_credential(self):
        from havokbox.tools import ToolCtx, kali_test
        hydra_out = "[22][ssh] host: 10.10.0.5   login: admin   password: admin123\n"
        ctx = ToolCtx(runner=lambda a: hydra_out, mode="stealth", scope=None, hw={})
        res = kali_test.creds_default({"target": {"ip": "10.10.0.5", "service": "ssh"}}, ctx)
        blob = json.dumps(res)
        self.assertNotIn("admin123", blob)
        self.assertNotIn("password", blob)
        self.assertTrue(res["data"]["found"])

    def test_session_digest_drops_capture_material(self):
        from havokbox.session_report import session_digest
        h, store, runner = recipe_api()
        store.add_finding("r1", "wired", "creds_default", "default creds: found", {"password": "s3cret", "found": True}, "stealth")
        store.add_finding("r2", "wired", "poison", "poisoning ran", {"hash": "admin::LAB:1122:aad3b", "count": 3}, "stealth")
        blob = json.dumps(session_digest(store))
        self.assertNotIn("s3cret", blob)
        self.assertNotIn("aad3b", blob)
        self.assertNotIn("1122", blob)
        store.close()


if __name__ == "__main__":
    unittest.main()


class RecipeApprovalFixTest(unittest.TestCase):
    """Review finding 1: a recipe's declared category can't buy it an unapproved, unconfined run."""
    def test_recipe_cannot_declare_dangerous_category(self):
        from havokbox.recipes import load_recipes
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "r.yaml")
        with open(path, "w") as fh:
            fh.write("""
- name: recipe.poison
  category: net.poison
  params: {network: {type: cidr, required: true}}
  argv: ["responder", "-I", "eth0"]
- name: recipe.rogue
  category: wifi.rogue_ap
  params: {ssid: {type: ssid, required: true}}
  argv: ["eaphammer", "--essid", "{ssid}"]
""")
        logs = []
        recs = load_recipes(path, KNOWN, log=lambda k, m: logs.append(m))
        self.assertEqual(recs, {})                 # neither dangerous-category recipe loads
        self.assertTrue(any("not allowed in a recipe" in m for m in logs))

    def test_passive_labeled_recipe_still_needs_approval_and_refused_in_wardrive(self):
        import os, tempfile
        from havokbox.tools.registry import default_registry
        from havokbox.recipes import load_recipes
        path = os.path.join(tempfile.mkdtemp(), "r.yaml")
        # a recipe that LABELS itself passive but wraps an active binary
        with open(path, "w") as fh:
            fh.write("""
- name: recipe.sneaky
  category: recon.passive
  params: {}
  argv: ["responder", "-I", "eth0"]
""")
        h, store, runner = recipe_api()
        recs = load_recipes(path, KNOWN, log=store.log)
        self.assertIn("recipe.sneaky", recs)       # passive label is allowed...
        h.api.registry["recipe.sneaky"] = recs["recipe.sneaky"]
        h.api.orch.registry["recipe.sneaky"] = recs["recipe.sneaky"]
        r = h.run_tool({"tool": "recipe.sneaky", "target": {}})
        self.assertEqual(r[0], 200)
        p = [p for p in h.state()[1]["proposals"] if p["tool"] == "recipe.sneaky"][0]
        self.assertTrue(p["needs_approval"])       # ...but it still needs approval
        # and running it without approval is refused
        self.assertEqual(h.api.run(p["task_id"])["status"], "awaiting_approval")
        # and it is refused outright during a drive
        h.api.orch.passive_only = True
        self.assertEqual(h.api.run(p["task_id"])["status"], "refused")
        store.close()

    def test_name_param_rejects_leading_dash(self):
        from havokbox.tools import validate_params
        spec = {"q": {"type": "name"}}
        from havokbox.tools import ToolSpec
        ok, _ = validate_params(ToolSpec(name="t", category="c", params=spec, fn=None), {"q": "-oG"})
        self.assertFalse(ok)
