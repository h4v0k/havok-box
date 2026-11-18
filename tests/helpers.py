import json

from havokbox.api import Api
from havokbox.config import BoxConfig
from havokbox.orchestrator import Orchestrator
from havokbox.scope import Scope
from havokbox.server import Handlers, Jobs
from havokbox.store import Store
from havokbox.tools.registry import default_registry

DISCOVERY_XML = '<nmaprun><host><status state="up"/><address addr="10.10.0.50" addrtype="ipv4"/></host></nmaprun>'
SERVICES_XML = ('<nmaprun><host><address addr="10.10.0.50" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
                '</ports></host></nmaprun>')
DEVICES = json.dumps([
    {"type": "AP", "ssid": "LAB-NET", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6},
    {"type": "AP", "ssid": "<img src=x onerror=alert(1)>", "bssid": "11:22:33:44:55:66", "channel": 6},
    {"type": "AP", "ssid": "LAB-NET", "bssid": "11:22:33:44:55:77", "channel": 6},
])
SCOPE = {
    "name": "lab",
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"]},
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "auto_allow": ["recon.passive", "recon.discovery"],
    "approval_required": ["recon.active", "wifi.deauth"],
}


class Recorder:
    def __init__(self):
        self.cmds = []
        self.fail = False

    def __call__(self, cmd):
        if self.fail:
            raise RuntimeError("tool crashed")
        self.cmds.append(cmd)
        if cmd[0] == "curl":
            return DEVICES
        return DISCOVERY_XML if "-sn" in cmd else SERVICES_XML


def make(token="s3cret", **cfg):
    scope = Scope(SCOPE)
    store = Store(":memory:")
    runner = Recorder()
    reg = default_registry()
    api = Api(scope, store, Orchestrator(scope, store, reg, runner))
    conf = BoxConfig(token=token, db_path=":memory:", lan_cidrs=["192.168.4.0/24"], **cfg)
    h = Handlers(api, conf, Jobs(store, start=False))
    return h, store, runner, scope, reg
