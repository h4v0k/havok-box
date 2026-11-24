import json
import os

from havokbox import hwcheck, mesh
from havokbox.helpers import meshbridge as mb
from havokbox.helpers import radio as hr
from havokbox.tools import mesh as mesh_tool
from havokbox.tools import registry

OWNER = "!a1b2c3d4"


class FakeIface:
    def __init__(self):
        self.sent = []
        self.nodes = {
            "!11112222": {"user": {"id": "!11112222", "longName": "Trail Node", "shortName": "TRL"},
                          "lastHeard": 1000 - 120, "snr": 6.5, "hopsAway": 1,
                          "position": {"latitude": 27.95123, "longitude": -82.45678}},
            "!deadbeef": {"user": {"id": "!deadbeef", "longName": "havok-box"}, "lastHeard": 1000},
        }

    def sendText(self, text, destinationId=None, wantAck=False):
        self.sent.append((text, destinationId))

    def getMyNodeInfo(self):
        return {"user": {"id": "!deadbeef"}}


def clock():
    return 1000.0


def test_outbox_rate_limits_and_bridge_delivers_to_owner_only(tmp_path):
    box = mesh.MeshOutbox(str(tmp_path), clock=clock)
    assert box.send("tpms:x", "tpms_follow", "high", "same tire sensor for 20 min", 1000, 27.9, -82.4)
    assert not box.send("tpms:x", "tpms_follow", "high", "again", 1000)     # same key within 10 min
    iface = FakeIface()
    b = mb.Bridge(iface, OWNER, str(tmp_path), str(tmp_path / "scans"), clock=clock, replier=lambda c: "r")
    assert b.send_outbox() == 1 and iface.sent[0][1] == OWNER
    assert iface.sent[0][0].startswith("[HIGH] tpms_follow — same tire sensor") and "@27.9000" in iface.sent[0][0]
    assert os.listdir(tmp_path / "mesh" / "outbox") == []
    assert mb.Bridge(FakeIface(), None, str(tmp_path), "", clock=clock).send_outbox() == 0   # no owner, no send


def test_stale_alerts_are_dropped(tmp_path):
    box = mesh.MeshOutbox(str(tmp_path), clock=lambda: 0.0)
    box.send("k", None, "info", "old", 0)
    assert mb.pending(str(tmp_path / "mesh" / "outbox"), now=3 * 3600) == []


def test_replies_only_owner_known_commands_rate_limited(tmp_path):
    t = [1000.0]
    iface = FakeIface()
    b = mb.Bridge(iface, OWNER, str(tmp_path), "", clock=lambda: t[0], replier=lambda c: f"reply:{c}")
    b.on_text({"fromId": "!99999999", "decoded": {"text": "status"}})          # stranger: ignored
    b.on_text({"fromId": OWNER, "decoded": {"text": "rm -rf /"}})              # not a command
    b.on_text({"fromId": OWNER, "decoded": {"text": " Status "}})
    assert b.handle_inbox() == 1 and iface.sent == [("reply:status", OWNER)]
    b.on_text({"fromId": OWNER, "decoded": {"text": "hw"}})
    assert b.handle_inbox() == 0                                               # within 10 s
    t[0] += 11
    b.on_text({"fromId": OWNER, "decoded": {"text": "hw"}})
    assert b.handle_inbox() == 1


def test_snapshot_and_nodes_tool(tmp_path):
    b = mb.Bridge(FakeIface(), OWNER, str(tmp_path), "", clock=clock)
    b.snapshot("/dev/ttyACM1")
    snap = json.loads((tmp_path / "mesh" / "nodes.json").read_text())
    assert [n["id"] for n in snap["nodes"]] == ["!11112222"]           # our own node left out
    n = snap["nodes"][0]
    assert n["last_heard_s"] == 120 and n["lat"] == 27.9512 and n["hops"] == 1

    class Ctx:
        mode, scope, hw = "standard", None, {"data_dir": str(tmp_path)}

        def runner(self, argv):
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                mb.main(argv[3:])
            return buf.getvalue()
    r = mesh_tool.nodes({"target": {}}, Ctx())
    assert r["summary"] == "1 Meshtastic node(s) known, 1 heard in the last hour"
    assert registry.default_registry()["mesh.nodes"].category == "recon.passive"


def test_replies_text():
    rows = [{"board": "GPS", "status": "check", "detail": "no fix yet"}, {"board": "Alfa (x)", "status": "ok"}]
    assert mesh.reply_for("hw", scans_dir="/nope", hw_rows=lambda: rows) == "hw: 1 ok, 1 need a look — GPS: no fix yet"
    assert mesh.reply_for("last", scans_dir="/nope") == "last scan: unreadable"
    assert "status, hw or last" in mesh.reply_for("help", scans_dir="/nope")
    assert len(mesh.clip("x" * 500).encode()) <= mesh.MAX_TEXT


def test_fanout():
    class N:
        def __init__(self, en):
            self.enabled, self.got = en, []

        def send(self, *a, **k):
            self.got.append(a)
            return True

        def flush(self):
            return 1
    a, b = N(True), N(False)
    f = mesh.Fanout(a, b, None)
    assert f.enabled and f.send("k", "kind", "high", "t", 0) and a.got and not b.got and f.flush() == 1


def test_hwcheck_lora_row():
    rows = hwcheck.check(run=lambda a, t=10: (0, ""), which=lambda b: None, exists=lambda p: False,
                         wifi_iface=lambda: None, mesh_status=lambda: {"connected": True, "my_node": "!deadbeef"})
    lora = [r for r in rows if r["board"].startswith("LoRa")][0]
    assert lora["status"] == "check" and "mesh-owner" in lora["fix"]
    rows = hwcheck.check(run=lambda a, t=10: (0, ""), which=lambda b: None, exists=lambda p: False,
                         wifi_iface=lambda: None, mesh_status=lambda: None)
    assert not [r for r in rows if r["board"].startswith("LoRa")]


def test_915_band_labels():
    assert hr.label_for(906.875).startswith("915 ISM: Meshtastic")
    assert hr.label_for(915.2) == "915 ISM: LoRa / sensors / meters"
    assert "915" in hr.DEFAULT_BANDS
