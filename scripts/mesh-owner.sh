#!/usr/bin/env bash
# Tell the box which Meshtastic node is YOUR phone's, so only it gets alerts and replies.
#   sudo ./scripts/mesh-owner.sh '!a1b2c3d4'
# Find the id in the Meshtastic app: Settings > your node (it starts with "!"), or run
#   python3 -m havokbox.helpers.meshbridge nodes --data-dir /data/havokbox
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${HAVOKBOX_CONFIG:-$APP_DIR/config/box.json}"
ID="${1:-}"
[[ "$ID" =~ ^![0-9a-f]{8}$ ]] || { echo "usage: $0 '!a1b2c3d4'  (8 hex digits after !, quote it)" >&2; exit 2; }
[ -f "$CONFIG" ] || { echo "no $CONFIG yet: run kali-setup.sh first" >&2; exit 1; }
python3 - "$CONFIG" "$ID" <<'PY'
import json, sys
p, node = sys.argv[1], sys.argv[2]
cfg = json.load(open(p))
cfg.setdefault("hw", {})["mesh_owner"] = node
json.dump(cfg, open(p, "w"), indent=2)
open(p, "a").write("\n")
PY
systemctl restart havokbox-mesh havokbox-dashboard 2>/dev/null || true
echo "Owner set to $ID. Text 'status' from your phone's Meshtastic app to the box to test."
