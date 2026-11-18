#!/usr/bin/env bash
# havok-box first-boot bring-up for Kali (Raspberry Pi 5).
#
# Idempotent. Re-runnable. Does ONLY setup: installs tools, provisions the TLS
# cert + dashboard token, lays down gpsd/Kismet/VNC and the systemd units, and
# wires the box-LAN firewall. It never runs a scan and never touches a target.
#
# Security posture is preserved: the Console (raw shell) and Desktop (noVNC) are
# scope-gate BYPASSES, so they stay OFF unless you ask for them, and the Desktop
# only turns on after you've actually set a VNC password (the box can't check for
# one, so setting it here is the attestation the code requires).
#
# Usage:
#   sudo ./scripts/kali-setup.sh [options]
#
#   --box-ip <ip>        box-LAN address handed out in links   (default 192.168.4.1)
#   --lan-cidr <cidr>    box-LAN subnet for the firewall       (default 192.168.4.0/24)
#   --iface <iface>      box-LAN interface                     (default wlan0)
#   --no-recon           skip the RF/recon tool packs (core + dashboard only)
#   --no-desktop         don't install/enable the noVNC desktop
#   --enable-console     install ttyd and enable the web shell (prompts for a password)
#   --unattended         never prompt; skips vncpasswd, so the desktop is installed but left OFF
#   --app-dir <path>     where the repo lives                  (default: this repo)
#   -h, --help           show this and exit
set -euo pipefail

# ---- defaults ---------------------------------------------------------------
BOX_IP="192.168.4.1"
LAN_CIDR="192.168.4.0/24"
IFACE="wlan0"
WANT_RECON=1
WANT_DESKTOP=1
WANT_CONSOLE=0
UNATTENDED=0
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DATA_DIR="/data/havokbox"
OPT_DIR="/opt/havokbox"
ETC_DIR="/etc/havokbox"
VENV="$OPT_DIR/venv"
CONFIG="$APP_DIR/config/box.json"
RUN_USER="${SUDO_USER:-$(id -un)}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32mok\033[0m  %s\n' "$*"; }
warn() { printf '    \033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

# ---- args -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --box-ip)        BOX_IP="$2"; shift 2;;
    --lan-cidr)      LAN_CIDR="$2"; shift 2;;
    --iface)         IFACE="$2"; shift 2;;
    --no-recon)      WANT_RECON=0; shift;;
    --no-desktop)    WANT_DESKTOP=0; shift;;
    --enable-console) WANT_CONSOLE=1; shift;;
    --unattended)    UNATTENDED=1; shift;;
    --app-dir)       APP_DIR="$2"; CONFIG="$APP_DIR/config/box.json"; shift 2;;
    -h|--help)       sed -n '2,40p' "$0"; exit 0;;
    *) die "unknown option: $1 (try --help)";;
  esac
done

# ---- preflight --------------------------------------------------------------
say "Preflight"
[ "$(id -u)" -eq 0 ] || die "run with sudo (needs apt, systemd, nftables)."
command -v apt-get >/dev/null || die "no apt-get — this script targets Kali/Debian."
[ -f "$APP_DIR/havokbox/server.py" ] || die "repo not found at $APP_DIR (pass --app-dir)."
command -v python3 >/dev/null || die "python3 missing."
PYVER="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
ok "repo: $APP_DIR   python: $PYVER   box: $BOX_IP ($IFACE, $LAN_CIDR)   user: $RUN_USER"

# ---- packages ---------------------------------------------------------------
say "Installing packages (missing tools just hide their buttons; failures are non-fatal)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || warn "apt update had warnings; continuing"

CORE_PKGS="python3 python3-venv python3-pip openssl nftables ca-certificates curl"
RECON_PKGS="kismet gpsd gpsd-clients rtl-sdr rtl-433 aircrack-ng hcxtools hcxdumptool tshark tcpdump nmap iw bluez testssl.sh seclists responder"
DESKTOP_PKGS="kali-desktop-xfce tigervnc-standalone-server novnc websockify"
CONSOLE_PKGS="ttyd"

install_group() {   # name "pkg list"
  local name="$1"; shift
  local ok_n=0 miss=""
  for p in $1; do
    if apt-get install -y -qq "$p" >/dev/null 2>&1; then ok_n=$((ok_n+1)); else miss="$miss $p"; fi
  done
  ok "$name: $ok_n installed${miss:+;  unavailable:$miss}"
}
install_group "core"    "$CORE_PKGS"
[ "$WANT_RECON"   -eq 1 ] && install_group "recon"   "$RECON_PKGS"
[ "$WANT_DESKTOP" -eq 1 ] && install_group "desktop" "$DESKTOP_PKGS"
[ "$WANT_CONSOLE" -eq 1 ] && install_group "console" "$CONSOLE_PKGS"

# ---- directories ------------------------------------------------------------
say "Creating directories"
install -d -m 0750 "$DATA_DIR" "$DATA_DIR/evidence" "$DATA_DIR/tls" "$OPT_DIR" "$ETC_DIR"
chown -R "$RUN_USER":"$RUN_USER" "$DATA_DIR"
ok "$DATA_DIR  $OPT_DIR  $ETC_DIR"

# ---- python runtime ---------------------------------------------------------
say "Python runtime (venv at $VENV)"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || warn "pip self-upgrade skipped"
if "$VENV/bin/pip" install -q starlette uvicorn pyyaml pyserial >/dev/null 2>&1; then
  ok "installed starlette uvicorn pyyaml pyserial"
else
  die "could not install Python runtime deps (is the Pi online?)."
fi

# ---- config -----------------------------------------------------------------
say "Config ($CONFIG)"
if [ ! -f "$CONFIG" ]; then
  cp "$APP_DIR/config/box.example.json" "$CONFIG"
  ok "created from box.example.json"
else
  ok "existing config kept"
fi
for pair in scope:scope.example.yaml recipes:recipes.example.yaml; do
  dst="$APP_DIR/config/${pair%%:*}.yaml"; src="$APP_DIR/config/${pair##*:}"
  [ -f "$dst" ] || { [ -f "$src" ] && cp "$src" "$dst" && ok "seeded ${dst##*/} from example"; }
done
# Apply network identity to the config (python, so no jq dependency).
python3 - "$CONFIG" "$BOX_IP" "$LAN_CIDR" "$IFACE" <<'PY'
import json, sys
path, ip, cidr, iface = sys.argv[1:5]
c = json.load(open(path))
c["box_address"] = ip
c["lan_cidrs"] = [cidr]
c["console_iface"] = iface
c["desktop_iface"] = iface
json.dump(c, open(path, "w"), indent=2)
PY
chmod 0640 "$CONFIG"; chown "$RUN_USER":"$RUN_USER" "$CONFIG"
ok "box_address/lan_cidrs/iface set"

# ---- secrets env (dashboard token etc, 0600, systemd EnvironmentFile) -------
say "Secrets ($ETC_DIR/havokbox.env)"
ENVFILE="$ETC_DIR/havokbox.env"
if [ ! -f "$ENVFILE" ]; then
  umask 077
  {
    echo "HAVOKBOX_CONFIG=$CONFIG"
    echo "HAVOKBOX_TOKEN=$(openssl rand -hex 24)"
    echo "# ANTHROPIC_API_KEY=sk-ant-...        # optional: enables the AI commander"
    echo "# HAVOKBOX_GUARD_TOKEN=$(openssl rand -hex 24)   # tablet/Drive-Guard token"
    echo "# HAVOKBOX_CONSOLE_PASSWORD=change-me  # required before the web shell runs"
    echo "# HAVOKBOX_DISCORD_WEBHOOK=https://discord.com/api/webhooks/..."
  } > "$ENVFILE"
  chmod 0600 "$ENVFILE"; ok "generated dashboard token"
else
  ok "existing secrets kept"
fi

# ---- TLS cert + token provisioning -----------------------------------------
say "Provisioning TLS (box CA pinned to $BOX_IP)"
( cd "$APP_DIR" && HAVOKBOX_CONFIG="$CONFIG" "$VENV/bin/python" -m havokbox.provision ) \
  && ok "cert at $DATA_DIR/tls/box.crt" || die "provision failed"
CA_CRT="$DATA_DIR/tls/box-ca.crt"
[ -f "$CA_CRT" ] && ok "install $CA_CRT on the phone/tablet as a trusted CA"

# ---- gpsd -------------------------------------------------------------------
if [ "$WANT_RECON" -eq 1 ] && command -v gpsd >/dev/null; then
  say "gpsd (read-only; wardrive GPS + Kismet gps=gpsd)"
  if [ -f /etc/default/gpsd ]; then
    sed -i 's|^DEVICES=.*|DEVICES="/dev/ttyACM0 /dev/ttyUSB0"|; s|^GPSD_OPTIONS=.*|GPSD_OPTIONS="-n -b"|' /etc/default/gpsd || true
    grep -q '^USBAUTO=' /etc/default/gpsd || echo 'USBAUTO="true"' >> /etc/default/gpsd
  fi
  systemctl enable --now gpsd.socket >/dev/null 2>&1 || warn "gpsd not started (no receiver yet is fine)"
  ok "gpsd configured (-b read-only)"
fi

# ---- Kismet -----------------------------------------------------------------
if [ "$WANT_RECON" -eq 1 ] && command -v kismet >/dev/null; then
  say "Kismet (gps=gpsd; read-only API key is a one-time manual step)"
  install -d -m 0755 /etc/kismet
  SITE=/etc/kismet/kismet_site.conf
  if [ ! -f "$SITE" ]; then
    { echo "gps=gpsd:host=localhost,port=2947,reconnect=true"
      echo "# Add your box-LAN capture sources here, e.g.:"
      echo "# source=wlan1:type=linuxwifi,name=wifi"
      echo "# source=hci0:type=linuxbluetooth,name=ble"
    } > "$SITE"
    ok "wrote $SITE"
  else ok "existing kismet_site.conf kept"; fi
  # Point the poller at where its read-only key header will live.
  python3 - "$CONFIG" <<'PY'
import json, sys
p = sys.argv[1]; c = json.load(open(p)); hw = c.setdefault("hw", {})
hw.setdefault("kismet_header", "/data/havokbox/kismet-apikey.header")
json.dump(c, open(p, "w"), indent=2)
PY
  cat > "$DATA_DIR/kismet-apikey.header.README" <<EOF
Kismet read-only API key — one-time, needs the daemon running:
  1) Start kismet once and create the admin login in its web UI (http://$BOX_IP:2501).
  2) Settings -> API keys -> create a key with role 'readonly'.
  3) Save it as the HTTP header the poller sends:
       echo 'Authorization: Bearer <KEY>' > /data/havokbox/kismet-apikey.header
       chmod 600 /data/havokbox/kismet-apikey.header
The poller only reads (last-time/-15 + fields filter); it never writes to Kismet.
EOF
  ok "poller header path set; see kismet-apikey.header.README for the one manual step"
fi

# ---- noVNC desktop ----------------------------------------------------------
DESKTOP_ON=0
if [ "$WANT_DESKTOP" -eq 1 ] && command -v websockify >/dev/null; then
  say "Remote desktop (noVNC) — scope-gate bypass, box-LAN + TLS + VNC password"
  NOVNC_DIR=/usr/share/novnc
  [ -d "$NOVNC_DIR" ] || warn "noVNC assets not at $NOVNC_DIR; set novnc_web_dir if elsewhere"
  VNC_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
  if [ "$UNATTENDED" -eq 1 ]; then
    warn "unattended: skipping vncpasswd — desktop stays OFF until you set one and flip the flag"
  elif [ -f "$VNC_HOME/.vnc/passwd" ]; then
    ok "VNC password already set"; DESKTOP_ON=1
  else
    echo "    Set the VNC password now (its own secret — never the dashboard token):"
    sudo -u "$RUN_USER" vncpasswd && DESKTOP_ON=1 || warn "vncpasswd failed; desktop left OFF"
  fi
  # systemd user-less service that owns the :1 display, bound to localhost.
  if [ "$DESKTOP_ON" -eq 1 ]; then
    cat > /etc/systemd/system/havokbox-vnc.service <<EOF
[Unit]
Description=havok-box VNC :1 (localhost only, for noVNC bridge)
After=network.target
[Service]
User=$RUN_USER
Type=forking
ExecStart=/usr/bin/vncserver -localhost yes -geometry 1280x800 :1
ExecStop=/usr/bin/vncserver -kill :1
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now havokbox-vnc.service >/dev/null 2>&1 \
      && ok "VNC :1 running on localhost:5901" || warn "VNC service didn't start"
    # Attest the password + enable the desktop (the bridge/link gate on both).
    python3 - "$CONFIG" <<'PY'
import json, sys
p = sys.argv[1]; c = json.load(open(p))
c["desktop_enabled"] = True
c["desktop_vnc_password_set"] = True
json.dump(c, open(p, "w"), indent=2)
PY
    ok "desktop_enabled + desktop_vnc_password_set = true"
  fi
fi

# ---- console (optional) -----------------------------------------------------
if [ "$WANT_CONSOLE" -eq 1 ] && command -v ttyd >/dev/null; then
  say "Web console (ttyd) — scope-gate bypass"
  if [ "$UNATTENDED" -eq 0 ]; then
    read -rsp "    Set a console password (different from the dashboard token): " CPW; echo
    if [ -n "$CPW" ]; then
      sed -i '/^# HAVOKBOX_CONSOLE_PASSWORD=/d; /^HAVOKBOX_CONSOLE_PASSWORD=/d' "$ENVFILE"
      echo "HAVOKBOX_CONSOLE_PASSWORD=$CPW" >> "$ENVFILE"
      python3 - "$CONFIG" <<'PY'
import json, sys
p=sys.argv[1]; c=json.load(open(p)); c["console_enabled"]=True
json.dump(c, open(p,"w"), indent=2)
PY
      ok "console_enabled = true"
    else warn "empty password; console left OFF"; fi
  else warn "unattended: console left OFF (set HAVOKBOX_CONSOLE_PASSWORD + console_enabled)"; fi
fi

# ---- firewall (box-LAN only for the bypass ports) ---------------------------
say "Firewall (nftables: drop non-$LAN_CIDR to the bypass ports)"
install -d -m 0750 /etc/nftables.d
cat > /etc/nftables.d/havokbox.nft <<EOF
# Managed by havok-box kali-setup.sh — bypass ports are box-LAN only.
table inet havokbox {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 7681 ip saddr != $LAN_CIDR drop   # console (ttyd)
    tcp dport 6080 ip saddr != $LAN_CIDR drop   # desktop (noVNC)
    tcp dport 2501 ip saddr != $LAN_CIDR drop   # kismet web UI
  }
}
EOF
grep -q 'include "/etc/nftables.d/\*\.nft"' /etc/nftables.conf 2>/dev/null \
  || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
systemctl enable --now nftables >/dev/null 2>&1 && nft -f /etc/nftables.conf 2>/dev/null \
  && ok "rules loaded" || warn "nftables reload failed; check /etc/nftables.conf"

# ---- systemd units: dashboard + watchdog ------------------------------------
say "systemd units (dashboard + watchdog)"
cat > /etc/systemd/system/havokbox-dashboard.service <<EOF
[Unit]
Description=havok-box dashboard (Starlette/uvicorn over TLS)
After=network-online.target
Wants=network-online.target
[Service]
User=$RUN_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENVFILE
ExecStart=$VENV/bin/python -m havokbox.server
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/havokbox-watchdog.service <<EOF
[Unit]
Description=havok-box watchdog (collectors, drain, console/desktop bridges)
After=havokbox-dashboard.service
Wants=havokbox-dashboard.service
[Service]
User=$RUN_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENVFILE
ExecStart=$VENV/bin/python -m havokbox.watchdog
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now havokbox-dashboard.service havokbox-watchdog.service >/dev/null 2>&1 \
  && ok "dashboard + watchdog enabled and started" || warn "services failed; journalctl -u havokbox-dashboard"

# ---- summary ----------------------------------------------------------------
FP="$(openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
TOKEN="$(grep '^HAVOKBOX_TOKEN=' "$ENVFILE" | cut -d= -f2)"
cat <<EOF

$(say "Done")
  Dashboard :  https://$BOX_IP:8443/
  Token     :  $TOKEN
  CA cert   :  $CA_CRT   (install on phone/tablet; verify fingerprint)
  CA SHA-256:  ${FP:-<run provision to see>}
EOF
[ "$DESKTOP_ON" -eq 1 ] && echo "  Desktop   :  on — dashboard 'Desktop' tab (prompts for the VNC password)" \
                        || echo "  Desktop   :  installed but OFF — run vncpasswd, then set the two desktop_* flags true"
[ "$WANT_RECON" -eq 1 ] && command -v kismet >/dev/null && \
  echo "  Kismet    :  create the read-only API key (see $DATA_DIR/kismet-apikey.header.README)"
cat <<EOF
  Status    :  systemctl status havokbox-dashboard havokbox-watchdog
  Logs      :  journalctl -u havokbox-watchdog -f

  Re-run any time — this script is idempotent. Turn the Console/Desktop back off
  when you're done: set console_enabled / desktop_enabled false in $CONFIG.
EOF
