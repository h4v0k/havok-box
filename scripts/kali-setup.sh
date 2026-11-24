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
#   --admin-pass <pw>    the one password (VNC + Kismet + console); else prompted once
#   --no-recon           skip the RF/recon tool packs (core + dashboard only)
#   --no-desktop         don't install/enable the noVNC desktop
#   --enable-console     install ttyd and enable the web shell (uses the admin password)
#   --tailscale          install Tailscale; then run 'sudo tailscale up' once to sign in
#   --wifi 'SSID:PASS'   a known network to join (repeat; first = preferred). Prompted if none given
#   --ap-ssid <name>     the box's own fallback network name  (default free-candy-van)
#   --unattended         never prompt; needs --admin-pass (or env) or one is generated
#   --app-dir <path>     where the repo lives                  (default: this repo)
#   -h, --help           show this and exit
#
# You enter ONE password (or pass --admin-pass / $HAVOKBOX_ADMIN_PASSWORD) and
# everything else — the VNC password, the Kismet admin login, and the read-only
# Kismet API key — is set up automatically.
set -euo pipefail

# ---- defaults ---------------------------------------------------------------
BOX_IP="192.168.4.1"
LAN_CIDR="192.168.4.0/24"
IFACE="wlan0"
WANT_RECON=1
WANT_DESKTOP=1
WANT_CONSOLE=0
WANT_TAILSCALE=0
WIFI_LIST=()
AP_SSID="free-candy-van"
UNATTENDED=0
ADMIN_PW="${HAVOKBOX_ADMIN_PASSWORD:-}"
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
    --admin-pass)    ADMIN_PW="$2"; shift 2;;
    --no-recon)      WANT_RECON=0; shift;;
    --no-desktop)    WANT_DESKTOP=0; shift;;
    --enable-console) WANT_CONSOLE=1; shift;;
    --tailscale)     WANT_TAILSCALE=1; shift;;
    --wifi)          WIFI_LIST+=("$2"); shift 2;;
    --ap-ssid)       AP_SSID="$2"; shift 2;;
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

# ---- the one password -------------------------------------------------------
# Used for the VNC desktop, the Kismet admin login, and (if enabled) the console.
# Everything downstream is automated from it.
NEED_PW=1   # always: it is also the WPA2 key of the box's own Wi-Fi
{ [ "$WANT_DESKTOP" -eq 1 ] || [ "$WANT_CONSOLE" -eq 1 ]; } && NEED_PW=1
{ [ "$WANT_RECON" -eq 1 ] && NEED_PW=1; } || true     # Kismet admin login
if [ "$NEED_PW" -eq 1 ] && [ -z "$ADMIN_PW" ]; then
  if [ "$UNATTENDED" -eq 1 ]; then
    ADMIN_PW="$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)"
    PW_GENERATED=1
    warn "unattended with no --admin-pass: generated one, recorded in $ETC_DIR/havokbox.env"
  else
    say "Set the box admin password (the only thing you enter — used for VNC, Kismet, console)"
    read -rsp "    Password: " ADMIN_PW; echo
    read -rsp "    Confirm : " _pw2; echo
    [ -n "$ADMIN_PW" ] || die "empty password."
    [ "$ADMIN_PW" = "$_pw2" ] || die "passwords didn't match."
    [ "${#ADMIN_PW}" -ge 8 ] || die "use at least 8 characters (it is also the box Wi-Fi's WPA2 key)."
    unset _pw2
  fi
  # VNC only honors the first 8 characters of the password it checks.
  [ "${#ADMIN_PW}" -gt 8 ] && [ "$WANT_DESKTOP" -eq 1 ] && \
    warn "note: the VNC desktop only uses the first 8 characters of the password"
fi

# ---- packages ---------------------------------------------------------------
say "Installing packages (missing tools just hide their buttons; failures are non-fatal)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || warn "apt update had warnings; continuing"

CORE_PKGS="python3 python3-venv python3-pip openssl nftables ca-certificates curl network-manager dnsmasq-base iw"
RECON_PKGS="kismet gpsd gpsd-clients rtl-sdr rtl-433 aircrack-ng hcxtools hcxdumptool tshark tcpdump nmap iw bluez testssl.sh seclists responder"
# Tools the dashboard buttons already call (hidden until installed), + the Yard Stick and quiet discovery
RECON_PKGS="$RECON_PKGS rfcat direwolf multimon-ng python3-serial python3-intelhex nuclei netexec feroxbuster p0f onesixtyone snmp ldap-utils thc-ipv6 mitm6 hydra whatweb smbclient exploitdb arp-scan netdiscover bettercap usbutils"
# Build deps for readsb (ADS-B), which isn't packaged
BUILD_PKGS="git build-essential cmake pkg-config librtlsdr-dev libusb-1.0-0-dev zlib1g-dev libzstd-dev libncurses-dev"
DESKTOP_PKGS="kali-desktop-xfce tigervnc-standalone-server novnc websockify"
# Point-and-click tools for the desktop: packet view, nmap GUI, spectrum viewer/listening (gqrx),
# sub-GHz analysis (URH), and CHIRP for programming Baofeng/ham/GMRS handhelds over USB
GUI_PKGS="wireshark zenmap-kbx gqrx-sdr urh chirp"
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
[ "$WANT_RECON"   -eq 1 ] && install_group "build"   "$BUILD_PKGS"
[ "$WANT_DESKTOP" -eq 1 ] && install_group "desktop" "$DESKTOP_PKGS"
[ "$WANT_DESKTOP" -eq 1 ] && install_group "gui"     "$GUI_PKGS"
[ "$WANT_CONSOLE" -eq 1 ] && install_group "console" "$CONSOLE_PKGS"

# ---- directories ------------------------------------------------------------
say "Creating directories"
install -d -m 0750 "$DATA_DIR" "$DATA_DIR/evidence" "$DATA_DIR/tls" "$OPT_DIR" "$ETC_DIR"
chown -R "$RUN_USER":"$RUN_USER" "$DATA_DIR"
ok "$DATA_DIR  $OPT_DIR  $ETC_DIR"

# ---- python runtime ---------------------------------------------------------
say "Python runtime (venv at $VENV)"
[ -d "$VENV" ] || python3 -m venv --system-site-packages "$VENV"
# apt-installed radio libraries (rflib from rfcat) must be importable by the box's helpers
sed -i 's/^include-system-site-packages = false/include-system-site-packages = true/' "$VENV/pyvenv.cfg"
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
if [ "${PW_GENERATED:-0}" -eq 1 ] && ! grep -q '^HAVOKBOX_ADMIN_PASSWORD=' "$ENVFILE"; then
  printf 'HAVOKBOX_ADMIN_PASSWORD=%s\n' "$ADMIN_PW" >> "$ENVFILE"   # generated in --unattended
  ok "recorded generated admin password"
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

# ---- Kismet (fully automated: pre-seed admin -> start -> mint read-only key) -
if [ "$WANT_RECON" -eq 1 ] && command -v kismet >/dev/null; then
  say "Kismet (gps=gpsd; admin login pre-seeded; read-only API key auto-minted)"
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

  KHEADER="$DATA_DIR/secrets/kismet.header"   # matches the poller default
  install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR/secrets"
  python3 - "$CONFIG" "$KHEADER" <<'PY'
import json, sys
p, hdr = sys.argv[1:3]; c = json.load(open(p)); c.setdefault("hw", {})["kismet_header"] = hdr
json.dump(c, open(p, "w"), indent=2)
PY

  # Pre-seed the admin login so there is no first-run web wizard.
  KHOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
  install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$KHOME/.kismet"
  HTTPD_CONF="$KHOME/.kismet/kismet_httpd.conf"
  umask 077
  printf 'httpd_username=admin\nhttpd_password=%s\n' "$ADMIN_PW" > "$HTTPD_CONF"
  chown "$RUN_USER":"$RUN_USER" "$HTTPD_CONF"; chmod 0600 "$HTTPD_CONF"
  ok "admin login pre-seeded ($HTTPD_CONF)"

  # A service so the REST API is up (no capture sources needed just to mint a key).
  cat > /etc/systemd/system/havokbox-kismet.service <<EOF
[Unit]
Description=havok-box Kismet (REST API; sources from kismet_site.conf)
After=network.target gpsd.socket
[Service]
User=$RUN_USER
ExecStart=/usr/bin/kismet --no-ncurses
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now havokbox-kismet.service >/dev/null 2>&1 || warn "kismet service didn't start"

  # Wait for the REST API, then mint a read-only key (idempotent: keep a working one).
  if [ -s "$KHEADER" ] && curl -s --fail --max-time 5 -H "@$KHEADER" \
        http://localhost:2501/system/status.json >/dev/null 2>&1; then
    ok "existing read-only key still valid — kept"
  else
    ready=0
    for _ in $(seq 1 30); do
      curl -s --fail --max-time 3 http://localhost:2501/system/status.json >/dev/null 2>&1 \
        && { ready=1; break; }; sleep 1
    done
    if [ "$ready" -eq 1 ]; then
      KCFG="$(mktemp)"; printf 'user = "admin:%s"\n' "$ADMIN_PW" > "$KCFG"; chmod 600 "$KCFG"
      TOKEN="$(curl -s --fail --max-time 10 --config "$KCFG" \
        -d 'json={"name":"havokbox-ro","role":"readonly","duration":0}' \
        http://localhost:2501/auth/apikey/generate.cmd 2>/dev/null || true)"
      rm -f "$KCFG"
      if [ -n "$TOKEN" ] && [ "${#TOKEN}" -lt 200 ]; then
        printf 'KISMET: %s\n' "$TOKEN" > "$KHEADER"
        chown "$RUN_USER":"$RUN_USER" "$KHEADER"; chmod 0600 "$KHEADER"
        if curl -s --fail --max-time 5 -H "@$KHEADER" \
             http://localhost:2501/system/status.json >/dev/null 2>&1; then
          ok "read-only API key minted and verified ($KHEADER)"
        else warn "key written but validation failed; check the readonly role"; fi
      else
        warn "couldn't mint the key (admin login?); set it later:"
        warn "  curl -u admin:<pw> -d 'json={\"name\":\"havokbox-ro\",\"role\":\"readonly\",\"duration\":0}' \\"
        warn "    http://localhost:2501/auth/apikey/generate.cmd  > the token, then: printf 'KISMET: <tok>\\n' > $KHEADER"
      fi
    else warn "Kismet REST API didn't come up in 30s; journalctl -u havokbox-kismet"; fi
  fi
fi

# ---- noVNC desktop ----------------------------------------------------------
DESKTOP_ON=0
if [ "$WANT_DESKTOP" -eq 1 ] && command -v websockify >/dev/null; then
  say "Remote desktop (noVNC) — scope-gate bypass, box-LAN + TLS + VNC password"
  NOVNC_DIR=/usr/share/novnc
  [ -d "$NOVNC_DIR" ] || warn "noVNC assets not at $NOVNC_DIR; set novnc_web_dir if elsewhere"
  VNC_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
  install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$VNC_HOME/.vnc"
  # Non-interactive: derive ~/.vnc/passwd from the one admin password (filter mode).
  if printf '%s\n' "$ADMIN_PW" | sudo -u "$RUN_USER" vncpasswd -f > "$VNC_HOME/.vnc/passwd" 2>/dev/null \
     && [ -s "$VNC_HOME/.vnc/passwd" ]; then
    chown "$RUN_USER":"$RUN_USER" "$VNC_HOME/.vnc/passwd"; chmod 0600 "$VNC_HOME/.vnc/passwd"
    DESKTOP_ON=1; ok "VNC password set from the admin password"
  else
    warn "vncpasswd -f failed; desktop left OFF"
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
  say "Web console (ttyd) — scope-gate bypass, uses the admin password"
  if [ -n "$ADMIN_PW" ]; then
    sed -i '/^# HAVOKBOX_CONSOLE_PASSWORD=/d; /^HAVOKBOX_CONSOLE_PASSWORD=/d' "$ENVFILE"
    printf 'HAVOKBOX_CONSOLE_PASSWORD=%s\n' "$ADMIN_PW" >> "$ENVFILE"
    python3 - "$CONFIG" <<'PY'
import json, sys
p=sys.argv[1]; c=json.load(open(p)); c["console_enabled"]=True
json.dump(c, open(p,"w"), indent=2)
PY
    ok "console_enabled = true"
  else warn "no admin password; console left OFF"; fi
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

# ---- radio software that isn't packaged (Sniffle, readsb) --------------------
if [ "$WANT_RECON" -eq 1 ]; then
  say "Radio software from source (Sniffle, readsb)"
  SRC="$OPT_DIR/src"; install -d "$SRC"
  if [ -d /opt/sniffle/.git ]; then git -C /opt/sniffle pull -q --ff-only >/dev/null 2>&1 || true
  else git clone -q --depth 1 https://github.com/nccgroup/Sniffle /opt/sniffle >/dev/null 2>&1 || true; fi
  [ -f /opt/sniffle/python_cli/sniff_receiver.py ] && ok "Sniffle at /opt/sniffle (flash the dongle once: sudo $APP_DIR/scripts/flash-sniffle.sh)" \
    || warn "Sniffle clone failed (is the box online?)"
  if ! command -v readsb >/dev/null; then
    rm -rf "$SRC/readsb"
    if git clone -q --depth 1 https://github.com/wiedehopf/readsb "$SRC/readsb" >/dev/null 2>&1 \
       && make -C "$SRC/readsb" -j4 RTLSDR=yes >/dev/null 2>&1; then
      install -m 0755 "$SRC/readsb/readsb" /usr/local/bin/readsb && ok "readsb built (ADS-B)"
    else warn "readsb build failed: ADS-B button stays hidden"; fi
  else ok "readsb present"; fi
  # Radios are used by the box user without sudo: dialout (serial dongles), plugdev (USB SDR/Yard Stick)
  usermod -aG dialout,plugdev "$RUN_USER" 2>/dev/null || true
  cat > /etc/udev/rules.d/60-havokbox-radios.rules <<'UDEV'
# Yard Stick One (rfcat) and RTL-SDR: usable without root
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="605b", MODE="0660", GROUP="plugdev"
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", MODE="0660", GROUP="plugdev"
UDEV
  udevadm control --reload-rules >/dev/null 2>&1 || true
  # The DVB-T TV driver grabs RTL-SDR dongles before rtl-sdr can; keep it off
  echo "blacklist dvb_usb_rtl28xxu" > /etc/modprobe.d/havokbox-rtlsdr.conf
fi

# ---- Wi-Fi: join known networks, else the box's own network ----------------
say "Wi-Fi ($IFACE): known networks first, '$AP_SSID' as fallback"
[ "${#ADMIN_PW}" -ge 8 ] || die "the admin password must be at least 8 characters (WPA2 key for '$AP_SSID')."
if [ "${#WIFI_LIST[@]}" -eq 0 ] && [ "$UNATTENDED" -eq 0 ]; then
  echo "    Add the networks the box should join (home Wi-Fi, car hotspot). Blank name = done."
  while true; do
    read -rp "    Network name: " _ss; [ -n "$_ss" ] || break
    read -rsp "    Password    : " _pp; echo
    WIFI_LIST+=("$_ss:$_pp")
  done
  unset _ss _pp
fi
# Only the built-in radio is NetworkManager's; the Alfa and other radios belong to the recon tools.
install -d /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/havokbox-radios.conf <<NMCONF
[keyfile]
unmanaged-devices=type:wifi;except:interface-name:$IFACE
NMCONF
systemctl enable --now NetworkManager >/dev/null 2>&1 || warn "NetworkManager not running"
nmcli general reload >/dev/null 2>&1 || true
prio=50
for entry in "${WIFI_LIST[@]}"; do
  ss="${entry%%:*}"; pp="${entry#*:}"
  con="havokbox-wifi-$(printf '%s' "$ss" | tr -c 'A-Za-z0-9._-' '_')"
  nmcli con delete "$con" >/dev/null 2>&1 || true
  if [ -n "$pp" ] && [ "$pp" != "$ss" ]; then
    nmcli con add type wifi ifname "$IFACE" con-name "$con" ssid "$ss" \
      wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$pp" \
      connection.autoconnect yes connection.autoconnect-priority "$prio" >/dev/null \
      && ok "known network: $ss" || warn "could not add $ss"
  else
    nmcli con add type wifi ifname "$IFACE" con-name "$con" ssid "$ss" \
      connection.autoconnect yes connection.autoconnect-priority "$prio" >/dev/null \
      && ok "known network (open): $ss" || warn "could not add $ss"
  fi
  prio=$((prio - 10))
done
nmcli con delete havokbox-ap >/dev/null 2>&1 || true
nmcli con add type wifi ifname "$IFACE" con-name havokbox-ap autoconnect no ssid "$AP_SSID" \
  802-11-wireless.mode ap 802-11-wireless.band bg \
  ipv4.method shared ipv4.addresses "$BOX_IP/${LAN_CIDR#*/}" ipv6.method disabled \
  wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp \
  wifi-sec.psk "$ADMIN_PW" >/dev/null && ok "box network: '$AP_SSID' (WPA2, admin password) at $BOX_IP" \
  || warn "could not create the box network profile"
install -m 0755 "$APP_DIR/scripts/havokbox-net.sh" /usr/local/sbin/havokbox-net
cat > /etc/systemd/system/havokbox-net.service <<UNIT
[Unit]
Description=havok-box Wi-Fi: known networks first, own network as fallback
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Environment=HAVOKBOX_NET_IFACE=$IFACE
ExecStartPre=-/usr/sbin/iw reg set US
ExecStart=/usr/local/sbin/havokbox-net
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable havokbox-net >/dev/null 2>&1 && ok "fallback watcher enabled (starts on next boot; 'havokbox-net status')" \
  || warn "could not enable havokbox-net"

# ---- SSH (laptop access; see docs/hb.md for key-only login) -----------------
say "SSH server"
if command -v sshd >/dev/null 2>&1 || apt-get install -y -qq openssh-server >/dev/null 2>&1; then
  systemctl enable --now ssh >/dev/null 2>&1 && ok "ssh enabled (port 22)" || warn "could not start ssh"
else
  warn "openssh-server not installed"
fi

# ---- Tailscale (optional: reach the box from anywhere without opening ports) --
if [ "$WANT_TAILSCALE" -eq 1 ]; then
  say "Tailscale"
  if command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1; then
    systemctl enable --now tailscaled >/dev/null 2>&1 || true
    if tailscale status >/dev/null 2>&1; then ok "tailscale already signed in: $(tailscale ip -4 2>/dev/null | head -1)"
    else ok "tailscale installed: run 'sudo tailscale up' and open the link it prints to sign in"; fi
  else
    warn "tailscale install failed (is the box online?)"
  fi
fi

# ---- hb: command-line scan helpers (Console / SSH / Desktop) -----------------
say "Installing the 'hb' scan helper"
install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR/scans"
cat > /usr/local/bin/hb <<EOF
#!/usr/bin/env bash
# havok-box 'hb' launcher (generated by kali-setup.sh). Scope-checked nmap profiles + parsers.
export PYTHONPATH="$APP_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
export HB_SCANS_DIR="\${HB_SCANS_DIR:-$DATA_DIR/scans}"
exec "$VENV/bin/python" -m havokbox.hbcli --scope "\${HB_SCOPE:-$APP_DIR/config/scope.yaml}" "\$@"
EOF
chmod 0755 /usr/local/bin/hb
# Let nmap send raw packets without sudo (nmap --privileged). Scripts (NSE) still run as you, not root.
apt-get install -y -qq zenity libcap2-bin >/dev/null 2>&1 || warn "zenity/libcap2-bin not installed"
if command -v nmap >/dev/null && command -v setcap >/dev/null; then
  setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f "$(command -v nmap)")" \
    && ok "nmap can scan without sudo" || warn "setcap on nmap failed; hb will use sudo"
fi
# Clickable launchers on the Kali desktop + app menu
for f in havok-box havok-box-terminal; do
  if [ "$f" = havok-box ]; then name="havok-box scans"; exec_line="hb gui"; term=false
  else name="havok-box scans (terminal)"; exec_line="hb"; term=true; fi
  cat > "/usr/share/applications/$f.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=$name
Comment=Scope-checked nmap scans, device lists and reports
Exec=$exec_line
Icon=kali-nmap
Terminal=$term
Categories=Network;
DESKTOP
done
DESK="$(getent passwd "$RUN_USER" | cut -d: -f6)/Desktop"
install -d -o "$RUN_USER" -g "$RUN_USER" "$DESK"
install -m 0755 -o "$RUN_USER" -g "$RUN_USER" /usr/share/applications/havok-box.desktop "$DESK/"
ok "hb installed: run 'hb' for menus, 'hb gui' or the desktop icon for windows (scans in $DATA_DIR/scans)"

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
if [ "$WANT_RECON" -eq 1 ] && command -v kismet >/dev/null; then
  if [ -s "$DATA_DIR/secrets/kismet.header" ]; then
    echo "  Kismet    :  read-only API key minted; add capture sources in /etc/kismet/kismet_site.conf"
  else
    echo "  Kismet    :  daemon up; API key not minted — journalctl -u havokbox-kismet"
  fi
fi
cat <<EOF
  Status    :  systemctl status havokbox-dashboard havokbox-watchdog
  Logs      :  journalctl -u havokbox-watchdog -f

  Re-run any time — this script is idempotent. Turn the Console/Desktop back off
  when you're done: set console_enabled / desktop_enabled false in $CONFIG.
EOF
