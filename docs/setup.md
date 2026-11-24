# First-boot setup — `scripts/kali-setup.sh`

One idempotent, re-runnable script that does every setup action on the Pi once
Kali is up. It installs tools, provisions TLS + the dashboard token, configures
gpsd/Kismet/VNC, writes the systemd units and the box-LAN firewall, and starts
the dashboard + watchdog. It runs **no** scans and touches **no** targets.

```
sudo ./scripts/kali-setup.sh                 # prompts once for the admin password
sudo ./scripts/kali-setup.sh --admin-pass 'secret' --box-ip 192.168.4.1 --iface wlan0
sudo ./scripts/kali-setup.sh --unattended --admin-pass 'secret'   # hands-free image build
```

Options: `--box-ip --lan-cidr --iface --no-recon --no-desktop --enable-console
--unattended --app-dir --tailscale --wifi 'SSID:PASS' --ap-ssid <name>`.

## Wi-Fi: known networks first, the box's own network as fallback
The Pi's **built-in** Wi-Fi (`--iface`, default `wlan0`) is the only radio NetworkManager manages;
the Alfa and other radios are left to the recon tools.

- **Known networks** (home Wi-Fi, car hotspot): pass `--wifi 'Name:password'` (repeat it; the first
  one is preferred), or enter them when prompted. The box joins whichever is in range, which gives
  it internet (Claude API, Tailscale).
- **Fallback:** if none connects within about a minute, the box turns on its own WPA2 network,
  **`free-candy-van`** by default (`--ap-ssid` to change it). The password is the admin password,
  which must be at least 8 characters, and the box is at `192.168.4.1`.
- **Switching back:** while its own network is up and nobody is connected to it, the box retries
  the known networks every 3 minutes. It never drops someone who's connected.
- **By hand:** `havokbox-net status`, `sudo havokbox-net ap` (force the box network),
  `sudo havokbox-net client` (try the known networks now).

The watcher starts on the next boot, so running setup over SSH won't cut your connection.

## Security posture is preserved
- Console (raw shell) and Desktop (noVNC) are scope-gate **bypasses**, so they
  stay **off** unless asked for. The Desktop turns on only after `vncpasswd`
  actually runs (the box can't check for a VNC password, so setting it is the
  attestation the code requires) — `--unattended` skips the prompt and leaves it
  off.
- Bypass ports (console 7681, desktop 6080, Kismet UI 2501) are firewalled to the
  box-LAN subnet.

## You enter one password; the rest is automated
Pass `--admin-pass` (or `$HAVOKBOX_ADMIN_PASSWORD`), or let it prompt you once.
That single password is used to:
- set the **VNC** desktop password (`vncpasswd -f`, non-interactive),
- pre-seed the **Kismet** admin login (no first-run web wizard), and
- set the **console** password when `--enable-console` is given.

From it the script also **auto-mints the read-only Kismet API key**: it starts a
Kismet service, waits for the REST API, calls `auth/apikey/generate.cmd` with the
`readonly` role, and writes `KISMET: <token>` to the poller's header file
(`/data/havokbox/secrets/kismet.header`, 0600). Re-runs keep a working key. The
only thing left for you is adding capture **sources** to `kismet_site.conf` (a
hardware choice, not a secret). Note: VNC only uses the first 8 characters of the
password.

## After it runs
- Dashboard: `https://<box-ip>:8443/` (token printed at the end + in
  `/etc/havokbox/havokbox.env`).
- Install `/data/havokbox/tls/box-ca.crt` on the phone/tablet as a trusted CA;
  verify the printed SHA-256.
- `systemctl status havokbox-dashboard havokbox-watchdog` · `journalctl -u havokbox-watchdog -f`.
- Turn the Console/Desktop back off when done (set the `*_enabled` flags false).
