# First-boot setup — `scripts/kali-setup.sh`

One idempotent, re-runnable script that does every setup action on the Pi once
Kali is up. It installs tools, provisions TLS + the dashboard token, configures
gpsd/Kismet/VNC, writes the systemd units and the box-LAN firewall, and starts
the dashboard + watchdog. It runs **no** scans and touches **no** targets.

```
sudo ./scripts/kali-setup.sh                 # core + recon + desktop
sudo ./scripts/kali-setup.sh --enable-console --box-ip 192.168.4.1 --iface wlan0
sudo ./scripts/kali-setup.sh --no-desktop --no-recon      # dashboard only
```

Options: `--box-ip --lan-cidr --iface --no-recon --no-desktop --enable-console
--unattended --app-dir`.

## Security posture is preserved
- Console (raw shell) and Desktop (noVNC) are scope-gate **bypasses**, so they
  stay **off** unless asked for. The Desktop turns on only after `vncpasswd`
  actually runs (the box can't check for a VNC password, so setting it is the
  attestation the code requires) — `--unattended` skips the prompt and leaves it
  off.
- Bypass ports (console 7681, desktop 6080, Kismet UI 2501) are firewalled to the
  box-LAN subnet.

## The one manual step it can't do for you
Kismet's **read-only API key** needs the daemon running and an admin login, so the
script sets the poller's header path and drops a README with the exact steps
(`/data/havokbox/kismet-apikey.header.README`).

## After it runs
- Dashboard: `https://<box-ip>:8443/` (token printed at the end + in
  `/etc/havokbox/havokbox.env`).
- Install `/data/havokbox/tls/box-ca.crt` on the phone/tablet as a trusted CA;
  verify the printed SHA-256.
- `systemctl status havokbox-dashboard havokbox-watchdog` · `journalctl -u havokbox-watchdog -f`.
- Turn the Console/Desktop back off when done (set the `*_enabled` flags false).
