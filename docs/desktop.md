# Remote desktop (noVNC) — full Kali in the browser

A "Desktop" tab that opens a full Kali desktop with mouse and keyboard, in the browser (phone,
tablet or laptop). Like the Console it is a scope-gate **bypass** — you are at the keyboard — so it
is OFF by default, box-LAN only, over TLS, behind the VNC password, and every link issuance is
logged to evidence.

## One-time setup on the Pi

1. Install a lightweight desktop, a VNC server, and noVNC:
   ```
   sudo apt install kali-desktop-xfce tigervnc-standalone-server novnc websockify
   ```
2. Set the VNC password (its own secret, never the dashboard token):
   ```
   vncpasswd          # writes ~/.vnc/passwd (0600)
   ```
3. Start the VNC server **bound to localhost** (so only the box can reach it; websockify is the only
   LAN-facing part), on display :1 / port 5901:
   ```
   vncserver -localhost yes -geometry 1280x800 :1
   ```
   Run it from a systemd user service so it survives reboots.
4. In `config/box.json` set `"desktop_enabled": true` AND `"desktop_vnc_password_set": true` (the
   box can't read `~/.vnc/passwd`, so this flag is your attestation that step 2's password is set —
   the bridge refuses to start and no link is issued until it's true; never run VNC passwordless).
   Set `desktop_vnc_port` if not 5901. Run
   `python3 -m havokbox.provision` if you haven't, so the TLS cert exists — the desktop refuses to
   start without it. The watchdog then launches websockify/noVNC on `desktop_port` (6080).
5. Restrict the port to box-LAN clients (websockify binds the box address but add belt-and-braces):
   ```
   # /etc/nftables.d/havokbox-desktop.nft
   table inet havokbox_desktop {
     chain input { type filter hook input priority 0; policy accept;
       tcp dport 6080 ip saddr != 192.168.4.0/24 drop }
   }
   ```

Open it from the dashboard's **Desktop** tab. The page prompts for the VNC password.

## Notes / limits

- The VNC password is held by the VNC server (`~/.vnc/passwd`, 0600); it is never on a command line
  and never leaves the box. The dashboard only hands out the URL after checking enabled + box-LAN + TLS.
- websockify serves noVNC over TLS with the same box cert the dashboard uses; install `box-ca.crt`
  on the device (see `docs/console.md`) so the browser trusts it.
- The VNC server is bound to `-localhost yes`; the only LAN exposure is websockify on `desktop_port`.
- websockify has no cross-origin flag like ttyd's `-O`; the protection against a DNS-rebinding page
  is the TLS cert being pinned to the box IP (so another hostname fails validation) plus the LAN
  filter and the VNC password. Always reach it via the `https://<box-ip>:6080` URL.
- This is a full desktop: it is NOT scope-gated. Use it for the times the gated buttons and the
  Console aren't enough. Turn `desktop_enabled` back off when you're done.
