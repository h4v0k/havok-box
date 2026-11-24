# `hb` — scan helpers for the Kali command line

`hb` wraps standard nmap for use in the Console, over SSH, or in the Desktop terminal. It is
installed by `scripts/kali-setup.sh` as `/usr/local/bin/hb`. Lab only.

It follows the same scope file as the dashboard: every target must be an IP or CIDR inside
`networks.include` in `config/scope.yaml`, hostnames are refused, and `networks.exclude` is always
passed to nmap as `--exclude`. No scope file means no scan.

Unlike the dashboard buttons, `hb` does **not** ask for approval. You're at the keyboard, the same
as in the Console.

## No commands to remember

- **`hb`** with nothing after it opens numbered menus: pick what to do, pick a network from your
  scope file, a host from your last scan, or type an IP, then pick how hard to look.
- **`hb gui`**, or the **havok-box scans** icon on the Kali desktop, does the same with clickable
  windows and a progress bar you can cancel.

Both cover: scan, quick workflow with a report, devices from a scan, open ports, find hosts by port
or service, compare two scans, browse past scans, and **check my hardware**.

## Hardware check

`hb hw` (also in the menus, and on the dashboard's Report tab) goes board by board and says
**Working**, **Needs attention** or **Not plugged in**, with the fix for each:

- **Alfa:** detected, and its interface came up.
- **RTL-SDR V4:** answers. The check reads its EEPROM, and flags it if another program has it open.
- **ZigBee dongle:** Sniffle installed, and the firmware flashed (`sudo scripts/flash-sniffle.sh`, once).
- **Yard Stick One:** detected, and rfcat installed.
- **GPS:** gpsd reading it, and whether it has a 2D/3D fix.
- **Software:** which dashboard buttons are hidden because their tool isn't installed.
- **Spares:** the Flipper (backup sub-GHz) and the CC1101 are listed when present.

The check is read-only. It never transmits and never changes a radio's mode.

Setup gives nmap raw-packet rights (`setcap`), so scans run without sudo. nmap scripts still run as
your user, not root. On a shared machine, note that this lets any local user send raw packets.

## Profiles

| Profile | What it does |
|---|---|
| `discover` | Who's up. ARP on the local segment, ping elsewhere. No ports. |
| `quiet` | Stealthy. SYN scan, top 100 ports, `-T2`, 300 ms delay, 1 retry, random host order. |
| `standard` | Balanced. SYN scan, top 1000 ports, service versions. |
| `robust` | Everything. All 65535 TCP ports, versions, default scripts, OS guess. |
| `udp` | Top 50 UDP ports, light version detection. Slow by nature. |
| `web` | Common web ports with page title, headers and TLS cert. |

`hb profiles` prints these with the exact nmap flags. `--ports 22,80,443` overrides a profile's
ports. `-n` / `--dry-run` prints the nmap command without running it.

## Everyday use

```bash
hb scan 10.10.0.0/24 -p quiet          # stealthy sweep of the lab VLAN
hb scan 10.10.0.20 -p robust           # go deep on one host
hb hosts                                    # live IPs from the last scan, one per line
hb hosts --port 445                         # only hosts with SMB open
hb hosts --service http -f table            # web hosts, with ports and names
hb hosts -f csv > devices.csv               # IP, hostname, MAC, vendor, OS, open ports
hb ports                                    # every open port with service + version
hb ports -f targets                         # ip:port lines for other tools
hb last                                     # folder of the most recent scan
```

### Workflow: discover, then scan only what's alive

```bash
hb flow 10.10.0.0/24 -p standard
```

1. Runs `discover` on the range.
2. Scans only the live, in-scope hosts with the chosen profile.
3. Writes `report.md`: a host table, a service list and the exact commands run.

### Chaining into other tools

`hb hosts` prints one IP per line, so it pipes straight into other tools:

```bash
hb hosts --port 443 > web.txt && testssl.sh --file web.txt
hb hosts --port 445 | xargs -I{} netexec smb {}
```

### Spot changes

```bash
hb diff /data/havokbox/scans/<old>/scan.xml /data/havokbox/scans/<new>/scan.xml
```

This lists new hosts, hosts that disappeared, and ports that opened or closed on each host.

## Where scans go

Each run gets its own folder in `/data/havokbox/scans/<time>_<profile>_<target>/`. It holds
nmap's `scan.xml`, `scan.nmap` and `scan.gnmap`, plus `command.txt`, and `report.md` for flows.
Set `HB_SCANS_DIR` to change the location, or `HB_SCOPE` to point at another scope file.

## Connecting from a MacBook

### 1. Get on the same network

- **Box Wi-Fi:** join the box's own access point. The box is at `192.168.4.1`.
- **Same lab LAN:** use the box's LAN address.
- **Anywhere:** install Tailscale on both and use the box's Tailscale name.

### Tailscale (keep the Mac on its own Wi-Fi)

Use this when you want to reach the box without leaving your normal network.

1. **On the box** (it needs internet, so it has to be on your Wi-Fi, the car hotspot or Ethernet):
   `sudo ./scripts/kali-setup.sh --tailscale`, then `sudo tailscale up`. Open the link it prints
   and sign in.
2. **On the Mac:** install the Tailscale app and sign in with the same account.
3. In the Tailscale admin page, rename the box to `havok-box`. Turn on MagicDNS if it isn't
   already on. Then use `HostName havok-box` in the SSH config below instead of `192.168.4.1`.

Over Tailscale you get SSH, `hb`, and the full desktop through the SSH tunnel below. The dashboard,
web Console and noVNC stay box-Wi-Fi-only on purpose; their firewall rules only allow
`192.168.4.0/24`.

### 2. SSH with a key (once)

```bash
ssh-keygen -t ed25519                   # skip if you already have ~/.ssh/id_ed25519
ssh-copy-id kali@192.168.4.1
```

Add this to `~/.ssh/config` on the Mac:

```
Host havok
  HostName 192.168.4.1
  User kali
```

Then `ssh havok` gets you a shell, and `ssh -t havok hb flow 10.10.0.0/24` runs a flow
from the Mac. Once key login works, turn off password logins on the box: set
`PasswordAuthentication no` in `/etc/ssh/sshd_config`, then `sudo systemctl restart ssh`.

### 3. Pull results back

```bash
scp -r "havok:$(ssh havok hb last)" .   # copies the most recent scan folder
```

### 4. Other options

- **VS Code Remote-SSH:** open the `havok` host and edit, run and browse files on the box as if
  they were local.
- **Full Kali desktop with mouse, from the Mac's built-in Screen Sharing:**
  ```bash
  ssh -N -L 5901:localhost:5901 havok      # leave running; tunnels the box's VNC over SSH
  ```
  Then in Finder: **Go → Connect to Server**, enter `vnc://localhost:5901`, and give the VNC
  password. The VNC server only listens on the box itself, so the SSH tunnel is the way in.
- **Full Kali desktop in a browser:** the dashboard's Desktop tab (noVNC) works in Safari, on the
  Mac, a tablet or a phone. See `docs/desktop.md`.
