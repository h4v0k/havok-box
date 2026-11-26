# `hb` — scan helpers for the Kali command line

`hb` wraps standard nmap for use in the Console, over SSH, or in the Desktop terminal. It is
installed by `scripts/kali-setup.sh` as `/usr/local/bin/hb`. Lab only.

It follows the same scope as the dashboard: every target must be an IP or CIDR inside the active
**engagement** (or a fixed `networks.include`, if you keep one), hostnames are refused, and the
**never list** (`networks.exclude` in `config/scope.yaml`) is always passed to nmap as `--exclude`.
No engagement and no fixed include means no scan.

## Engagements: find the lab, pick it, carry on

Lab IPs change, so the scope is per engagement rather than fixed:

1. **Find the lab.** `hb find` lists the networks the box is plugged into or joined (read from its
   own interfaces, nothing is sent), marking any that are public, bigger than a /16 or on the never
   list. `hb find 10.20.0.0/24` then shows who's up there (ARP sweep, no ports). A range the box
   isn't attached to gets a ping sweep, and `hb` asks you to type `yes` first, unless that range
   is inside your active engagement (you already picked it).
2. **Pick it.** `hb engage start 10.20.0.0/24 --name lab-a` makes it the engagement for 12 hours
   (`--hours` up to 72). Ranges must be private, no bigger than a /16, and off the never list.
3. **Carry on.** `hb scan`, `hb flow` and the dashboard now reach only that range. Scan folders get
   an `engagement.txt` with the name. `hb engage` shows the time left. `hb engage end` stops it,
   and so does the clock: when it expires, lab scans are refused again.
4. **Next time.** Every engagement is saved by name. `hb engage labs` lists them,
   `hb engage start --lab lab-a` starts one again (re-checked against the never list), and
   `hb engage forget --lab lab-a` drops it. On the dashboard they're under **Your saved labs**
   with **Start again**.

The menus (`hb`, `hb gui`) have this as the first item, **Engagement: find and pick the lab**. On
the dashboard, it's the **Engagement** card at the top of Recon: **Find lab networks**, then
**Find hosts** or **Use as engagement**. While an engagement runs, the card has a **Find hosts**
button for each of its ranges; those sweeps (ping only, no ports) don't ask for approval.

**Approve all steps.** When a finding has two or more steps waiting for approval, its card shows
**Approve all N steps**. The sheet lists every exact command; one tap approves and queues them,
and each one is still digest- and scope-checked when it runs. Default-login tries, Wi-Fi attacks,
transmitting and your own recipes are left out and keep their own approval sheet each time.

**Known devices** (the tab that used to be called Mine) is your whitelist: tap **Known** on a scan
result to add it. Bluetooth probes, remote replays, Wi-Fi actions and transmitting only work on
things listed there.

Unlike the dashboard buttons, `hb` does **not** ask for approval. You're at the keyboard, the same
as in the Console.

## No commands to remember

- **`hb`** with nothing after it opens numbered menus: pick what to do, pick a network from your
  engagement, a host from your last scan, or type an IP, then pick how hard to look.
- **`hb gui`**, or the **havok-box scans** icon on the Kali desktop, does the same with clickable
  windows and a progress bar you can cancel.

Both cover: scan, quick workflow with a report, devices from a scan, open ports, find hosts by port
or service, compare two scans, browse past scans, and **check my hardware**.

## Hardware check

`hb hw` (also in the menus, and on the dashboard's Report tab) goes board by board and says
**Working**, **Needs attention** or **Not plugged in**, with the fix for each:

- **Alfa:** detected, and its interface came up.
- **RTL-SDR V3:** answers. The check reads its EEPROM, and flags it if another program has it open.
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

## Command toolbox (`hb kit`)

A catalog of about 70 common recon and enumeration commands (host discovery, port scans, nmap
scripts, web, SMB/AD, DNS, SNMP, Wi-Fi, Bluetooth, SDR receive, traffic capture, box info) plus
step-by-step chains such as **New network triage**, **Windows host enum**, **Web app first look**,
**BLE survey** and **Wi-Fi survey**.

- **Desktop:** double-click **havok-box toolbox** (or run `hb kit --gui`). It opens a page in the
  browser: pick a category or search, fill in the blanks (targets are suggested from the
  engagement), **Preview command**, then **Copy** or **Run in terminal**. Closing the small terminal
  window that started it stops the page.
- **SSH:** `hb kit` for numbered menus, `hb kit list`, `hb kit show <id>`,
  `hb kit run <id> target=10.20.0.0/24 [-n]` (`-n` prints without running).
- Every run gets a folder in `~/havok/kit/<time>_<id>/` with `command.txt`, `run.sh` and
  `output.log`, and a line in `~/havok/kit/history.log`.

Rules it enforces: there's no free-form command box; every blank is checked. Network targets must be
in the engagement and off the never list (nmap gets `--exclude`, and tools that can't skip addresses
refuse ranges that contain never-list hosts). Bluetooth recipes that connect to a device need it on
the Known devices tab. Exploitation, credential attacks, poisoning, deauth and RF transmit aren't in the
catalog, and the tests fail if one is added. Recipes are in `havokbox/kit_recipes.json`.
