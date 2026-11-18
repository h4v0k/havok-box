# Kali expansion — recipes, Recon/Enumerate pack, Test pack, AI session report (design)

Lab-only. Everything wraps standard installed Kali tools; no hand-written exploit code or payloads.
Every tool still goes through the registry → category binding → scope gate → typed params →
(approval for anything active) → orchestrator. The Console stays the only free-form shell.

## 1. Recipe file (`config/recipes.yaml`)

Owner-written YAML that turns any installed tool into a gated dashboard button without a code wrapper.

```yaml
- name: recipe.sslscan            # must start with "recipe."
  label: "TLS scan {ip}:{port}"
  space: wired
  phase: enumerate                 # recon | enumerate | test
  category: recon.active           # must be a known gate category
  params:
    ip:   {type: ip, required: true}
    port: {type: int, min: 1, max: 65535, default: 443}
  argv: ["sslscan", "--no-colour", "{ip}:{port}"]
  timeout_s: 300
  parse: lines                     # lines | json | xml | none — generic parser, capped
```

- Loaded once at boot (never hot-reloaded), human-written like the scope file.
- Validation fails closed on: unknown category, a missing gate target key for that category
  (`recon.active`/`auth.attempt` need `ip`; `wifi.*` need `bssid`; …), argv[0] that is a shell or
  interpreter (`sh`, `bash`, `python*`, `perl`, `env`, `busybox`, …), a placeholder not declared in
  params, a placeholder inside argv[0], or param type `str`.
- Placeholders substitute **whole argv elements or part of one element** after validation; there is
  never a shell. Defaults are applied before the preview, so the digest covers real values.
- A recipe whose binary isn't installed (`shutil.which`) is hidden (inventory).
- Recipes appear as buttons on their space's card (recon) or as proposals the operator can add to
  a finding target (enumerate/test).

## 2. Tool inventory

At boot, `shutil.which` every registered tool's binary. Missing tools are hidden from cards and the
planner, and the Report tab lists "not installed: …".

## 3. Recon + Enumerate pack

| Tool | Name | Category | Notes |
|---|---|---|---|
| Responder `-A` (analyze) | `responder.analyze` | recon.passive | listens only; parse names + requesting hosts |
| p0f | `p0f.listen` | recon.passive | passive OS fingerprint, timed |
| tshark cleartext finder | `cleartext.find` | recon.passive | protocol presence only (telnet/ftp/http-basic/snmpv1/pop3/imap); never credentials |
| THC-IPv6 `detect-new-ip6` | `ipv6.listen` | recon.passive | timed |
| nuclei | `nuclei.scan` | recon.active | allowlisted tags only (exposure, misconfig, tech, default-login *detection*), `-exclude-tags intrusive,dos,fuzz`, rate limited, `-disable-update-check`, no interactsh |
| testssl.sh | `tls.scan` | recon.active | `--fast` stealth / full standard |
| feroxbuster | `web.content` | recon.active | small bundled wordlist, rate limit, depth 1 |
| netexec smb | `smb.nxc` | recon.active | null session: shares, signing, OS |
| ldapsearch | `ldap.anon` | recon.active | anonymous base/rootDSE + naming contexts |
| onesixtyone + snmpwalk | `snmp.enum` | recon.active | community list = public/private only |
| searchsploit | `exploit.lookup` | (offline, no target) | maps service versions to Exploit-DB titles in the report; runs nothing |

## 4. Test pack (approval, per action)

| Tool | Name | Category | Limits |
|---|---|---|---|
| netexec / hydra | `creds.default` | auth.attempt | bundled default-cred list ≤ 20 pairs per service; 1 thread; ≥ 1 s between tries; stops on first success |
| Responder (poisoning) | `net.poison.responder` | **net.poison** (new) | interface bound; target network must be in `networks.poison_allowed` (separate, explicit list — isolated lab VLAN only); duration ≤ 300 s |
| mitm6 | `net.poison.mitm6` | **net.poison** | same + `-d` domain must be in scope `domains`; duration ≤ 300 s |
| eaphammer / hostapd-mana | `wifi.rogue_ap` | **wifi.rogue_ap** (new) | SSID must be in `wifi.ssids`; duration ≤ 300 s; Alfa only |

New gate categories: `net.poison` (network ⊂ `networks.poison_allowed`), `wifi.rogue_ap` (ssid ∈ `wifi.ssids`). Both approval, both refused during wardrive.

## 5. AI session report

`
The AI session report is an optional, read-only write-up produced at the end of a session (or on
demand from the Report tab). It takes the on-box digest of findings + attack path + evidence and
asks the existing API commander (same key, same hard spend cap as the wardrive commander) to write
a short prose summary: what was found, notable services/vulns, the attack path taken, and suggested
next *standard* steps. Constraints:
- Off unless the commander is enabled and under its spend cap; never blocks anything.
- Only the capped digest leaves the box (no raw tool output, no captured hashes, no credentials).
- The model only writes prose; it proposes nothing executable and triggers no action.
- Stored locally (`session_reports`), shown on the Report tab, never published to Cloudflare.

## Scope limits (these govern the build; where they differ from the tables above, these win)

- **Recipes, inventory, and the whole Recon/Enumerate pack (section 3):** build as written. nuclei
  stays detection-only (`-exclude-tags intrusive,dos,fuzz`, allowlisted tags, no interactsh); the
  cleartext finder reports protocol presence only and never captures or prints credential material.
- **`creds.default`:** build as written — bundled list ≤ 20 pairs, 1 thread, ≥ 1 s between tries,
  stop on first success, per-action approval.
- **`net.poison.*` and `wifi.rogue_ap`:** build, but only against an **isolated lab VLAN** the owner
  has put in a separate, explicit `networks.poison_allowed` (poisoning) / own `wifi.ssids` (rogue AP)
  list. Per-action approval, ≤ 300 s, refused during wardrive/sentry/survey. Anything these capture
  (hashes, etc.) stays on the box: it is never sent to the AI commander and the box never cracks it
  (capture, don't crack — cracking is offloaded to the homelab, as with Wi-Fi handshakes).
- **Not built, in any framing:** poisoning or a rogue AP on any network/SSID not in those explicit
  lab lists; extracting or displaying credentials from captured traffic; any cracking on the box;
  exploit code or payloads; autonomous exploitation. These are refusals, not TODOs.
