# Claude on the box

## Claude Code (terminal)

`scripts/kali-setup.sh` installs Claude Code for the box user (skip it with `--no-claude`).

1. SSH in (or open the **Claude Code (havok-box)** icon on the Kali desktop).
2. Run `cd ~/havok-box && claude`. The first run prints a sign-in link. Open it on your phone or Mac,
   sign in with your Claude account, and paste the code back if it asks. A Pro or Max plan covers
   it; an `ANTHROPIC_API_KEY` works too, but bills per token.
3. Ask in plain words, for example: "run hb hw and tell me what's broken", "summarize the last
   scan", "which hosts have SMB open", "why won't the RTL-SDR open".

`CLAUDE.md` in the repo gives every session the box's ground rules: lab scope only, standard tools,
no exploit writing, no transmitting, and leave the secrets alone. `.claude/settings.json` backs that up:

- **Runs without asking:** `hb hw`, `hb hosts`, `hb ports`, `hb diff`, `hb last`, and the tests.
- **Asks you first:** `hb scan`, `hb flow`, raw `nmap`, `sudo`, `systemctl`, `nmcli`.
- **Blocked:** rfcat, aireplay-ng, mdk4, mitm6, responder and hydra from the shell. It also can't
  edit `config/scope.yaml` or `config/box.json`, or read `/etc/havokbox` or the secrets folder.

These rules match the command Claude types. They are guardrails, not a sandbox: like the Console,
a Claude Code session on the box is a shell, so the dashboard's approval gate is still the real
control for anything active.

## Claude in a browser

On the Kali desktop (Screen Sharing or noVNC), open Firefox and go to claude.ai.
