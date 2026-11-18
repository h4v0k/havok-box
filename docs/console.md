# Console (web terminal) — setup

Off by default. To turn it on:

1. Set `"console_enabled": true` in `config/box.json`.
2. Run `python3 -m havokbox.provision` so the TLS cert exists — the console refuses to start without it.
3. Set a console password **different from the dashboard token**: `HAVOKBOX_CONSOLE_PASSWORD` in the
   watchdog's environment (systemd `EnvironmentFile=`, mode 0600). ttyd's `-c` credential is visible in
   `/proc/*/cmdline`, which is why it is never the dashboard token.
4. Restrict the port to box-LAN clients. ttyd can only bind an interface, so filter by source:

```
# /etc/nftables.d/havokbox-console.nft
table inet havokbox {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 7681 ip saddr != 192.168.4.0/24 drop
  }
}
```

Keep `lan_cidrs`, `box_address` and this rule in sync.

## Known limits

- The transcript is hashed when the session **ends**. Someone in the shell could edit it mid-session,
  so the hash only shows the file hasn't changed since the session closed.
