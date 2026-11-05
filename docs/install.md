# Installation and Operations

## Build

```sh
cargo build --release -p lanfp
install -m 0755 target/release/lanfp ~/.local/bin/lanfp   # Linux/macOS
```

On Windows, just copy `target\release\lanfp.exe`. The current release is a portable binary; no
installer is provided.

## First Run

Any data command spawns the background instance automatically when needed:

```sh
lanfp daemon start
lanfp daemon status
```

`lanfp serve` is the foreground debugging mode; logs go straight to stderr.

## Login Autostart (Optional)

```sh
lanfp daemon install
lanfp daemon uninstall
```

| Platform | Mechanism |
|---|---|
| Linux | `~/.config/systemd/user/lanfp.service`, `systemctl --user enable --now`; falls back to `~/.config/autostart/lanfp.desktop` without systemd |
| macOS | `~/Library/LaunchAgents/com.lanfp.serve.plist`, `launchctl load -w` |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\lanfp` |

Autostart is not registered by default; `uninstall` stops and removes it.

## Firewall

- Inbound TCP on the agent port must be allowed (default 47811).
- mDNS uses UDP 5353 multicast; when blocked by a firewall/AP isolation, pair manually with
  `lanfp pair <ip>[:port]`.
- Linux: `ufw allow 47811/tcp` (as needed).
- macOS: the system prompts "allow incoming connections" on first listen; macOS 15+ may also
  require the "Local Network" permission.
- Windows: Windows Firewall prompts on first listen; choose to allow private networks.

## Ports and Addresses

- The agent port is configured as `[agent] listen` in `config.toml`, default `0.0.0.0:47811`.
- After changing the agent port, restart the background instance:
  `lanfp daemon stop && lanfp daemon start`.
- Forwarding listeners bind `127.0.0.1` only, so no firewall opening is needed.

## Logs and Troubleshooting

```sh
lanfp daemon status          # PID, uptime, agent address, IPC, log path
tail -f ~/.local/state/lanfp/lanfp.log
RUST_LOG=debug lanfp serve   # foreground debugging
```

Common issues:

| Symptom | Action |
|---|---|
| `daemon did not start within 5s` | Check the logs; verify the agent port is not in use |
| `lanfp is already running` | The single-instance lock is working; inspect it with `daemon status` |
| `lanfp pair` exits with 6 | The peer is not running `lanfp pair wait`, or a firewall is blocking it |
| `lanfp remote` exits with 4 | The peer is offline; check the agent port/firewall |
| `forward add` exits with 5 | The local listening port is in use; pick another with `--listen` |
| `forward add` exits with 7 | Port `<1024` without root; use a high port |
| Port owner shows `-` | The current user cannot see that process; the port itself still works |

## Upgrading and Reinstalling a Device

- Upgrading the binary does not change the identity keys (`identity.key` is persisted).
- Deleting the data directory or reinstalling the OS generates new keys; the peer must then
  re-trust this device with `lanfp pair <peer> --force`.
- Backing up the data directory preserves identity, pairings and rules.

## Uninstall

```sh
lanfp daemon uninstall
lanfp daemon stop
rm -rf ~/.config/lanfp ~/.local/share/lanfp ~/.local/state/lanfp
```

On macOS the equivalent is `~/Library/Application Support/lanfp`; on Windows it is
`%APPDATA%\lanfp` and `%LOCALAPPDATA%\lanfp`.
