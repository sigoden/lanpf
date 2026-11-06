# Installation and Operations

`lanfp` is distributed as a single portable binary. There is no installer, package manager
package or system service to set up.

## Pre-built binaries (recommended)

Download the archive for your platform from
[GitHub Releases](https://github.com/sigoden/lanfp/releases/latest), unpack it, and place the
`lanfp` binary (`lanfp.exe` on Windows) in a directory on your `PATH`.

| Platform | Archive |
| --- | --- |
| Linux x86_64 | `lanfp-v*-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `lanfp-v*-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `lanfp-v*-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `lanfp-v*-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `lanfp-v*-x86_64-pc-windows-msvc.zip` |

Verify the download:

```sh
lanfp --version
```

### Unix installer

`install.sh` detects the platform, downloads the latest release and installs the binary:

```sh
curl -fsSL https://raw.githubusercontent.com/sigoden/lanfp/main/install.sh \
  | sh -s -- --to "$HOME/.local/bin"
```

Options:

| Option | Description |
| --- | --- |
| `--to DIR` | Install into `DIR` (default: `/usr/local/bin`) |
| `--tag TAG` | Install a specific release tag instead of the latest |
| `--target TARGET` | Override platform detection, e.g. `x86_64-unknown-linux-musl` |
| `--force`, `-f` | Overwrite an existing binary |

The installer is intended for Linux and macOS. It needs `curl`, `tar` and `install`. Installing
to `/usr/local/bin` usually requires root. The `--to "$HOME/.local/bin"` form avoids that, but the
directory must be in your `PATH`.

### Windows

Download the `.zip` from Releases, extract `lanfp.exe`, and add its directory to `PATH`. A
PowerShell equivalent:

```powershell
$tag = (Invoke-RestMethod https://api.github.com/repos/sigoden/lanfp/releases/latest).tag_name
$zip = "lanfp-$tag-x86_64-pc-windows-msvc.zip"
Invoke-WebRequest "https://github.com/sigoden/lanfp/releases/download/$tag/$zip" -OutFile $zip
Expand-Archive $zip -DestinationPath "$env:LOCALAPPDATA\Programs\lanfp" -Force
```

Then add `%LOCALAPPDATA%\Programs\lanfp` to your `PATH`.

## Build from source

Requires Rust 1.84 or newer.

```sh
cargo build --release -p lanfp
# artifact: target/release/lanfp (target\release\lanfp.exe on Windows)
```

Install it into Cargo's binary directory:

```sh
cargo install --path crates/lanfp --locked
```

Run the tests:

```sh
cargo test --workspace
```

## First run

Any data command spawns the background instance automatically when needed. To start it
explicitly:

```sh
lanfp daemon start
lanfp daemon status
```

`lanfp serve` is the foreground debugging mode; logs go straight to stderr.

## Login autostart (optional)

```sh
lanfp daemon install
lanfp daemon uninstall
```

| Platform | Mechanism |
|---|---|
| Linux | `~/.config/systemd/user/lanfp.service`, `systemctl --user enable --now`; falls back to `~/.config/autostart/lanfp.desktop` without systemd |
| macOS | `~/Library/LaunchAgents/com.lanfp.serve.plist`, `launchctl bootstrap gui/<uid>` (falls back to the `user/<uid>` domain) |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\lanfp` |

Autostart is not registered by default; `uninstall` stops and removes it.

On macOS, when the command runs from a plain SSH session, launchd may refuse to bootstrap any
service in that session; the plist is still installed and starts at the next GUI login, and
`daemon install` says so. Run it from Terminal.app to activate the agent immediately.

## Firewall

- Inbound TCP on the agent port must be allowed (default 47811).
- mDNS uses UDP 5353 multicast; when blocked by a firewall/AP isolation, authorize manually
  with `lanfp peer grant <ip>[:port]` on the exposing machine.
- Linux: `ufw allow 47811/tcp` (as needed).
- macOS: the system prompts "allow incoming connections" on first listen; macOS 15+ may also
  require the "Local Network" permission.
- Windows: Windows Firewall prompts on first listen; choose to allow private networks.

## Ports and addresses

- The agent port is configured as `[agent] listen` in `config.toml`, default `0.0.0.0:47811`.
- After changing the agent port, restart the background instance:
  `lanfp daemon stop && lanfp daemon start`.
- Forwarding listeners bind `127.0.0.1` only, so no firewall opening is needed.

## Logs and troubleshooting

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
| `lanfp peer grant` exits with 4 | The target is not running `lanfp serve`, or the agent port is blocked |
| `lanfp remote` exits with 4 | The peer is offline; check the agent port/firewall |
| `forward add` exits with 5 | The local listening port is in use; pick another with `--listen`, or use `--listen 0` to let the OS choose |
| `forward add` exits with 7 | Port `<1024` without root; use a high port |
| Port owner shows `-` | The current user cannot see that process; the port itself still works |

## Upgrading and reinstalling a device

- Upgrading the binary does not change the identity keys (`identity.key` is persisted).
- Deleting the data directory or reinstalling the OS generates new keys; the peer must then
  re-authorize this device with `lanfp peer grant <peer> --force`.
- Backing up the data directory preserves identity, authorization records and
  forwarding rules.

## Uninstall

```sh
lanfp daemon uninstall
lanfp daemon stop
rm -rf ~/.config/lanfp ~/.local/share/lanfp ~/.local/state/lanfp
```

On macOS the equivalent is `~/Library/Application Support/lanfp`; on Windows it is
`%APPDATA%\lanfp` and `%LOCALAPPDATA%\lanfp`.
