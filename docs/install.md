# Installation and operations

`lanpf` is a single portable binary; there is no installer or system service to set up.

## Pre-built binaries

Download the archive for your platform from [GitHub Releases](https://github.com/sigoden/lanpf/releases/latest), unpack it, and put `lanpf` (`lanpf.exe` on Windows) in a directory on your `PATH`.

| Platform | Archive |
|---|---|
| Linux x86_64 | `lanpf-v*-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `lanpf-v*-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `lanpf-v*-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `lanpf-v*-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `lanpf-v*-x86_64-pc-windows-msvc.zip` |

**Unix installer.** `install.sh` detects the platform, downloads the latest release and installs the binary:

```sh
curl -fsSL https://raw.githubusercontent.com/sigoden/lanpf/main/install.sh | sh -s -- --to "$HOME/.local/bin"
```

| Option | Description |
| --- | --- |
| `--to DIR` | Install directory (default `/usr/local/bin`) |
| `--tag TAG` | Specific release instead of the latest |
| `--target TARGET` | Override platform detection, e.g. `x86_64-unknown-linux-musl` |
| `--force`, `-f` | Overwrite an existing binary |

Needs `curl`, `tar` and `install`. Installing to `/usr/local/bin` usually requires root; `--to "$HOME/.local/bin"` avoids that if the directory is in `PATH`.

## Build from source

Rust 1.84 or newer:

```sh
cargo build --release -p lanpf              # target/release/lanpf
cargo install --path crates/lanpf --locked
```

## First run and autostart

Data commands auto-start the daemon on the local machine; `lanpf daemon start` and `lanpf daemon status` manage it explicitly. The other machine must already be running its own daemon for `scan` and `peer grant` to reach it. `lanpf serve` runs it in the foreground with logs on stderr.

Login autostart is optional: `lanpf daemon install` registers it and `lanpf daemon uninstall` removes it.

| Platform | Mechanism |
|---|---|
| Linux | systemd user unit `~/.config/systemd/user/lanpf.service`; falls back to `~/.config/autostart/lanpf.desktop` without systemd |
| macOS | LaunchAgent `~/Library/LaunchAgents/com.lanpf.serve.plist` |
| Windows | HKCU `...\CurrentVersion\Run\lanpf`, running `serve --hidden` |

On macOS, `daemon install` from a plain SSH session may register the plist but activate it only at the next GUI login; run it from Terminal.app to activate immediately.

## Firewall and ports

- Allow inbound TCP on the agent port (default 47811); mDNS uses UDP 5353.
- If mDNS is blocked, authorize manually with `lanpf peer grant <ip>[:port]`.
- macOS may prompt to allow incoming connections and, on 15+, for "Local Network" access; Windows Firewall prompts on first listen (allow private networks).
- A daemon started from SSH or login autostart cannot show that prompt. On a Public network profile Windows blocks inbound by default, so add the inbound TCP rule for 47811 (and UDP 5353 if you rely on discovery) yourself, for example `netsh advfirewall firewall add rule name="lanpf" dir=in action=allow protocol=TCP localport=47811` from an elevated prompt.
- The agent port is `[agent] listen` in `config.toml`, default `0.0.0.0:47811`; restart after changing it. Forwarding listeners bind `127.0.0.1` only, so no firewall opening is needed.

## Logs and troubleshooting

```sh
lanpf daemon status
tail -f ~/.local/state/lanpf/lanpf.log
RUST_LOG=debug lanpf serve
```

| Symptom | Action |
|---|---|
| `daemon did not start within 5s` | Check the logs; verify the agent port is not in use |
| `peer grant` exits 4 | Target not running `lanpf serve`, or agent port blocked |
| `remote` exits 4 | Peer offline; check agent port/firewall |
| `forward add` exits 5 | Local port in use; use `--listen` or `--listen 0` |
| `forward add` exits 7 | Port `<1024` without root; use a high port |
| Port owner shows `-` | Process not visible to this user; the port still works |

## Upgrade, backup and uninstall

- Upgrading the binary keeps the identity (`identity.key` is persisted); deleting the data directory or reinstalling the OS creates new keys, so re-authorize with `lanpf peer grant <peer> --force`.
- Backing up the data directory preserves identity, authorizations and rules.

```sh
lanpf daemon uninstall
lanpf daemon stop
rm -rf ~/.config/lanpf ~/.local/share/lanpf ~/.local/state/lanpf
```

macOS uses `~/Library/Application Support/lanpf`; Windows uses `%APPDATA%\lanpf` and `%LOCALAPPDATA%\lanpf`.
