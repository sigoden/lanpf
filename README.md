# lanpf

**Reach a service on another computer in your LAN as if it were running on your own machine.**

`lanpf` forwards TCP ports between computers on the same LAN. Install it on two machines, authorize one to use the other, and `127.0.0.1:3000` on one machine reaches the dev server on the other. No router changes, no public exposure, no SSH tunnel, no root.

## Features

**Forwarding**

- **Local loopback forwarding.** `lanpf forward add <peer> 3000` opens `127.0.0.1:3000` on the machine running the command; `--listen` picks another port and `--listen 0` picks a free one.
- **Zero-config discovery.** `lanpf scan` finds devices over mDNS, so you do not have to know addresses or ports; `lanpf local` and `lanpf remote` show what is listening on either side.

**Access control**

- **One-way authorization.** The machine that exposes a service authorizes the machine that may use it. No pairing code, no waiting screen, and no reciprocal access unless you grant it.
- **Explicit exposure.** Share every listening port by default, or whitelist ports and ranges in `config.toml`. A whitelisted port can be shared before its service starts.
- **Instant revocation.** `lanpf peer revoke` removes the key from the allow-list and drops the live session.

**Trust and identity**

- **Safe by default.** Forwarded ports bind `127.0.0.1`, the agent port is the only LAN-facing listener, and sessions use TLS 1.3 with pinned Ed25519 keys.
- **Identity survives network changes.** A stable UUID and pinned key follow a device across IP changes, with `peer set-address` when mDNS cannot be used.

**Operations**

- **One binary, no root.** Linux, macOS and Windows; runs as your user with no system service, and login autostart is optional.
- **Scriptable and self-starting.** `--json` with `schema: 2` plus stable exit codes; data commands auto-start the local daemon.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/sigoden/lanpf/releases/latest), unpack it, and put `lanpf` (`lanpf.exe` on Windows) in your `PATH`.

Unix one-liner:

```sh
curl -fsSL https://raw.githubusercontent.com/sigoden/lanpf/main/install.sh | sh -s -- --to "$HOME/.local/bin"
```

Build from source (Rust 1.84 or newer):

```sh
cargo install --path crates/lanpf --locked
```

## Quick start

`nix` runs a web app on port 3000; open it from `mac-mini`.

**1. Start the daemon on both machines.**

Devices are advertised and reached through the daemon, so it must already be running on the other machine before you scan or grant:

```sh
lanpf daemon start    # background, run on both nix and mac-mini
# lanpf serve         # foreground alternative, logs on stderr
```

`lanpf daemon install` registers the daemon at login. Data commands auto-start it only on the machine you run them on, so starting `lanpf scan` on `nix` does not start anything on `mac-mini`; a device whose daemon is not running cannot be discovered or granted.

**2. On `nix`, find the device and authorize it.**

```sh
$ lanpf scan
PEER ID    PEER                    PORT    VERSION   STATE
5e6f7a8b   mac-mini@192.168.8.11   47811   2         unknown

$ lanpf peer grant mac-mini@192.168.8.11
granted mac-mini@192.168.8.11 [5e6f7a8b]
key fingerprint: 1a2b...
mac-mini@192.168.8.11 may now connect and forward exposed ports on this machine
```

If `mac-mini` is not listed, check that its daemon is running (`lanpf daemon status` on that machine) and that mDNS is not blocked; see [If mDNS discovery fails](#if-mdns-discovery-fails). `peer grant` also needs the other machine's daemon, because the grant handshake runs against its agent port.

**3. Optionally restrict what it can reach.** Without a whitelist every listening port is exposed. Add one in `config.toml`:

```toml
[agent]
expose_ports = ["3000", "3001", "8000-8100"]
```

The daemon picks up the whitelist within about 5 seconds. A whitelisted port may be listed before its service listens.

**4. On `mac-mini`, see the exposed ports and forward one.**

```sh
$ lanpf remote
PEER ID    PEER               PORT   STATE       BIND        PROCESS   USER   FORWARDED
5e6f7a8b   nix@192.168.8.10   3000   listening   127.0.0.1   node      sigo   -

$ lanpf forward add nix 3000
created 3000 -> nix@192.168.8.10:3000 (active)

$ curl http://127.0.0.1:3000
```

If 3000 is taken locally, `--listen 0` picks a free loopback port. Remove the forward with `lanpf forward remove 3000`.

### If mDNS discovery fails

Some firewalls, VPNs and Wi-Fi access points block mDNS. On `nix`, authorize `mac-mini` by address instead: `lanpf peer grant 192.168.8.11` (add `:port` when its agent port is not 47811). If `nix`'s address changes later, update it on `mac-mini` with `lanpf peer set-address nix 192.168.8.23`.

## Documentation

| Document | Covers |
| --- | --- |
| [Installation and operations](docs/install.md) | Downloads, source builds, autostart, firewall, logs, upgrades, uninstall |
| [Usage and command reference](docs/usage.md) | Commands, selectors, exposure, JSON, exit codes, configuration |
| [Security model](docs/security.md) | Trust boundaries, authorization, exposure, transport, accepted risks |
| [Known limitations](docs/limitations.md) | Platform behaviour and current gaps |
| [Tests and verification](docs/verification.md) | Automated coverage and current verification status |

## License

Licensed under either of the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.
