# lanfp

**Reach a service on another computer in your LAN as if it were running on your own machine.**

`lanfp` forwards TCP ports between computers on the same LAN. Install it on two machines, authorize one to use the other, then `127.0.0.1:3000` on your laptop reaches the dev server on your desktop. No router changes, no public exposure, no SSH tunnel, no root.

## Features

- **One-way authorization.** The machine that exposes a service authorizes the machine that may use it. No pairing code, no waiting screen, and no reciprocal access unless you grant it.
- **Explicit exposure.** Share every listening port by default, or whitelist ports and ranges in `config.toml`. A whitelisted port can be shared before its service starts.
- **Local loopback forwarding.** `lanfp forward add <peer> 3000` opens `127.0.0.1:3000` on your machine; `--listen` picks another port and `--listen 0` picks a free one.
- **Zero-config discovery.** `lanfp scan` finds devices over mDNS; `lanfp local` and `lanfp remote` show what is listening or exposed, so you do not have to guess ports.
- **Safe by default.** Forwarded ports bind `127.0.0.1`, the agent port is the only LAN-facing listener, and sessions use TLS 1.3 with pinned Ed25519 keys.
- **Instant revocation.** `lanfp peer revoke` removes the key from the allow-list and drops the live session.
- **Identity survives network changes.** A stable UUID and pinned key follow a device across IP changes, with `peer set-address` when mDNS cannot be used.
- **One binary, no root.** Linux, macOS and Windows; runs as your user with no system service, and login autostart is optional.
- **Scriptable and self-starting.** `--json` with `schema: 2` plus stable exit codes; data commands auto-start the daemon.

## Install

Download the archive for your platform from [GitHub Releases](https://github.com/sigoden/lanfp/releases/latest), unpack it, and put `lanfp` (`lanfp.exe` on Windows) in your `PATH`.

Unix one-liner:

```sh
curl -fsSL https://raw.githubusercontent.com/sigoden/lanfp/main/install.sh | sh -s -- --to "$HOME/.local/bin"
```

Build from source (Rust 1.84 or newer):

```sh
cargo install --path crates/lanfp --locked
```

## Quick start

`nix` runs a web app on port 3000; open it from `mac-mini`.

**1. On `nix`, find the device and authorize it.**

```sh
$ lanfp scan
PEER ID    PEER                    PORT    VERSION   STATE
5e6f7a8b   mac-mini@192.168.8.11   47811   2         unknown

$ lanfp peer grant mac-mini@192.168.8.11
granted mac-mini@192.168.8.11 [5e6f7a8b]
key fingerprint: 1a2b...
mac-mini@192.168.8.11 may now connect and forward exposed ports on this machine
```

**2. Optionally restrict what it can reach.** Without a whitelist every listening port is exposed. Add one in `config.toml`:

```toml
[agent]
expose_ports = ["3000", "3001", "8000-8100"]
```

The daemon picks up the whitelist within about 5 seconds. A whitelisted port may be listed before its service listens.

**3. On `mac-mini`, see the exposed ports and forward one.**

```sh
$ lanfp remote
PEER ID    PEER               PORT   STATE       BIND        PROCESS   USER   FORWARDED
5e6f7a8b   nix@192.168.8.10   3000   listening   127.0.0.1   node      sigo   -

$ lanfp forward add nix 3000
created 3000 -> nix@192.168.8.10:3000 (active)

$ curl http://127.0.0.1:3000
```

If 3000 is taken locally, `--listen 0` picks a free loopback port. Remove the forward with `lanfp forward remove 3000`.

**4. Start the daemon at login (optional).**

```sh
lanfp daemon install
```

### If mDNS discovery fails

Some firewalls, VPNs and Wi-Fi access points block mDNS. On `nix`, authorize `mac-mini` by address instead: `lanfp peer grant 192.168.8.11` (add `:port` when its agent port is not 47811). If `nix`'s address changes later, update it on `mac-mini` with `lanfp peer set-address nix 192.168.8.23`.

## Good to know

- **`peer list` is not everyone you know.** It lists only devices this machine authorized; on the consumer, servers appear in `remote` and in `scan` as `server`.
- **Emptying the whitelist** returns to exposing every listening port. There is no per-device ACL: every authorized device sees the same set.
- **Trust is pin-based.** The grant is confirmed by Ed25519 identities and, when available, the mDNS key; manual addresses are trust-on-first-use. Compare the printed fingerprint with `lanfp daemon status` if needed.
- **Revocation is not pushed.** `peer revoke` drops the session immediately, but the consumer keeps an offline record until a later grant.
- **TCP only.** No UDP, multi-hop, NAT traversal or public relay.
- **`lanfp inbound`** is the read-only view of ports currently forwarded by other devices.

Read the [security model](docs/security.md) before authorizing a device you do not fully control.

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
