# lanfp

**Reach a service on another computer in your LAN as if it were running on your own machine.**

`lanfp` forwards TCP ports between computers on the same local network. Install it on two
machines, authorize one device to use the other, and then `127.0.0.1:3000` on your laptop can
reach the dev server running on your desktop.

No router port forwarding, no public exposure, no SSH tunnel to keep open, and no administrator
rights.

## Why lanfp?

You have something useful running on another machine at home or in the office: a dev server, a
database, a dashboard. You want to use it from your laptop without exposing it to the internet
or configuring network gear.

`lanfp` gives you:

- **One-way authorization.** The machine that exposes a service authorizes the machine that may
  use it. No six-digit code, no waiting screen.
- **Explicit exposure.** Expose every listening port by default, or switch to a whitelist and
  decide exactly which ports authorized devices may reach. A port may be exposed before the
  service starts listening.
- **Port discovery.** See which ports the other machine is listening on or has exposed, instead
  of guessing.
- **Local forwarding.** `lanfp forward add mac-mini 3000` opens `127.0.0.1:3000` on your machine.
- **Safe defaults.** Forwarded ports are localhost-only; the agent port is the only LAN-facing
  listener.
- **Runs as you.** One binary for Linux, macOS and Windows. No root, no system service, optional
  login autostart.

## Install

### Download a release (recommended)

Pick the archive for your OS and CPU from
[GitHub Releases](https://github.com/sigoden/lanfp/releases/latest), unpack it, and put `lanfp`
(`lanfp.exe` on Windows) somewhere in your `PATH`.

### Unix one-liner

The installer detects your platform, downloads the latest release and puts `lanfp` in
`~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/sigoden/lanfp/main/install.sh \
  | sh -s -- --to "$HOME/.local/bin"
```

### Build from source

Rust 1.84 or newer:

```sh
cargo install --path crates/lanfp --locked
```

See [Installation and operations](docs/install.md) for source builds, autostart, firewall rules
and uninstall steps.

## Quick start

Suppose `mac-mini` runs a web app on port 3000 and you want to open it from `nix`.

**1. On `mac-mini` (the exposing machine), find the device to authorize.**

```sh
$ lanfp scan
PEER ID   PEER                    PORT    VERSION   STATE
5e6f7a8b  nix@192.168.8.11        47811   2         unknown
```

**2. Authorize it.**

```sh
$ lanfp peer grant
discovered devices:
  1. 5e6f7a8b nix@192.168.8.11        unknown
select device [1-1] (q to cancel): 1
granted nix@192.168.8.11 [5e6f7a8b]
key fingerprint: 1a2b...
this device may now connect and forward exposed ports on this machine
```

Or pass the selector directly: `lanfp peer grant nix@192.168.8.11`.

**3. Optionally restrict what `nix` may reach.**

Without any `lanfp expose` entries, every listening port on `mac-mini` is exposed. Add a
whitelist when you want to reduce that set:

```sh
$ lanfp expose add 3000
exposed 3000
$ lanfp expose list
mode: whitelist (only listed ports are exposed)
PORT   STATE       BIND         PROCESS   USER   INBOUND
3000   listening   127.0.0.1    node      sigo   -
```

A whitelist entry may be added before the service starts listening; `expose list` and `remote`
show it as `not listening`.

**4. On `nix`, see what `mac-mini` exposes.**

```sh
$ lanfp remote
PEER ID   PEER                     PORT   STATE       BIND        PROCESS   USER   FORWARDED
5e6f7a8b  mac-mini@192.168.8.10    3000   listening   127.0.0.1   node      sigo   -
```

`lanfp remote` without a peer lists every server that authorized this machine. If the peer is
still connecting, wait a moment and run it again.

**5. Forward the port and use it locally.**

```sh
$ lanfp forward add mac-mini 3000
created 3000 -> mac-mini@192.168.8.10:3000 (active)
$ curl http://127.0.0.1:3000
```

If `3000` is already in use locally, add `--listen 0`; lanfp prints the free loopback port it
picked.

**6. Remove the forward when you are done.**

```sh
$ lanfp forward remove 3000
removed 3000
```

The background daemon starts automatically. To start it at login:

```sh
lanfp daemon install
```

### If discovery does not work

Some firewalls, VPNs and Wi-Fi access points block mDNS. Authorize by address instead:

```sh
# On the exposing machine:
lanfp peer grant 192.168.8.11
# or, when the consumer's agent port is not 47811:
lanfp peer grant 192.168.8.11:5000
```

If a device's address changes later, update it without granting again:

```sh
lanfp peer set-address mac-mini 192.168.8.23
```

## Good to know

- **Authorization is one-way.** `lanfp peer grant` on the exposing machine lets the selected
  device connect and forward to exposed ports. It does not let the exposing machine access the
  consumer. `lanfp peer list` shows only devices this machine has authorized.
- **Exposure is a whitelist.** With no entries, every listening Native port is exposed. Once
  there is at least one entry, only those ports are exposed. Removing the last entry returns to
  "all listening ports".
- **No code-based pairing.** The grant is confirmed by the devices' Ed25519 identities and the
  public key advertised over mDNS; manually entered addresses are trust-on-first-use. Verify the
  printed fingerprint with `lanfp daemon status` on the other device if you need to.
- **Authorization can be revoked.** `lanfp peer revoke <peer>` immediately removes the device
  from the TLS allow-list and drops its session. The consumer's `lanfp remote` then reports the
  server as offline.
- **Traffic stays on your LAN.** Connections use TLS 1.3 with pinned keys. There is no cloud relay
  and no public exposure.
- **TCP only.** UDP, multi-hop, NAT traversal and public relays are not supported.
- **Forwarded ports listen on `127.0.0.1` only.** The agent port is the only LAN-facing listener.
- `lanfp inbound` remains the read-only view of which ports are currently being forwarded by
  other devices.

Read the [security model](docs/security.md) before authorizing a device you do not fully control.

## Documentation

| Document | What it covers |
| --- | --- |
| [Installation and operations](docs/install.md) | Downloads, source builds, autostart, firewall, logs, upgrades, uninstall |
| [Usage and command reference](docs/usage.md) | Every command, selectors, exposure, JSON output, exit codes, configuration |
| [Security model](docs/security.md) | Trust boundaries, authorization, exposure, transport and accepted risks |
| [Known limitations](docs/limitations.md) | Platform behaviour and current gaps |
| [Verification](docs/verification.md) | Automated tests and real-hardware acceptance results |

## Platform support

Linux, macOS and Windows are supported. Linux has passed the loopback end-to-end tests, and
two-host LAN runs have passed between Linux and macOS and between Linux and Windows under the
earlier pairing model. See [Verification](docs/verification.md) for details and
[Known limitations](docs/limitations.md) for what is still unverified.

## License

Licensed under either of the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
