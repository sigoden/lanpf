# lanfp

**Reach a service on another computer in your LAN as if it were running on your own machine.**

`lanfp` forwards TCP ports between computers on the same local network. Install it on two
machines, pair them once with a 6-digit code, and then `127.0.0.1:3000` on your laptop can reach
the dev server running on your desktop.

No router port forwarding, no public exposure, no SSH tunnel to keep open, and no administrator
rights.

## Why lanfp?

You have something useful running on another machine at home or in the office: a dev server, a
database, a dashboard. You want to use it from your laptop without exposing it to the internet
or configuring network gear.

`lanfp` gives you:

- **One-time pairing.** Two machines learn to trust each other through a 6-digit code.
- **Port discovery.** See which TCP ports the other machine is listening on, instead of guessing.
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

**1. On `mac-mini`, wait for a pairing request.**

```sh
$ lanfp pair wait
waiting for pairing request (Ctrl-C to cancel)...
```

**2. On `nix`, find `mac-mini` and start pairing.**

```sh
$ lanfp scan
PEER ID   PEER                    PORT    STATE
5e6f7a8b  mac-mini@192.168.8.10   47811   unpaired

$ lanfp pair mac-mini
connecting to mac-mini...
pairing code (shown on mac-mini):
```

**3. Read the code from `mac-mini` and type it into the prompt on `nix`.**

`mac-mini` now shows:

```sh
incoming: nix@192.168.8.11
pairing code: 123456   expires in 300s
```

After entering the code, `nix` confirms:

```sh
paired with mac-mini@192.168.8.10 [5e6f7a8b]
```

**4. See what `mac-mini` is serving.**

```sh
$ lanfp remote
PEER ID   PEER                    PORT   BIND        PROCESS   USER   FORWARDED
5e6f7a8b  mac-mini@192.168.8.10   3000   127.0.0.1   node      sigo   -
```

**5. Forward the port and use it locally.**

```sh
$ lanfp forward add mac-mini 3000
created 3000 -> mac-mini@192.168.8.10:3000 (active)
$ curl http://127.0.0.1:3000
```

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

Some firewalls, VPNs and Wi-Fi access points block mDNS. Pair by address instead:

```sh
lanfp pair 192.168.8.10
# or, when the agent port is not 47811:
lanfp pair 192.168.8.10:5000
```

If a device's address changes later, update it without pairing again:

```sh
lanfp peer set-address mac-mini 192.168.8.23
```

## Good to know

- **Pairing is authorization.** A paired device can forward to any TCP port this machine is
  listening on. This version has no per-port approval or revoke command, so only pair devices you
  trust. `lanfp inbound` shows who is forwarding your ports.
- **Traffic stays on your LAN.** Connections use TLS 1.3 with pinned keys. There is no cloud relay
  and no public exposure.
- **TCP only.** UDP, multi-hop, NAT traversal and public relays are not supported.
- **Forwarded ports listen on `127.0.0.1` only.** The agent port is the only LAN-facing listener.

Read the [security model](docs/security.md) before pairing a device you do not fully control.

## Documentation

| Document | What it covers |
| --- | --- |
| [Installation and operations](docs/install.md) | Downloads, source builds, autostart, firewall, logs, upgrades, uninstall |
| [Usage and command reference](docs/usage.md) | Every command, peer selectors, JSON output, exit codes, configuration |
| [Security model](docs/security.md) | Trust boundaries, pairing, transport, accepted risks |
| [Known limitations](docs/limitations.md) | Platform behaviour and current gaps |
| [Verification](docs/verification.md) | Automated tests and real-hardware acceptance results |

## Platform support

Linux, macOS and Windows are supported. Linux has passed the loopback end-to-end tests, and
two-host LAN runs have passed between Linux and macOS and between Linux and Windows. See
[Verification](docs/verification.md) for details and [Known limitations](docs/limitations.md) for
what is still unverified.

## License

Licensed under either of the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
