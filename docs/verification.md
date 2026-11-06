# Tests and verification

## Automated tests

`cargo test --workspace` runs each crate's unit tests plus the loopback suite in `crates/lanpf/tests/e2e.rs`.

| Suite | Coverage |
|---|---|
| `lanpf-core` | Frame and IPC codecs, protocol messages, grant/exposure round-trips, peer selectors and display names |
| `lanpf-crypto` | Identity persistence, Ed25519 signatures, transcripts, fingerprints, certificate parsing and key pinning |
| `lanpf-inventory` | Port classification, native filtering, self-listener exclusion, macOS `netstat` parsing |
| `lanpf` | Configuration, database trust directions, exposure policy, discovery TXT parsing, output helpers and CLI utilities |
| Loopback E2E | Two daemons, one-way grant, session establishment, exposure and listening views, non-listening whitelist targets, revocation, forwarding (100 MiB transfer, half-close, 100 concurrent streams, `--listen 0`), IPC privacy, exit codes, JSON, rule recovery, selectors and address updates |

## Key commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --release -p lanpf
```

## Current status

- CI builds, tests, formats and lints the workspace on Ubuntu, macOS and Windows (`.github/workflows/ci.yml`).
- The loopback E2E suite runs on Unix (Linux and macOS); Windows runs the unit tests only.
- macOS runs the full suite including the loopback E2E; Windows runs the unit tests. Both passed on the current tree.

## Two-host LAN run

A macOS 15.5 (Apple silicon) machine and a Windows 11 VM were paired over a switched
100BASE-TX LAN, both running the release binary with isolated `LANPF_HOME` trees.

| Area | Result |
|---|---|
| Discovery | mDNS advertisement and browsing worked in both directions; `scan` and `scan --json` reported name, UUID, port and key. Only the agent port was opened in the Windows firewall (no UDP 5353 rule). |
| Authorization | `peer grant` by name and by address, text and JSON; the granting side showed `authorized`/`online`, the consumer showed the peer as a `server`; fingerprints matched on both sides. Grant, revoke, `peer set-address` and ambiguous-selector exit 2 were exercised. |
| Exposure | Blanket mode listed every Native port of the Windows host. A whitelist reloaded live within about 5 s, listed the configured ranges plus listening whitelisted ports, and rejected a listening but non-whitelisted port with exit 8. |
| Forwarding | Rules in both directions, `--listen 0`, JSON, `target_gone` rules that became `active` when the target started listening, 100 MiB transfers with matching SHA-256 (~9-10 s at 100 Mbit/s link speed) and 20 concurrent streams. A revoked peer left rules `peer_offline` and reset new connections. |
| Lifecycle | Rules, identity, trust and whitelist survived daemon restarts. A second `serve` exited with "already running". Windows `daemon install` wrote the HKCU Run entry with `serve --hidden`; the macOS LaunchAgent plist was written and removed correctly and still warned that an SSH session cannot bootstrap it. |
| Exit codes | 0, 2, 3, 4, 5, 7 and 8 verified on both platforms. Windows allows `forward add --listen 80`; an occupied high port exits 5 and names the occupant. |

Defects found during the run and fixed:

- mDNS advertised every interface address regardless of the agent's bind family. With the default
  `0.0.0.0` listener the agent is IPv4-only, yet peers could resolve an AAAA record; after a host
  restart the consumer dialed the unreachable IPv6 address and forwarding timed out. Advertising now
  follows the listener family, A/AAAA results are merged instead of replaced, and dialing falls back
  to the last working address when the fresh mDNS hint fails.
- Windows reports a reserved or occupied port as `WSAEACCES`. `forward add --listen 445` therefore
  exited 7 with a "use a port >= 1024" hint; a permission-denied bind now maps to exit 7 only below
  port 1024, and other conflicts exit 5.
- `forward add` accepted a peer's agent port as the target when a whitelist range covered it,
  creating a rule that could never become active; the peer's announced agent port is now rejected
  with exit 8.
- `remote` printed a listening whitelisted port twice; a one-port range already listed as a
  listening port is no longer repeated.
- `daemon uninstall` with nothing installed exited 10 ("daemon unavailable"); it now exits 3.

One operational caveat remains: on a Windows Public network profile, inbound is blocked by
default; a daemon started from SSH or autostart cannot show the firewall prompt, so the agent port
rule must be added manually.
