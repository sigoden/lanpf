# Verification

This document records automated coverage and real-hardware acceptance for `lanfp`.

## Automated Tests

`cargo test --workspace` runs the unit tests of every crate plus the loopback end-to-end suite in
`crates/lanfp/tests/e2e.rs`.

| Suite | Coverage |
|---|---|
| `lanfp-core` | Frame and IPC codecs, protocol messages, grant/exposure message round-trips, peer selectors and display names |
| `lanfp-crypto` | Identity persistence, Ed25519 signatures, grant/identity transcripts, fingerprints, TLS certificate parsing and key pinning |
| `lanfp-inventory` | Port classification, native filtering, self-listener exclusion, macOS `netstat` parsing |
| `lanfp` | Configuration, database trust directions and migration, expose policy, discovery TXT parsing, output helpers and CLI utilities |
| Loopback E2E | Two daemons, one-way grant, session establishment, exposure/listening views, non-listening whitelist targets, revocation, forwarding (100 MiB transfer, half-close, 100 concurrent streams, automatic listen-port selection), IPC privacy, exit codes, JSON, rule recovery, peer selectors and address updates |

The E2E file is `#![cfg(unix)]`, so Windows compiles and runs the unit tests only. CI builds,
tests, formats and lints the workspace on Ubuntu, macOS and Windows; see
`.github/workflows/ci.yml`.

Key commands:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --release -p lanfp
```

## Coverage of the New Authorization Flow

The loopback suite asserts, among other things:

- `peer grant` is one-way: the host's `peer list` contains the consumer, the consumer's
  `peer list` is empty, and the consumer's `remote` lists the host as a known server.
- An ungranted consumer's `remote`/`forward add` is rejected (exit 4).
- `peer revoke` drops the session and clears the host's inbound references.
- `expose` defaults to all listening ports; a whitelist hides unlisted ports and exposes
  configured ports that are not listening with a `not listening` state.
- `forward add` accepts a non-listening whitelist port, creates a `target_gone` rule, and the
  rule becomes active when the service starts listening.
- Removing an exposed port rejects the active rule and clears inbound; returning to `mode: all`
  recovers it.
- Removing a missing port is all-or-nothing (exit 3).
- Rules, trust records and expose entries survive a daemon restart.
- JSON output uses `schema: 2`.

## Real-Hardware Acceptance (Historical)

The prior real-hardware runs were performed under the earlier pairing model. Their port
inventory, forwarding, offline/target-gone, IPC, autostart and JSON checks remain relevant, but
the authorization and exposure flows have changed and need a fresh two-host run.

### macOS 15.5 (arm64)

Date: 2026-11-05. User `sigo`, non-root, release build, default paths. Verified auto-spawn, port
inventory against `netstat`, ownership columns, bind rendering, inventory refresh, IPC mode,
paths, daemon lifecycle and login autostart.

### Windows 11 25H2

Date: 2026-11-05. Windows 11 25H2 (build 26300.9711), non-elevated shell. Verified auto-spawn,
port inventory against `Get-NetTCPConnection`, ownership, bind rendering, named-pipe isolation,
daemon lifecycle, HKCU Run registration and `<1024` listening.

### Two-Host LAN Runs

Date: 2026-11-05. Linux ↔ macOS and Linux ↔ Windows, same `/24` subnet, non-root, default agent
port. Covered mDNS discovery, pairing, remote inventory, forward + curl, `--listen`, removal,
offline/target-gone recovery, exit codes, JSON, listener exposure and inventory comparison with
`ss`/`netstat`.

## Pending Verification

- Two-host `lanfp scan` + `lanfp peer grant` + `lanfp remote` exposure view + `forward add` +
  `revoke` under the new one-way model.
- mDNS public-key verification on a real LAN (including a spoofed/mismatched key).
- macOS "Local Network" permission prompt with the new grant flow.
- Windows loopback E2E (the suite is Unix-only).
