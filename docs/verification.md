# Tests and verification

## Automated tests

`cargo test --workspace` runs each crate's unit tests plus the loopback suite in `crates/lanfp/tests/e2e.rs`.

| Suite | Coverage |
|---|---|
| `lanfp-core` | Frame and IPC codecs, protocol messages, grant/exposure round-trips, peer selectors and display names |
| `lanfp-crypto` | Identity persistence, Ed25519 signatures, transcripts, fingerprints, certificate parsing and key pinning |
| `lanfp-inventory` | Port classification, native filtering, self-listener exclusion, macOS `netstat` parsing |
| `lanfp` | Configuration, database trust directions, exposure policy, discovery TXT parsing, output helpers and CLI utilities |
| Loopback E2E | Two daemons, one-way grant, session establishment, exposure and listening views, non-listening whitelist targets, revocation, forwarding (100 MiB transfer, half-close, 100 concurrent streams, `--listen 0`), IPC privacy, exit codes, JSON, rule recovery, selectors and address updates |

## Key commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --release -p lanfp
```

## Current status

- CI builds, tests, formats and lints the workspace on Ubuntu, macOS and Windows (`.github/workflows/ci.yml`).
- The loopback E2E suite runs on Unix (Linux and macOS); Windows runs the unit tests only.
- A two-host LAN run (mDNS grant, `remote` exposure view, `forward add`, revoke) under the current one-way model has not been repeated.
