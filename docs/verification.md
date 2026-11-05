# Verification and Milestone Log

This file records the M0 go/no-go evidence, real-hardware acceptance runs, deviations from
`PLAN.md` and the milestone status. It is updated as verification progresses.

## M0 Prototype Conclusions

- Date: 2026-11-05
- Environment: Linux x86_64, rustc 1.99.1, cargo 1.99.1, user-level runtime (non-root); macOS
  15.5 arm64 (Apple silicon), same toolchain, user-level runtime (non-root)
- Conclusion: **Linux GO** and **macOS GO for M1** (real hardware); the Windows code path is
  implemented, but real-hardware verification is still pending.

### Dependency Pinning

| Purpose | crate | Version |
|---|---|---|
| Runtime | tokio | 1.54 |
| CLI | clap | 4.6 |
| Storage | rusqlite (bundled) | 0.41 |
| Port enumeration | netstat2 | 0.11.2 |
| Processes/users | sysinfo | 0.40.1 |
| mDNS | mdns-sd | 0.21.7 |
| TLS | rustls / tokio-rustls | 0.23.46 / 0.26.6 |
| Certificates | rcgen | 0.13.2 |
| Certificate parsing | x509-parser | 0.16.0 |
| Identity signatures | ed25519-dalek | 2.2.0 |
| Multiplexing | yamux | 0.13.10 |
| SPAKE2 | spake2 | 0.4.0 (RustCrypto, Ed25519 group) |
| AEAD / KDF | chacha20poly1305 / hkdf / sha2 | 0.10 / 0.12 / 0.10 |

### Prototype Point Results

#### 1. User-Level Port Enumeration Coverage

- On Linux, `netstat2` returns TCP `LISTEN` sockets via netlink, with port coverage identical to
  `ss -ltn`.
- The PID, process name and user of same-user processes resolve correctly (in the test, the
  self-created listeners plus adb, node, opencode and others were all correct).
- The PIDs of other users/system services (sshd, systemd-resolved, etc.) are often invisible when
  non-root: the port is still listed and the owner shows `-`, which matches fallback 1 in the
  plan.
- Docker/WSL2 internal namespaces are out of enumeration scope (documented).

On macOS 15.5 arm64, `netstat2` enumerates sockets by walking processes with libproc
(`PROC_PIDLISTFDS`). Without root that call fails for other users' processes and the crate
silently skips them, so their listening ports were missing entirely (e.g. sshd on 22, VNC on
5900, the system 88/1080 listeners). This violated fallback 1 of the plan ("list the port, show
the owner as `-`"). `crates/lanfp-inventory/src/macos.rs` now merges the full `LISTEN` set from
`/usr/sbin/netstat`; ownership is still resolved with `netstat2` + `sysinfo` where visible. After
the fix `lanfp local` matched `netstat -an -p tcp` exactly (10 of 10 listening ports, agent port
excluded), with correct PID/process/user for same-user listeners and `-` for root-owned ones.

Conclusion: GO. The implementation lives in `crates/lanfp-inventory`; unit tests cover PID
attribution of self-created listeners and the macOS netstat parser.

#### 2. mDNS Mutual Discovery Between Two Instances

- `mdns-sd` 0.21.7 completed advertise + browse between two isolated instances on the same host;
  `lanfp scan --timeout 3s` listed the peer within 3 seconds with correct `PEER`, `PORT` and
  `STATE`.
- One implementation detail surfaced: the `ServiceInfo` host name must end with `.local.`,
  otherwise registration fails; fixed.
- Firewall/AP isolation and the macOS local network permission were not verified on hardware;
  manual-address pairing is implemented and tested as a first-class fallback.

Conclusion: GO (verified on a single Linux host). Cross-host mDNS and macOS permissions await
real-hardware verification in M2/M5.

#### 3. SPAKE2

- Uses `spake2` 0.4.0 (Ed25519 group). Unit tests cover:
  - same code → both sides derive the same key;
  - different codes → different keys;
  - different device identities (UUID) → different keys.
- The crate's Ed25519 parameter set is not the RFC 9382 P-256 test-vector suite; both sides use the
  same binary, so cross-implementation interoperability is not required. Security relies on SPAKE2
  itself + the 6-digit code + 5 attempts + a 300-second TTL + AEAD key confirmation.
- `pakery-spake2` 0.6 (RFC 9382, P-256 suite) was evaluated, but it depends on rand_core 0.10,
  which would coexist with ed25519-dalek 2's rand_core 0.6 and pull in two RNG stacks; this
  version uses `spake2` 0.4 and records the decision in the docs.

Conclusion: GO, with the notes above. The pairing flow passes the loopback end-to-end tests
(including the 5-attempt limit on wrong codes).

#### 4. rustls Pinned Ed25519 Public Keys + yamux Throughput

- Mutual self-signed certificates, pinned by Ed25519 public key (the client pins the target's key;
  the server validates clients against the known-key set).
- Unit tests verify certificate public-key extraction, pin checks, and rejection of unknown keys.
- Loopback E2E: two daemons + an echo service; 100 MiB bidirectional transfer, half-close and 100
  concurrent streams all pass.
- Throughput (release build, 200 MiB sent + 200 MiB echoed, through one forward):

  ```
  sent=200.0 MiB recv=200.0 MiB elapsed=0.47s
  combined ≈ 857 MiB/s, one-way ≈ 429 MiB/s
  ```

  Above the M0 target of 300 MB/s. The test machine uses the local loopback; a real LAN is limited
  by the NIC and Wi-Fi.

Conclusion: GO.

#### 5. Auto-Spawn, IPC, Single Instance

- Linux: when the daemon is not running, the client spawns `lanfp serve` detached and connects to
  IPC within 5 seconds.
- The single-instance file lock works: a second `lanfp serve` prints the existing instance's
  PID/IPC and exits 0.
- IPC Unix socket mode 0600, runtime directory 0700 (asserted by the E2E tests).
- `lanfp daemon install/uninstall` complete enable/disable and file cleanup in a systemd --user
  environment.

macOS 15.5 arm64: auto-spawn from `lanfp local` completed in 0.13 s; IPC appeared at
`$TMPDIR/lanfp/ctl.sock` with mode 0600 and the runtime directory 0700; the single-instance lock,
`daemon start/stop/status`, pid file and socket cleanup all behaved as specified. The LaunchAgent
plist is written and valid. `launchctl load -w` is deprecated and fails silently on current
macOS, so `daemon install` now uses `launchctl bootstrap gui/<uid>` with a `user/<uid>` fallback.
A plain SSH session runs in launchd's **Background** session, where macOS 15 refuses to bootstrap
any service (EIO even for a trivial agent), so the command leaves the plist registered, prints a
warning and exits 0; activation then happens at the next GUI login. Running
`lanfp daemon install` from Terminal.app (GUI session) activates it immediately.

Conclusion: GO (Linux and macOS). The Windows HKCU Run code path awaits real-hardware
verification.

## M1 Real-Hardware Acceptance (macOS 15.5 arm64)

Date: 2026-11-05. User `sigo`, non-root, release build, default paths (no `LANFP_HOME`).
The check script asserted 63 conditions; all passed.

| Area | Result |
|---|---|
| Auto-spawn | `lanfp local` with no daemon running spawned `lanfp serve` and returned in 0.13 s (budget 5 s) |
| Port inventory | `lanfp local --json` port set == `netstat -an -p tcp` `LISTEN` set minus the agent port (10/10) |
| Self exclusion | agent port 47811 absent from `lanfp local`; the daemon PID owned only that TCP listener |
| Ownership | same-user listeners show PID/process/user (verified against `lsof`); root-owned ports 22/88/1080/5900/12345 are listed with `-` |
| Binds | `127.0.0.1`, `0.0.0.0`, `::1` and dual-stack wildcard addresses all rendered correctly |
| Inventory refresh | a killed test listener disappeared, the remaining ones stayed |
| IPC | `$TMPDIR/lanfp/ctl.sock`, socket mode 0600, runtime directory 0700 |
| Paths | config/db/identity under `~/Library/Application Support/lanfp`, log under `logs/lanfp.log`; `identity.key` mode 0600 |
| Lifecycle | `daemon status` (text and `--json`), `daemon start` (idempotent), `daemon stop` (socket/pid removed), restart, single instance |
| Login autostart | plist written and linted; bootstrap blocked in the SSH background session, warning printed, exit 0; uninstall removes it |
| Test suite | `cargo test --workspace` on macOS: 15 + 21 + 14 + 5 unit tests and 8 loopback E2E tests pass (pairing, 100 MiB transfer, 100 concurrent streams, rule recovery) |

Key commands used for the inventory comparison:

```sh
lanfp local --json | jq -r '.ports[].port' | sort -n
netstat -an -p tcp | awk '$NF == "LISTEN" { print $4 }' | sed 's/.*\.//' | sort -n
lsof -nP -iTCP -sTCP:LISTEN
```

## Two-Host LAN Acceptance (Linux ↔ macOS)

Date: 2026-11-05. Linux x86_64 (`nix`, 192.168.8.10) and macOS 15.5 arm64
(`sigos-Mac-mini.local`, 192.168.8.14), same `/24` subnet, same switch, `ufw` inactive and the
macOS application firewall disabled, non-root, default paths and agent port 47811 on both sides.
HTTP targets were local Python servers (macOS 18100/18101, Linux 18110).

| Check | Result |
|---|---|
| mDNS discovery | `lanfp scan` found the peer in both directions on the first 3 s query, `PEER`/`PORT`/`STATE` and `--json` correct |
| Pairing without `pair wait` | exit 6 in 7 ms, no connection stall |
| Wrong pairing code | five attempts, each exit 9; the waiter reported the decreasing attempt count and failed after the fifth |
| Pairing after 15 s code entry | succeeded on both sides (see the timeout defect below); both SSL-pinned sessions came up |
| Pairing persistence | restarting either daemon kept `peers: 1 paired, 1 online`; sessions and inventories recovered automatically |
| Manual address fallback | a second isolated Linux instance (agent 47820, mDNS off) was paired with `lanfp pair 192.168.8.10:47820`, exercising the bare `ip:port` selector |
| `lanfp remote` | full Native inventory of the peer, correct ownership and `FORWARDED` column; two peers listed together; non-default agent port shown as `nix@192.168.8.10:47820` |
| Offline peer | `remote` exits 0 and prints `skipping offline device(s): ...` on stderr when one of two peers is down; an explicit offline peer exits 4 |
| Forward + curl | Linux `forward add ... 18100` → `curl 127.0.0.1:18100` returned the macOS target body; reverse direction (macOS → Linux 18110) worked as well |
| `--listen` | `--listen 18102` created a second rule; both listeners served traffic |
| `forward list` / removal | `LOCAL` shows only the port; removal closed the listener, dropped connections and cleared the peer's `inbound` reference |
| Rule recovery | rules survived a daemon restart on both sides and resumed as `active` once the session was back |
| Peer offline state | rule state became `peer_offline`, new connections were closed immediately, `forward add` exited 4 |
| Target gone/recovered | rule state became `target_gone` with a reason, new connections failed fast; the port reappearing restored `active` |
| Conflict reporting | exit 5 with `by python3 (pid N) on 127.0.0.1`; an existing rule on the same port also exits 5 |
| Other exit codes | missing rule 3, `<1024` listen 7, target not in inventory 8 |
| Listener exposure | only `0.0.0.0:47811` is non-loopback on either host; forward listeners bind `127.0.0.1` |
| Inventory vs system tools | Linux `lanfp local` == `ss -ltn` minus the agent and forward ports; macOS was verified against `netstat` in the M1 run |
| JSON | `scan`/`remote`/`forward list`/`forward add`/`forward remove`/`inbound` all parse with `jq`, `schema: 1` |

Defects found and fixed during this run:

1. **Pairing aborted after 10 s of human code entry.** The responder applied the network
   `PAIR_TIMEOUT` (10 s) while waiting for the initiator's SPAKE2 message, which is only sent after
   the user types the code shown on the other screen. It now waits for the remaining lifetime of
   the pairing code (default 300 s). Regression test: `pairing_survives_slow_code_entry` (12 s
   delay).
2. **Bind-conflict message lacked the occupying process.** The occupant was looked up in an
   inventory cache that could lag a just-started listener; the inventory is now refreshed before
   reporting, so the error names process, PID and bind address.
3. **Piping output panicked.** `lanfp remote | head` panicked on `EPIPE`; the CLI now restores the
   default `SIGPIPE` disposition and terminates quietly like other Unix tools.

Not covered by this run: mDNS discovery across AP client isolation, Wi-Fi power-saving multicast
loss, and Windows (still unverified).

## Deviations from the Plan

| Item | Implementation |
|---|---|
| SPAKE2 library | `spake2` 0.4 (Ed25519) instead of `pakery-spake2`; rationale above |
| Stream buffer | Self-implemented 64 KiB bidirectional copy (the plan asked for 64 KB) |
| Config hot reload | Polls the config file about every 5 seconds; `agent.listen` / `discovery.mdns` need a restart |
| Log rotation | Rotates once at 5 MiB when the background instance is auto-spawned |
| Windows named pipe DACL | Uses the process default DACL, not further restricted to the current user SID |
| CLI output language | English per the PLAN 4.3 examples; docs in English |
| `lanfp inbound` columns | Added a `STATE` column to show online/offline (the plan only asked to mark offline) |
| Control messages | Added an internal `RuleSnapshot` to clean up inbound references deleted while the peer was offline when a session is established |
| macOS port enumeration | `netstat2` cannot see other users' sockets without root, so `/usr/sbin/netstat` supplies the full `LISTEN` set; those rows keep owner `-` |
| macOS IPC path | `$TMPDIR/lanfp/ctl.sock` instead of `$TMPDIR/lanfp-<uid>/ctl.sock`; `$TMPDIR` is already per-user on macOS and the directory is 0700 |
| macOS autostart activation | `launchctl bootstrap` (gui domain, then user domain) instead of the deprecated `launchctl load -w`; a background session only registers the plist for the next login |
| `daemon install` output | Reports whether the daemon started immediately or will start at the next login |

## Follow-Up (M1–M5) Status

- M1 skeleton: done on Linux and verified on macOS hardware (serve/IPC/auto-spawn/enumeration/
  `local`/`daemon status`).
- M2 discovery: done; mDNS discovery verified between a Linux host and a macOS host on the same
  LAN, including the manual `ip:port` fallback.
- M3 pairing: done; verified on the same two hosts (exit 6 without `pair wait`, 5-attempt limit,
  300 s TTL, slow human code entry, restart persistence).
- M4 forwarding: done and verified across the LAN in both directions, including removal, offline,
  target-gone and recovery states.
- M5 wrap-up: done (rule recovery, daemon install, --json, exit codes, docs, log rotation,
  loopback tests).
- Remaining: Wi-Fi/AP-isolation and macOS "Local Network" permission behaviour, Windows
  verification, and the three-platform CI matrix.
