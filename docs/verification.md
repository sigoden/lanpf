# Verification

This document records the automated test coverage and the real-hardware acceptance runs for
`lanfp`. Acceptance runs used release builds, a non-root user and the default data paths unless
noted otherwise.

## Automated Tests

`cargo test --workspace` runs the unit tests of every crate plus the loopback end-to-end suite in
`crates/lanfp/tests/e2e.rs`:

| Suite | Coverage |
|---|---|
| `lanfp-core` | Frame and IPC codecs, protocol messages, peer selectors and display names |
| `lanfp-crypto` | Identity persistence, Ed25519 signatures, SPAKE2, pairing records, TLS certificate parsing and key pinning |
| `lanfp-inventory` | Port classification, native filtering, self-listener exclusion, macOS `netstat` parsing |
| `lanfp` | Configuration, database, paths, output helpers and CLI utilities |
| Loopback E2E | Two daemons, pairing (slow code entry, wrong code, unpaired TLS client), forwarding (100 MiB transfer, half-close, 100 concurrent streams), IPC privacy, exit codes, JSON, rule recovery, peer selectors and address updates |

On Linux x86_64 with rustc 1.99.1 the suite reports 55 unit tests (15 + 23 + 14 + 3) and 12
loopback E2E tests, all passing. The inventory crate adds two macOS-only tests on that platform.
The E2E file is `#![cfg(unix)]`, so Windows compiles and runs the unit tests only.

CI builds, tests, formats and lints the workspace on Ubuntu, macOS and Windows; see
`.github/workflows/ci.yml`.

## macOS 15.5 (arm64)

Date: 2026-11-05. User `sigo`, non-root, release build, default paths (no `LANFP_HOME`).
A check script asserted 63 conditions; all passed.

| Area | Result |
|---|---|
| Auto-spawn | `lanfp local` with no daemon running spawned `lanfp serve` and returned in 0.13 s |
| Port inventory | `lanfp local --json` port set == `netstat -an -p tcp` `LISTEN` set minus the agent port (10/10) |
| Self exclusion | Agent port 47811 absent from `lanfp local`; the daemon PID owned only that TCP listener |
| Ownership | Same-user listeners show PID/process/user (verified against `lsof`); root-owned ports 22/88/1080/5900/12345 are listed with `-` |
| Binds | `127.0.0.1`, `0.0.0.0`, `::1` and dual-stack wildcard addresses all rendered correctly |
| Inventory refresh | A killed test listener disappeared, the remaining ones stayed |
| IPC | `$TMPDIR/lanfp/ctl.sock`, socket mode 0600, runtime directory 0700 |
| Paths | Config/db/identity under `~/Library/Application Support/lanfp`, log under `logs/lanfp.log`; `identity.key` mode 0600 |
| Lifecycle | `daemon status` (text and `--json`), `daemon start` (idempotent), `daemon stop` (socket/pid removed), restart, single instance |
| Login autostart | Plist written and linted; bootstrap blocked in the SSH background session, warning printed, exit 0; uninstall removes it |

Key commands used for the inventory comparison:

```sh
lanfp local --json | jq -r '.ports[].port' | sort -n
netstat -an -p tcp | awk '$NF == "LISTEN" { print $4 }' | sed 's/.*\.//' | sort -n
lsof -nP -iTCP -sTCP:LISTEN
```

## Windows 11 25H2

Date: 2026-11-05. Windows 11 25H2 (build 26300.9711), user `sigod`, a non-elevated shell in the
Administrators group, release build. Two PowerShell check scripts asserted 40 conditions with an
isolated `LANFP_HOME` (agent port 47911, mDNS off) and 47 conditions with the default paths
(agent port 47811, mDNS on, HKCU Run registration); a third script asserted 8 isolation/autostart
conditions. All passed.

| Area | Result |
|---|---|
| Auto-spawn | `lanfp local --json` with no daemon spawned `lanfp serve` and returned within the 5 s budget |
| Port inventory | `lanfp local --json` port set == `Get-NetTCPConnection -State Listen` minus the agent port (IPv4 and IPv6 merged per port) |
| Self exclusion | Agent port 47811 absent from `lanfp local` |
| Ownership | Own listeners show PID/process/user; system listeners resolve too (`sshd.exe`, `svchost.exe`, `spoolsv.exe`, `System`, `LOCAL SERVICE`) |
| Binds | `127.0.0.1`, `0.0.0.0`, `::1` and `::` rendered correctly |
| Inventory refresh | A stopped test listener disappeared from the next snapshot |
| IPC | Named pipe `\\.\pipe\lanfp-<user>-<hash8>`; two `LANFP_HOME` instances ran side by side with different PIDs, pipes and agent ports |
| Paths | `%APPDATA%\lanfp\config.toml`, `%APPDATA%\lanfp\lanfp.db`, `%APPDATA%\lanfp\identity.key`, log at `%APPDATA%\lanfp\logs\lanfp.log` |
| Lifecycle | `daemon status` (text/JSON), `daemon start` idempotent, a second `serve` reports the existing instance and exits 0, `daemon stop` closes the pipe, removes the pid file and exits the process; restart works |
| Login autostart | HKCU `Software\Microsoft\Windows\CurrentVersion\Run\lanfp` set to `"<exe>" serve --hidden`, written by `daemon install` and removed by `daemon uninstall` |
| `<1024` listen | Permitted for an administrator; a forward listener on port 80 served traffic |
| `serve --hidden` | Detaches from the console (`FreeConsole`) and keeps serving; this is what the HKCU entry starts |

Key commands used for the inventory comparison:

```powershell
lanfp local --json
Get-NetTCPConnection -State Listen | ForEach-Object { $_.LocalPort } | Sort-Object -Unique
lanfp daemon status --json
```

## Two-Host LAN Acceptance (Linux ↔ macOS)

Date: 2026-11-05. Linux x86_64 (`nix`, 192.168.8.10) and macOS 15.5 arm64
(`sigos-Mac-mini.local`, 192.168.8.14), same `/24` subnet, same switch, `ufw` inactive and the
macOS application firewall disabled, non-root, default paths and agent port 47811 on both sides.
HTTP targets were local Python servers (macOS 18100/18101, Linux 18110).

| Check | Result |
|---|---|
| mDNS discovery | `lanfp scan` found the peer in both directions on the first 3 s query, `PEER`/`PORT`/`STATE` and `--json` correct |
| Pairing without `peer wait` | Exit 6 in 7 ms, no connection stall |
| Wrong pairing code | Five attempts, each exit 9; the waiter reported the decreasing attempt count and failed after the fifth |
| Pairing after 15 s code entry | Succeeded on both sides; both pinned TLS sessions came up |
| Pairing persistence | Restarting either daemon kept `peers: 1 paired, 1 online`; sessions and inventories recovered automatically |
| Manual address fallback | A second isolated Linux instance (agent 47820, mDNS off) was paired with `lanfp peer add 192.168.8.10:47820`, exercising the bare `ip:port` selector |
| `lanfp remote` | Full Native inventory of the peer, correct ownership and `FORWARDED` column; two peers listed together; non-default agent port shown as `nix@192.168.8.10:47820` |
| Offline peer | `remote` exits 0 and prints `skipping offline device(s): ...` on stderr when one of two peers is down; an explicit offline peer exits 4 |
| Forward + curl | Linux `forward add ... 18100` → `curl 127.0.0.1:18100` returned the macOS target body; reverse direction (macOS → Linux 18110) worked as well |
| `--listen` | `--listen 18102` created a second rule; both listeners served traffic |
| `forward list` / removal | `LOCAL` shows only the port; removal closed the listener, dropped connections and cleared the peer's `inbound` reference |
| Rule recovery | Rules survived a daemon restart on both sides and resumed as `active` once the session was back |
| Peer offline state | Rule state became `peer_offline`, new connections were closed immediately, `forward add` exited 4 |
| Target gone/recovered | Rule state became `target_gone` with a reason, new connections failed fast; the port reappearing restored `active` |
| Conflict reporting | Exit 5 with `by python3 (pid N) on 127.0.0.1`; an existing rule on the same port also exits 5 |
| Other exit codes | Missing rule 3, `<1024` listen 7, target not in inventory 8 |
| Listener exposure | Only `0.0.0.0:47811` is non-loopback on either host; forward listeners bind `127.0.0.1` |
| Inventory vs system tools | Linux `lanfp local` == `ss -ltn` minus the agent and forward ports; macOS was verified against `netstat` |
| JSON | `scan`/`remote`/`forward list`/`forward add`/`forward remove`/`inbound` all parse with `jq`, `schema: 1` |

Not covered by this run: mDNS discovery across AP client isolation and Wi-Fi power-saving
multicast loss.

## Two-Host LAN Acceptance (Linux ↔ Windows)

Date: 2026-11-05. Linux x86_64 (`nix`, 192.168.8.10) and Windows 11 25H2
(`DESKTOP-N7FJS9T`, 192.168.8.8), same `/24` subnet, user-level runtime, default paths and agent
port 47811 on both sides. Windows Defender Firewall was on for all profiles; an inbound
`program` allow rule for `lanfp.exe` was added for the run (the equivalent of accepting the
first-run prompt). HTTP targets were a PowerShell `TcpListener` on Windows 18100 and
`python3 -m http.server` on Linux 18110.

| Check | Result |
|---|---|
| mDNS discovery | `lanfp scan` found the peer in both directions on the first 3 s query, with correct `PEER`/`PORT`/`STATE` |
| Pairing (Linux initiates) | Code shown on Windows, entered on Linux; both sides completed and reported `1 paired, 1 online` |
| Pairing (Windows initiates, manual address) | `lanfp peer add 192.168.8.10:47920` against a second isolated Linux instance with mDNS off; the non-default agent port displayed as `nix@192.168.8.10:47920` |
| Pairing without `peer wait` | Exit 6 in 8 ms |
| `peer wait` already active | Second waiter exits 6 |
| Wrong pairing code | Five attempts, each exit 9; the waiter reported the decreasing attempt count (4, 3, 2; the final decrement can fall between polls) and failed after the fifth |
| Slow code entry | A 12 s delay before entering the code still paired (the 300 s TTL applies) |
| Pairing persistence | Restarting either daemon kept `1 paired`; sessions recovered automatically |
| `lanfp remote` | Full Native inventory of the peer with ownership (`sshd.exe`, `svchost.exe`, `System`, `chrome.exe`, `python3`, ...) and the `FORWARDED` column (`-> 18100,18102`, ascending) |
| Forward + curl | Linux `forward add ... 18100` → `curl 127.0.0.1:18100` returned the Windows body; the reverse direction (Windows → Linux 18110) returned the Linux body |
| `--listen` | `--listen 18102` created a second rule; both listeners served traffic |
| `<1024` listen on Windows | `--listen 80` succeeded and served traffic (on Linux, as a normal user, the same request exits 7) |
| `forward list` / removal | Removal closed the listener immediately and cleared the peer's `inbound` entry |
| Rule recovery | Rules survived restarts of both daemons and resumed as `active` |
| Peer offline | `remote` exits 4, rules became `peer_offline`, new connections were closed immediately |
| Target gone/recovered | Rules became `target_gone` with no traffic; the port reappearing restored `active` and traffic |
| Other exit codes | Conflict 5, missing rule 3, target not in inventory 8, `<1024` on Linux 7, unknown device 3 |
| Listener exposure | Only `0.0.0.0:47811` is non-loopback on either host; forward listeners bind `127.0.0.1` |
| JSON | `scan`/`remote`/`forward list`/`forward add`/`inbound`/`daemon status` all parse on both sides (`schema: 1`), including PowerShell `ConvertFrom-Json` |
| Throughput + integrity | 64 MiB through a Windows→Linux forward in 7.23 s (≈8.9 MiB/s) versus 6.95 s direct on the same link (≈96 % of the direct rate); SHA-256 of the forwarded file matched the source |

Not covered by this run: real login activation of the HKCU Run entry (needs a GUI logon), the
Windows Firewall first-run prompt (the rule was added explicitly), and the loopback E2E suite on
Windows. Note that Win32-OpenSSH terminates the session's process tree when the SSH connection
closes, so an auto-spawned daemon does not outlive an SSH session; that is sshd behaviour, not a
lanfp defect.

## Throughput

Loopback, release build, 200 MiB sent and 200 MiB returned through one forward:

```
sent=200.0 MiB recv=200.0 MiB elapsed=0.47s
combined ≈ 857 MiB/s, one-way ≈ 429 MiB/s
```

A real LAN is limited by the NIC and Wi-Fi; the Linux↔Windows run above reached about 96 % of the
direct transfer rate on the same link.

## Untested Areas

- mDNS discovery across Wi-Fi access-point client isolation and power-saving multicast loss.
- The macOS 15+ "Local Network" permission prompt.
- Real login activation of the autostart entries (macOS LaunchAgent and Windows HKCU Run).
- The loopback E2E suite on Windows.
- Process attribution for listeners inside Docker, WSL2 and other network namespaces (out of
  scope by design; see [Known limitations](limitations.md)).

## Reproducing the Checks

```sh
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

Inventory comparisons:

```sh
# Linux
lanfp local --json | jq -r '.ports[].port' | sort -n
ss -ltn

# macOS
lanfp local --json | jq -r '.ports[].port' | sort -n
netstat -an -p tcp

# Windows (PowerShell)
lanfp local --json
Get-NetTCPConnection -State Listen | ForEach-Object { $_.LocalPort } | Sort-Object -Unique
```
