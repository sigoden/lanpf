# lanfp — LAN Port Forwarding Manager (CLI)

`lanfp` forwards a TCP port from the local machine to a listening port on an already paired
device in the same LAN. All forwarding listeners bind `127.0.0.1` only; the single port exposed
to the LAN is the agent port (default `0.0.0.0:47811`).

- Single binary: `lanfp serve` is the long-running process, every other subcommand is a
  short-lived client.
- User-level runtime: no system service, no root/Administrator required.
- Pairing is authorization: `lanfp inbound` is read-only, and this version has **no**
  reject/revoke command.
- Table output by default; every data command supports `--json` (`schema: 1`).

> Documentation and help text are in English. Command names, table headers and JSON fields are
> English as well, matching the examples in section 4.3 of `PLAN.md`.

## Status

Linux is fully working and passes the loopback end-to-end tests. The macOS / Windows code paths
are implemented (IPC named pipes, LaunchAgent, HKCU Run, the `<1024` port difference), but they
have not been verified on real hardware in the current environment; see
[Known limitations](docs/limitations.md).

## Build

Requires Rust 1.84+.

```sh
cargo build --release -p lanfp
# artifact: target/release/lanfp
```

Run the tests:

```sh
cargo test --workspace
```

## Quick start

On both machines A and B, run any command once (this spawns the background instance
automatically), or start it explicitly:

```sh
lanfp daemon start
```

### 1. Pairing

On B, wait for a pairing request; the terminal shows a 6-digit pairing code:

```sh
B$ lanfp pair wait
waiting for pairing request (Ctrl-C to cancel)...
```

On A, initiate the pairing:

```sh
A$ lanfp pair mac-mini@192.168.8.10
connecting to mac-mini@192.168.8.10...
pairing code (shown on mac-mini): ******
paired with mac-mini@192.168.8.10
```

- The device being paired must run `lanfp pair wait` first, otherwise the initiator fails
  immediately (exit code 6).
- The pairing code is 6 digits, valid for 300 seconds by default, with at most 5 attempts, and is
  shown only on the device being paired.
- If mDNS is blocked by a firewall, pair directly with `lanfp pair 192.168.8.10` or
  `lanfp pair 192.168.8.10:47811`.
- When a reinstall changes the public key, the initiator must add `--force` to replace the old
  trust.

### 2. Inspect ports

```sh
A$ lanfp scan
PEER                    PORT    STATE
mac-mini@192.168.8.10   47811   paired

A$ lanfp remote
PEER                    PORT   BIND         PROCESS    USER   FORWARDED
mac-mini@192.168.8.10   3000   127.0.0.1    node       sigo   -
mac-mini@192.168.8.10   5432   127.0.0.1    postgres   sigo   -

A$ lanfp local
PORT   BIND         PROCESS    PID    USER
3000   127.0.0.1    node       3512   sigo
```

### 3. Create a forward

```sh
A$ lanfp forward add mac-mini@192.168.8.10 3000
created 3000 -> mac-mini@192.168.8.10:3000 (active)
A$ curl http://127.0.0.1:3000
```

The listening port defaults to the target port; on a conflict, pick one with `--listen`:

```sh
A$ lanfp forward add mac-mini@192.168.8.10 3000 --listen 3001
created 3001 -> mac-mini@192.168.8.10:3000 (active)
```

Remove a rule (closes the listener and drops the rule's active connections):

```sh
A$ lanfp forward remove 3000
removed 3000
```

On the serving side, see who forwards your ports (read-only):

```sh
B$ lanfp inbound
PEER                    MY PORT   PEER LISTEN   SINCE    LAST SEEN   STATE
mac-mini@192.168.8.10   3000      3000          2m ago   3s ago      online
```

## Command reference

| Command | Description |
|---|---|
| `lanfp scan [--timeout 3s] [--json]` | Live mDNS scan, lists devices |
| `lanfp pair <peer> [--code <code>] [--force] [--json]` | Initiate pairing |
| `lanfp pair wait [--timeout 300s]` | Wait for a pairing request and show the 6-digit code |
| `lanfp local [--json]` | Local **Native** service ports |
| `lanfp remote [peer] [--json]` | Native ports of paired devices; without `peer`, lists all online devices |
| `lanfp forward add <peer> <target_port> [--listen <port>] [--json]` | Create a forward |
| `lanfp forward list [--json]` | Local rules |
| `lanfp forward remove <local_port> [--json]` | Remove a rule and close its listener |
| `lanfp inbound [--json]` | Read-only: who forwards my ports |
| `lanfp serve` | Run the long-running process in the foreground (debugging) |
| `lanfp daemon start\|stop\|status` | Manage the background instance |
| `lanfp daemon install\|uninstall` | Register/remove login autostart |

### Identifier rules

- Device: `<name>@<address>`, e.g. `mac-mini@192.168.8.10`. When the agent port is non-default it
  is displayed as `mac-mini@192.168.8.10:47811`; IPv6 uses brackets `mac-mini@[fe80::1]`.
- Rule: the user-visible ID is the local listening port. The listener is always `127.0.0.1`, so
  the address is omitted when displayed.
- The `FORWARDED` column of `lanfp remote` shows the local listening port, e.g. `-> 3000`.
- `@` and whitespace in device names are replaced with `-` at registration time.

### JSON output

The `--json` output of every data command is a single object carrying `schema: 1`, for example:

```json
{
  "schema": 1,
  "peers": [
    {
      "peer": "mac-mini@192.168.8.10",
      "name": "mac-mini",
      "address": "192.168.8.10",
      "port": 47811,
      "paired": true,
      "online": true
    }
  ]
}
```

With `--json`, stdout contains only JSON; error messages go to stderr.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid arguments |
| 3 | Device / rule not found |
| 4 | Device not paired or offline |
| 5 | Listening port already in use / bind failure |
| 6 | Peer is not running `lanfp pair wait` |
| 7 | Insufficient permission (listen on `<1024`) |
| 8 | Target port is not in the peer's Native inventory |
| 9 | Pairing failed / wrong code / expired |
| 10 | Daemon failed to start or IPC unreachable |

## Configuration

Linux: `~/.config/lanfp/config.toml`; macOS: `~/Library/Application Support/lanfp/config.toml`;
Windows: `%APPDATA%\lanfp\config.toml`. Generated automatically on first start:

```toml
[agent]
listen = "0.0.0.0:47811"
max_streams = 256
idle_timeout_secs = 1800

[discovery]
mdns = true
scan_timeout_secs = 3

[inventory]
interval_ms = 2000

[pairing]
code_ttl_secs = 300
max_attempts = 5
```

After a change, the background instance hot-reloads within about 5 seconds; changes to
`agent.listen` and `discovery.mdns` take effect only after
`lanfp daemon stop && lanfp daemon start`.

### Data and logs

| Platform | Config | Database | Logs |
|---|---|---|---|
| Linux | `~/.config/lanfp/config.toml` | `~/.local/share/lanfp/lanfp.db` | `~/.local/state/lanfp/lanfp.log` |
| macOS | `~/Library/Application Support/lanfp/config.toml` | `lanfp.db` in the same directory | `logs/lanfp.log` in the same directory |
| Windows | `%APPDATA%\lanfp\config.toml` | `%LOCALAPPDATA%\lanfp\lanfp.db` | `logs\lanfp.log` in the same directory |

- Identity keys: `identity.key` (0600) and `identity.crt` in the data directory.
- IPC: Linux `$XDG_RUNTIME_DIR/lanfp/ctl.sock` (fallback `/tmp/lanfp-<uid>/ctl.sock`), mode 0600;
  macOS uses `$TMPDIR`; Windows uses `\\.\pipe\lanfp-<username>`.
- For tests or portable runs, set `LANFP_HOME=/some/dir` to collect all paths under that directory.
- Logs rotate once at 5 MiB (`lanfp.log.1`) when the background instance is auto-spawned.

## Security model (must read)

- Pairing is authorization. Any paired device can create a forward to, and access, any of your
  Native ports; this version has **no** reject/revoke/allow-list command, and `lanfp inbound` is
  view-only.
- Transport: TLS 1.3 + mutual self-signed certificates + pinned Ed25519 public keys, ALPN
  `lanfp/1`, 0-RTT disabled.
- Pairing: SPAKE2 (Ed25519 group) + a 6-digit code; the code is shown only on the device being
  paired, and 5 failures abort. The pairing channel does not rely on TLS; its security comes from
  the PAKE.
- Target containment: only ports in the peer's Native inventory can be forwarded to, and only the
  peer's loopback addresses are dialed.
- Listener exposure: forwarding listeners are forced to `127.0.0.1`; only the agent port is open
  to the LAN.
- Other local users: IPC socket 0600 / runtime directory 0700 (Windows uses a per-user named
  pipe).
- Low ports: on Linux/macOS a user-level process cannot listen on `<1024` and gets a direct error
  (exit code 7) instead of a sudo hint. On Windows a normal user can usually listen on `<1024`.

See [Security model](docs/security.md) for details.

## Known limitations

- Under user-level permissions, the PID/process name of other users' processes may be invisible:
  the port is still listed and its owner shows as `-`.
- Ports inside separate network namespaces such as Docker containers and WSL2 are not enumerated.
- mDNS may be blocked by a firewall/AP isolation: pair manually with `lanfp pair <ip>[:port]`.
- The macOS 15+ "Local Network" privacy permission may affect mDNS and outbound connections.
- TCP only; no UDP, multi-hop, NAT traversal, public relay, or auto-update.
- The port inventory comes from `netstat2` + `sysinfo`; process attribution is best effort.

See [Known limitations](docs/limitations.md) for the full list.

## Development

```
crates/lanfp-core        protocol messages, IPC types, exit codes, PEER parsing, frame format
crates/lanfp-inventory   TCP listener enumeration and classification on three platforms
crates/lanfp-crypto      identity, certificates, TLS public-key pinning, SPAKE2, pairing payload encryption
crates/lanfp             single binary: serve + all subcommands
```

Tests: unit tests cover PEER parsing, frame/protocol codecs, configuration, database, inventory
classification, SPAKE2, AEAD and TLS public-key pinning; `crates/lanfp/tests/e2e.rs` runs pairing,
sessions, a 4 MiB transfer, half-close, 16 concurrent streams, rule recovery after restart, exit
codes and IPC permissions against two isolated daemons plus an echo service.

See [docs/M0.md](docs/M0.md) for the M0 prototype conclusions and dependency versions.
