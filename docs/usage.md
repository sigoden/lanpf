# Usage and command reference

`lanfp` is one binary. `lanfp serve` runs in the foreground; data commands are short-lived clients that reach the daemon over local IPC and auto-start it when needed. The default output is a table; every data command supports `--json` (`schema: 2`). CLI text and JSON fields are English.

## Commands

| Command | Description |
|---|---|
| `lanfp scan [--timeout 3s] [--json]` | mDNS scan: devices and their authorization state |
| `lanfp peer list [--json]` | Devices authorized to access this machine |
| `lanfp peer grant [PEER]... [--force] [--json]` | Authorize devices; without PEER, pick from a scan (text only) |
| `lanfp peer revoke <PEER>... [--json]` | Revoke authorization and drop sessions |
| `lanfp peer set-address <PEER> <ip[:port]> [--json]` | Update a known device's stored address |
| `lanfp local [--json]` | Local TCP services (lanfp and forwarded listeners excluded) |
| `lanfp remote [PEER] [--json]` | Exposed ports of servers that authorized this machine |
| `lanfp forward add <PEER> <TARGET_PORT> [--listen PORT] [--json]` | Create a forward |
| `lanfp forward list [--json]` | Local rules |
| `lanfp forward remove <LOCAL_PORT> [--json]` | Remove a rule and close its listener |
| `lanfp inbound [--json]` | Read-only: who is forwarding this machine's ports |
| `lanfp serve` | Run the daemon in the foreground (debugging; `RUST_LOG=debug`) |
| `lanfp daemon start\|stop\|status` | Manage the background instance |
| `lanfp daemon install\|uninstall` | Register/remove login autostart |

## Authorization (one-way)

The machine that exposes a service is the **host**; the machine that uses it is the **consumer**. Both machines must be running the daemon (`lanfp daemon start`, `lanfp serve`, or login autostart): discovery and the grant handshake talk to the other machine's daemon, and data commands auto-start the daemon only on the machine where you run them.

1. On the host, `lanfp scan` lists devices running `lanfp serve`; authorize one with `lanfp peer grant` (pick from the scan) or pass selectors:

   ```sh
   $ lanfp peer grant mac-mini@192.168.8.11
   granted mac-mini@192.168.8.11 [5e6f7a8b]
   key fingerprint: 1a2b...
   mac-mini@192.168.8.11 may now connect and forward exposed ports on this machine
   ```

2. The consumer can now run `lanfp remote` to see every host that authorized it and that host's exposure view.

- The grant uses a one-way `FPG1` handshake on the agent port: the host stores `may_connect`, the consumer stores the host as a known server (`may_dial`) for pinning and dialing. The consumer is not authorized to be accessed by the host.
- `lanfp peer list` shows only devices this machine authorized. On the consumer, the host appears in `remote` and in `scan` as `server`, not in `peer list`.
- `--force` replaces a stored key after a device reinstall; without it a key change exits 9.
- `peer revoke` clears `may_connect`, removes the key from the TLS allow-list, drops the session and deletes inbound references. The consumer's server record stays and reports offline until a later grant.
- `peer set-address` works for any known device, including a server learned by `remote`; use it when mDNS is unavailable.

## Exposure

Exposure is machine-wide, configured by `agent.expose_ports` in `config.toml` (single ports and inclusive ranges). **all** (default, empty list) exposes every Native listening port; **whitelist** (entries) exposes only covered ports:

```toml
[agent]
expose_ports = ["80", "443", "3000-4000", "8000-8100"]
```

- The daemon applies `agent.expose_ports` changes within about 5 seconds and re-advertises the view; an invalid entry fails startup or is ignored on hot reload.
- Whitelisted ports need not be listening: they stay exposed and start forwarding once a service binds them, and ranges cover any listening port inside them. The agent port is never exposed, even inside a range; `forward add` rejects it with exit 8. Forwarding listeners are never valid targets either.
- On the consumer, `remote` lists every listening port in all mode; in whitelist mode it lists listening whitelisted ports plus the configured ranges, and `forward add` accepts a non-listening target as `target_gone` until it listens.

## Peer identifiers and selectors

- Identity is the UUID; tables show the first 8 lowercase hex as `PEER ID`, lengthened on collision. `--json` carries the full UUID. Moving the data directory moves the identity.
- `PEER` is a view (`<name>@<current address>`), formatted per command and refreshed from mDNS and authenticated session hellos. Use the ID in scripts.

| Form | Example | Rule |
|---|---|---|
| Full UUID | `5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b` | exact |
| Short ID prefix | `5e6f7a8b` | at least 4 hex chars, unique |
| Device name | `mac-mini` | case-insensitive, unique |
| `name@IP` | `mac-mini@192.168.8.23` | name and current address; port checked only when written |
| Bare IP | `192.168.8.23`, `192.168.8.23:5000` | current address, unique |

- Ambiguous matches exit 2 and list the candidates. `peer grant` with a bare address is a manual target and must be an IP; hostnames must come from `scan` or a trust record.
- Names come from the remote hostname, refreshed on session establishment and authenticated by the pinned key; `@` and whitespace become `-` at registration.
- A rule ID is its local listening port; listeners are always `127.0.0.1`, so the address is omitted.

## Forwarding

`lanfp forward add <peer> <target_port>` listens on `127.0.0.1:<target_port>`; `--listen <port>` picks another local port and `--listen 0` lets the OS choose:

```sh
$ lanfp forward add nix 3000
created 3000 -> nix@192.168.8.10:3000 (active)
$ lanfp forward add nix 5000 --listen 0
created 52714 -> nix@192.168.8.10:5000 (active)
```

The target must be in the peer's exposure view. The listen port is the rule ID: it appears in `forward list` and the `FORWARDED` column of `remote`, and is the argument to `forward remove`. It is stored with the rule, so a restart rebinds the same port. When a rule is not `active`, the `ERROR` column of `forward list` (and the `error` field of `--json`) carries the reason, for example a target that stopped listening or a listener that could not be restored.

## JSON output

Every data command's `--json` prints one object with `schema: 2`; errors go to stderr.

```json
{
  "schema": 2,
  "peers": [{"id": "5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b", "name": "nix", "address": "192.168.8.10", "port": 47811, "online": true, "since": 1762300000, "fingerprint": "..."}]
}
```

- Peer-scoped entries carry `id` (full UUID; `ForwardInfo` calls it `peer_id`); `daemon status` carries this machine's `device_id` and `fingerprint`.
- `remote` returns the peer's exposure `mode`, the configured `ranges`, a `listening` flag per port, and `offline_peers`.
- `peer grant --json` returns `{schema, granted, failed}` and exits non-zero when `failed` is non-empty.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid arguments (including `agent.expose_ports`) or ambiguous peer selector |
| 3 | Device, rule or autostart entry not found |
| 4 | Not authorized, not a known server, or offline |
| 5 | Listen port in use / bind failure |
| 7 | Privileged port (`<1024`) |
| 8 | Target not exposed by the peer |
| 9 | Authorization failed / key changed / protocol mismatch |
| 10 | Daemon failed to start or IPC unreachable |

## Configuration

Paths: Linux `~/.config/lanfp/config.toml`, macOS `~/Library/Application Support/lanfp/config.toml`, Windows `%APPDATA%\lanfp\config.toml`. The file is generated on first start:

```toml
[agent]
listen = "0.0.0.0:47811"
max_streams = 256
idle_timeout_secs = 1800
# Exposure whitelist: single ports and inclusive ranges ("3000-4000").
# An empty list exposes every Native listening port.
expose_ports = []

[discovery]
mdns = true
scan_timeout_secs = 3

[inventory]
interval_ms = 2000
```

Most settings hot-reload within about 5 seconds; `agent.listen` and `discovery.mdns` take effect after `lanfp daemon stop && lanfp daemon start`. Set `LANFP_HOME=/some/dir` to keep config, data, identity and logs in one tree.

## Data and logs

| Platform | Config | Database | Logs |
|---|---|---|---|
| Linux | `~/.config/lanfp/config.toml` | `~/.local/share/lanfp/lanfp.db` | `~/.local/state/lanfp/lanfp.log` |
| macOS | `~/Library/Application Support/lanfp/config.toml` | `lanfp.db` in the same directory | `logs/lanfp.log` in the same directory |
| Windows | `%APPDATA%\lanfp\config.toml` | `%LOCALAPPDATA%\lanfp\lanfp.db` | `logs\lanfp.log` in the same directory |

- Identity: `identity.key` (0600) and `identity.crt` in the data directory, which moves the identity; IPC is `$XDG_RUNTIME_DIR/lanfp/ctl.sock` on Linux (fallback `/tmp/lanfp-<uid>/ctl.sock`, mode 0600), `$TMPDIR/lanfp/ctl.sock` on macOS, and `\\.\pipe\lanfp-<username>-<hash>` on Windows.
- Logs rotate once at 5 MiB (`lanfp.log.1`) when the CLI spawns the daemon.
