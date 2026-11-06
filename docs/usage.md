# Usage and Command Reference

`lanfp` runs as a single binary. `lanfp serve` is the long-running background process; every
other subcommand is a short-lived client that talks to it over local IPC. Any data command starts
the background process automatically when needed, so `lanfp daemon start` is optional.

The default output is a table. Every data command supports `--json` (`schema: 1`) for scripts and
other tools.

## Commands

| Command | Description |
|---|---|
| `lanfp scan [--timeout 3s] [--json]` | Live mDNS scan, lists devices |
| `lanfp pair <peer> [--code <code>] [--force] [--json]` | Initiate pairing |
| `lanfp pair wait [--timeout 300s]` | Wait for a pairing request and show the 6-digit code |
| `lanfp peer list [--json]` | Paired devices with their stable IDs, addresses and state |
| `lanfp peer set-address <peer> <ip[:port]> [--json]` | Update the stored address of a paired device |
| `lanfp local [--json]` | Local TCP services (lanfp itself and forwarded listeners are excluded) |
| `lanfp remote [peer] [--json]` | TCP services on paired devices; without `peer`, lists all online devices |
| `lanfp forward add <peer> <target_port> [--listen <port>] [--json]` | Create a forward |
| `lanfp forward list [--json]` | Local rules |
| `lanfp forward remove <local_port> [--json]` | Remove a rule and close its listener |
| `lanfp inbound [--json]` | Read-only: who forwards my ports |
| `lanfp serve` | Run the long-running process in the foreground (debugging) |
| `lanfp daemon start\|stop\|status` | Manage the background instance |
| `lanfp daemon install\|uninstall` | Register/remove login autostart |

Run `lanfp <command> --help` for the exact options of a command.

## Peer identifiers and selectors

- A device's stable identity is its UUID. Tables show the first 8 lowercase hex characters as
  `PEER ID` (lengthened if two devices would collide); `lanfp peer list` and every `--json`
  output carry the full UUID. The UUID survives address and hostname changes, and moving the data
  directory moves the identity.
- `PEER` is a view, not an identity: `<name>@<current address>`. It is formatted when a command
  runs, prefers a fresh mDNS result, and changes when the address or the peer's hostname changes.
  Use the ID as a persistent key in scripts.
- Peer selectors accept these forms (a selector matching more than one device exits 2 and lists
  the candidates):

  | Form | Example | Rule |
  |---|---|---|
  | Full UUID | `5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b` | exact |
  | Short ID prefix | `5e6f7a8b` | at least 4 hex characters, unique |
  | Device name | `mac-mini` | case-insensitive, unique |
  | `name@IP` | `mac-mini@192.168.8.23` | name and the **current** address must match; the port is checked only when written |
  | Bare IP | `192.168.8.23`, `192.168.8.23:5000` | current address, unique |

- The displayed name comes from the remote hostname and is refreshed on the next session
  establishment (the hello is authenticated by the pinned key). Two devices can share a name;
  bare-name selection is then ambiguous, so use the ID.
- The user-visible rule ID is the local listening port. The listener is always `127.0.0.1`, so the
  address is omitted when a rule is displayed.
- The `FORWARDED` column of `lanfp remote` shows the local listening port, e.g. `-> 3000`.
- `@` and whitespace in device names are replaced with `-` at registration time.

## Peer address changes

A device is identified by its UUID and pinned key, so a new IP address does not create a new
device. The daemon refreshes the stored address from mDNS and from inbound sessions, and
re-advertises its own addresses within about 60 seconds of an interface or DHCP change. If mDNS
is blocked, set the address explicitly instead of pairing again:

```sh
$ lanfp peer set-address mac-mini 192.168.8.23
updated mac-mini@192.168.8.23 [5e6f7a8b] (online)
```

The port defaults to 47811; use `<ip>:47811` for a non-default agent port. `--json` prints
`{schema, peer, id, address, online}`. An established session is left untouched; the new address
is used for the next dial (the next supervisor tick if the peer is offline).

Use `lanfp peer list` to see every paired device with its full UUID, current address and state.

## JSON output

The `--json` output of every data command is a single object carrying `schema: 1`, for example:

```json
{
  "schema": 1,
  "peers": [
    {
      "peer": "mac-mini@192.168.8.10",
      "id": "5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b",
      "name": "mac-mini",
      "address": "192.168.8.10",
      "port": 47811,
      "paired": true,
      "online": true
    }
  ]
}
```

With `--json`, stdout contains only JSON; error messages go to stderr. Peer-scoped entries carry
an `id` (full UUID; `ForwardInfo` calls it `peer_id`), and `lanfp daemon status` carries
`device_id` for this machine. `lanfp remote` also returns `offline_peers` with the IDs of skipped
devices.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid arguments or ambiguous peer selector |
| 3 | Device / rule not found |
| 4 | Device not paired or offline |
| 5 | Listening port already in use / bind failure |
| 6 | Peer is not running `lanfp pair wait` |
| 7 | Insufficient permission (listen on `<1024`) |
| 8 | Target port is not in the peer's listening-port inventory |
| 9 | Pairing failed / wrong code / expired |
| 10 | Daemon failed to start or IPC unreachable |

## Configuration

Linux: `~/.config/lanfp/config.toml`; macOS: `~/Library/Application Support/lanfp/config.toml`;
Windows: `%APPDATA%\lanfp\config.toml`. The file is generated automatically on first start:

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

Set `LANFP_HOME=/some/dir` to collect all configuration, data, identity and log paths under that
directory for tests or portable runs.

## Data and logs

| Platform | Config | Database | Logs |
|---|---|---|---|
| Linux | `~/.config/lanfp/config.toml` | `~/.local/share/lanfp/lanfp.db` | `~/.local/state/lanfp/lanfp.log` |
| macOS | `~/Library/Application Support/lanfp/config.toml` | `lanfp.db` in the same directory | `logs/lanfp.log` in the same directory |
| Windows | `%APPDATA%\lanfp\config.toml` | `%LOCALAPPDATA%\lanfp\lanfp.db` | `logs\lanfp.log` in the same directory |

- Identity keys: `identity.key` (0600) and `identity.crt` in the data directory.
- IPC: Linux `$XDG_RUNTIME_DIR/lanfp/ctl.sock` (fallback `/tmp/lanfp-<uid>/ctl.sock`), mode 0600;
  macOS uses `$TMPDIR`; Windows uses `\\.\pipe\lanfp-<username>-<hash>`.
- Logs rotate once at 5 MiB (`lanfp.log.1`) when the background instance is auto-spawned.

## Background process

```sh
lanfp daemon start       # start it explicitly
lanfp daemon status      # PID, uptime, agent address, IPC and log path
lanfp daemon stop        # stop it
```

`lanfp serve` runs the daemon in the foreground and logs to stderr; use it for debugging with
`RUST_LOG=debug`. Any other command auto-spawns the daemon when needed. Register login autostart
with `lanfp daemon install`; remove it with `lanfp daemon uninstall`.

The single-instance lock applies per `LANFP_HOME`/user runtime directory. Do not run multiple
instances for normal use.

## See also

- [Installation and operations](install.md): releases, builds, firewall, troubleshooting,
  upgrades and uninstall.
- [Security model](security.md): trust boundaries, pairing, transport and accepted risks.
- [Known limitations](limitations.md): platform behaviour and current gaps.
