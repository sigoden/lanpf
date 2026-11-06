# Usage and Command Reference

`lanfp` runs as a single binary. `lanfp serve` is the long-running background process; every
other subcommand is a short-lived client that talks to it over local IPC. Any data command starts
the background process automatically when needed, so `lanfp daemon start` is optional.

The default output is a table. Every data command supports `--json` (`schema: 2`) for scripts and
other tools. CLI messages, table headers and JSON fields are in English.

## Commands

| Command | Description |
|---|---|
| `lanfp scan [--timeout 3s] [--json]` | Live mDNS scan; list devices and their authorization state |
| `lanfp peer list [--json]` | Devices authorized to access this machine |
| `lanfp peer grant [PEER]... [--force] [--json]` | Authorize devices; without PEER, scan and pick one |
| `lanfp peer revoke <PEER>... [--json]` | Revoke authorization and drop existing sessions |
| `lanfp peer set-address <peer> <ip[:port]> [--json]` | Update the stored address of a known device |
| `lanfp expose list [--json]` | Show the effective exposure view |
| `lanfp expose add <PORT>... [--json]` | Add ports to the whitelist (they need not be listening) |
| `lanfp expose remove <PORT>... [--json]` | Remove ports from the whitelist |
| `lanfp local [--json]` | Local TCP services (lanfp itself and forwarded listeners are excluded) |
| `lanfp remote [peer] [--json]` | Exposed ports of servers that authorized this machine |
| `lanfp forward add <peer> <target_port> [--listen <port>] [--json]` | Create a forward |
| `lanfp forward list [--json]` | Local rules |
| `lanfp forward remove <local_port> [--json]` | Remove a rule and close its listener |
| `lanfp inbound [--json]` | Read-only: who is currently forwarding my ports |
| `lanfp serve` | Run the long-running process in the foreground (debugging) |
| `lanfp daemon start\|stop\|status` | Manage the background instance |
| `lanfp daemon install\|uninstall` | Register/remove login autostart |

Run `lanfp <command> --help` for the exact options of a command. For a grouped command, use
`lanfp <group> <command> --help`.

## Command model

Commands are either flat actions (`scan`, `local`, `remote`, `inbound`, `serve`) or a noun group
with verbs (`peer`, `expose`, `forward`, `daemon`). A group exists only when one resource has
several verbs; a one-off action stays a top-level command. `lanfp peer grant` without a selector
is interactive and text-only; `--json` requires at least one `PEER`.

## Authorization (one-way)

The machine that exposes a service is the **host**. The machine that uses it is the
**consumer**.

1. On the host, run `lanfp scan` to see devices that are running `lanfp serve`.
2. On the host, run `lanfp peer grant` (pick from the scan) or pass one or more selectors:

   ```sh
   $ lanfp peer grant
   discovered devices:
     1. 5e6f7a8b nix@192.168.8.11        unknown
   select device [1-1] (q to cancel): 1
   granted nix@192.168.8.11 [5e6f7a8b]
   key fingerprint: 1a2b...
   this device may now connect and forward exposed ports on this machine
   ```

   The grant uses a one-way `FPG1` handshake on the agent port. The host stores the consumer
   with `may_connect`; the consumer stores the host as a known server (`may_dial`) so it can
   dial back. The consumer is **not** authorized to be accessed by the host.

3. The consumer can now run `lanfp remote` without a selector and see every host that
   authorized it, plus that host's exposure view.

`lanfp peer list` shows only devices this machine authorized (`may_connect`). On the consumer,
the host does not appear in `peer list`; it appears in `remote` and in `scan` as `server`.

- `--force` replaces a stored public key after a device reinstall. Without it, a key change is
  rejected (exit 9).
- `lanfp peer revoke <peer>` clears `may_connect`, removes the key from the TLS allow-list, drops
  the current session, and deletes the peer's inbound references. The consumer's server record
  remains and is reported offline; a later `peer grant` refreshes it.
- `lanfp peer set-address` works for any known device, including a server learned by `remote`;
  this is useful when mDNS is unavailable.

## Exposure

Exposure is machine-wide and has two modes:

- **all** (default): every Native listening port is exposed. No `expose` rows exist.
- **whitelist**: only the configured ports are exposed. This mode starts as soon as the first
  port is added.

```sh
$ lanfp expose add 3000 3001
exposed 3000,3001
warning: whitelist mode enabled; only ports in `lanfp expose list` are accessible

$ lanfp expose list
mode: whitelist (only listed ports are exposed)
PORT   STATE          BIND         PROCESS   USER   INBOUND
3000   listening      127.0.0.1    node      sigo   52714
3001   not listening  -            -         -      -
```

- A port does **not** need to be listening when it is added. It remains in the whitelist and is
  reported as `not listening` until a service binds it.
- `lanfp expose remove` accepts one or more ports; if any requested port is not in the list the
  command changes nothing (exit 3). Removing the last entry returns to `mode: all` and prints a
  warning.
- The agent port and local forwarding listeners are not valid expose targets (exit 2).
- The consumer sees the same view through `lanfp remote`: in `all` mode it lists every listening
  port; in `whitelist` mode it lists the configured ports with a `listening` / `not listening`
  state. Ports that are listening but not exposed are not shown.
- In whitelist mode, `lanfp forward add` accepts a non-listening exposed port. The rule is
  created as `target_gone` and becomes `active` automatically when the service starts listening.
- `lanfp inbound` is unchanged: it lists only ports that are currently being forwarded by other
  devices (active `inbound_ref` rows).

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

- `lanfp peer grant` with a bare address treats it as a manual target; the address must be an IP.
  Hostnames must come from `scan` or an existing trust record.
- The displayed name comes from the remote hostname and is refreshed on the next session
  establishment (the hello is authenticated by the pinned key). Two devices can share a name;
  bare-name selection is then ambiguous, so use the ID.
- The user-visible rule ID is the local listening port. The listener is always `127.0.0.1`, so the
  address is omitted when a rule is displayed.
- The `FORWARDED` column of `lanfp remote` shows the local listening port, e.g. `-> 3000`.
- `@` and whitespace in device names are replaced with `-` at registration time.

## Forwarding

`lanfp forward add <peer> <target_port>` listens on `127.0.0.1:<target_port>` by default. Pass
`--listen <port>` to choose another local port, or `--listen 0` to let the OS pick a free
loopback port:

```sh
$ lanfp forward add mac-mini 3000
created 3000 -> mac-mini@192.168.8.10:3000 (active)

$ lanfp forward add mac-mini 5000 --listen 0
created 52714 -> mac-mini@192.168.8.10:5000 (active)
```

The target must be in the peer's exposure view. In `mode: all` that means a currently listening
port; in whitelist mode it may be a configured port that is not listening yet. The chosen listen
port is the rule ID: it appears in `lanfp forward list` and in the `FORWARDED` column of
`lanfp remote`, and it is the argument to `lanfp forward remove`. It is stored with the rule, so
a daemon restart rebinds the same port instead of picking a new one.

## Peer address changes

A device is identified by its UUID and pinned key, so a new IP address does not create a new
device. The daemon refreshes the stored address from mDNS and from inbound sessions, and
re-advertises its own addresses within about 60 seconds of an interface or DHCP change. If mDNS
is blocked, set the address explicitly instead of granting again:

```sh
$ lanfp peer set-address mac-mini 192.168.8.23
updated mac-mini@192.168.8.23 [5e6f7a8b] (online)
```

The port defaults to 47811; use `<ip>:47811` for a non-default agent port. `--json` prints
`{schema, peer, id, address, online}`. An established session is left untouched; the new address
is used for the next dial.

## JSON output

The `--json` output of every data command is a single object carrying `schema: 2`, for example:

```json
{
  "schema": 2,
  "peers": [
    {
      "id": "5e6f7a8b-1c2d-4e3f-8a9b-0c1d2e3f4a5b",
      "name": "mac-mini",
      "address": "192.168.8.10",
      "port": 47811,
      "online": true,
      "since": 1762300000,
      "fingerprint": "..."
    }
  ]
}
```

With `--json`, stdout contains only JSON; error messages go to stderr. Peer-scoped entries carry
an `id` (full UUID; `ForwardInfo` calls it `peer_id`), and `lanfp daemon status` carries
`device_id` and `fingerprint` for this machine. `lanfp remote` returns the peer's exposure
`mode` and a `listening` flag per port; it also returns `offline_peers` with the IDs of skipped
devices.

`lanfp peer grant --json` returns `{schema, granted: [...], failed: [...]}`; a non-empty `failed`
array makes the command exit non-zero.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid arguments or ambiguous peer selector |
| 3 | Device / rule / expose entry not found |
| 4 | Device not authorized, not a known server, or offline |
| 5 | Listening port already in use / bind failure |
| 7 | Insufficient permission (listen on `<1024`) |
| 8 | Target port is not exposed by the peer |
| 9 | Authorization failed / key changed / protocol mismatch |
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
```

After a change, the background instance hot-reloads within about 5 seconds; changes to
`agent.listen` and `discovery.mdns` take effect only after
`lanfp daemon stop && lanfp daemon start`. An old `[pairing]` section is ignored.

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
lanfp daemon status      # PID, uptime, agent address, allowed/servers, IPC and log path
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
- [Security model](security.md): trust boundaries, authorization, exposure, transport and
  accepted risks.
- [Known limitations](limitations.md): platform behaviour and current gaps.
