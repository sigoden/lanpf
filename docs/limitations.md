# Known Limitations and Blind Spots

## Port Enumeration

- Only TCP `LISTEN` sockets are enumerated; UDP, established connections and TIME_WAIT are not in
  the inventory.
- Under user-level permissions, the PID/process name/user of other users' processes may be
  invisible. The port is still listed and its owner shows as `-`. On Linux this commonly affects
  system services such as systemd-resolved and sshd when not running as root.
- On macOS, `netstat2` (libproc) can only read the sockets of processes owned by the current user.
  The inventory therefore merges the full `LISTEN` set from `/usr/sbin/netstat`; ports owned by
  root/other users are listed but their PID, process and user stay `-`. Root-owned system ports
  below 1024 (e.g. 22) are listed normally.
- Listeners inside Docker containers, inside WSL2, or in other network namespaces are not
  enumerated; container ports published to the host are visible, but the process attribution for
  them usually shows `-`.
- Process attribution is best effort: PID reuse, short-lived processes and kernel sockets can all
  leave the owner missing.
- Ports are polled every 2 seconds, so a target port may appear/disappear with up to about 2
  seconds of delay.

## Discovery and Pairing

- mDNS may be blocked by firewalls, AP client isolation, VPNs or the macOS 15+ "Local Network"
  privacy permission. Fallback: `lanfp pair <ip>`, `lanfp pair <ip>:<port>`.
- mDNS advertises only the device name, UUID, protocol version and agent port; it never
  advertises the port inventory.
- Only one `lanfp pair wait` is allowed at a time; a second initiator gets "busy" (exit code 6).
- A 6-digit code has only 1,000,000 combinations; security relies on SPAKE2 + the 5-attempt limit
  + a 300-second TTL.
- IPv6 link-local addresses need a scope id (e.g. `fe80::1%eth0`), and PEER parsing currently does
  not support the `%` form; prefer IPv4 or global IPv6 addresses.
- The pairing code is handed to the CLI for display over local IPC; IPC permissions are 0600.

## Sessions and Forwarding

- TCP only. No UDP, multi-hop, NAT traversal or public relay.
- The target must be a port in the server's Native inventory; an arbitrary `host:port` cannot be
  specified.
- Forwarding listeners are forced to `127.0.0.1`; binding `0.0.0.0` is not supported.
- While the peer is offline the listener stays in place but new connections are closed
  immediately; they resume automatically once the peer is back.
- Rules exist only on the listening side; the serving side is read-only.
- A single session carries at most 256 streams and opens at most 100 per second; a stream with no
  bytes flowing for 30 minutes is closed.
- Only one rule may use a given listening port; conflicts are not resolved by picking another
  port automatically.
- Both sides must allow inbound traffic on the agent port, otherwise dialing fails in both
  directions and is retried.

## Permissions and Ports

- Linux/macOS: a user-level process cannot listen on `<1024`; `forward add --listen 80` returns 7.
  This version does not guide the user to sudo.
- Windows: a normal user can usually listen on `<1024`, unlike Unix.
- Native ports below 1024 on the local machine can still be forwarding targets.

## Security

- **No reject/revoke/allow-list.** A paired device can access any Native TCP port on this
  machine; `lanfp inbound` is read-only. Revocation only happens indirectly, by deleting the
  peer's data directory and pairing again.
- Windows named pipes use the process default DACL (usually the current user and administrators);
  they are not further restricted to the current user SID only.
- There is no code signing; the first run may be blocked by system security prompts.
- No auto-update, telemetry or multi-user support.

## Configuration and Operations

- Forwards changed `agent.listen` and `discovery.mdns` settings need a restart of the background
  instance; all other settings hot-reload within about 5 seconds.
- macOS login autostart is a LaunchAgent. When `lanfp daemon install` runs from a plain SSH
  session, macOS launchd may refuse to bootstrap any service (the session belongs to the
  "Background" manager), so the plist is registered but only takes effect at the next GUI login;
  the command warns about this. Running it from Terminal.app activates the agent immediately.
- Logs rotate once at 5 MiB on each `serve` start and do not rotate while running.
- The single-instance lock applies per `LANFP_HOME`/user runtime directory; do not run multiple
  instances for normal use.
- Configuration, database and identity keys all live under the user directory; backing up the
  data directory preserves identity, pairings and rules.

## Platform Verification Status

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Port enumeration | Verified | Verified on macOS 15.5 arm64 (`netstat` fallback) | Not verified on hardware |
| IPC | UDS verified | UDS verified on macOS 15.5 (0600, runtime dir 0700) | Named pipe code path |
| Login autostart | systemd --user verified | LaunchAgent plist verified; activation needs a GUI session | HKCU Run code path |
| mDNS | Verified (two instances, one host) | Code path; two-host and "Local Network" permission not verified | Not verified |
| `<1024` listen | Not possible (exit code 7 verified) | Not possible (exit code 7 verified in E2E) | Usually possible |

macOS M1 (serve, IPC, auto-spawn, inventory, `local`, `daemon status`) is verified on real
hardware; macOS M2–M5 are covered by the loopback E2E suite but still need a live two-host
check. Windows verification remains pending, so treat Windows as "code implemented but not
accepted".

## Output Language

Section 19 of `PLAN.md` states "output in Chinese", but every example output in section 4.3 is in
English. The current implementation follows the concrete examples: CLI messages, table headers
and JSON fields are in English, and the documentation is in English as well. CLI message
localization can be revisited in a later release if needed.
