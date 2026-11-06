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

## Discovery and Authorization

- mDNS may be blocked by firewalls, AP client isolation, VPNs or the macOS 15+ "Local Network"
  privacy permission. Fallback: `lanfp peer grant <ip>`, `lanfp peer grant <ip>:<port>`.
- Interactive `lanfp peer grant` needs at least one mDNS-discovered device; without mDNS, pass
  the consumer's address explicitly.
- The UUID, name and public key shown for a discovered device come from its mDNS TXT record and
  are unauthenticated until the grant handshake. They are bound to the live identity proof, but
  a forged mDNS record can still make an attacker appear under a chosen name.
- `lanfp peer grant` requires the target to be online: it opens the grant channel to the target's
  agent port. A device that is not running `lanfp serve` cannot be authorized.
- The grant is one-way. It does not let the exposing machine access the consumer. Authorize the
  other direction separately if needed.
- Manual addresses are trust-on-first-use: there is no shared code to compare. `peer grant` prints
  the device fingerprint; verify it with `lanfp daemon status` on the other device if the LAN is
  not trusted.
- IPv6 link-local addresses need a scope id (e.g. `fe80::1%eth0`), and PEER parsing currently does
  not support the `%` form; prefer IPv4 or global IPv6 addresses.
- The grant transcript and authorization state are exchanged over local IPC between the CLI and
  the daemon; IPC permissions are 0600/current-user only.

## Exposure

- Exposure is machine-wide, not per device. Every authorized device sees the same set of exposed
  ports.
- An `expose` entry does not bind a service. Adding a port before it is listening is allowed and
  appears as `not listening`; it becomes reachable only when a service actually listens on it.
- In `mode: all`, only currently listening ports can be listed; ports that start listening later
  are exposed automatically but cannot be shown in advance.
- The agent port and local forwarding listeners cannot be exposed.
- `lanfp inbound` shows only ports that are currently being forwarded by other devices; it does
  not list the expose policy.

## Sessions and Forwarding

- TCP only. No UDP, multi-hop, NAT traversal or public relay.
- The target must be in the server's exposure view. In whitelist mode a non-listening exposed
  target creates a rule in `target_gone` state; it becomes active when the service starts.
- Forwarding listeners are forced to `127.0.0.1`; binding `0.0.0.0` is not supported.
- While the peer is offline the listener stays in place but new connections are closed
  immediately; they resume automatically once the peer is back.
- A device's identity is its UUID; `<name>@<address>` (the `PEER` column) is a view that is
  formatted on every command. It prefers a fresh mDNS result, falls back to the stored address,
  and uses the hostname last reported in an authenticated session hello.
- The daemon updates the stored address from successful dials (which prefer a fresh mDNS
  result), from the source of inbound sessions, and via `lanfp peer set-address`; it
  re-advertises its own addresses within about 60 seconds of an interface or DHCP change.
- Selectors accept a full UUID, a unique short-ID prefix, a unique name, `name@address` (the
  address must be current), and a bare address. A selector that matches more than one device
  exits 2 with the candidates instead of silently picking one.
- Re-advertising after a network change unregisters and re-registers the mDNS record, so peers
  may briefly see the device disappear from `lanfp scan`; established sessions and forwarding
  rules are unaffected.
- Rules exist only on the consumer side; the exposing side is read-only apart from `inbound`
  references.
- A pure consumer always dials the exposing side; the UUID-based dialer election only applies
  when both devices have authorized each other.
- A single session carries at most 256 streams and opens at most 100 per second; a stream with no
  bytes flowing for 30 minutes is closed.
- Only one rule may use a given listening port by default; pass `--listen 0` to let the OS pick
  a free loopback port instead.
- Both sides must allow inbound traffic on the agent port, otherwise dialing fails in both
  directions and is retried.
- Revoking on the exposing side does not notify the consumer. Its known-server record remains
  and is reported offline; a later `peer grant` refreshes it.
- A session is shared by both directions. Revoking one direction of a mutual authorization
  drops the session; the other direction recovers on the next dial if it is still authorized.

## Permissions and Ports

- Linux/macOS: a user-level process cannot listen on `<1024`; `forward add --listen 80` returns 7.
  This version does not guide the user to sudo.
- Windows: a normal user can usually listen on `<1024`, unlike Unix.
- Native ports below 1024 on the local machine can still be exposed and used as forwarding
  targets.

## Security

- **No per-device port ACL.** Exposure is global; every authorized device shares the same set.
- **No code-based MITM resistance.** Authorization relies on mDNS public keys and signed
  identity proofs; manual addresses are trust-on-first-use. See
  [Security model](security.md).
- Windows named pipes use the process default DACL (usually the current user and administrators);
  they are not further restricted to the current user SID only.
- There is no code signing; the first run may be blocked by system security prompts.
- No auto-update, telemetry or multi-user support.

## Configuration and Operations

- Forwards changed `agent.listen` and `discovery.mdns` settings need a restart of the background
  instance; all other settings hot-reload within about 5 seconds.
- An old `[pairing]` section in `config.toml` is ignored.
- macOS login autostart is a LaunchAgent. When `lanfp daemon install` runs from a plain SSH
  session, macOS launchd may refuse to bootstrap any service (the session belongs to the
  "Background" manager), so the plist is registered but only takes effect at the next GUI login;
  the command warns about this. Running it from Terminal.app activates the agent immediately.
- Logs rotate once at 5 MiB on each `serve` start and do not rotate while running.
- The single-instance lock applies per `LANFP_HOME`/user runtime directory; do not run multiple
  instances for normal use.
- Configuration, database and identity keys all live under the user directory; backing up the
  data directory preserves identity, authorization records and rules.

## Platform Verification Status

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Port enumeration | Verified | Verified on macOS 15.5 arm64 (`netstat` fallback) | Verified on Windows 11 25H2 (`Get-NetTCPConnection` comparison) |
| IPC | UDS verified | UDS verified on macOS 15.5 (0600, runtime dir 0700) | Named pipe verified on Windows 11 25H2; the name is scoped per `LANFP_HOME` |
| Login autostart | systemd --user verified | LaunchAgent plist verified; activation needs a GUI session | HKCU Run value verified (write/remove); real login activation untested |
| mDNS | Verified (two instances, one host; Linux↔macOS LAN) | Verified between a Linux and a macOS host; "Local Network" permission behaviour still untested | Verified between a Linux and a Windows host |
| Cross-host forwarding | Verified (Linux↔macOS, Linux↔Windows) | Verified (Linux↔macOS) | Verified (Linux↔Windows) |
| `<1024` listen | Not possible (exit code 7 verified) | Not possible (exit code 7 verified in E2E) | Allowed for an administrator (port 80 verified) |

The two-host LAN runs above were performed under the earlier pairing model. Port inventory,
forwarding, offline/target-gone recovery and JSON results remain relevant, but the one-way
authorization and expose view need a new real-hardware run. The loopback E2E suite covers the new
flow on Linux; see [Verification](verification.md).

Windows specifics:

- The IPC endpoint is `\\.\pipe\lanfp-<user>-<hash of the runtime directory>`, so every
  `LANFP_HOME` gets its own daemon.
- `lanfp daemon install` writes a HKCU Run value named `lanfp` that runs `serve --hidden`; the
  hidden flag calls `FreeConsole` so no console window stays on screen. The registry entry does
  not carry `LANFP_HOME`, so it always starts the default data directory.
- Win32-OpenSSH terminates the process tree of a session when the connection closes, so a daemon
  auto-spawned by an SSH command does not outlive the session. Keep a `lanfp serve` session open
  for long-running remote tests; a desktop logon is not affected.
- The loopback E2E suite is `#![cfg(unix)]`; on Windows `cargo test --workspace` runs the unit
  tests only.
