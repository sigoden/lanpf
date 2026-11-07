# Known limitations

## Port enumeration

- Only TCP `LISTEN` sockets are enumerated; UDP, established connections and TIME_WAIT are not.
- Under user permissions, other users' PID, process name and user may be invisible; the port is listed with owner `-` (common for system services such as systemd-resolved and sshd on Linux).
- macOS merges the full `LISTEN` set from `/usr/sbin/netstat` because libproc only reads the current user's sockets; root-owned ports are listed but their attribution stays `-` (low root-owned ports such as 22 are listed normally).
- Listeners inside Docker containers, WSL2 or other network namespaces are not enumerated; published container ports appear, usually with `-` attribution.
- Attribution is best effort: PID reuse, short-lived processes and kernel sockets can leave the owner missing.
- Ports are polled every 2 seconds; a target can appear or disappear with up to about 2 seconds of delay.

## Discovery and authorization

- mDNS may be blocked by firewalls, AP client isolation, VPNs or the macOS 15+ "Local Network" permission; fall back to `lanpf peer grant <ip>[:port]`.
- Interactive `peer grant` needs at least one discovered device; without mDNS, pass the address explicitly.
- Discovered name, UUID and key come from the mDNS TXT record and are unauthenticated until the grant handshake; a forged record can still show an attacker under a chosen name. Manual addresses are trust-on-first-use; verify the printed fingerprint if the LAN is not trusted.
- The target must be online to be granted (it must run `lanpf serve`).
- The grant is one-way; authorize the other direction separately if needed.
- IPv6 link-local addresses need a scope id (`fe80::1%eth0`), and the `%` form is not parsed; prefer IPv4 or global IPv6.

## Exposure

- Exposure is machine-wide, not per device.
- The whitelist does not bind a service; a whitelisted port becomes reachable when something listens on it.
- In all mode only currently listening ports can be listed; later listeners are exposed automatically but cannot be shown in advance.
- The agent port and local forwarding listeners are never exposed.
- `lanpf inbound` shows only ports currently forwarded by other devices, not the exposure policy; edit the whitelist in `config.toml`.

## Sessions and forwarding

- TCP only; no UDP, multi-hop, NAT traversal or public relay.
- The target must be in the server's exposure view. A non-listening whitelisted target creates a `target_gone` rule that becomes active when the service starts.
- Forwarding listeners are forced to `127.0.0.1`.
- While the peer is offline the listener stays in place but new connections close immediately; they resume when the peer returns.
- `PEER` (`<name>@<address>`) is a per-command view built from mDNS, the stored address and the hostname from the last authenticated hello; the UUID is the identity.
- The daemon updates stored addresses from successful dials, mDNS, inbound sessions and `peer set-address`, and re-advertises within about 60 seconds of a network change. Re-advertising briefly removes the device from `scan`; sessions and rules are unaffected.
- Selectors accept a full UUID, a unique short prefix, a unique name, the current `name@address`, and a bare address; an ambiguous match exits 2 with the candidates.
- Rules exist only on the consumer side; the exposing side is read-only apart from `inbound` references.
- A pure consumer always dials; the UUID dialer election applies only when both sides have authorized each other.
- A session carries at most `agent.max_streams` streams (default 256, maximum 511), opens at most `agent.max_new_streams_per_sec` per direction per second (default 100), and closes a stream idle for 30 minutes. When the stream limit is reached, the least recently active stream that has been idle for at least two minutes is closed to make room.
- One rule per listening port by default; `--listen 0` lets the OS pick a free loopback port.
- Both sides must allow inbound traffic on the agent port, or dialing fails in both directions.
- Revoking does not notify the consumer; its known-server record stays and reports offline until a later grant.
- A session is shared by both directions; revoking one direction drops it, and the other recovers on the next dial if still authorized.

## Permissions and low ports

- Linux/macOS: a user process cannot listen on `<1024`; `forward add --listen 80` exits 7. Windows usually allows it.
- Native low ports can still be exposed and used as forwarding targets.

## Security

- No per-device port ACL, no code-based MITM resistance, Windows named pipes not restricted to the current-user SID alone, no code signing, and no auto-update, telemetry or multi-user support. See the [Security model](security.md) for accepted risks.

## Configuration and operations

- Changed `agent.listen` and `discovery.mdns` settings need a daemon restart; all other settings hot-reload within about 5 seconds.
- macOS autostart is a LaunchAgent; from a plain SSH session it may activate only at the next GUI login.
- Logs rotate once at 5 MiB when the CLI spawns the daemon and do not rotate while running.
- One instance per `LANPF_HOME`/user runtime directory.
- Config, database and identity live under the user directory; backing up the data directory preserves identity, authorizations and rules.

## Platform notes

- Windows: the IPC pipe name includes the runtime directory, so each `LANPF_HOME` gets its own daemon; the HKCU Run entry does not carry `LANPF_HOME` and always uses the default data directory.
- Win32-OpenSSH terminates the process tree on disconnect, so an SSH-spawned daemon does not outlive the session; keep `lanpf serve` open for long remote tests.
- The loopback E2E suite is Unix-only; Windows runs the unit tests only.
