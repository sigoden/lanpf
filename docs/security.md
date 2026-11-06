# Security Model

This document describes the trust boundaries, threat model and explicitly accepted risks of
`lanfp`. Read the "explicitly accepted risks" section before use.

## Trust Boundaries

| Component | Trust assumption |
|---|---|
| Local user account | Trusted. IPC is accessible only to the current user. |
| Authorized device (`may_connect`) | May open a TLS session and forward to the exposed ports of this machine. |
| Unauthorized device | Untrusted. The TLS server rejects its client certificate outright. |
| Known server (`may_dial`) | A device that authorized this machine. Its key is pinned when this machine dials it. |
| LAN | Untrusted. Sessions use TLS 1.3 and the agent port is the only LAN-facing listener. |
| Grant channel | No shared secret. Identity is proven with Ed25519 signatures and, when available, bound to the mDNS public key. |

## Transport Layer

- TLS 1.3 (rustls), only TLS 1.3 enabled, ALPN `lanfp/1`, 0-RTT disabled.
- Both sides use self-signed certificates; the public key in the certificate must equal the
  Ed25519 public key of the trust record.
- The server (agent port) validates client certificates against the `may_connect` key set; the
  client accepts only the exact public key of the target server.
- Pinning does not depend on a CA, host names or the system certificate store; certificates are
  merely carriers for public keys.
- Once the session is established, `yamux` is layered on top: one control stream plus one data
  stream per TCP connection.

## One-Way Authorization

`lanfp peer grant` on the exposing machine S authorizes a consumer C. The two directions are
stored separately:

- `may_connect`: S allows C to connect to S. Only a grant sets this.
- `may_dial`: C may dial S. The grant responder on C stores S this way so C can pin S's key. This
  is not a reciprocal authorization: C does not allow S to connect to C.

Flow:

```
S: lanfp peer grant C
  S → C: FPG1, Hello(S identity, nonce, pubkey, cert)
  C → S: Challenge(C identity, nonce, pubkey, cert)
  S → C: Prove(signature over both identities/nonces/keys)
  C: verify, store/refresh S as may_dial (this grant does not set may_connect), Prove
  S: verify, store C as may_connect, add C's key to the TLS allow-list
  S → C: Done
  C: Done, then the supervisor dials S
```

- The transcript binds both UUIDs, both nonces and both public keys; both sides sign it with
  Ed25519.
- `nonce` is 32 random bytes; the handshake has a 10-second timeout and requires protocol
  version 2.
- When the target is discovered over mDNS, its `pk` TXT value must match the key presented in the
  handshake. This blocks a simple on-path key substitution but not a device that advertises a
  forged mDNS record.
- With a manually entered IP there is no mDNS key to compare, so the grant is trust-on-first-use.
  `peer grant` prints the authorized device's fingerprint; compare it with
  `lanfp daemon status` on that device if the LAN is not trusted.
- A changed public key (device reinstall) is rejected unless the grant is run with `--force`.
  The old key is removed from the TLS allow-list before the new one is added.
- On the consumer, if the device was already authorized in the other direction and its key
  changed, the grant responder rejects the update; run `lanfp peer grant --force` on that device
  to re-authorize deliberately.
- `lanfp peer revoke` clears `may_connect`, removes the key from the TLS allow-list, cancels the
  current session and deletes the peer's inbound references. The consumer's `may_dial` record is
  left in place and is reported offline until a later grant refreshes it.

### No Six-Digit Code

The earlier model used a 6-digit code with SPAKE2 and a `peer wait` session. That flow has
been removed. The current model is:

- no short code, no waiting session, no code TTL or attempt counter;
- authorization is confirmed by the devices' Ed25519 identities and the mDNS public key;
- manually entered addresses are trust-on-first-use.

This is a deliberate trade-off: it removes the interactive pairing step but also removes the
offline-guessing resistance of SPAKE2. On a LAN where an attacker can spoof mDNS records, a user
can be tricked into authorizing the wrong device. Verify fingerprints when that matters.

## Exposure Policy

- The whitelist lives in `config.toml` (`agent.expose_ports`, single ports and inclusive ranges
  such as `3000-4000`).
- The default is **all**: with an empty whitelist, every Native TCP listening port can be reached
  by an authorized device.
- A non-empty whitelist switches to **whitelist** mode; only ports covered by it are exposed.
  Ranges are stored sorted and merged (overlapping/adjacent ranges fold together).
- A whitelist entry does not have to be listening. It is advertised to authorized devices as a
  range and becomes reachable when a service binds it.
- Exposure is machine-wide, not per device. Every authorized device sees the same set.
- Enforcement is not only in the inventory shown to consumers:
  - `RuleUpsert` for a non-exposed or non-listening target is rejected and is not stored as an
    inbound reference;
  - a data stream for a non-exposed port is rejected before dialing the target; the agent port is
    always rejected.
- `lanfp inbound` remains read-only and shows only ports that are currently being forwarded by
  other devices.
- The agent port is never exposed, even if a whitelist range spans it; local forwarding listeners
  are not Native inventory and are therefore never exposed.
- The whitelist is hot-reloaded; an invalid `agent.expose_ports` keeps the previous whitelist.

## Target Boundaries

- A forwarding target must be in the server's exposure view. In all mode that means a currently
  listening port; in whitelist mode it may be a configured port that is not listening yet.
- Only server loopback addresses are dialed: `127.0.0.1`, `::1`, then the address the port is
  actually bound to.
- Arbitrary `host:port` targets are not accepted, so lanfp cannot be used as a jump host.
- The data stream header carries the internal `rule_id`, which the server uses for logging and
  rejection reasons.

## Local IPC

- Linux/macOS: Unix domain socket, file mode 0600, inside a runtime directory with mode 0700.
- Windows: named pipe `\\.\pipe\lanfp-<username>-<hash>` using the process default DACL (usually
  allowing only the current user and administrators).
- Frame format: `u32 BE length + JSON`, maximum 16 MiB.

## Listener Exposure

- The only listener open to the LAN is the agent port (default `0.0.0.0:47811`).
- Every forwarding listener is forced to bind `127.0.0.1`.
- `lanfp local` / `lanfp remote` hide the local agent port and forwarding listeners.
- The daemon ignores `SIGPIPE`; a peer closing a socket mid-write cannot terminate the process.

## Low Ports

- Linux/macOS: a user-level process cannot bind `<1024`. `forward add --listen 80` returns exit
  code 7 and suggests a high port; this version does not guide the user to sudo.
- Native ports below 1024 on the local machine can still be exposed and used as forwarding
  targets (the consumer listens on its own high port; the host only dials loopback).
- Windows: a normal user can usually listen on `<1024`, which differs from Unix behavior.

## Explicitly Accepted Risks

1. **No per-device port ACL.** Exposure is machine-wide; every authorized device sees the same
   port set. Per-device port grants are not implemented.
2. **No code-based MITM resistance.** Authorization depends on mDNS public keys and signed
   identity proofs. A forged mDNS record or a user selecting the wrong device can grant access
   to an attacker. Manual addresses are trust-on-first-use.
3. **Consumer-side server records are persistent.** Revoking on the exposing side does not
   notify the consumer; its `may_dial` record remains and is reported offline until a later
   grant. It cannot be used to access the host after revocation.
4. **Any LAN device can send a grant to a consumer.** The consumer stores the sender as a known
   server (`may_dial`) but does not authorize it to access the consumer. The consumer's user
   should only create forwards to servers they recognize; a forged grant can otherwise make an
   unfamiliar server appear in `lanfp remote`.
5. User-level enumeration cannot see process attribution for other users or separate netns; ports
   are still listed and their owner shows as `-`.
6. mDNS broadcasts the device name, UUID, protocol version, agent port and public key in
   cleartext; this reveals the existence and key of the device but not its port inventory.
7. There is no code signing on first run, so system security prompts may block it.
8. Windows named pipes rely on the process default DACL and are not further restricted to the
   current user SID only.

If these risks are unacceptable, do not authorize devices you do not control and use a
whitelist with only the ports you intend to share.
