# Security model

Trust boundaries, threat model and accepted risks. Read [explicitly accepted risks](#explicitly-accepted-risks) before authorizing devices.

## Trust boundaries

| Component | Assumption |
|---|---|
| Local user account | Trusted; IPC is current-user only |
| Authorized device (`may_connect`) | May open a TLS session and forward to exposed ports |
| Unauthorized device | Untrusted; the TLS server rejects its client certificate |
| Known server (`may_dial`) | A device that authorized this machine; its key is pinned when dialing |
| LAN | Untrusted; TLS 1.3, and the agent port is the only LAN-facing listener |
| Grant channel | No shared secret; Ed25519 signatures, bound to the mDNS key when available |

## Transport

- TLS 1.3 (rustls) only, ALPN `lanpf/1`, 0-RTT disabled.
- Both sides use self-signed certificates; the certificate key must equal the Ed25519 public key of the trust record.
- The agent port validates client certificates against `may_connect`; the client accepts only the exact public key of the target server.
- No CA, hostname or system certificate store dependency; certificates only carry public keys.
- `yamux` is layered on top: one control stream plus one data stream per proxied TCP connection.

## One-way authorization

`lanpf peer grant` on the exposing machine S authorizes consumer C. The directions are stored separately:

- `may_connect`: S allows C to connect. Only a grant sets it.
- `may_dial`: C may dial S. The grant responder on C stores S this way so it can pin S's key; this is not reciprocal access.

```
S: lanpf peer grant C
  S → C: FPG1 Hello(S identity, nonce, pubkey, cert)
  C → S: Challenge(C identity, nonce, pubkey, cert)
  S → C: Prove(signature over both identities, nonces and keys)
  C: store/refresh S as may_dial, Prove
  S: store C as may_connect, add C's key to the TLS allow-list
  both: Done; C's supervisor dials S
```

- The transcript binds both UUIDs, both nonces and both public keys, signed by both Ed25519 keys. Nonces are 32 random bytes; the handshake times out after 10 seconds and requires protocol version 2.
- With mDNS, the target's `pk` TXT value must match the handshake key. This blocks simple on-path key substitution but not a forged mDNS record. Manual addresses are trust-on-first-use; compare the printed fingerprint with `lanpf daemon status` on the other device if the LAN is not trusted.
- A changed key (device reinstall) is rejected unless the grant uses `--force`; the old key is removed from the allow-list before the new one is added.
- `peer revoke` clears `may_connect`, removes the key from the allow-list, cancels the session and deletes inbound references. The consumer's `may_dial` record stays and reports offline until a later grant.

## Exposure enforcement

- Exposure is machine-wide, not per device: every authorized device sees the same set.
- An empty `agent.expose_ports` exposes every Native listening port; entries switch to whitelist mode; ranges are stored sorted and merged.
- Whitelisted ports need not be listening; they are advertised and become reachable when a service binds them.
- Enforcement is server-side: `RuleUpsert` for a non-exposed or non-listening target is rejected and not stored; a data stream for a non-exposed port is rejected before dialing; the agent port is always rejected.
- The agent port is never exposed, even inside a whitelist range; forwarding listeners are not Native inventory.
- Hot reload keeps the previous whitelist when the new one is invalid.

## Target boundaries

- Targets must be in the server's exposure view (all mode: currently listening; whitelist: may be non-listening).
- Dial targets are chosen server-side: `127.0.0.1`, `::1`, then the address the port is bound to. Arbitrary `host:port` targets are rejected, so lanpf cannot be used as a jump host.

## Local IPC

- Unix socket, mode 0600, in a runtime directory with mode 0700; Windows named pipe `\\.\pipe\lanpf-<username>-<hash>` using the process default DACL.
- Frames are `u32 BE length + JSON`, maximum 16 MiB.

## Listener exposure

- The agent port (default `0.0.0.0:47811`) is the only LAN-facing listener; forwarding listeners are forced to `127.0.0.1`.
- `local` and `remote` hide the agent port and forwarding listeners.
- The daemon ignores `SIGPIPE`.

## Low ports

- Linux/macOS: a user process cannot bind `<1024`; `forward add --listen 80` exits 7. Native low ports can still be exposed and used as forwarding targets.
- Windows: a normal user can usually bind `<1024`.

## Explicitly accepted risks

1. **No per-device port ACL.** Exposure is machine-wide; every authorized device sees the same ports.
2. **No code-based MITM resistance.** Authorization relies on mDNS public keys and signed identity proofs; manual addresses are trust-on-first-use. A forged mDNS record or a wrong device selection can grant an attacker access.
3. **Consumer-side server records persist.** Revoking on the exposing side is not pushed; the consumer keeps an offline `may_dial` record until a later grant and cannot access the host after revocation.
4. **Any LAN device can send a grant to a consumer.** It is stored as a known server but does not authorize access to the consumer; only create forwards to servers you recognize.
5. **User-level enumeration cannot attribute other users' processes.** The port is still listed, with owner `-`.
6. **mDNS is cleartext.** Device name, UUID, protocol version, agent port and public key are broadcast; the port inventory is not.
7. **No code signing.** First-run security prompts may block the binary.
8. **Windows named pipes** rely on the process default DACL, not the current-user SID alone.

If these risks are unacceptable, do not authorize devices you do not control and whitelist only the ports you intend to share.
