//! One-way device authorization (`lanfp peer grant` / `peer revoke`) and the
//! read-only identity query used when a consumer learns a server.
//!
//! The exposing device S opens a `FPG1` channel to the consumer C. S stores C
//! with `may_connect=1`; C stores S with `may_dial=1` so it can dial S later.
//! C's record is not a reciprocal authorization: it is only a pinned server
//! identity.

use crate::daemon::{internal, ipc_err, Daemon};
use crate::db::PeerRecord;
use crate::discovery::DiscoveredPeer;
use crate::session::SessionHandle;
use crate::util::now_ts;
use anyhow::{Context, Result};
use lanfp_core::error::ExitCode;
use lanfp_core::frame::{read_json, write_json};
use lanfp_core::ipc::*;
use lanfp_core::peer::PeerAddr;
use lanfp_core::protocol::{GrantMessage, IdentityMessage};
use lanfp_core::{
    format_peer, sanitize_device_name, GRANT_MAGIC, IDENTITY_MAGIC, PROTOCOL_VERSION,
};
use lanfp_crypto::{fingerprint, grant_transcript, identity_transcript, verify_signature};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GRANT_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum AuthTarget {
    Discovered(DiscoveredPeer),
    Trusted(PeerRecord),
    Manual(PeerAddr),
}

struct TargetSpec {
    connect_addr: String,
    expected_uuid: Option<Uuid>,
    expected_pubkey: Option<[u8; 32]>,
}

impl Daemon {
    // ------------------------------------------------------------------
    // Target resolution
    // ------------------------------------------------------------------

    pub fn auth_target(&self, selector: &str) -> Result<AuthTarget, IpcError> {
        let s = selector.trim();
        let discovered = self.discovered_matches(s);
        let trusted = self.trust_matches(s)?;

        let mut ids: Vec<Uuid> = Vec::new();
        for peer in &discovered {
            if !ids.contains(&peer.uuid) {
                ids.push(peer.uuid);
            }
        }
        for peer in &trusted {
            if !ids.contains(&peer.device_id) {
                ids.push(peer.device_id);
            }
        }
        if ids.len() > 1 {
            let mut message = format!("`{s}` matches {} devices:", ids.len());
            for id in &ids {
                let display = discovered
                    .iter()
                    .find(|p| p.uuid == *id)
                    .map(|p| p.display())
                    .or_else(|| {
                        trusted
                            .iter()
                            .find(|p| p.device_id == *id)
                            .map(|p| self.display_peer(p))
                    })
                    .unwrap_or_else(|| id.to_string());
                message.push_str(&format!("\n  {}  {}", lanfp_core::short_id(*id), display));
            }
            message.push_str("\nuse the device ID (`lanfp scan`) to disambiguate");
            return Err(ipc_err(ExitCode::Usage, message));
        }
        if ids.len() == 1 {
            let id = ids[0];
            if id == self.device_id {
                return Err(ipc_err(
                    ExitCode::Usage,
                    "cannot grant this machine access to itself",
                ));
            }
            if let Some(peer) = discovered.into_iter().find(|p| p.uuid == id) {
                if peer.version != PROTOCOL_VERSION {
                    return Err(ipc_err(
                        ExitCode::AuthorizationFailed,
                        format!(
                            "{} speaks protocol v{}; upgrade both devices to v{PROTOCOL_VERSION}",
                            peer.display(),
                            peer.version
                        ),
                    ));
                }
                return Ok(AuthTarget::Discovered(peer));
            }
            if let Some(peer) = trusted.into_iter().find(|p| p.device_id == id) {
                return Ok(AuthTarget::Trusted(peer));
            }
        }
        match PeerAddr::parse(s) {
            // The manual fallback is an address, not a hostname: names must
            // come from discovery or an existing trust record.
            Ok(addr) if addr.host.parse::<std::net::IpAddr>().is_ok() => {
                Ok(AuthTarget::Manual(addr))
            }
            Ok(_) => Err(ipc_err(
                ExitCode::DeviceNotFound,
                format!(
                    "`{s}` is not a known device; use a name/ID from `lanfp scan` or an IP address"
                ),
            )),
            Err(err) => Err(ipc_err(
                ExitCode::DeviceNotFound,
                format!("cannot resolve peer `{s}`: {err}"),
            )),
        }
    }

    fn target_spec(&self, target: &AuthTarget) -> Result<TargetSpec, IpcError> {
        match target {
            AuthTarget::Discovered(peer) => Ok(TargetSpec {
                connect_addr: peer.best_addr().map(|a| a.to_string()).ok_or_else(|| {
                    ipc_err(
                        ExitCode::DeviceNotFound,
                        format!("{} has no reachable address", peer.display()),
                    )
                })?,
                expected_uuid: Some(peer.uuid),
                expected_pubkey: peer.pubkey,
            }),
            AuthTarget::Trusted(peer) => Ok(TargetSpec {
                connect_addr: self
                    .current_peer_addr(peer)
                    .map(|a| a.to_string())
                    .ok_or_else(|| {
                        ipc_err(
                            ExitCode::DeviceNotFound,
                            format!(
                                "{} has no known address; use `lanfp peer set-address` first",
                                self.display_peer(peer)
                            ),
                        )
                    })?,
                expected_uuid: Some(peer.device_id),
                expected_pubkey: peer.pubkey_array(),
            }),
            AuthTarget::Manual(addr) => Ok(TargetSpec {
                connect_addr: addr.connect_addr(),
                expected_uuid: None,
                expected_pubkey: None,
            }),
        }
    }

    // ------------------------------------------------------------------
    // `lanfp peer grant`
    // ------------------------------------------------------------------

    pub async fn peer_grant_json(
        self: &Arc<Self>,
        selectors: Vec<String>,
        force: bool,
    ) -> Result<serde_json::Value, IpcError> {
        if selectors.is_empty() {
            return Err(ipc_err(
                ExitCode::Usage,
                "at least one peer selector is required",
            ));
        }
        // Resolve everything first so a typo cannot produce a partial grant.
        let mut targets = Vec::new();
        for selector in &selectors {
            targets.push((selector.clone(), self.auth_target(selector)?));
        }
        let mut granted = Vec::new();
        let mut failed = Vec::new();
        for (selector, target) in targets {
            match self.grant_to(&target, force).await {
                Ok(peer) => granted.push(peer),
                Err(err) => failed.push(PeerGrantFailure {
                    peer: selector,
                    code: err.code,
                    message: err.message,
                }),
            }
        }
        serde_json::to_value(PeerGrantResult {
            schema: lanfp_core::JSON_SCHEMA,
            granted,
            failed,
        })
        .map_err(internal)
    }

    async fn grant_to(
        self: &Arc<Self>,
        target: &AuthTarget,
        force: bool,
    ) -> Result<GrantedPeer, IpcError> {
        let spec = self.target_spec(target)?;
        let mut stream = connect(&spec.connect_addr).await?;
        stream.write_all(GRANT_MAGIC).await.map_err(|e| {
            ipc_err(
                ExitCode::NotAuthorizedOrOffline,
                format!("send grant magic: {e}"),
            )
        })?;

        let nonce_a = random_nonce();
        let hello = GrantMessage::Hello {
            version: PROTOCOL_VERSION,
            uuid: self.device_id,
            name: self.device_name.clone(),
            agent_port: self.agent_port,
            nonce: nonce_a.clone(),
            pubkey: self.identity.public_key_bytes().to_vec(),
            cert_der: self.identity.cert_der().to_vec(),
        };
        send(&mut stream, &hello).await?;
        let challenge = match read(&mut stream).await? {
            GrantMessage::Challenge {
                version,
                uuid,
                name,
                agent_port,
                nonce,
                pubkey,
                cert_der,
            } => {
                validate_version(version)?;
                if nonce.len() != 32 || pubkey.len() != 32 {
                    return Err(ipc_err(
                        ExitCode::AuthorizationFailed,
                        "peer sent a malformed grant challenge",
                    ));
                }
                validate_cert(&pubkey, &cert_der)?;
                if let Some(expected) = spec.expected_uuid {
                    if expected != uuid {
                        return Err(ipc_err(
                            ExitCode::AuthorizationFailed,
                            format!(
                                "device identity changed at {}; rescan the device before granting",
                                spec.connect_addr
                            ),
                        ));
                    }
                }
                if let Some(expected) = spec.expected_pubkey {
                    if expected != <[u8; 32]>::try_from(pubkey.as_slice()).unwrap_or_default()
                        && !force
                    {
                        return Err(ipc_err(
                            ExitCode::AuthorizationFailed,
                            format!(
                                "{name} at {} has a new public key (mDNS mismatch); rescan or re-run with --force",
                                spec.connect_addr
                            ),
                        ));
                    }
                }
                (
                    uuid,
                    sanitize_device_name(&name),
                    agent_port,
                    nonce,
                    pubkey,
                    cert_der,
                )
            }
            GrantMessage::Reject { reason, code } => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::AuthorizationFailed),
                    reason,
                ))
            }
            other => {
                return Err(ipc_err(
                    ExitCode::AuthorizationFailed,
                    format!("unexpected grant reply: {other:?}"),
                ))
            }
        };
        let (peer_uuid, peer_name, peer_agent_port, nonce_b, peer_pubkey, peer_cert) = challenge;
        if peer_uuid == self.device_id {
            return Err(ipc_err(
                ExitCode::Usage,
                "cannot grant this machine access to itself",
            ));
        }

        // Check the key-change policy before the responder stores us.
        if let Some(existing) = self.db.get_peer(peer_uuid).map_err(internal)? {
            if existing.ed25519_pub != peer_pubkey && !force {
                let reason = format!(
                    "{} has a new public key (device reinstalled?); re-run with --force",
                    peer_name
                );
                let _ = send(
                    &mut stream,
                    &GrantMessage::Reject {
                        reason: reason.clone(),
                        code: ExitCode::AuthorizationFailed.code(),
                    },
                )
                .await;
                return Err(ipc_err(ExitCode::AuthorizationFailed, reason));
            }
        }

        let transcript = grant_transcript(
            self.device_id,
            peer_uuid,
            &nonce_a,
            &nonce_b,
            &self.identity.public_key_bytes(),
            &peer_pubkey,
        );
        let signature = self.identity.sign(&transcript);
        send(
            &mut stream,
            &GrantMessage::Prove {
                signature: signature.to_vec(),
            },
        )
        .await?;

        match read(&mut stream).await? {
            GrantMessage::Prove { signature } => {
                if !verify_signature(&peer_pubkey, &transcript, &signature) {
                    return Err(ipc_err(
                        ExitCode::AuthorizationFailed,
                        "peer failed to prove its identity",
                    ));
                }
            }
            GrantMessage::Reject { reason, code } => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::AuthorizationFailed),
                    reason,
                ))
            }
            other => {
                return Err(ipc_err(
                    ExitCode::AuthorizationFailed,
                    format!("unexpected grant proof: {other:?}"),
                ))
            }
        }

        match read(&mut stream).await? {
            GrantMessage::Done => {}
            GrantMessage::Reject { reason, code } => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::AuthorizationFailed),
                    reason,
                ))
            }
            other => {
                return Err(ipc_err(
                    ExitCode::AuthorizationFailed,
                    format!("unexpected grant confirmation: {other:?}"),
                ))
            }
        }
        let _ = send(&mut stream, &GrantMessage::Done).await;

        let source_ip = stream
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
        let existing = self.db.get_peer(peer_uuid).map_err(internal)?;
        let already_granted = existing
            .as_ref()
            .map(|e| e.may_connect && e.ed25519_pub == peer_pubkey)
            .unwrap_or(false);
        if let Some(old) = existing.as_ref() {
            if old.ed25519_pub != peer_pubkey {
                if let Ok(key) = <[u8; 32]>::try_from(old.ed25519_pub.as_slice()) {
                    self.remove_known_peer(&key);
                }
            }
        }
        let record = PeerRecord {
            device_id: peer_uuid,
            name: peer_name.clone(),
            ed25519_pub: peer_pubkey.clone(),
            cert_der: peer_cert.clone(),
            last_addr: Some(SocketAddr::new(source_ip, peer_agent_port).to_string()),
            paired_at: existing
                .as_ref()
                .map(|e| e.paired_at)
                .unwrap_or_else(now_ts),
            last_seen_at: Some(now_ts()),
            may_connect: true,
            may_dial: existing.as_ref().map(|e| e.may_dial).unwrap_or(false),
        };
        self.db.upsert_peer(&record).map_err(internal)?;
        if let Ok(key) = <[u8; 32]>::try_from(peer_pubkey.as_slice()) {
            self.add_known_peer(key);
        }
        self.reset_backoff(peer_uuid);
        tracing::info!(
            "authorized {} [{}] to connect; key {}",
            format_peer(&peer_name, &source_ip.to_string(), peer_agent_port),
            lanfp_core::short_id(peer_uuid),
            fingerprint(&peer_pubkey)
        );
        Ok(GrantedPeer {
            peer: format_peer(&peer_name, &source_ip.to_string(), peer_agent_port),
            id: peer_uuid,
            name: peer_name,
            address: SocketAddr::new(source_ip, peer_agent_port).to_string(),
            fingerprint: fingerprint(&peer_pubkey),
            already_granted,
        })
    }

    // ------------------------------------------------------------------
    // Responder side (`FPG1` on the agent port)
    // ------------------------------------------------------------------

    pub async fn handle_grant_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        let hello = match read(&mut stream).await.map_err(ipc_to_anyhow)? {
            GrantMessage::Hello {
                version,
                uuid,
                name,
                agent_port,
                nonce,
                pubkey,
                cert_der,
            } => {
                if version != PROTOCOL_VERSION {
                    reject(
                        &mut stream,
                        &format!(
                            "protocol version mismatch: peer speaks v{version}, this build speaks v{PROTOCOL_VERSION}"
                        ),
                        ExitCode::AuthorizationFailed,
                    )
                    .await;
                    return Ok(());
                }
                if nonce.len() != 32 || pubkey.len() != 32 {
                    reject(
                        &mut stream,
                        "malformed grant hello",
                        ExitCode::AuthorizationFailed,
                    )
                    .await;
                    return Ok(());
                }
                if let Err(err) = validate_cert(&pubkey, &cert_der) {
                    reject(&mut stream, &err.message, ExitCode::AuthorizationFailed).await;
                    return Ok(());
                }
                (
                    uuid,
                    sanitize_device_name(&name),
                    agent_port,
                    nonce,
                    pubkey,
                    cert_der,
                )
            }
            other => {
                reject(
                    &mut stream,
                    &format!("expected grant hello, got {other:?}"),
                    ExitCode::AuthorizationFailed,
                )
                .await;
                return Ok(());
            }
        };
        let (peer_uuid, peer_name, peer_agent_port, nonce_a, peer_pubkey, peer_cert) = hello;
        if peer_uuid == self.device_id {
            reject(
                &mut stream,
                "a grant cannot target the same device",
                ExitCode::Usage,
            )
            .await;
            return Ok(());
        }

        // If this device has an mDNS record for the initiator, bind the live
        // key to it. When mDNS is unavailable this is trust-on-first-use.
        if let Some(discovered) = self
            .discovery
            .snapshot()
            .into_iter()
            .find(|p| p.uuid == peer_uuid)
        {
            if let Some(expected) = discovered.pubkey {
                if expected != <[u8; 32]>::try_from(peer_pubkey.as_slice()).unwrap_or_default() {
                    reject(
                        &mut stream,
                        "grant public key does not match the mDNS record",
                        ExitCode::AuthorizationFailed,
                    )
                    .await;
                    return Ok(());
                }
            }
        }

        let nonce_b = random_nonce();
        let local_pub = self.identity.public_key_bytes().to_vec();
        send(
            &mut stream,
            &GrantMessage::Challenge {
                version: PROTOCOL_VERSION,
                uuid: self.device_id,
                name: self.device_name.clone(),
                agent_port: self.agent_port,
                nonce: nonce_b.clone(),
                pubkey: local_pub.clone(),
                cert_der: self.identity.cert_der().to_vec(),
            },
        )
        .await
        .map_err(ipc_to_anyhow)?;

        let transcript = grant_transcript(
            peer_uuid,
            self.device_id,
            &nonce_a,
            &nonce_b,
            &peer_pubkey,
            &local_pub,
        );
        let signature = match read(&mut stream).await.map_err(ipc_to_anyhow)? {
            GrantMessage::Prove { signature } => signature,
            other => {
                reject(
                    &mut stream,
                    &format!("expected grant proof, got {other:?}"),
                    ExitCode::AuthorizationFailed,
                )
                .await;
                return Ok(());
            }
        };
        if !verify_signature(&peer_pubkey, &transcript, &signature) {
            reject(
                &mut stream,
                "grant proof is invalid",
                ExitCode::AuthorizationFailed,
            )
            .await;
            return Ok(());
        }

        let existing = self.db.get_peer(peer_uuid)?;
        if let Some(old) = existing.as_ref() {
            if old.ed25519_pub != peer_pubkey && old.may_connect {
                reject(
                    &mut stream,
                    &format!(
                        "{} has a new public key; run `lanfp peer grant --force` on this device",
                        old.name
                    ),
                    ExitCode::AuthorizationFailed,
                )
                .await;
                return Ok(());
            }
        }

        let record = PeerRecord {
            device_id: peer_uuid,
            name: peer_name.clone(),
            ed25519_pub: peer_pubkey.clone(),
            cert_der: peer_cert,
            last_addr: Some(SocketAddr::new(addr.ip(), peer_agent_port).to_string()),
            paired_at: existing
                .as_ref()
                .map(|e| e.paired_at)
                .unwrap_or_else(now_ts),
            last_seen_at: Some(now_ts()),
            may_connect: existing.as_ref().map(|e| e.may_connect).unwrap_or(false),
            may_dial: true,
        };
        self.db.upsert_peer(&record)?;
        self.reset_backoff(peer_uuid);

        let signature = self.identity.sign(&transcript);
        send(
            &mut stream,
            &GrantMessage::Prove {
                signature: signature.to_vec(),
            },
        )
        .await
        .map_err(ipc_to_anyhow)?;
        // Confirm that the locally stored record is durable, then wait for the
        // initiator's confirmation that it stored this device.
        send(&mut stream, &GrantMessage::Done)
            .await
            .map_err(ipc_to_anyhow)?;
        match read(&mut stream).await.map_err(ipc_to_anyhow)? {
            GrantMessage::Done => {}
            other => {
                tracing::warn!("unexpected grant confirmation: {other:?}");
            }
        }
        tracing::info!(
            "granted by {} [{}]; this device may now dial it",
            format_peer(&peer_name, &addr.ip().to_string(), peer_agent_port),
            lanfp_core::short_id(peer_uuid)
        );

        // Let the supervisor dial on its next tick. Dialing here as well would
        // race the supervisor and can leave both sides with a canceled
        // duplicate session during the dialer-election handshake.
        self.reset_backoff(peer_uuid);
        self.force_dial.lock().unwrap().insert(peer_uuid);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Read-only identity query (`FPID`)
    // ------------------------------------------------------------------

    pub async fn handle_identity_connection(
        &self,
        mut stream: TcpStream,
        _addr: SocketAddr,
    ) -> Result<()> {
        let request =
            tokio::time::timeout(GRANT_TIMEOUT, read_json::<_, IdentityMessage>(&mut stream))
                .await
                .context("timed out reading identity request")?
                .context("read identity request")?;
        let nonce = match request {
            IdentityMessage::Request { version, nonce } => {
                if version != PROTOCOL_VERSION {
                    let _ = write_json(
                        &mut stream,
                        &IdentityMessage::Reject {
                            reason: format!(
                                "protocol version mismatch: peer speaks v{version}, this build speaks v{PROTOCOL_VERSION}"
                            ),
                            code: ExitCode::AuthorizationFailed.code(),
                        },
                    )
                    .await;
                    return Ok(());
                }
                nonce
            }
            other => {
                let _ = write_json(
                    &mut stream,
                    &IdentityMessage::Reject {
                        reason: format!("expected identity request, got {other:?}"),
                        code: ExitCode::AuthorizationFailed.code(),
                    },
                )
                .await;
                return Ok(());
            }
        };
        let pubkey = self.identity.public_key_bytes();
        let signature = self.identity.sign(&identity_transcript(
            &nonce,
            self.device_id,
            self.agent_port,
            &pubkey,
        ));
        write_json(
            &mut stream,
            &IdentityMessage::Response {
                version: PROTOCOL_VERSION,
                uuid: self.device_id,
                name: self.device_name.clone(),
                agent_port: self.agent_port,
                nonce,
                pubkey: pubkey.to_vec(),
                cert_der: self.identity.cert_der().to_vec(),
                signature: signature.to_vec(),
            },
        )
        .await
        .context("send identity response")?;
        Ok(())
    }

    async fn query_identity(&self, spec: &TargetSpec) -> Result<PeerRecord, IpcError> {
        let mut stream = connect(&spec.connect_addr).await?;
        stream.write_all(IDENTITY_MAGIC).await.map_err(|e| {
            ipc_err(
                ExitCode::NotAuthorizedOrOffline,
                format!("send identity magic: {e}"),
            )
        })?;
        let nonce = random_nonce();
        send_identity(
            &mut stream,
            &IdentityMessage::Request {
                version: PROTOCOL_VERSION,
                nonce: nonce.clone(),
            },
        )
        .await?;
        let response = read_identity(&mut stream).await?;
        let (version, uuid, name, agent_port, peer_nonce, pubkey, cert_der, signature) =
            match response {
                IdentityMessage::Response {
                    version,
                    uuid,
                    name,
                    agent_port,
                    nonce,
                    pubkey,
                    cert_der,
                    signature,
                } => (
                    version, uuid, name, agent_port, nonce, pubkey, cert_der, signature,
                ),
                IdentityMessage::Reject { reason, code } => {
                    return Err(ipc_err(
                        ExitCode::from_code(code).unwrap_or(ExitCode::AuthorizationFailed),
                        reason,
                    ))
                }
                other => {
                    return Err(ipc_err(
                        ExitCode::AuthorizationFailed,
                        format!("unexpected identity reply: {other:?}"),
                    ))
                }
            };
        validate_version(version)?;
        if peer_nonce != nonce || pubkey.len() != 32 {
            return Err(ipc_err(
                ExitCode::AuthorizationFailed,
                "peer sent a malformed identity response",
            ));
        }
        validate_cert(&pubkey, &cert_der)?;
        if let Some(expected) = spec.expected_uuid {
            if expected != uuid {
                return Err(ipc_err(
                    ExitCode::AuthorizationFailed,
                    format!(
                        "device identity changed at {}; rescan the device",
                        spec.connect_addr
                    ),
                ));
            }
        }
        if let Some(expected) = spec.expected_pubkey {
            if expected != <[u8; 32]>::try_from(pubkey.as_slice()).unwrap_or_default() {
                return Err(ipc_err(
                    ExitCode::AuthorizationFailed,
                    format!(
                        "{name} at {} has a new public key (mDNS mismatch); rescan the device",
                        spec.connect_addr
                    ),
                ));
            }
        }
        if !verify_signature(
            &pubkey,
            &identity_transcript(&nonce, uuid, agent_port, &pubkey),
            &signature,
        ) {
            return Err(ipc_err(
                ExitCode::AuthorizationFailed,
                "peer failed to prove its identity",
            ));
        }
        let source_ip = stream
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
        Ok(PeerRecord {
            device_id: uuid,
            name: sanitize_device_name(&name),
            ed25519_pub: pubkey,
            cert_der,
            last_addr: Some(SocketAddr::new(source_ip, agent_port).to_string()),
            paired_at: now_ts(),
            last_seen_at: Some(now_ts()),
            may_connect: false,
            may_dial: true,
        })
    }

    /// Resolve a device this machine may dial, learning it from mDNS or a
    /// manual address when necessary.
    pub async fn resolve_dialable_or_learn(&self, selector: &str) -> Result<PeerRecord, IpcError> {
        let matches = self.dialable_matches(selector)?;
        match matches.len() {
            1 => return Ok(matches.into_iter().next().expect("one match")),
            n if n > 1 => return Err(self.ambiguous_error(selector, &matches)),
            _ => {}
        }
        let target = self.auth_target(selector)?;
        let spec = self.target_spec(&target)?;
        let identity = self.query_identity(&spec).await?;
        let existing = self.db.get_peer(identity.device_id).map_err(internal)?;
        if let Some(old) = existing.as_ref() {
            if old.ed25519_pub != identity.ed25519_pub && old.may_connect {
                return Err(ipc_err(
                    ExitCode::AuthorizationFailed,
                    format!(
                        "{} has a new public key; run `lanfp peer grant --force` on this device first",
                        old.name
                    ),
                ));
            }
        }
        let mut record = identity;
        if let Some(old) = existing {
            record.may_connect = old.may_connect;
            record.paired_at = old.paired_at;
        }
        self.db.upsert_peer(&record).map_err(internal)?;
        Ok(record)
    }

    /// Ensure a session with a dialable peer is up, waiting briefly for the
    /// first Inventory/Exposure messages.
    pub async fn ensure_online(
        self: &Arc<Self>,
        peer: &PeerRecord,
    ) -> Result<Arc<SessionHandle>, IpcError> {
        let mut dial_error = None;
        if self.sessions.get(peer.device_id).is_none() {
            if let Err(err) = self.dial_peer(peer).await {
                dial_error = Some(err);
            }
        }
        let deadline = Instant::now() + SESSION_WAIT;
        loop {
            if let Some(handle) = self.sessions.get(peer.device_id) {
                if handle.inventory_received() && handle.exposure_received() {
                    return Ok(handle);
                }
            }
            if Instant::now() >= deadline {
                let detail = dial_error
                    .map(|err| format!(": {err:#}"))
                    .unwrap_or_default();
                return Err(ipc_err(
                    ExitCode::NotAuthorizedOrOffline,
                    format!(
                        "cannot establish a session with {} [{}]{detail}; the peer may not have granted this device (run `lanfp peer grant` on the exposing device)",
                        self.display_peer(peer),
                        lanfp_core::short_id(peer.device_id)
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // ------------------------------------------------------------------
    // `peer list` / `peer revoke` / `peer set-address`
    // ------------------------------------------------------------------

    pub fn peer_list_json(&self) -> Result<serde_json::Value, IpcError> {
        let mut peers: Vec<PeerListEntry> = self
            .db
            .list_allowed()
            .map_err(internal)?
            .into_iter()
            .map(|record| {
                let (address, port) = match self.current_peer_addr(&record) {
                    Some(addr) => (addr.ip().to_string(), addr.port()),
                    None => (String::new(), lanfp_core::DEFAULT_AGENT_PORT),
                };
                PeerListEntry {
                    id: record.device_id,
                    name: record.name,
                    address,
                    port,
                    online: self.sessions.get(record.device_id).is_some(),
                    since: record.paired_at,
                    fingerprint: fingerprint(&record.ed25519_pub),
                }
            })
            .collect();
        peers.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        serde_json::to_value(PeerListResult {
            schema: lanfp_core::JSON_SCHEMA,
            peers,
        })
        .map_err(internal)
    }

    pub async fn peer_revoke_json(
        self: &Arc<Self>,
        selectors: Vec<String>,
    ) -> Result<serde_json::Value, IpcError> {
        if selectors.is_empty() {
            return Err(ipc_err(
                ExitCode::Usage,
                "at least one peer selector is required",
            ));
        }
        let mut peers = Vec::new();
        for selector in &selectors {
            let matches = self.allowed_matches(selector)?;
            match matches.len() {
                1 => peers.push(matches.into_iter().next().expect("one match")),
                n if n > 1 => return Err(self.ambiguous_error(selector, &matches)),
                _ => {
                    return Err(ipc_err(
                        ExitCode::DeviceNotFound,
                        format!("no authorized device matches `{selector}`"),
                    ))
                }
            }
        }
        let mut revoked = Vec::new();
        for peer in peers {
            if let Ok(key) = <[u8; 32]>::try_from(peer.ed25519_pub.as_slice()) {
                self.remove_known_peer(&key);
            }
            if let Some(handle) = self.sessions.get(peer.device_id) {
                handle.cancel.cancel();
            }
            self.db
                .clear_may_connect(peer.device_id)
                .map_err(internal)?;
            self.db
                .delete_inbound_for_peer(peer.device_id)
                .map_err(internal)?;
            if !peer.may_dial {
                self.db.delete_peer(peer.device_id).map_err(internal)?;
            }
            tracing::info!(
                "revoked authorization for {} [{}]",
                self.display_peer(&peer),
                lanfp_core::short_id(peer.device_id)
            );
            revoked.push(RevokedPeer {
                peer: self.display_peer(&peer),
                id: peer.device_id,
            });
        }
        serde_json::to_value(PeerRevokeResult {
            schema: lanfp_core::JSON_SCHEMA,
            revoked,
        })
        .map_err(internal)
    }
}

async fn connect(addr: &str) -> Result<TcpStream, IpcError> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            ipc_err(
                ExitCode::NotAuthorizedOrOffline,
                format!("timed out connecting to {addr}; is `lanfp serve` running there?"),
            )
        })?
        .map_err(|err| {
            ipc_err(
                ExitCode::NotAuthorizedOrOffline,
                format!("cannot connect to {addr}: {err}; is `lanfp serve` running there?"),
            )
        })?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

fn random_nonce() -> Vec<u8> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce.to_vec()
}

fn validate_version(version: u16) -> Result<(), IpcError> {
    if version != PROTOCOL_VERSION {
        return Err(ipc_err(
            ExitCode::AuthorizationFailed,
            format!(
                "protocol version mismatch: peer speaks v{version}, this build speaks v{PROTOCOL_VERSION}; upgrade both devices"
            ),
        ));
    }
    Ok(())
}

fn validate_cert(pubkey: &[u8], cert_der: &[u8]) -> Result<(), IpcError> {
    match lanfp_crypto::tls::ed25519_pubkey_from_cert(cert_der) {
        Ok(cert_key) if cert_key.as_slice() == pubkey => Ok(()),
        Ok(_) => Err(ipc_err(
            ExitCode::AuthorizationFailed,
            "device certificate does not match its public key",
        )),
        Err(err) => Err(ipc_err(
            ExitCode::AuthorizationFailed,
            format!("invalid device certificate: {err}"),
        )),
    }
}

async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &GrantMessage,
) -> Result<(), IpcError> {
    write_json(stream, message).await.map_err(|e| {
        ipc_err(
            ExitCode::AuthorizationFailed,
            format!("write grant message: {e}"),
        )
    })
}

async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<GrantMessage, IpcError> {
    tokio::time::timeout(GRANT_TIMEOUT, read_json(stream))
        .await
        .map_err(|_| ipc_err(ExitCode::AuthorizationFailed, "grant message timed out"))?
        .map_err(|e| {
            ipc_err(
                ExitCode::AuthorizationFailed,
                format!("read grant message: {e}"),
            )
        })
}

async fn send_identity<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &IdentityMessage,
) -> Result<(), IpcError> {
    write_json(stream, message).await.map_err(|e| {
        ipc_err(
            ExitCode::AuthorizationFailed,
            format!("write identity message: {e}"),
        )
    })
}

async fn read_identity<S: AsyncRead + Unpin>(stream: &mut S) -> Result<IdentityMessage, IpcError> {
    tokio::time::timeout(GRANT_TIMEOUT, read_json(stream))
        .await
        .map_err(|_| ipc_err(ExitCode::AuthorizationFailed, "identity response timed out"))?
        .map_err(|e| {
            ipc_err(
                ExitCode::AuthorizationFailed,
                format!("read identity response: {e}"),
            )
        })
}

fn ipc_to_anyhow(err: IpcError) -> anyhow::Error {
    anyhow::anyhow!(err.message)
}

async fn reject(stream: &mut TcpStream, reason: &str, code: ExitCode) {
    let _ = send(
        stream,
        &GrantMessage::Reject {
            reason: reason.to_string(),
            code: code.code(),
        },
    )
    .await;
}
