//! Pairing: `lanfp pair wait` on the responder side and `lanfp pair` on the
//! initiator side.
//!
//! Security model: the 6-digit code is the SPAKE2 password. The responder
//! displays it; the initiator types it. Both sides then exchange AEAD-encrypted
//! device info authenticated by the SPAKE2 key and an Ed25519 signature over a
//! transcript binding both UUIDs, both nonces and both public keys.

use crate::daemon::{ipc_err, Daemon, PairTarget};
use crate::db::PeerRecord;
use crate::util::now_ts;
use anyhow::{bail, Context, Result};
use lanfp_core::error::ExitCode;
use lanfp_core::frame::{read_json, write_json};
use lanfp_core::ipc::*;
use lanfp_core::protocol::{PairDeviceInfo, PairMessage};
use lanfp_core::{format_peer, sanitize_device_name, PROTOCOL_VERSION};
use lanfp_crypto::pair::{
    derive_pair_keys, open_device_info, pairing_transcript, seal_device_info,
};
use lanfp_crypto::spake::{generate_code, validate_code, SpakeSession};
use lanfp_crypto::tls::ed25519_pubkey_from_cert;
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

const PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const PENDING_TTL: Duration = Duration::from_secs(300);

pub struct PairManager {
    wait: AsyncMutex<Option<WaitSession>>,
    pending: AsyncMutex<HashMap<Uuid, PendingPair>>,
}

impl PairManager {
    pub fn new() -> Self {
        Self {
            wait: AsyncMutex::new(None),
            pending: AsyncMutex::new(HashMap::new()),
        }
    }
}

impl Default for PairManager {
    fn default() -> Self {
        Self::new()
    }
}

struct WaitSession {
    token: Uuid,
    code: String,
    status: Arc<Mutex<WaitStatus>>,
    started: Instant,
    timeout: Duration,
    attempts: u32,
    busy: bool,
    max_attempts: u32,
}

impl WaitSession {
    fn expired(&self) -> bool {
        self.started.elapsed() >= self.timeout
    }

    fn remaining_secs(&self) -> u64 {
        self.timeout
            .saturating_sub(self.started.elapsed())
            .as_secs()
    }

    fn finished(&self) -> bool {
        matches!(
            &*self.status.lock().unwrap(),
            WaitStatus::Paired { .. } | WaitStatus::Failed { .. }
        )
    }
}

#[derive(Debug, Clone)]
enum WaitStatus {
    Waiting,
    Incoming { peer: String, code: String },
    Paired { peer: String },
    Failed { code: i32, message: String },
}

struct PendingPair {
    stream: TcpStream,
    peer_uuid: Uuid,
    peer_name: String,
    peer_ip: std::net::IpAddr,
    peer_agent_port: u16,
    peer_pubkey: Vec<u8>,
    nonce_a: Vec<u8>,
    nonce_b: Vec<u8>,
    expires: Instant,
}

impl Daemon {
    // ------------------------------------------------------------------
    // `lanfp pair wait`
    // ------------------------------------------------------------------

    pub async fn pair_wait_start_json(
        self: &Arc<Self>,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, IpcError> {
        let timeout = Duration::from_secs(if timeout_secs == 0 {
            self.config().pairing_ttl().as_secs()
        } else {
            timeout_secs
        });
        let code = generate_code();
        let token = Uuid::new_v4();
        let mut guard = self.pairing.wait.lock().await;
        if let Some(existing) = guard.as_ref() {
            if !existing.expired() && !existing.finished() {
                return Err(ipc_err(
                    ExitCode::PeerNotWaiting,
                    "another `lanfp pair wait` session is already active",
                ));
            }
        }
        *guard = Some(WaitSession {
            token,
            code: code.clone(),
            status: Arc::new(Mutex::new(WaitStatus::Waiting)),
            started: Instant::now(),
            timeout,
            attempts: 0,
            busy: false,
            max_attempts: self.config().pairing.max_attempts,
        });
        serde_json::to_value(PairWaitStartResult {
            schema: lanfp_core::JSON_SCHEMA,
            token,
            code,
            timeout_secs: timeout.as_secs(),
        })
        .map_err(crate::daemon::internal)
    }

    pub async fn pair_wait_poll_json(
        self: &Arc<Self>,
        token: Uuid,
    ) -> Result<serde_json::Value, IpcError> {
        let mut guard = self.pairing.wait.lock().await;
        let Some(session) = guard.as_mut().filter(|s| s.token == token) else {
            return Err(ipc_err(
                ExitCode::PairingFailed,
                "unknown or expired pairing session",
            ));
        };
        if session.expired() && !session.finished() {
            *session.status.lock().unwrap() = WaitStatus::Failed {
                code: ExitCode::PairingFailed.code(),
                message: "pairing request timed out".into(),
            };
        }
        let status = session.status.lock().unwrap().clone();
        let mut result = PairWaitPollResult::new(PairWaitState::Waiting);
        result.attempts_left = Some(session.max_attempts.saturating_sub(session.attempts));
        result.expires_in = Some(session.remaining_secs());
        match status {
            WaitStatus::Waiting => {}
            WaitStatus::Incoming { peer, code } => {
                result.state = PairWaitState::Incoming;
                result.peer = Some(peer);
                result.code = Some(code);
            }
            WaitStatus::Paired { peer } => {
                result.state = PairWaitState::Paired;
                result.peer = Some(peer);
            }
            WaitStatus::Failed { code, message } => {
                result.state = PairWaitState::Failed;
                result.exit_code = Some(code);
                result.message = Some(message);
            }
        }
        serde_json::to_value(result).map_err(crate::daemon::internal)
    }

    pub async fn pair_cancel_json(
        self: &Arc<Self>,
        token: Uuid,
    ) -> Result<serde_json::Value, IpcError> {
        let mut guard = self.pairing.wait.lock().await;
        if guard.as_ref().map(|s| s.token) == Some(token) {
            *guard = None;
        }
        Ok(serde_json::json!({"cancelled": true}))
    }

    // ------------------------------------------------------------------
    // Responder side (agent-port pairing channel)
    // ------------------------------------------------------------------

    pub async fn handle_pair_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        let hello = tokio::time::timeout(PAIR_TIMEOUT, read_json::<_, PairMessage>(&mut stream))
            .await
            .context("timed out reading pairing hello")?
            .context("read pairing hello")?;
        let (uuid, name, agent_port, nonce_a, pubkey_a) = match hello {
            PairMessage::Hello {
                version,
                uuid,
                name,
                agent_port,
                nonce,
                pubkey,
            } => {
                if version != PROTOCOL_VERSION {
                    reject(&mut stream, "protocol version mismatch", 6).await;
                    return Ok(());
                }
                if nonce.len() != 32 || pubkey.len() != 32 {
                    reject(&mut stream, "malformed pairing hello", 6).await;
                    return Ok(());
                }
                (uuid, sanitize_device_name(&name), agent_port, nonce, pubkey)
            }
            _ => {
                reject(&mut stream, "expected pairing hello", 6).await;
                return Ok(());
            }
        };

        let session = {
            let mut wait = self.pairing.wait.lock().await;
            match wait.as_mut() {
                Some(session) if !session.busy && !session.expired() && !session.finished() => {
                    session.busy = true;
                    let display = format_peer(&name, &addr.ip().to_string(), agent_port);
                    *session.status.lock().unwrap() = WaitStatus::Incoming {
                        peer: display,
                        code: session.code.clone(),
                    };
                    // The initiator must type the code shown on this screen
                    // before it sends the SPAKE2 message; allow up to the
                    // remaining code TTL, not a network-sized timeout.
                    let remaining = session.timeout.saturating_sub(session.started.elapsed());
                    Some((
                        session.code.clone(),
                        session.token,
                        session.status.clone(),
                        session.max_attempts,
                        remaining,
                    ))
                }
                _ => None,
            }
        };
        let Some((code, token, status, max_attempts, exchange_timeout)) = session else {
            reject(
                &mut stream,
                "no pairing request is waiting; run `lanfp pair wait` on the peer device",
                ExitCode::PeerNotWaiting.code(),
            )
            .await;
            return Ok(());
        };

        let result = self
            .responder_handshake(
                &mut stream,
                addr,
                uuid,
                &name,
                agent_port,
                &nonce_a,
                &pubkey_a,
                &code,
                exchange_timeout,
            )
            .await;

        let mut wait = self.pairing.wait.lock().await;
        if let Some(session) = wait.as_mut().filter(|s| s.token == token) {
            session.busy = false;
            match result {
                Ok(peer) => {
                    *status.lock().unwrap() = WaitStatus::Paired {
                        peer: peer.display(),
                    };
                }
                Err(err) => {
                    session.attempts += 1;
                    if session.attempts >= max_attempts {
                        *status.lock().unwrap() = WaitStatus::Failed {
                            code: ExitCode::PairingFailed.code(),
                            message: format!(
                                "pairing failed after {} attempts: {err}",
                                session.attempts
                            ),
                        };
                    } else {
                        *status.lock().unwrap() = WaitStatus::Waiting;
                    }
                    tracing::warn!("pairing attempt failed: {err:#}");
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn responder_handshake(
        self: &Arc<Self>,
        stream: &mut TcpStream,
        addr: SocketAddr,
        peer_uuid: Uuid,
        _peer_name: &str,
        peer_agent_port: u16,
        nonce_a: &[u8],
        pubkey_a: &[u8],
        code: &str,
        exchange_timeout: Duration,
    ) -> Result<PeerRecord> {
        let nonce_b = random_nonce();
        let local_pub = self.identity.public_key_bytes().to_vec();
        send(
            stream,
            &PairMessage::Challenge {
                nonce: nonce_b.clone(),
                uuid: self.device_id,
                name: self.device_name.clone(),
                agent_port: self.agent_port,
                pubkey: local_pub.clone(),
            },
        )
        .await?;

        // Waiting for the initiator to type the code can take a while; the
        // timeout is the remaining lifetime of the pairing code.
        let spake_a = match read_with_timeout(stream, exchange_timeout).await? {
            PairMessage::SpakeA { msg } => msg,
            PairMessage::Failed { reason, code } => {
                bail!("peer aborted pairing ({code}): {reason}")
            }
            other => bail!("expected SPAKE2 message, got {other:?}"),
        };
        let (session_b, msg_b) =
            SpakeSession::start_b(code, peer_uuid.as_bytes(), self.device_id.as_bytes());
        send(stream, &PairMessage::SpakeB { msg: msg_b }).await?;
        let shared = session_b
            .finish(&spake_a)
            .context("SPAKE2 exchange failed")?;

        let transcript = pairing_transcript(
            peer_uuid,
            self.device_id,
            nonce_a,
            &nonce_b,
            pubkey_a,
            &local_pub,
        );
        let (a2b, b2a) = derive_pair_keys(&shared, &transcript);

        let (nonce, payload) = match read(stream).await? {
            PairMessage::Secure { nonce, payload } => (nonce, payload),
            PairMessage::Failed { reason, code } => {
                bail!("peer aborted pairing ({code}): {reason}")
            }
            other => bail!("expected encrypted device info, got {other:?}"),
        };
        let info = match open_device_info(&a2b, &transcript, &nonce, &payload) {
            Ok(info) => info,
            Err(err) => {
                let _ = send(
                    stream,
                    &PairMessage::Failed {
                        reason: "invalid pairing code".into(),
                        code: ExitCode::PairingFailed.code(),
                    },
                )
                .await;
                return Err(err.context("invalid pairing code"));
            }
        };
        if info.uuid != peer_uuid || info.pubkey != pubkey_a {
            let _ = send(
                stream,
                &PairMessage::Failed {
                    reason: "device identity mismatch".into(),
                    code: ExitCode::PairingFailed.code(),
                },
            )
            .await;
            bail!("peer device identity mismatch");
        }

        let (nonce_out, payload_out) = seal_device_info(
            &b2a,
            &transcript,
            self.identity.as_ref(),
            self.device_id,
            &self.device_name,
            self.agent_port,
        )?;
        send(
            stream,
            &PairMessage::Secure {
                nonce: nonce_out,
                payload: payload_out,
            },
        )
        .await?;

        match tokio::time::timeout(PAIR_TIMEOUT, read(stream)).await {
            Ok(Ok(PairMessage::Done)) => {}
            Ok(Ok(PairMessage::Failed { reason, code })) => {
                bail!("peer rejected pairing ({code}): {reason}")
            }
            Ok(Ok(other)) => bail!("unexpected pairing message: {other:?}"),
            Ok(Err(err)) => return Err(err.context("peer did not confirm pairing")),
            Err(_) => bail!("peer did not confirm pairing"),
        }

        let peer = PeerRecord {
            device_id: peer_uuid,
            name: sanitize_device_name(&info.name),
            ed25519_pub: info.pubkey.clone(),
            cert_der: info.cert_der.clone(),
            last_addr: Some(SocketAddr::new(addr.ip(), peer_agent_port).to_string()),
            paired_at: now_ts(),
            last_seen_at: Some(now_ts()),
        };
        self.store_peer(&peer, true)?;
        send(stream, &PairMessage::Done).await?;
        Ok(peer)
    }

    // ------------------------------------------------------------------
    // Initiator side (`lanfp pair <peer>`)
    // ------------------------------------------------------------------

    pub async fn pair_start_json(
        self: &Arc<Self>,
        selector: String,
    ) -> Result<serde_json::Value, IpcError> {
        let target = self.pairing_target(&selector)?;
        let (connect_addr, peer_uuid_hint) = match &target {
            PairTarget::Paired(peer) => (
                peer.connect_addr().ok_or_else(|| {
                    ipc_err(
                        ExitCode::DeviceNotFound,
                        format!(
                            "{} has no known address; use `lanfp pair <ip>`",
                            peer.display()
                        ),
                    )
                })?,
                Some(peer.device_id),
            ),
            PairTarget::Discovered(discovered) => (
                discovered
                    .best_addr()
                    .map(|a| a.to_string())
                    .ok_or_else(|| {
                        ipc_err(
                            ExitCode::DeviceNotFound,
                            format!("{} has no reachable address", discovered.display()),
                        )
                    })?,
                Some(discovered.uuid),
            ),
            PairTarget::Manual(addr) => (addr.connect_addr(), None),
        };

        let mut stream =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&connect_addr))
                .await
                .map_err(|_| {
                    ipc_err(
                        ExitCode::PeerNotWaiting,
                        format!(
                    "timed out connecting to {connect_addr}; is `lanfp pair wait` running there?"
                ),
                    )
                })?
                .map_err(|err| {
                    ipc_err(
                        ExitCode::PeerNotWaiting,
                        format!(
                    "cannot connect to {connect_addr}: {err}; is `lanfp pair wait` running there?"
                ),
                    )
                })?;
        stream.set_nodelay(true).ok();
        stream
            .write_all(lanfp_core::PAIR_MAGIC)
            .await
            .map_err(|e| ipc_err(ExitCode::PeerNotWaiting, format!("send pairing magic: {e}")))?;

        let nonce_a = random_nonce();
        let hello = PairMessage::Hello {
            version: PROTOCOL_VERSION,
            uuid: self.device_id,
            name: self.device_name.clone(),
            agent_port: self.agent_port,
            nonce: nonce_a.clone(),
            pubkey: self.identity.public_key_bytes().to_vec(),
        };
        send(&mut stream, &hello)
            .await
            .map_err(|e| ipc_err(ExitCode::PeerNotWaiting, format!("send pairing hello: {e}")))?;

        let reply = tokio::time::timeout(PAIR_TIMEOUT, read(&mut stream))
            .await
            .map_err(|_| {
                ipc_err(
                    ExitCode::PeerNotWaiting,
                    "no pairing response; run `lanfp pair wait` on the other device",
                )
            })?
            .map_err(|e| {
                ipc_err(
                    ExitCode::PeerNotWaiting,
                    format!("no pairing response: {e}"),
                )
            })?;

        let (nonce_b, peer_uuid, peer_name, peer_agent_port, peer_pubkey) = match reply {
            PairMessage::Challenge {
                nonce,
                uuid,
                name,
                agent_port,
                pubkey,
            } => (nonce, uuid, name, agent_port, pubkey),
            PairMessage::Reject { reason, code } => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::PeerNotWaiting),
                    reason,
                ))
            }
            other => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("unexpected pairing reply: {other:?}"),
                ))
            }
        };
        if nonce_b.len() != 32 || peer_pubkey.len() != 32 {
            return Err(ipc_err(
                ExitCode::PairingFailed,
                "peer sent a malformed pairing challenge",
            ));
        }
        if let Some(hint) = peer_uuid_hint {
            if hint != peer_uuid {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!(
                        "device identity changed at {connect_addr}; if the device was reinstalled, use `lanfp pair --force`"
                    ),
                ));
            }
        }
        let peer_ip = stream
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1]));
        let display = format_peer(&peer_name, &peer_ip.to_string(), peer_agent_port);
        let token = Uuid::new_v4();
        let mut pending = self.pairing.pending.lock().await;
        pending.retain(|_, p| p.expires > Instant::now());
        pending.insert(
            token,
            PendingPair {
                stream,
                peer_uuid,
                peer_name: sanitize_device_name(&peer_name),
                peer_ip,
                peer_agent_port,
                peer_pubkey,
                nonce_a,
                nonce_b,
                expires: Instant::now() + PENDING_TTL,
            },
        );
        serde_json::to_value(PairStartResult {
            schema: lanfp_core::JSON_SCHEMA,
            token,
            peer: display,
            address: SocketAddr::new(peer_ip, peer_agent_port).to_string(),
        })
        .map_err(crate::daemon::internal)
    }

    pub async fn pair_finish_json(
        self: &Arc<Self>,
        token: Uuid,
        code: String,
        force: bool,
    ) -> Result<serde_json::Value, IpcError> {
        validate_code(&code).map_err(|e| ipc_err(ExitCode::PairingFailed, e.to_string()))?;
        let mut pending = self.pairing.pending.lock().await;
        let Some(mut pair) = pending.remove(&token) else {
            return Err(ipc_err(
                ExitCode::PairingFailed,
                "pairing session not found or expired; run `lanfp pair` again",
            ));
        };
        drop(pending);
        if pair.expires <= Instant::now() {
            return Err(ipc_err(
                ExitCode::PairingFailed,
                "pairing session expired; run `lanfp pair` again",
            ));
        }

        let local_pub = self.identity.public_key_bytes().to_vec();
        let (session_a, msg_a) =
            SpakeSession::start_a(&code, self.device_id.as_bytes(), pair.peer_uuid.as_bytes());
        send(&mut pair.stream, &PairMessage::SpakeA { msg: msg_a })
            .await
            .map_err(|e| ipc_err(ExitCode::PairingFailed, format!("send SPAKE2 message: {e}")))?;
        let spake_b = match read(&mut pair.stream).await {
            Ok(PairMessage::SpakeB { msg }) => msg,
            Ok(PairMessage::Failed { reason, code }) => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::PairingFailed),
                    reason,
                ))
            }
            Ok(other) => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("unexpected pairing message: {other:?}"),
                ))
            }
            Err(err) => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("pairing failed: {err}"),
                ))
            }
        };
        let shared = session_a
            .finish(&spake_b)
            .map_err(|e| ipc_err(ExitCode::PairingFailed, format!("SPAKE2 failed: {e}")))?;

        let transcript = pairing_transcript(
            self.device_id,
            pair.peer_uuid,
            &pair.nonce_a,
            &pair.nonce_b,
            &local_pub,
            &pair.peer_pubkey,
        );
        let (a2b, b2a) = derive_pair_keys(&shared, &transcript);
        let (nonce, payload) = seal_device_info(
            &a2b,
            &transcript,
            self.identity.as_ref(),
            self.device_id,
            &self.device_name,
            self.agent_port,
        )
        .map_err(|e| ipc_err(ExitCode::PairingFailed, format!("seal device info: {e}")))?;
        send(&mut pair.stream, &PairMessage::Secure { nonce, payload })
            .await
            .map_err(|e| ipc_err(ExitCode::PairingFailed, format!("send device info: {e}")))?;

        let reply = match read(&mut pair.stream).await {
            Ok(reply) => reply,
            Err(err) => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("pairing failed: {err}"),
                ))
            }
        };
        let info: PairDeviceInfo = match reply {
            PairMessage::Secure { nonce, payload } => {
                match open_device_info(&b2a, &transcript, &nonce, &payload) {
                    Ok(info) => info,
                    Err(err) => {
                        return Err(ipc_err(
                            ExitCode::PairingFailed,
                            format!("pairing failed (wrong code?): {err}"),
                        ))
                    }
                }
            }
            PairMessage::Failed { reason, code } => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::PairingFailed),
                    reason,
                ))
            }
            other => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("unexpected pairing message: {other:?}"),
                ))
            }
        };
        if info.uuid != pair.peer_uuid || info.pubkey != pair.peer_pubkey {
            return Err(ipc_err(
                ExitCode::PairingFailed,
                "peer identity changed during pairing",
            ));
        }
        if ed25519_pubkey_from_cert(&info.cert_der)
            .map(|pk| pk.to_vec() != info.pubkey)
            .unwrap_or(true)
        {
            return Err(ipc_err(
                ExitCode::PairingFailed,
                "peer certificate does not match its public key",
            ));
        }

        if let Some(existing) = self.db.get_peer(pair.peer_uuid).ok().flatten() {
            if existing.ed25519_pub != info.pubkey {
                if !force {
                    let _ = send(
                        &mut pair.stream,
                        &PairMessage::Failed {
                            reason: "device public key changed".into(),
                            code: ExitCode::PairingFailed.code(),
                        },
                    )
                    .await;
                    return Err(ipc_err(
                        ExitCode::PairingFailed,
                        format!(
                            "{} has a new public key (device reinstalled?); re-run with `--force`",
                            pair.peer_name
                        ),
                    ));
                }
                if let Ok(old_key) = <[u8; 32]>::try_from(existing.ed25519_pub.as_slice()) {
                    self.remove_known_peer(&old_key);
                }
            }
        }

        let peer = PeerRecord {
            device_id: pair.peer_uuid,
            name: sanitize_device_name(&info.name),
            ed25519_pub: info.pubkey.clone(),
            cert_der: info.cert_der.clone(),
            last_addr: Some(SocketAddr::new(pair.peer_ip, pair.peer_agent_port).to_string()),
            paired_at: now_ts(),
            last_seen_at: Some(now_ts()),
        };
        let _ = send(&mut pair.stream, &PairMessage::Done).await;
        match read(&mut pair.stream).await {
            Ok(PairMessage::Done) => {}
            Ok(PairMessage::Failed { reason, code }) => {
                return Err(ipc_err(
                    ExitCode::from_code(code).unwrap_or(ExitCode::PairingFailed),
                    reason,
                ))
            }
            Ok(other) => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("unexpected final pairing message: {other:?}"),
                ))
            }
            Err(err) => {
                return Err(ipc_err(
                    ExitCode::PairingFailed,
                    format!("peer did not confirm pairing: {err}"),
                ))
            }
        }
        self.store_peer(&peer, true)
            .map_err(crate::daemon::internal)?;

        let display = peer.display();
        serde_json::to_value(PairFinishResult {
            schema: lanfp_core::JSON_SCHEMA,
            peer: display,
            name: peer.name.clone(),
            address: SocketAddr::new(pair.peer_ip, pair.peer_agent_port).to_string(),
        })
        .map_err(crate::daemon::internal)
    }

    fn store_peer(&self, peer: &PeerRecord, reset_backoff: bool) -> Result<()> {
        if let Some(old) = self.db.get_peer(peer.device_id)? {
            if old.ed25519_pub != peer.ed25519_pub {
                if let Ok(old_key) = <[u8; 32]>::try_from(old.ed25519_pub.as_slice()) {
                    self.remove_known_peer(&old_key);
                }
                if let Some(session) = self.sessions.get(peer.device_id) {
                    session.cancel.cancel();
                }
            }
        }
        self.db.upsert_peer(peer)?;
        if let Ok(key) = <[u8; 32]>::try_from(peer.ed25519_pub.as_slice()) {
            self.add_known_peer(key);
        }
        if reset_backoff {
            self.reset_backoff(peer.device_id);
        }
        Ok(())
    }
}

fn random_nonce() -> Vec<u8> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce.to_vec()
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, message: &PairMessage) -> Result<()> {
    write_json(stream, message)
        .await
        .context("write pairing message")
}

async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<PairMessage> {
    read_with_timeout(stream, PAIR_TIMEOUT).await
}

async fn read_with_timeout<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> Result<PairMessage> {
    tokio::time::timeout(timeout, read_json(stream))
        .await
        .context("pairing message timeout")?
        .context("read pairing message")
}

async fn reject<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str, code: i32) {
    let _ = write_json(
        stream,
        &PairMessage::Reject {
            reason: reason.to_string(),
            code,
        },
    )
    .await;
}
