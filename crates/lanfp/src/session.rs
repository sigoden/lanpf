//! Peer sessions: TLS + yamux, control messages and the data plane.

use crate::daemon::{inbound_record, rules_for_peer_snapshot, Daemon};
use crate::db::PeerRecord;
use crate::util::{human_bytes, jitter_millis, now_ts};
use anyhow::{bail, Context as _, Result};

use futures::io::{AsyncRead, AsyncWrite};
use lanfp_core::frame::{read_json, write_json};
use lanfp_core::protocol::{ControlMessage, DataHeader, PortInfo, RuleState};
use lanfp_core::{build_id, DATA_HEADER_LEN, PAIR_MAGIC, PROTOCOL_VERSION};
use lanfp_crypto::tls::ed25519_pubkey_from_cert;
use lanfp_crypto::TLS_SERVER_NAME;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncRead as TokioAsyncRead, AsyncReadExt, AsyncWrite as TokioAsyncWrite, AsyncWriteExt,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use yamux::{Connection, Mode, Stream};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const DEAD_AFTER: Duration = Duration::from_secs(60);

pub struct Backoff {
    pub attempts: u32,
    pub next: Instant,
    pub first: Instant,
}

pub struct OpenRequest {
    tx: oneshot::Sender<std::result::Result<Stream, String>>,
}

struct RateState {
    window_start: Instant,
    count: u32,
}

pub struct StreamLimiter {
    max: usize,
    current: AtomicUsize,
    rate: Mutex<RateState>,
}

pub struct StreamPermit {
    limiter: Arc<StreamLimiter>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        self.limiter.current.fetch_sub(1, Ordering::Relaxed);
    }
}

impl StreamLimiter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            current: AtomicUsize::new(0),
            rate: Mutex::new(RateState {
                window_start: Instant::now(),
                count: 0,
            }),
        })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<StreamPermit> {
        let now = Instant::now();
        {
            let mut rate = self.rate.lock().unwrap();
            if now.duration_since(rate.window_start) >= Duration::from_secs(1) {
                rate.window_start = now;
                rate.count = 0;
            }
            if rate.count >= 100 {
                return None;
            }
            rate.count += 1;
        }
        if self.current.fetch_add(1, Ordering::SeqCst) >= self.max {
            self.current.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(StreamPermit {
            limiter: self.clone(),
        })
    }
}

pub struct SessionHandle {
    pub id: Uuid,
    pub peer_id: Uuid,
    pub peer_name: String,
    pub dialer_uuid: Uuid,
    inventory: RwLock<Vec<PortInfo>>,
    inventory_received: AtomicBool,
    control_tx: mpsc::Sender<ControlMessage>,
    open_tx: mpsc::Sender<OpenRequest>,
    limiter: Arc<StreamLimiter>,
    pub cancel: CancellationToken,
    last_rx: Mutex<Instant>,
}

impl SessionHandle {
    pub fn native_ports(&self) -> Vec<PortInfo> {
        self.inventory.read().unwrap().clone()
    }

    pub fn inventory_received(&self) -> bool {
        self.inventory_received.load(Ordering::Relaxed)
    }

    pub fn touch(&self) {
        *self.last_rx.lock().unwrap() = Instant::now();
    }

    pub fn last_rx_elapsed(&self) -> Duration {
        self.last_rx.lock().unwrap().elapsed()
    }

    pub async fn send(&self, message: ControlMessage) {
        let _ = self.control_tx.send(message).await;
    }

    pub async fn open_stream(&self) -> Result<(Stream, StreamPermit)> {
        let permit = self
            .limiter
            .try_acquire()
            .context("session stream limit reached")?;
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(OpenRequest { tx })
            .await
            .map_err(|_| anyhow::anyhow!("session closed"))?;
        let stream = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| anyhow::anyhow!("timed out opening data stream"))?
            .map_err(|_| anyhow::anyhow!("session closed"))?
            .map_err(|e| anyhow::anyhow!("cannot open data stream: {e}"))?;
        Ok((stream, permit))
    }
}

pub enum InsertOutcome {
    New,
    Replaced(Arc<SessionHandle>),
    KeptExisting,
}

pub struct SessionRegistry {
    inner: RwLock<HashMap<Uuid, Arc<SessionHandle>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, peer_id: Uuid) -> Option<Arc<SessionHandle>> {
        self.inner.read().unwrap().get(&peer_id).cloned()
    }

    /// Keep exactly one session per peer, preferring the one dialed by the
    /// peer with the smaller UUID.
    pub fn insert(&self, handle: Arc<SessionHandle>) -> InsertOutcome {
        let mut map = self.inner.write().unwrap();
        match map.get(&handle.peer_id) {
            None => {
                map.insert(handle.peer_id, handle);
                InsertOutcome::New
            }
            Some(existing) => {
                if handle.dialer_uuid < existing.dialer_uuid {
                    let old = map.insert(handle.peer_id, handle).expect("existing");
                    InsertOutcome::Replaced(old)
                } else {
                    InsertOutcome::KeptExisting
                }
            }
        }
    }

    pub fn remove_if(&self, peer_id: Uuid, id: Uuid) -> bool {
        let mut map = self.inner.write().unwrap();
        if map.get(&peer_id).map(|h| h.id) == Some(id) {
            map.remove(&peer_id);
            true
        } else {
            false
        }
    }

    pub fn online(&self) -> Vec<Arc<SessionHandle>> {
        self.inner.read().unwrap().values().cloned().collect()
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Daemon {
    pub async fn dial_peer(self: &Arc<Self>, peer: &PeerRecord) -> Result<()> {
        // Prefer the freshest mDNS address so that DHCP changes and network
        // switches are picked up without restarting the daemon.
        let discovered_addr = self
            .discovery
            .snapshot()
            .into_iter()
            .find(|d| d.uuid == peer.device_id && d.last_seen.elapsed() < Duration::from_secs(120))
            .and_then(|d| d.best_addr())
            .map(|addr| addr.to_string());
        let addr = discovered_addr
            .or_else(|| peer.connect_addr())
            .context("peer has no known address")?;
        let pubkey = peer.pubkey_array().context("peer public key is invalid")?;
        let config = lanfp_crypto::client_config(&self.identity, pubkey)?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .context("connect timeout")?
            .with_context(|| format!("connect {addr}"))?;
        tcp.set_nodelay(true).ok();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(TLS_SERVER_NAME.to_string())
                .context("invalid TLS server name")?;
        let tls =
            tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
                .await
                .context("TLS handshake timeout")?
                .context("TLS handshake failed")?;
        let _ = self
            .db
            .update_peer_seen(peer.device_id, Some(&addr), now_ts());
        self.establish_session(tls, peer.clone(), true).await
    }

    pub async fn establish_session<S>(
        self: &Arc<Self>,
        stream: S,
        peer: PeerRecord,
        is_dialer: bool,
    ) -> Result<()>
    where
        S: TokioAsyncRead + TokioAsyncWrite + Unpin + Send + 'static,
    {
        let peer_id = peer.device_id;
        let mode = if is_dialer {
            Mode::Client
        } else {
            Mode::Server
        };
        let conn = Connection::new(stream.compat(), yamux::Config::default(), mode);
        let (open_tx, open_rx) = mpsc::channel::<OpenRequest>(64);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Stream>(64);
        let session_cancel = self.shutdown.child_token();
        let driver_cancel = session_cancel.clone();
        tokio::spawn(yamux_driver(conn, open_rx, inbound_tx, driver_cancel));

        let control: Stream = if is_dialer {
            let (tx, rx) = oneshot::channel();
            open_tx
                .send(OpenRequest { tx })
                .await
                .map_err(|_| anyhow::anyhow!("yamux driver stopped"))?;
            tokio::time::timeout(CONTROL_TIMEOUT, rx)
                .await
                .context("timed out opening control stream")?
                .map_err(|_| anyhow::anyhow!("yamux driver stopped"))?
                .map_err(|e| anyhow::anyhow!("cannot open control stream: {e}"))?
        } else {
            tokio::time::timeout(CONTROL_TIMEOUT, inbound_rx.recv())
                .await
                .context("timed out waiting for control stream")?
                .ok_or_else(|| anyhow::anyhow!("connection closed before control stream"))?
        };

        let control = control.compat();
        let (mut read_half, mut write_half) = tokio::io::split(control);

        let hello = ControlMessage::Hello {
            version: PROTOCOL_VERSION,
            uuid: self.device_id,
            name: self.device_name.clone(),
            agent_port: self.agent_port,
            build: build_id(),
        };
        write_json(&mut write_half, &hello)
            .await
            .context("send session hello")?;
        let peer_hello: ControlMessage =
            tokio::time::timeout(CONTROL_TIMEOUT, read_json(&mut read_half))
                .await
                .context("timed out waiting for session hello")?
                .context("read session hello")?;
        let (peer_uuid, peer_version) = match peer_hello {
            ControlMessage::Hello { version, uuid, .. } => (uuid, version),
            other => bail!("unexpected first control message: {other:?}"),
        };
        if peer_uuid != peer_id {
            bail!("session identity mismatch: TLS peer {peer_id}, hello {peer_uuid}");
        }
        if peer_version != PROTOCOL_VERSION {
            bail!("peer speaks protocol v{peer_version}, this build speaks v{PROTOCOL_VERSION}");
        }

        let (control_tx, control_rx) = mpsc::channel::<ControlMessage>(256);
        let handle = Arc::new(SessionHandle {
            id: Uuid::new_v4(),
            peer_id,
            peer_name: peer.name.clone(),
            dialer_uuid: if is_dialer { self.device_id } else { peer_id },
            inventory: RwLock::new(Vec::new()),
            inventory_received: AtomicBool::new(false),
            control_tx,
            open_tx,
            limiter: StreamLimiter::new(self.config().agent.max_streams),
            cancel: session_cancel,
            last_rx: Mutex::new(Instant::now()),
        });

        match self.sessions.insert(handle.clone()) {
            InsertOutcome::KeptExisting => {
                tracing::debug!(
                    "discarding duplicate session with {} (dialer precedence)",
                    peer.display()
                );
                handle.cancel.cancel();
                return Ok(());
            }
            InsertOutcome::Replaced(old) => {
                tracing::debug!("replacing session with {} after reconnect", peer.display());
                old.cancel.cancel();
            }
            InsertOutcome::New => {}
        }

        tracing::info!(
            "session established with {} ({})",
            peer.display(),
            if is_dialer { "dialed" } else { "accepted" }
        );

        let writer_handle = handle.clone();
        tokio::spawn(async move {
            control_writer(write_half, control_rx, writer_handle.cancel.clone()).await;
        });

        let reader_daemon = self.clone();
        let reader_handle = handle.clone();
        tokio::spawn(async move {
            let result =
                control_reader(reader_daemon.clone(), reader_handle.clone(), read_half).await;
            if let Err(err) = &result {
                tracing::debug!("session with {} closed: {err:#}", reader_handle.peer_name);
            }
            reader_daemon
                .session_closed(reader_handle.peer_id, reader_handle.id)
                .await;
        });

        let keepalive_handle = handle.clone();
        tokio::spawn(async move {
            keepalive(keepalive_handle).await;
        });

        let data_daemon = self.clone();
        let data_handle = handle.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = data_handle.cancel.cancelled() => break,
                    stream = inbound_rx.recv() => match stream {
                        Some(stream) => {
                            let daemon = data_daemon.clone();
                            let handle = data_handle.clone();
                            tokio::spawn(async move {
                                daemon.handle_inbound_data(handle, stream).await;
                            });
                        }
                        None => break,
                    }
                }
            }
        });

        handle
            .send(ControlMessage::Inventory {
                seq: self.inventory.seq(),
                ports: self.inventory.native(),
            })
            .await;
        let rules = rules_for_peer_snapshot(self, peer_id);
        for rule in &rules {
            handle
                .send(ControlMessage::RuleUpsert {
                    rule_id: rule.rule_id,
                    target_port: rule.target_port,
                    listen_port: rule.listen_port,
                    state: rule.state,
                })
                .await;
        }
        handle
            .send(ControlMessage::RuleSnapshot {
                rule_ids: rules.iter().map(|r| r.rule_id).collect(),
            })
            .await;

        Ok(())
    }

    async fn session_closed(self: &Arc<Self>, peer_id: Uuid, session_id: Uuid) {
        if !self.sessions.remove_if(peer_id, session_id) {
            return;
        }
        tracing::info!("session with peer {peer_id} closed");
        let _ = self.db.mark_peer_inbound_offline(peer_id, now_ts());
        self.recompute_rules_for_peer(peer_id).await;
    }

    async fn handle_control_message(
        self: &Arc<Self>,
        handle: &Arc<SessionHandle>,
        message: ControlMessage,
    ) -> Result<()> {
        match message {
            ControlMessage::Hello { .. } => {}
            ControlMessage::Inventory { seq, ports } => {
                let _ = seq;
                *handle.inventory.write().unwrap() = ports;
                handle.inventory_received.store(true, Ordering::Relaxed);
                let now = now_ts();
                let _ = self.db.update_peer_seen(handle.peer_id, None, now);
                let _ = self.db.touch_peer_inbound(handle.peer_id, now);
                self.recompute_rules_for_peer(handle.peer_id).await;
            }
            ControlMessage::RuleUpsert {
                rule_id,
                target_port,
                listen_port,
                state,
            } => {
                let _ = state;
                let rec = inbound_record(
                    handle.peer_id,
                    rule_id,
                    target_port,
                    listen_port,
                    now_ts(),
                    true,
                );
                let _ = self.db.upsert_inbound(&rec);
            }
            ControlMessage::RuleRemove { rule_id } => {
                let _ = self.db.delete_inbound(handle.peer_id, rule_id);
            }
            ControlMessage::RuleSnapshot { rule_ids } => {
                let keep: HashSet<Uuid> = rule_ids.into_iter().collect();
                if let Ok(existing) = self.db.list_inbound_for_peer(handle.peer_id) {
                    for rec in existing {
                        if !keep.contains(&rec.rule_id) {
                            let _ = self.db.delete_inbound(handle.peer_id, rec.rule_id);
                        }
                    }
                }
            }
            ControlMessage::RuleRejected { rule_id, reason } => {
                let rule = self
                    .rules
                    .read()
                    .unwrap()
                    .values()
                    .find(|r| r.rule_id == rule_id)
                    .cloned();
                if let Some(mut rule) = rule {
                    rule.state = RuleState::TargetGone;
                    rule.last_error = Some(reason);
                    rule.updated_at = now_ts();
                    let _ = self.db.update_rule_state(
                        rule.listen_port,
                        rule.state,
                        rule.last_error.as_deref(),
                        rule.updated_at,
                    );
                    self.rules.write().unwrap().insert(rule.listen_port, rule);
                }
            }
            ControlMessage::Ping { nonce } => {
                handle.send(ControlMessage::Pong { nonce }).await;
            }
            ControlMessage::Pong { .. } => {}
            ControlMessage::Error { code, message } => {
                tracing::warn!("peer {} reported error {code}: {message}", handle.peer_name);
            }
        }
        Ok(())
    }

    async fn handle_inbound_data(self: &Arc<Self>, handle: Arc<SessionHandle>, stream: Stream) {
        let Some(permit) = handle.limiter.try_acquire() else {
            tracing::warn!("dropping data stream: session limit reached");
            return;
        };
        let mut stream = stream.compat();
        let mut header = [0u8; DATA_HEADER_LEN];
        match tokio::time::timeout(CONTROL_TIMEOUT, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let header = match DataHeader::decode(&header) {
            Ok(header) => header,
            Err(err) => {
                tracing::warn!("invalid data stream header: {err}");
                return;
            }
        };
        if !self.inventory.is_native(header.target_port)
            && (self.inventory.refresh().await.is_err()
                || !self.inventory.is_native(header.target_port))
        {
            tracing::warn!(
                "peer {} requested target port {} which is not a local listener",
                handle.peer_name,
                header.target_port
            );
            handle
                .send(ControlMessage::RuleRejected {
                    rule_id: header.rule_id,
                    reason: format!("target port {} is no longer listening", header.target_port),
                })
                .await;
            return;
        }
        let Some(target) = self.dial_target(header.target_port).await else {
            tracing::warn!(
                "peer {} requested target port {} but dialing it failed",
                handle.peer_name,
                header.target_port
            );
            return;
        };
        let cancel = handle.cancel.child_token();
        let (up, down) = proxy_streams(stream, target, self.config().idle_timeout(), cancel).await;
        tracing::debug!(
            "data stream to port {} finished ({} -> peer, {} <- peer)",
            header.target_port,
            human_bytes(up),
            human_bytes(down)
        );
        drop(permit);
    }

    async fn dial_target(&self, port: u16) -> Option<TcpStream> {
        let mut candidates: Vec<IpAddr> = vec![
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        ];
        for info in self.inventory.native() {
            if info.port != port {
                continue;
            }
            for bind in info.bind {
                if let Ok(ip) = bind.parse::<IpAddr>() {
                    if !ip.is_unspecified() && !candidates.contains(&ip) {
                        candidates.push(ip);
                    }
                }
            }
        }
        for ip in candidates {
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true).ok();
                    return Some(stream);
                }
                _ => continue,
            }
        }
        None
    }
}

async fn control_writer(
    mut writer: tokio::io::WriteHalf<tokio_util::compat::Compat<Stream>>,
    mut rx: mpsc::Receiver<ControlMessage>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            message = rx.recv() => match message {
                Some(message) => {
                    if write_json(&mut writer, &message).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    }
    cancel.cancel();
}

async fn control_reader(
    daemon: Arc<Daemon>,
    handle: Arc<SessionHandle>,
    mut reader: tokio::io::ReadHalf<tokio_util::compat::Compat<Stream>>,
) -> Result<()> {
    loop {
        let message = tokio::select! {
            _ = handle.cancel.cancelled() => return Ok(()),
            message = tokio::time::timeout(DEAD_AFTER + Duration::from_secs(10), read_json(&mut reader)) => {
                match message {
                    Ok(Ok(message)) => message,
                    Ok(Err(err)) => return Err(anyhow::anyhow!("read control message: {err}")),
                    Err(_) => bail!("control stream timed out"),
                }
            }
        };
        handle.touch();
        daemon.handle_control_message(&handle, message).await?;
    }
}

async fn keepalive(handle: Arc<SessionHandle>) {
    let mut ticker = tokio::time::interval(KEEPALIVE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = handle.cancel.cancelled() => break,
            _ = ticker.tick() => {
                if handle.last_rx_elapsed() > DEAD_AFTER {
                    tracing::warn!("peer {} stopped responding", handle.peer_name);
                    handle.cancel.cancel();
                    break;
                }
                handle.send(ControlMessage::Ping { nonce: rand::random() }).await;
            }
        }
    }
}

enum DriverEvent {
    Inbound(Stream),
    Closed(Option<String>),
}

fn poll_driver<S>(
    cx: &mut Context<'_>,
    conn: &mut Connection<S>,
    open_rx: &mut mpsc::Receiver<OpenRequest>,
    pending: &mut Option<OpenRequest>,
) -> Poll<DriverEvent>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        if let Some(request) = pending.take() {
            match conn.poll_new_outbound(cx) {
                Poll::Ready(Ok(stream)) => {
                    let _ = request.tx.send(Ok(stream));
                    continue;
                }
                Poll::Ready(Err(err)) => {
                    let _ = request.tx.send(Err(err.to_string()));
                    return Poll::Ready(DriverEvent::Closed(Some(err.to_string())));
                }
                Poll::Pending => {
                    *pending = Some(request);
                    return Poll::Pending;
                }
            }
        }
        while let Poll::Ready(Some(request)) = open_rx.poll_recv(cx) {
            match conn.poll_new_outbound(cx) {
                Poll::Ready(Ok(stream)) => {
                    let _ = request.tx.send(Ok(stream));
                }
                Poll::Ready(Err(err)) => {
                    let _ = request.tx.send(Err(err.to_string()));
                    return Poll::Ready(DriverEvent::Closed(Some(err.to_string())));
                }
                Poll::Pending => {
                    *pending = Some(request);
                    return Poll::Pending;
                }
            }
        }
        match conn.poll_next_inbound(cx) {
            Poll::Ready(Some(Ok(stream))) => return Poll::Ready(DriverEvent::Inbound(stream)),
            Poll::Ready(Some(Err(err))) => {
                return Poll::Ready(DriverEvent::Closed(Some(err.to_string())))
            }
            Poll::Ready(None) => return Poll::Ready(DriverEvent::Closed(None)),
            Poll::Pending => return Poll::Pending,
        }
    }
}

async fn yamux_driver<S>(
    mut conn: Connection<S>,
    mut open_rx: mpsc::Receiver<OpenRequest>,
    inbound_tx: mpsc::Sender<Stream>,
    cancel: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending: Option<OpenRequest> = None;
    loop {
        let event = tokio::select! {
            _ = cancel.cancelled() => break,
            event = std::future::poll_fn(|cx| poll_driver(cx, &mut conn, &mut open_rx, &mut pending)) => event,
        };
        match event {
            DriverEvent::Inbound(stream) => {
                if inbound_tx.send(stream).await.is_err() {
                    break;
                }
            }
            DriverEvent::Closed(reason) => {
                if let Some(reason) = reason {
                    tracing::debug!("yamux connection closed: {reason}");
                }
                break;
            }
        }
    }
    cancel.cancel();
}

pub async fn agent_accept_loop(daemon: Arc<Daemon>, listener: TcpListener) {
    loop {
        tokio::select! {
            _ = daemon.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, addr)) => {
                    stream.set_nodelay(true).ok();
                    let daemon = daemon.clone();
                    tokio::spawn(async move {
                        if let Err(err) = daemon.handle_agent_connection(stream, addr).await {
                            tracing::debug!("agent connection from {addr} failed: {err:#}");
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!("agent accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

impl Daemon {
    async fn handle_agent_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<()> {
        let mut first = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut first))
            .await
            .context("timed out reading first byte")??;
        if first[0] == 0x16 {
            let acceptor = tokio_rustls::TlsAcceptor::from(self.tls_server.clone());
            let tls = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
                .await
                .context("TLS accept timeout")?
                .context("TLS accept failed")?;
            if tls.get_ref().1.alpn_protocol() != Some(lanfp_crypto::ALPN) {
                bail!("client did not negotiate the lanfp/1 ALPN protocol");
            }
            let pubkey = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| ed25519_pubkey_from_cert(cert.as_ref()).ok())
                .context("peer certificate has no Ed25519 key")?;
            let peer = self
                .db
                .peer_by_pubkey(&pubkey)?
                .context("TLS peer is not a paired device")?;
            self.establish_session(tls, peer, false).await?;
            return Ok(());
        }

        let mut magic = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut magic))
            .await
            .context("timed out reading pairing magic")??;
        if &magic != PAIR_MAGIC {
            bail!("unknown protocol on agent port from {addr}");
        }
        self.handle_pair_connection(stream, addr).await
    }
}

pub async fn session_supervisor(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = daemon.shutdown.cancelled() => break,
            _ = ticker.tick() => {
                let peers = match daemon.db.list_peers() {
                    Ok(peers) => peers,
                    Err(err) => {
                        tracing::warn!("cannot list peers: {err:#}");
                        continue;
                    }
                };
                for peer in peers {
                    if daemon.sessions.get(peer.device_id).is_some() {
                        daemon.backoff.lock().unwrap().remove(&peer.device_id);
                        continue;
                    }
                    let now = Instant::now();
                    let should_dial = {
                        let mut backoff = daemon.backoff.lock().unwrap();
                        let entry = backoff.entry(peer.device_id).or_insert_with(|| Backoff {
                            attempts: 0,
                            next: now,
                            first: now,
                        });
                        let local_is_dialer = daemon.device_id < peer.device_id;
                        let fallback = now.duration_since(entry.first) > Duration::from_secs(30);
                        if (!local_is_dialer && !fallback) || now < entry.next {
                            false
                        } else {
                            entry.attempts = entry.attempts.saturating_add(1);
                            let delay_ms = (1u64 << entry.attempts.saturating_sub(1).min(5)).min(30) * 1000
                                + jitter_millis(&peer.device_id);
                            entry.next = now + Duration::from_millis(delay_ms);
                            true
                        }
                    };
                    if !should_dial {
                        continue;
                    }
                    match daemon.dial_peer(&peer).await {
                        Ok(()) => {
                            daemon.backoff.lock().unwrap().remove(&peer.device_id);
                        }
                        Err(err) => {
                            tracing::debug!("dial {} failed: {err:#}", peer.display());
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Data-plane proxying
// ---------------------------------------------------------------------------

async fn copy_half<R, W>(
    mut reader: R,
    mut writer: W,
    counter: Arc<AtomicU64>,
) -> std::io::Result<u64>
where
    R: TokioAsyncRead + Unpin,
    W: TokioAsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        total += n as u64;
    }
}

/// Copy bytes in both directions with 64 KiB buffers until EOF, cancellation
/// or the idle timeout. Half-close is propagated to the peer.
pub async fn proxy_streams<A, B>(
    a: A,
    b: B,
    idle: Duration,
    cancel: CancellationToken,
) -> (u64, u64)
where
    A: TokioAsyncRead + TokioAsyncWrite + Unpin,
    B: TokioAsyncRead + TokioAsyncWrite + Unpin,
{
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let counter = Arc::new(AtomicU64::new(0));
    let counter_a = counter.clone();
    let counter_b = counter.clone();
    let copy = async move {
        let a_to_b = copy_half(a_read, b_write, counter_a);
        let b_to_a = copy_half(b_read, a_write, counter_b);
        tokio::try_join!(a_to_b, b_to_a)
    };
    tokio::pin!(copy);
    let check = Duration::from_secs(30).min(idle.max(Duration::from_secs(1)));
    let mut idle_acc = Duration::ZERO;
    let mut last = 0u64;
    loop {
        tokio::select! {
            result = &mut copy => {
                return match result {
                    Ok(pair) => pair,
                    Err(_) => (counter.load(Ordering::Relaxed), 0),
                };
            }
            _ = cancel.cancelled() => {
                return (counter.load(Ordering::Relaxed), 0);
            }
            _ = tokio::time::sleep(check) => {
                let current = counter.load(Ordering::Relaxed);
                if current == last {
                    idle_acc += check;
                    if idle_acc >= idle {
                        return (current, 0);
                    }
                } else {
                    idle_acc = Duration::ZERO;
                    last = current;
                }
            }
        }
    }
}

/// Used by `forward add` to validate a peer's native inventory.
pub fn peer_has_port(handle: &SessionHandle, port: u16) -> bool {
    handle.native_ports().iter().any(|p| p.port == port)
}
