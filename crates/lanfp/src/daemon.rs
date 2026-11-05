//! The long-running `lanfp serve` process: startup, IPC, background tasks and
//! request dispatch.

use crate::config::Config;
use crate::db::{Db, DeviceRecord, InboundRecord, PeerRecord, RuleRecord};
use crate::discovery::{DiscoveredPeer, Discovery};
use crate::inventory_svc::InventoryService;
use crate::paths::Paths;
use crate::session::{Backoff, SessionRegistry};
use crate::util::now_ts;
use crate::{forward, pairing, session};
use anyhow::{bail, Context, Result};
use lanfp_core::error::ExitCode;
use lanfp_core::ipc::*;
use lanfp_core::peer::PeerAddr;
use lanfp_core::protocol::{ControlMessage, PortInfo, RuleState};
use lanfp_core::{build_id, sanitize_device_name};
use lanfp_crypto::Identity;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct RuleListener {
    pub cancel: CancellationToken,
    pub task: tokio::task::JoinHandle<()>,
    pub connections: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

pub struct Daemon {
    pub paths: Paths,
    pub config: RwLock<Config>,
    pub identity: Arc<Identity>,
    pub device_id: Uuid,
    pub device_name: String,
    pub agent_addr: SocketAddr,
    pub agent_port: u16,
    pub started_at: Instant,
    pub db: Arc<Db>,
    pub known_peers: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub tls_server: Arc<rustls::ServerConfig>,
    pub inventory: Arc<InventoryService>,
    pub discovery: Arc<Discovery>,
    pub sessions: Arc<SessionRegistry>,
    pub rules: RwLock<HashMap<u16, RuleRecord>>,
    pub listeners: Mutex<HashMap<u16, RuleListener>>,
    pub forward_ports: Arc<RwLock<HashSet<u16>>>,
    pub backoff: Mutex<HashMap<Uuid, Backoff>>,
    pub pairing: pairing::PairManager,
    pub shutdown: CancellationToken,
    pub agent_listener: Mutex<Option<TcpListener>>,
    _lock: std::fs::File,
}

impl Daemon {
    pub async fn new(paths: Paths, config: Config, lock: std::fs::File) -> Result<Arc<Self>> {
        paths.ensure()?;
        let db = Arc::new(Db::open(&paths.db_file())?);

        let identity = Arc::new(Identity::load_or_generate(&paths.identity_dir())?);
        let device_name = sanitize_device_name(
            &hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "lanfp".into()),
        );

        let agent_addr: SocketAddr = config.agent.listen_addr()?;
        let agent_listener = TcpListener::bind(agent_addr)
            .await
            .with_context(|| format!("bind agent listener on {agent_addr}"))?;
        let agent_addr = agent_listener.local_addr()?;
        let agent_port = agent_addr.port();

        let pubkey = identity.public_key_bytes().to_vec();
        let device = match db.get_device()? {
            Some(existing) => {
                if existing.ed25519_pub != pubkey {
                    tracing::warn!("identity key changed; peers must re-pair to trust this device");
                }
                DeviceRecord {
                    id: existing.id,
                    name: device_name.clone(),
                    ed25519_pub: pubkey,
                    cert_der: identity.cert_der().to_vec(),
                    created_at: existing.created_at,
                }
            }
            None => DeviceRecord {
                id: Uuid::new_v4(),
                name: device_name.clone(),
                ed25519_pub: pubkey,
                cert_der: identity.cert_der().to_vec(),
                created_at: now_ts(),
            },
        };
        db.upsert_device(&device)?;
        let device_id = device.id;
        let _ = db.mark_all_inbound_offline(now_ts());

        let peers = db.list_peers()?;
        let known_peers: HashSet<[u8; 32]> =
            peers.iter().filter_map(|p| p.pubkey_array()).collect();
        let known_peers = Arc::new(RwLock::new(known_peers));
        let tls_server = lanfp_crypto::server_config(&identity, known_peers.clone())?;

        let forward_ports = Arc::new(RwLock::new(HashSet::new()));
        let mut rules = HashMap::new();
        for rule in db.list_rules()? {
            forward_ports.write().unwrap().insert(rule.listen_port);
            rules.insert(rule.listen_port, rule);
        }

        let inventory = InventoryService::new(agent_port, forward_ports.clone())?;
        let discovery = Discovery::new(device_id, config.discovery.mdns);

        Ok(Arc::new(Self {
            paths,
            config: RwLock::new(config),
            identity,
            device_id,
            device_name,
            agent_addr,
            agent_port,
            started_at: Instant::now(),
            db,
            known_peers,
            tls_server,
            inventory,
            discovery,
            sessions: Arc::new(SessionRegistry::new()),
            rules: RwLock::new(rules),
            listeners: Mutex::new(HashMap::new()),
            forward_ports,
            backoff: Mutex::new(HashMap::new()),
            pairing: pairing::PairManager::new(),
            shutdown: CancellationToken::new(),
            agent_listener: Mutex::new(Some(agent_listener)),
            _lock: lock,
        }))
    }

    pub fn config(&self) -> Config {
        self.config.read().unwrap().clone()
    }

    pub fn device_display(&self) -> String {
        lanfp_core::format_peer(&self.device_name, &primary_ip_string(), self.agent_port)
    }

    pub async fn start_background(self: &Arc<Self>) -> Result<()> {
        self.inventory.refresh().await?;
        self.spawn_inventory_poller();
        self.spawn_config_watcher();

        if self.discovery.enabled() {
            if let Err(err) = self.discovery.start(&self.device_name, self.agent_port) {
                tracing::warn!("mDNS discovery unavailable: {err:#}");
            }
        }

        forward::start_restored_rules(self).await;

        // Forward inventory updates to all connected sessions.
        let mut updates = self.inventory.subscribe();
        let daemon = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = daemon.shutdown.cancelled() => break,
                    update = updates.recv() => match update {
                        Ok(ports) => {
                            let seq = daemon.inventory.seq();
                            let msg = ControlMessage::Inventory { seq, ports: (*ports).clone() };
                            for session in daemon.sessions.online() {
                                session.send(msg.clone()).await;
                            }
                            daemon.refresh_rule_states().await;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
            }
        });

        let daemon = self.clone();
        tokio::spawn(async move {
            session::session_supervisor(daemon).await;
        });

        let daemon = self.clone();
        tokio::spawn(async move {
            let listener = daemon.agent_listener.lock().unwrap().take();
            if let Some(listener) = listener {
                session::agent_accept_loop(daemon.clone(), listener).await;
            }
        });

        self.start_ipc().await?;

        let daemon = self.clone();
        tokio::spawn(async move {
            if let Err(err) = tokio::signal::ctrl_c().await {
                tracing::warn!("cannot listen for Ctrl-C: {err}");
                return;
            }
            tracing::info!("Ctrl-C received, shutting down");
            daemon.shutdown.cancel();
        });

        #[cfg(unix)]
        {
            let daemon = self.clone();
            tokio::spawn(async move {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut term) = signal(SignalKind::terminate()) {
                    term.recv().await;
                    tracing::info!("SIGTERM received, shutting down");
                    daemon.shutdown.cancel();
                }
            });
        }

        Ok(())
    }

    fn spawn_inventory_poller(self: &Arc<Self>) {
        let daemon = self.clone();
        tokio::spawn(async move {
            loop {
                let interval = daemon.config().inventory_interval();
                tokio::select! {
                    _ = daemon.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        if let Err(err) = daemon.inventory.refresh().await {
                            tracing::warn!("inventory refresh failed: {err:#}");
                        }
                    }
                }
            }
        });
    }

    fn spawn_config_watcher(self: &Arc<Self>) {
        let daemon = self.clone();
        tokio::spawn(async move {
            let path = daemon.paths.config_file();
            let mut last_modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            loop {
                tokio::select! {
                    _ = daemon.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        let modified = std::fs::metadata(&path)
                            .and_then(|m| m.modified())
                            .ok();
                        if modified == last_modified {
                            continue;
                        }
                        last_modified = modified;
                        match Config::load(&path) {
                            Ok(new_config) => {
                                let old = daemon.config();
                                if new_config.agent.listen != old.agent.listen {
                                    tracing::warn!(
                                        "agent.listen changed; restart the daemon for it to take effect"
                                    );
                                }
                                if new_config.discovery.mdns != old.discovery.mdns {
                                    tracing::warn!(
                                        "discovery.mdns changed; restart the daemon for it to take effect"
                                    );
                                }
                                *daemon.config.write().unwrap() = new_config;
                                tracing::info!("configuration reloaded from {}", path.display());
                            }
                            Err(err) => {
                                tracing::warn!("cannot reload configuration: {err:#}");
                            }
                        }
                    }
                }
            }
        });
    }

    async fn start_ipc(self: &Arc<Self>) -> Result<()> {
        let endpoint = self.paths.socket_endpoint();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if endpoint.exists() {
                match tokio::net::UnixStream::connect(&endpoint).await {
                    Ok(_) => bail!(
                        "another lanfp daemon is already listening on {}",
                        endpoint.display()
                    ),
                    Err(_) => {
                        let _ = std::fs::remove_file(&endpoint);
                    }
                }
            }
            if let Some(parent) = endpoint.parent() {
                std::fs::create_dir_all(parent)?;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
            let listener = tokio::net::UnixListener::bind(&endpoint)
                .with_context(|| format!("bind IPC socket {}", endpoint.display()))?;
            std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
            let daemon = self.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let daemon = daemon.clone();
                            tokio::spawn(async move {
                                daemon.handle_ipc_connection(stream).await;
                            });
                        }
                        Err(err) => {
                            tracing::warn!("IPC accept failed: {err}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }
        #[cfg(windows)]
        {
            let name = endpoint.display().to_string();
            let daemon = self.clone();
            tokio::spawn(async move {
                loop {
                    let server =
                        match tokio::net::windows::named_pipe::ServerOptions::new().create(&name) {
                            Ok(server) => server,
                            Err(err) => {
                                tracing::warn!("create IPC pipe failed: {err}");
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                continue;
                            }
                        };
                    match server.connect().await {
                        Ok(()) => {
                            let daemon = daemon.clone();
                            tokio::spawn(async move {
                                daemon.handle_ipc_connection(server).await;
                            });
                        }
                        Err(err) => {
                            tracing::warn!("IPC pipe connect failed: {err}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }
        Ok(())
    }

    async fn handle_ipc_connection<S>(self: Arc<Self>, mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        loop {
            let request: Request = match lanfp_core::frame::read_json(&mut stream).await {
                Ok(req) => req,
                Err(_) => break,
            };
            let id = request.id;
            let stop = matches!(request.cmd, Command::DaemonStop);
            let response = self.handle_request(request).await;
            if lanfp_core::frame::write_json(&mut stream, &response)
                .await
                .is_err()
            {
                break;
            }
            let _ = id;
            if stop {
                self.shutdown.cancel();
                break;
            }
        }
    }

    pub async fn handle_request(self: &Arc<Self>, request: Request) -> Response {
        let id = request.id;
        let result = match request.cmd {
            Command::Ping => Ok(serde_json::json!({"pong": true})),
            Command::Status => self.status_json(),
            Command::Local => self.local_json().await,
            Command::Scan { timeout_ms } => self.scan_json(timeout_ms).await,
            Command::Remote { peer } => self.remote_json(peer).await,
            Command::ForwardAdd {
                peer,
                target_port,
                listen,
            } => self.forward_add_json(peer, target_port, listen).await,
            Command::ForwardList => self.forward_list_json(),
            Command::ForwardRemove { local_port } => self.forward_remove_json(local_port).await,
            Command::Inbound => self.inbound_json(),
            Command::PairStart { peer } => self.pair_start_json(peer).await,
            Command::PairFinish { token, code, force } => {
                self.pair_finish_json(token, code, force).await
            }
            Command::PairCancel { token } => self.pair_cancel_json(token).await,
            Command::PairWaitStart { timeout_secs } => {
                self.pair_wait_start_json(timeout_secs).await
            }
            Command::PairWaitPoll { token } => self.pair_wait_poll_json(token).await,
            Command::DaemonStop => Ok(serde_json::json!({"stopped": true})),
        };
        match result {
            Ok(data) => Response::raw_ok(id, data),
            Err(err) => Response {
                id,
                ok: false,
                data: None,
                error: Some(err),
            },
        }
    }

    fn status_json(&self) -> Result<serde_json::Value, IpcError> {
        let peers = self.db.list_peers().map_err(internal)?;
        let online = self
            .sessions
            .online()
            .into_iter()
            .filter(|s| peers.iter().any(|p| p.device_id == s.peer_id))
            .count();
        let rules = self.rules.read().unwrap().len();
        serde_json::to_value(StatusInfo {
            schema: lanfp_core::JSON_SCHEMA,
            pid: std::process::id(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            agent_addr: self.agent_addr.to_string(),
            ipc_path: self.paths.socket_display(),
            log_path: self.paths.log_file().display().to_string(),
            device: self.device_display(),
            version: build_id(),
            peers_paired: peers.len(),
            peers_online: online,
            rules,
        })
        .map_err(internal)
    }

    async fn local_json(&self) -> Result<serde_json::Value, IpcError> {
        self.inventory.refresh().await.map_err(internal)?;
        let ports = self.inventory.native();
        serde_json::to_value(LocalResult {
            schema: lanfp_core::JSON_SCHEMA,
            ports,
        })
        .map_err(internal)
    }

    async fn scan_json(&self, timeout_ms: u64) -> Result<serde_json::Value, IpcError> {
        let timeout = if timeout_ms == 0 {
            self.config().scan_timeout()
        } else {
            std::time::Duration::from_millis(timeout_ms)
        };
        let discovered = self.discovery.scan(timeout).await;
        let peers = self.db.list_peers().map_err(internal)?;
        let scan_peers: Vec<ScanPeer> = discovered
            .iter()
            .filter(|d| d.last_seen.elapsed() < std::time::Duration::from_secs(120))
            .map(|d| {
                let paired = peers.iter().any(|p| p.device_id == d.uuid);
                let online = self.sessions.get(d.uuid).is_some()
                    || d.last_seen.elapsed() < std::time::Duration::from_secs(30);
                let (address, port) = match d.best_addr() {
                    Some(addr) => (addr.ip().to_string(), addr.port()),
                    None => (String::new(), d.port),
                };
                ScanPeer {
                    peer: d.display(),
                    name: d.name.clone(),
                    address,
                    port,
                    paired,
                    online,
                }
            })
            .collect();
        serde_json::to_value(ScanResult {
            schema: lanfp_core::JSON_SCHEMA,
            peers: scan_peers,
        })
        .map_err(internal)
    }

    async fn remote_json(&self, selector: Option<String>) -> Result<serde_json::Value, IpcError> {
        let mut peers = Vec::new();
        let mut offline = Vec::new();
        if let Some(selector) = selector {
            let record = self.resolve_paired_peer(&selector)?;
            let Some(handle) = self.sessions.get(record.device_id) else {
                return Err(ipc_err(
                    ExitCode::NotPairedOrOffline,
                    format!("{} is offline", record.display()),
                ));
            };
            peers.push(self.remote_peer(&record, &handle));
        } else {
            for record in self.db.list_peers().map_err(internal)? {
                match self.sessions.get(record.device_id) {
                    Some(handle) => peers.push(self.remote_peer(&record, &handle)),
                    None => offline.push(record.display()),
                }
            }
            if peers.is_empty() {
                let message = if offline.is_empty() {
                    "no paired devices; use `lanfp pair <peer>` first".to_string()
                } else {
                    format!("all paired devices are offline: {}", offline.join(", "))
                };
                return Err(ipc_err(ExitCode::NotPairedOrOffline, message));
            }
        }
        serde_json::to_value(RemoteResult {
            schema: lanfp_core::JSON_SCHEMA,
            peers,
            offline,
        })
        .map_err(internal)
    }

    fn remote_peer(&self, record: &PeerRecord, handle: &Arc<session::SessionHandle>) -> RemotePeer {
        let (address, port) = peer_host_port(record);
        let rules = self.rules.read().unwrap();
        let ports = handle
            .native_ports()
            .into_iter()
            .map(|p: PortInfo| {
                let forwarded: Vec<u16> = rules
                    .values()
                    .filter(|r| r.peer_id == record.device_id && r.target_port == p.port)
                    .map(|r| r.listen_port)
                    .collect();
                RemotePort {
                    port: p.port,
                    bind: p.bind,
                    process: p.process,
                    user: p.user,
                    forwarded,
                }
            })
            .collect();
        RemotePeer {
            peer: record.display(),
            name: record.name.clone(),
            address,
            port,
            online: true,
            ports,
        }
    }

    fn inbound_json(&self) -> Result<serde_json::Value, IpcError> {
        let rows = self.db.list_inbound().map_err(internal)?;
        let peers = self.db.list_peers().map_err(internal)?;
        let mut inbound = Vec::new();
        for row in rows {
            let peer = peers.iter().find(|p| p.device_id == row.peer_id);
            let online = row.online && self.sessions.get(row.peer_id).is_some();
            inbound.push(InboundInfo {
                peer: peer
                    .map(|p| p.display())
                    .unwrap_or_else(|| row.peer_id.to_string()),
                my_port: row.target_port,
                peer_listen: row.peer_listen_port,
                since: row.first_seen_at,
                last_seen: row.last_seen_at,
                online,
            });
        }
        inbound.sort_by_key(|i| (i.my_port, i.peer.clone()));
        serde_json::to_value(InboundResult {
            schema: lanfp_core::JSON_SCHEMA,
            inbound,
        })
        .map_err(internal)
    }

    // ------------------------------------------------------------------
    // Peer selection helpers
    // ------------------------------------------------------------------

    /// Resolve a selector to a paired peer. Returns exit code 3 when nothing
    /// matches and 4 when the device is known but not paired.
    pub fn resolve_paired_peer(&self, selector: &str) -> Result<PeerRecord, IpcError> {
        let peers = self.db.list_peers().map_err(internal)?;
        if let Some(peer) = match_peer(&peers, selector) {
            return Ok(peer);
        }
        if let Some(found) = self.discovery_match(selector) {
            return Err(ipc_err(
                ExitCode::NotPairedOrOffline,
                format!("{} is not paired with this device", found.display()),
            ));
        }
        Err(ipc_err(
            ExitCode::DeviceNotFound,
            format!("no paired device matches `{selector}`"),
        ))
    }

    pub fn discovery_match(&self, selector: &str) -> Option<DiscoveredPeer> {
        let normalized = selector.trim();
        let parsed = PeerAddr::parse(normalized).ok();
        self.discovery.snapshot().into_iter().find(|d| {
            d.display() == normalized
                || d.name.eq_ignore_ascii_case(normalized)
                || d.uuid.to_string() == normalized
                || d.best_addr()
                    .map(|a| a.ip().to_string() == normalized)
                    .unwrap_or(false)
                || parsed
                    .as_ref()
                    .map(|p| {
                        d.addresses.iter().any(|ip| ip.to_string() == p.host) && p.port == d.port
                    })
                    .unwrap_or(false)
        })
    }

    pub fn pairing_target(&self, selector: &str) -> Result<PairTarget, IpcError> {
        let peers = self.db.list_peers().map_err(internal)?;
        if let Some(peer) = match_peer(&peers, selector) {
            return Ok(PairTarget::Paired(peer));
        }
        if let Some(found) = self.discovery_match(selector) {
            return Ok(PairTarget::Discovered(found));
        }
        match PeerAddr::parse(selector) {
            Ok(addr) => Ok(PairTarget::Manual(addr)),
            Err(err) => Err(ipc_err(
                ExitCode::DeviceNotFound,
                format!("cannot resolve peer `{selector}`: {err}"),
            )),
        }
    }

    pub fn add_known_peer(&self, pubkey: [u8; 32]) {
        self.known_peers.write().unwrap().insert(pubkey);
    }

    pub fn remove_known_peer(&self, pubkey: &[u8; 32]) {
        self.known_peers.write().unwrap().remove(pubkey);
    }

    pub fn reset_backoff(&self, peer: Uuid) {
        self.backoff.lock().unwrap().remove(&peer);
    }

    pub async fn refresh_rule_states(self: &Arc<Self>) {
        let peers: Vec<Uuid> = self
            .rules
            .read()
            .unwrap()
            .values()
            .map(|r| r.peer_id)
            .collect();
        for peer in peers {
            self.recompute_rules_for_peer(peer).await;
        }
    }

    pub async fn recompute_rules_for_peer(self: &Arc<Self>, peer_id: Uuid) {
        let handle = self.sessions.get(peer_id);
        let native: HashSet<u16> = handle
            .as_ref()
            .map(|h| h.native_ports().into_iter().map(|p| p.port).collect())
            .unwrap_or_default();
        let rules: Vec<RuleRecord> = self
            .rules
            .read()
            .unwrap()
            .values()
            .filter(|r| r.peer_id == peer_id)
            .cloned()
            .collect();
        for mut rule in rules {
            let has_listener = self
                .listeners
                .lock()
                .unwrap()
                .contains_key(&rule.listen_port);
            let (state, error) = if !has_listener {
                (
                    RuleState::ListenError,
                    Some(
                        rule.last_error
                            .clone()
                            .unwrap_or_else(|| "listener is not bound".into()),
                    ),
                )
            } else {
                match &handle {
                    None => (RuleState::PeerOffline, None),
                    Some(h) if !h.inventory_received() => (RuleState::PeerOffline, None),
                    Some(_) if !native.contains(&rule.target_port) => (
                        RuleState::TargetGone,
                        Some(format!(
                            "target port {} is no longer listening on the peer",
                            rule.target_port
                        )),
                    ),
                    Some(_) => (RuleState::Active, None),
                }
            };
            if rule.state != state || rule.last_error != error {
                rule.state = state;
                rule.last_error = error.clone();
                rule.updated_at = now_ts();
                let _ = self.db.update_rule_state(
                    rule.listen_port,
                    state,
                    error.as_deref(),
                    rule.updated_at,
                );
                self.rules
                    .write()
                    .unwrap()
                    .insert(rule.listen_port, rule.clone());
                if let Some(h) = &handle {
                    h.send(ControlMessage::RuleUpsert {
                        rule_id: rule.rule_id,
                        target_port: rule.target_port,
                        listen_port: rule.listen_port,
                        state,
                    })
                    .await;
                }
            }
        }
    }

    pub fn cleanup(&self) {
        self.shutdown.cancel();
        self.discovery.shutdown();
        for (_, listener) in self.listeners.lock().unwrap().drain() {
            listener.cancel.cancel();
            listener.task.abort();
        }
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(self.paths.socket_endpoint());
        }
        let _ = std::fs::remove_file(self.paths.pid_file());
    }
}

#[derive(Debug)]
pub enum PairTarget {
    Paired(PeerRecord),
    Discovered(DiscoveredPeer),
    Manual(PeerAddr),
}

fn match_peer(peers: &[PeerRecord], selector: &str) -> Option<PeerRecord> {
    let normalized = selector.trim();
    let parsed = PeerAddr::parse(normalized).ok();
    peers
        .iter()
        .find(|p| {
            p.display() == normalized
                || p.name.eq_ignore_ascii_case(normalized)
                || p.device_id.to_string() == normalized
                || p.last_addr.as_deref() == Some(normalized)
                || parsed
                    .as_ref()
                    .map(|a| {
                        p.last_addr
                            .as_deref()
                            .and_then(|addr| PeerAddr::parse(addr).ok())
                            .map(|stored| stored.host == a.host && stored.port == a.port)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
        })
        .cloned()
}

pub fn peer_host_port(record: &PeerRecord) -> (String, u16) {
    match record
        .last_addr
        .as_deref()
        .and_then(|addr| PeerAddr::parse(addr).ok())
    {
        Some(addr) => (addr.host, addr.port),
        None => (String::new(), lanfp_core::DEFAULT_AGENT_PORT),
    }
}

pub fn rules_for_peer_snapshot(daemon: &Daemon, peer_id: Uuid) -> Vec<RuleRecord> {
    daemon
        .rules
        .read()
        .unwrap()
        .values()
        .filter(|r| r.peer_id == peer_id)
        .cloned()
        .collect()
}

pub fn inbound_record(
    peer_id: Uuid,
    rule_id: Uuid,
    target_port: u16,
    peer_listen_port: u16,
    first_seen_at: i64,
    online: bool,
) -> InboundRecord {
    InboundRecord {
        peer_id,
        rule_id,
        target_port,
        peer_listen_port,
        first_seen_at,
        last_seen_at: now_ts(),
        online,
    }
}

pub fn ipc_err(code: ExitCode, message: impl Into<String>) -> IpcError {
    IpcError::new(code, message)
}

pub fn internal(err: impl std::fmt::Display) -> IpcError {
    IpcError::new(ExitCode::DaemonUnavailable, err.to_string())
}

pub fn acquire_lock(paths: &Paths) -> Result<Option<std::fs::File>> {
    use fs2::FileExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(paths.lock_file())
        .with_context(|| format!("open lock file {}", paths.lock_file().display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            let pid = std::process::id().to_string();
            let _ = std::fs::write(paths.pid_file(), pid);
            Ok(Some(file))
        }
        Err(_) => Ok(None),
    }
}

pub fn primary_ip_string() -> String {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return "127.0.0.1".into();
    };
    interfaces
        .iter()
        .map(|i| i.addr.ip())
        .find(|ip| ip.is_ipv4() && !ip.is_loopback())
        .or_else(|| {
            interfaces
                .iter()
                .map(|i| i.addr.ip())
                .find(|ip| !ip.is_loopback())
        })
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
        .to_string()
}

/// Format an offline notice used by `lanfp remote`.
pub fn offline_notice(offline: &[String]) -> Option<String> {
    if offline.is_empty() {
        None
    } else {
        Some(format!(
            "skipping offline device(s): {}",
            offline.join(", ")
        ))
    }
}

/// Entry point for `lanfp serve`.
pub async fn serve(paths: Paths, config: Config) -> Result<()> {
    lanfp_crypto::install_crypto_provider();
    paths.ensure()?;

    let Some(lock) = acquire_lock(&paths)? else {
        let pid = std::fs::read_to_string(paths.pid_file()).unwrap_or_default();
        println!(
            "lanfp is already running (pid {}, ipc {})",
            pid.trim(),
            paths.socket_display()
        );
        return Ok(());
    };

    let daemon = Daemon::new(paths.clone(), config, lock).await?;
    tracing::info!(
        "lanfp {} started: device {} agent {} ipc {}",
        env!("CARGO_PKG_VERSION"),
        daemon.device_display(),
        daemon.agent_addr,
        daemon.paths.socket_display()
    );
    if let Err(err) = daemon.start_background().await {
        daemon.cleanup();
        return Err(err);
    }
    daemon.shutdown.cancelled().await;
    tracing::info!("lanfp stopping");
    daemon.cleanup();
    Ok(())
}

/// Validate that a listen port may be bound by a user-level process.
pub fn low_port_error(port: u16) -> Option<IpcError> {
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() } == 0;
        if port < 1024 && !is_root {
            return Some(ipc_err(
                ExitCode::Permission,
                format!(
                    "cannot listen on port {port}: ports below 1024 require privileges; use `--listen <port>` with a port >= 1024"
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = port;
    }
    None
}
