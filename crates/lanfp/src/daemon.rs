//! The long-running `lanfp serve` process: startup, IPC, background tasks and
//! request dispatch.

use crate::config::Config;
use crate::db::{Db, DeviceRecord, InboundRecord, PeerRecord, RuleRecord};
use crate::discovery::{DiscoveredPeer, Discovery};
use crate::expose::ExposeManager;
use crate::inventory_svc::InventoryService;
use crate::paths::Paths;
use crate::session::{Backoff, SessionRegistry};
use crate::util::now_ts;
use crate::{forward, session};
#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use lanfp_core::error::ExitCode;
use lanfp_core::ipc::*;
use lanfp_core::peer::PeerAddr;
use lanfp_core::protocol::{ControlMessage, ExposeMode, ExposedPort, ExposureView, RuleState};
use lanfp_core::{build_id, sanitize_device_name};
use lanfp_crypto::Identity;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A peer's mDNS result is trusted for display/dialing for this long.
const DISCOVERY_FRESH: Duration = Duration::from_secs(120);
/// Shortest accepted UUID prefix.
const UUID_PREFIX_MIN: usize = 4;

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
    /// Peers whose next supervisor tick must dial regardless of the
    /// dialer-election delay (set by `lanfp peer set-address`).
    pub force_dial: Mutex<HashSet<Uuid>>,
    pub expose: Arc<ExposeManager>,
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

        let allowed = db.list_allowed()?;
        let known_peers: HashSet<[u8; 32]> = allowed
            .iter()
            .filter(|p| p.may_connect)
            .filter_map(|p| p.pubkey_array())
            .collect();
        let known_peers = Arc::new(RwLock::new(known_peers));
        let tls_server = lanfp_crypto::server_config(&identity, known_peers.clone())?;

        let forward_ports = Arc::new(RwLock::new(HashSet::new()));
        let mut rules = HashMap::new();
        for rule in db.list_rules()? {
            forward_ports.write().unwrap().insert(rule.listen_port);
            rules.insert(rule.listen_port, rule);
        }

        let inventory = InventoryService::new(agent_port, forward_ports.clone())?;
        let discovery = Discovery::new(
            device_id,
            identity.public_key_bytes(),
            config.discovery.mdns,
            agent_addr.ip(),
        );
        let expose_ranges = config.agent.expose_ranges()?;
        let expose = Arc::new(ExposeManager::load(expose_ranges));

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
            force_dial: Mutex::new(HashSet::new()),
            expose,
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
                        Ok(_) => {
                            let seq = daemon.inventory.seq();
                            let ports = daemon.exposed_inventory();
                            let view = daemon.exposure_view();
                            for session in daemon.sessions.online() {
                                session
                                    .send(ControlMessage::Inventory {
                                        seq,
                                        ports: ports.clone(),
                                    })
                                    .await;
                                session
                                    .send(ControlMessage::Exposure {
                                        mode: view.mode,
                                        ports: view.ports.clone(),
                                        ranges: view.ranges.clone(),
                                    })
                                    .await;
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
                                // agent.expose_ports takes effect immediately.
                                if let Ok(ranges) = new_config.agent.expose_ranges() {
                                    if ranges != daemon.expose.expose_ranges() {
                                        daemon.expose.set_ranges(ranges);
                                        tracing::info!("exposure whitelist reloaded");
                                        let daemon = daemon.clone();
                                        tokio::spawn(async move {
                                            daemon.broadcast_exposure().await;
                                        });
                                    }
                                } else {
                                    tracing::warn!(
                                        "cannot apply agent.expose_ports: invalid whitelist, keeping the previous one"
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
            Command::Inbound => self.inbound_json().await,
            Command::PeerGrant { peers, force } => self.peer_grant_json(peers, force).await,
            Command::PeerRevoke { peers } => self.peer_revoke_json(peers).await,
            Command::PeerSetAddress { peer, address } => {
                self.peer_set_address_json(peer, address).await
            }
            Command::PeerList => self.peer_list_json(),
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
        let allowed = self.db.list_allowed().map_err(internal)?.len();
        let servers = self.db.list_dialable().map_err(internal)?.len();
        let online = self.sessions.online().len();
        let rules = self.rules.read().unwrap().len();
        serde_json::to_value(StatusInfo {
            schema: lanfp_core::JSON_SCHEMA,
            pid: std::process::id(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            agent_addr: self.agent_addr.to_string(),
            ipc_path: self.paths.socket_display(),
            log_path: self.paths.log_file().display().to_string(),
            device: self.device_display(),
            device_id: self.device_id,
            fingerprint: lanfp_crypto::fingerprint(&self.identity.public_key_bytes()),
            version: build_id(),
            allowed,
            servers,
            online,
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
        let trusted = self.db.list_trust().map_err(internal)?;
        let scan_peers: Vec<ScanPeer> = discovered
            .iter()
            .filter(|d| d.last_seen.elapsed() < std::time::Duration::from_secs(120))
            .map(|d| {
                let record = trusted.iter().find(|p| p.device_id == d.uuid);
                let authorized = record.map(|p| p.may_connect).unwrap_or(false);
                let known = record.map(|p| p.may_dial).unwrap_or(false);
                let online = self.sessions.get(d.uuid).is_some()
                    || d.last_seen.elapsed() < std::time::Duration::from_secs(30);
                let (address, port) = match d.best_addr() {
                    Some(addr) => (addr.ip().to_string(), addr.port()),
                    None => (String::new(), d.port),
                };
                ScanPeer {
                    peer: d.display(),
                    id: d.uuid,
                    name: d.name.clone(),
                    address,
                    port,
                    version: d.version,
                    authorized,
                    known,
                    online,
                    fingerprint: d.pubkey.map(|pk| lanfp_crypto::fingerprint(&pk)),
                }
            })
            .collect();
        serde_json::to_value(ScanResult {
            schema: lanfp_core::JSON_SCHEMA,
            peers: scan_peers,
        })
        .map_err(internal)
    }

    async fn remote_json(
        self: &Arc<Self>,
        selector: Option<String>,
    ) -> Result<serde_json::Value, IpcError> {
        let mut peers = Vec::new();
        let mut offline = Vec::new();
        let mut offline_peers = Vec::new();
        if let Some(selector) = selector {
            let record = self.resolve_dialable_or_learn(&selector).await?;
            let handle = self.ensure_online(&record).await?;
            peers.push(self.remote_peer(&record, &handle));
        } else {
            for record in self.db.list_dialable().map_err(internal)? {
                match self.sessions.get(record.device_id) {
                    Some(handle) => peers.push(self.remote_peer(&record, &handle)),
                    None => {
                        let display = self.display_peer(&record);
                        offline.push(display.clone());
                        offline_peers.push(PeerRef {
                            id: record.device_id,
                            peer: display,
                        });
                    }
                }
            }
            if peers.is_empty() {
                let message = if offline.is_empty() {
                    "no servers known; run `lanfp scan` and ask the exposing device to run `lanfp peer grant` for this device".to_string()
                } else {
                    let shown: Vec<String> = offline_peers
                        .iter()
                        .map(|peer| format!("{} [{}]", peer.peer, lanfp_core::short_id(peer.id)))
                        .collect();
                    format!("all known servers are offline: {}", shown.join(", "))
                };
                return Err(ipc_err(ExitCode::NotAuthorizedOrOffline, message));
            }
        }
        serde_json::to_value(RemoteResult {
            schema: lanfp_core::JSON_SCHEMA,
            peers,
            offline,
            offline_peers,
        })
        .map_err(internal)
    }

    fn remote_peer(&self, record: &PeerRecord, handle: &Arc<session::SessionHandle>) -> RemotePeer {
        let (address, port) = match self.current_peer_addr(record) {
            Some(addr) => (addr.ip().to_string(), addr.port()),
            None => (String::new(), lanfp_core::DEFAULT_AGENT_PORT),
        };
        let rules = self.rules.read().unwrap();
        let view = handle.exposure();
        // The session is registered before its first Inventory/Exposure
        // messages are processed. Fall back to the raw inventory so a
        // just-granted server is not rendered with zero ports.
        let view = if handle.exposure_received() {
            view
        } else {
            ExposureView {
                mode: ExposeMode::All,
                ports: handle
                    .native_ports()
                    .into_iter()
                    .map(|p| ExposedPort {
                        port: p.port,
                        listening: true,
                        bind: p.bind,
                        process: p.process,
                        user: p.user,
                    })
                    .collect(),
                ranges: Vec::new(),
            }
        };
        let ports = view
            .ports
            .into_iter()
            .map(|p| {
                let mut forwarded: Vec<u16> = rules
                    .values()
                    .filter(|r| r.peer_id == record.device_id && r.target_port == p.port)
                    .map(|r| r.listen_port)
                    .collect();
                forwarded.sort_unstable();
                RemotePort {
                    port: p.port,
                    listening: p.listening,
                    bind: p.bind,
                    process: p.process,
                    user: p.user,
                    forwarded,
                }
            })
            .collect();
        RemotePeer {
            peer: self.display_peer(record),
            id: record.device_id,
            name: record.name.clone(),
            address,
            port,
            online: true,
            mode: view.mode,
            ranges: view.ranges,
            fingerprint: lanfp_crypto::fingerprint(&record.ed25519_pub),
            ports,
        }
    }

    async fn inbound_json(self: &Arc<Self>) -> Result<serde_json::Value, IpcError> {
        self.inventory.refresh().await.map_err(internal)?;
        let rows = self.db.list_inbound().map_err(internal)?;
        let peers = self.db.list_trust().map_err(internal)?;
        let mut inbound = Vec::new();
        for row in rows {
            // `inbound` is the live forwarding view: hide a reference while
            // the target service is not actually listening.
            if !self.inventory.is_native(row.target_port)
                || !self.expose.is_exposed(row.target_port)
            {
                continue;
            }
            let peer = peers.iter().find(|p| p.device_id == row.peer_id);
            let online = row.online && self.sessions.get(row.peer_id).is_some();
            inbound.push(InboundInfo {
                peer: peer
                    .map(|p| self.display_peer(p))
                    .unwrap_or_else(|| row.peer_id.to_string()),
                id: row.peer_id,
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

    /// Address used to reach a peer right now: a fresh mDNS result wins over
    /// the address stored in the database.
    pub fn current_peer_addr(&self, peer: &PeerRecord) -> Option<SocketAddr> {
        self.discovery
            .fresh_addr(peer.device_id, DISCOVERY_FRESH)
            .or_else(|| {
                peer.last_addr
                    .as_deref()
                    .and_then(|raw| PeerAddr::parse(raw).ok())
                    .and_then(|parsed| parsed.socket_addr())
            })
    }

    /// Addresses to try when dialing a peer: a fresh mDNS hint first, then the
    /// address stored in the database. Discovery is only a hint, so a stale or
    /// unreachable mDNS result must not make a reachable peer undialable.
    pub fn peer_dial_candidates(&self, peer: &PeerRecord) -> Vec<SocketAddr> {
        let fresh = self.discovery.fresh_addr(peer.device_id, DISCOVERY_FRESH);
        let stored = peer
            .last_addr
            .as_deref()
            .and_then(|raw| PeerAddr::parse(raw).ok())
            .and_then(|parsed| parsed.socket_addr());
        dial_candidates(fresh, stored)
    }

    /// `<name>@<current address>`, formatted when a list is printed. This is a
    /// view, not an identity: the stable identity is always [`PeerRecord::device_id`].
    pub fn display_peer(&self, peer: &PeerRecord) -> String {
        match self.current_peer_addr(peer) {
            Some(addr) => lanfp_core::format_peer(&peer.name, &addr.ip().to_string(), addr.port()),
            None => peer.display(),
        }
    }

    /// Reject a selector that matches more than one device instead of silently
    /// picking the first one.
    pub fn ambiguous_error(&self, selector: &str, matches: &[PeerRecord]) -> IpcError {
        let ids: Vec<Uuid> = matches.iter().map(|peer| peer.device_id).collect();
        let short = lanfp_core::short_ids(&ids);
        let mut message = format!("`{selector}` matches {} devices:", matches.len());
        for (peer, id) in matches.iter().zip(short) {
            let state = if self.sessions.get(peer.device_id).is_some() {
                "online"
            } else {
                "offline"
            };
            message.push_str(&format!("\n  {id}  {}  {state}", self.display_peer(peer)));
        }
        message.push_str("\nuse the device ID (`lanfp scan` / `lanfp peer list`) to disambiguate");
        ipc_err(ExitCode::Usage, message)
    }

    /// All trust rows matching a selector, in either direction. The same
    /// string is tried as a full UUID, a UUID prefix, a device name,
    /// `name@address`, and a bare address.
    pub fn trust_matches(&self, selector: &str) -> Result<Vec<PeerRecord>, IpcError> {
        let peers = self.db.list_trust().map_err(internal)?;
        let s = selector.trim();
        let mut found: Vec<Uuid> = Vec::new();

        if let Some(uuid) = parse_full_uuid(s) {
            if peers.iter().any(|peer| peer.device_id == uuid) {
                push_unique(&mut found, uuid);
            }
        }
        if let Some(prefix) = uuid_prefix(s) {
            for peer in &peers {
                if peer
                    .device_id
                    .simple()
                    .to_string()
                    .starts_with(prefix.as_str())
                {
                    push_unique(&mut found, peer.device_id);
                }
            }
        }

        let parsed = PeerAddr::parse(s).ok();
        if s.contains('@') {
            if let Some(parsed) = &parsed {
                if let Some(name) = &parsed.name {
                    let explicit = lanfp_core::has_explicit_port(s);
                    for peer in &peers {
                        if peer.name.eq_ignore_ascii_case(name)
                            && self.address_matches(peer, &parsed.host, parsed.port, explicit)
                        {
                            push_unique(&mut found, peer.device_id);
                        }
                    }
                }
            }
        } else {
            for peer in &peers {
                if peer.name.eq_ignore_ascii_case(s) {
                    push_unique(&mut found, peer.device_id);
                }
            }
            if let Some(parsed) = &parsed {
                if parsed.host.parse::<IpAddr>().is_ok() {
                    let explicit = lanfp_core::has_explicit_port(s);
                    for peer in &peers {
                        if self.address_matches(peer, &parsed.host, parsed.port, explicit) {
                            push_unique(&mut found, peer.device_id);
                        }
                    }
                }
            }
        }

        Ok(peers
            .into_iter()
            .filter(|peer| found.contains(&peer.device_id))
            .collect())
    }

    pub fn dialable_matches(&self, selector: &str) -> Result<Vec<PeerRecord>, IpcError> {
        Ok(self
            .trust_matches(selector)?
            .into_iter()
            .filter(|peer| peer.may_dial)
            .collect())
    }

    pub fn allowed_matches(&self, selector: &str) -> Result<Vec<PeerRecord>, IpcError> {
        Ok(self
            .trust_matches(selector)?
            .into_iter()
            .filter(|peer| peer.may_connect)
            .collect())
    }

    fn address_matches(
        &self,
        peer: &PeerRecord,
        host: &str,
        port: u16,
        explicit_port: bool,
    ) -> bool {
        let Ok(ip) = host.parse::<IpAddr>() else {
            return false;
        };
        let Some(addr) = self.current_peer_addr(peer) else {
            return false;
        };
        addr.ip() == ip && (!explicit_port || addr.port() == port)
    }

    pub(crate) fn discovered_matches(&self, selector: &str) -> Vec<DiscoveredPeer> {
        let s = selector.trim();
        let full = parse_full_uuid(s);
        let prefix = uuid_prefix(s);
        let parsed = PeerAddr::parse(s).ok();
        let explicit = lanfp_core::has_explicit_port(s);
        self.discovery
            .snapshot()
            .into_iter()
            .filter(|peer| {
                if full == Some(peer.uuid) {
                    return true;
                }
                if let Some(prefix) = &prefix {
                    if peer.uuid.simple().to_string().starts_with(prefix.as_str()) {
                        return true;
                    }
                }
                if s.contains('@') {
                    if let Some(parsed) = &parsed {
                        if let Some(name) = &parsed.name {
                            return peer.name.eq_ignore_ascii_case(name)
                                && discovered_address_matches(
                                    peer,
                                    &parsed.host,
                                    parsed.port,
                                    explicit,
                                );
                        }
                    }
                    return false;
                }
                if peer.name.eq_ignore_ascii_case(s) {
                    return true;
                }
                match &parsed {
                    Some(parsed) if parsed.host.parse::<IpAddr>().is_ok() => {
                        discovered_address_matches(peer, &parsed.host, parsed.port, explicit)
                    }
                    _ => false,
                }
            })
            .collect()
    }

    /// Point a known device at a new address, e.g. after a DHCP or Wi-Fi
    /// change when mDNS cannot find it. Devices this machine may dial are
    /// redialed immediately.
    pub async fn peer_set_address_json(
        self: &Arc<Self>,
        selector: String,
        address: String,
    ) -> Result<serde_json::Value, IpcError> {
        let matches = self.trust_matches(&selector)?;
        let peer = match matches.len() {
            1 => matches.into_iter().next().expect("one match"),
            n if n > 1 => return Err(self.ambiguous_error(&selector, &matches)),
            _ => {
                return Err(ipc_err(
                    ExitCode::DeviceNotFound,
                    format!("no known device matches `{selector}`"),
                ))
            }
        };
        let parsed = PeerAddr::parse(&address).map_err(|err| {
            ipc_err(
                ExitCode::Usage,
                format!("invalid address `{address}`: {err}"),
            )
        })?;
        let ip: IpAddr = parsed.host.parse().map_err(|_| {
            ipc_err(
                ExitCode::Usage,
                format!(
                    "`{}` is not an IP address; use <ip>[:port], e.g. 192.168.8.23 or [2001:db8::1]:47811",
                    parsed.host
                ),
            )
        })?;
        if ip.is_unspecified() {
            return Err(ipc_err(
                ExitCode::Usage,
                "address must be a concrete IP, not the unspecified address",
            ));
        }
        if matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
            return Err(ipc_err(
                ExitCode::Usage,
                "IPv6 link-local addresses need a scope id, which is not supported; use a global IPv6 or IPv4 address",
            ));
        }
        let addr = SocketAddr::new(ip, parsed.port).to_string();
        self.db
            .update_peer_seen(peer.device_id, Some(&addr), now_ts())
            .map_err(internal)?;
        if peer.may_dial {
            self.reset_backoff(peer.device_id);
            self.force_dial.lock().unwrap().insert(peer.device_id);
        }
        self.discovery.forget(peer.device_id);
        tracing::info!("address for {} set to {addr}", peer.name);

        let online = self.sessions.get(peer.device_id).is_some();
        let display = lanfp_core::format_peer(&peer.name, &ip.to_string(), parsed.port);
        serde_json::to_value(PeerSetAddressResult {
            schema: lanfp_core::JSON_SCHEMA,
            peer: display,
            id: peer.device_id,
            address: addr,
            online,
        })
        .map_err(internal)
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

fn parse_full_uuid(selector: &str) -> Option<Uuid> {
    let s = selector.trim();
    if s.len() == 32 || s.len() == 36 {
        Uuid::parse_str(s).ok()
    } else {
        None
    }
}

fn uuid_prefix(selector: &str) -> Option<String> {
    let s = selector.trim().to_ascii_lowercase();
    if (UUID_PREFIX_MIN..32).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(s)
    } else {
        None
    }
}

fn push_unique(found: &mut Vec<Uuid>, id: Uuid) {
    if !found.contains(&id) {
        found.push(id);
    }
}

fn discovered_address_matches(
    peer: &DiscoveredPeer,
    host: &str,
    port: u16,
    explicit_port: bool,
) -> bool {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    peer.addresses.contains(&ip) && (!explicit_port || peer.port == port)
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

/// Entry point for `lanfp serve`.
pub async fn serve(paths: Paths, config: Config, hidden: bool) -> Result<()> {
    // The CLI uses SIG_DFL so a closed pipe exits quietly; the daemon must not
    // die when a peer closes a socket mid-write, so ignore SIGPIPE here.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    lanfp_crypto::install_crypto_provider();
    #[cfg(windows)]
    if hidden {
        hide_console();
    }
    #[cfg(not(windows))]
    let _ = hidden;
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

/// Detach from the parent console so the login autostart entry does not leave
/// a console window on screen.
#[cfg(windows)]
fn hide_console() {
    use windows_sys::Win32::System::Console::FreeConsole;
    unsafe {
        FreeConsole();
    }
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

/// Try the fresh mDNS hint first, then the last address that worked.
fn dial_candidates(fresh: Option<SocketAddr>, stored: Option<SocketAddr>) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(2);
    for addr in [fresh, stored].into_iter().flatten() {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 168, 8, 8), port))
    }

    #[test]
    fn dial_candidates_put_the_fresh_hint_first() {
        let fresh = SocketAddr::from((Ipv4Addr::new(192, 168, 8, 9), 47811));
        assert_eq!(
            dial_candidates(Some(fresh), Some(v4(47811))),
            vec![fresh, v4(47811)]
        );
    }

    #[test]
    fn dial_candidates_deduplicate_and_tolerate_missing_addresses() {
        assert_eq!(
            dial_candidates(Some(v4(47811)), Some(v4(47811))),
            vec![v4(47811)]
        );
        assert_eq!(dial_candidates(None, Some(v4(47811))), vec![v4(47811)]);
        assert_eq!(dial_candidates(Some(v4(47811)), None), vec![v4(47811)]);
        assert!(dial_candidates(None, None).is_empty());
    }
}
