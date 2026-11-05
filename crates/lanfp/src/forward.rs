//! Forwarding rules: local loopback listeners, validation and the data plane
//! on the rule-owning side.

use crate::daemon::{internal, ipc_err, low_port_error, Daemon, RuleListener};
use crate::db::RuleRecord;
use crate::session::{peer_has_port, proxy_streams};
use crate::util::{human_bytes, now_ts};
use anyhow::Result;
use lanfp_core::error::ExitCode;
use lanfp_core::ipc::*;
use lanfp_core::protocol::{ControlMessage, DataHeader, RuleState};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

impl Daemon {
    pub async fn forward_add_json(
        self: &Arc<Self>,
        peer_selector: String,
        target_port: u16,
        listen: Option<u16>,
    ) -> Result<serde_json::Value, IpcError> {
        if target_port == 0 {
            return Err(ipc_err(ExitCode::Usage, "target port must not be 0"));
        }
        let peer = self.resolve_paired_peer(&peer_selector)?;
        let Some(handle) = self.sessions.get(peer.device_id) else {
            return Err(ipc_err(
                ExitCode::NotPairedOrOffline,
                format!("{} is offline", peer.display()),
            ));
        };
        if !peer_has_port(&handle, target_port) {
            return Err(ipc_err(
                ExitCode::TargetNotInInventory,
                format!(
                    "port {target_port} is not in {}'s Native inventory",
                    peer.display()
                ),
            ));
        }
        let listen_port = listen.unwrap_or(target_port);
        if listen_port == 0 {
            return Err(ipc_err(ExitCode::Usage, "listen port must not be 0"));
        }
        if let Some(err) = low_port_error(listen_port) {
            return Err(err);
        }
        if listen_port == self.agent_port {
            return Err(ipc_err(
                ExitCode::ListenConflict,
                format!(
                    "127.0.0.1:{listen_port} is lanfp's own agent port; choose another --listen port"
                ),
            ));
        }
        if self.forward_ports.read().unwrap().contains(&listen_port)
            || self.rules.read().unwrap().contains_key(&listen_port)
        {
            return Err(ipc_err(
                ExitCode::ListenConflict,
                format!("a forwarding rule already exists on local port {listen_port}"),
            ));
        }

        let listener = match TcpListener::bind(("127.0.0.1", listen_port)).await {
            Ok(listener) => listener,
            Err(err) => {
                return Err(map_bind_error(self, listen_port, &err).await);
            }
        };

        let now = now_ts();
        let rule = RuleRecord {
            peer_id: peer.device_id,
            rule_id: Uuid::new_v4(),
            target_port,
            listen_port,
            enabled: true,
            state: RuleState::Active,
            last_error: None,
            created_at: now,
            updated_at: now,
        };
        if let Err(err) = self.db.insert_rule(&rule) {
            return Err(internal(err));
        }
        self.rules
            .write()
            .unwrap()
            .insert(listen_port, rule.clone());
        self.forward_ports.write().unwrap().insert(listen_port);
        spawn_rule_listener(self, listen_port, listener);

        handle
            .send(ControlMessage::RuleUpsert {
                rule_id: rule.rule_id,
                target_port: rule.target_port,
                listen_port: rule.listen_port,
                state: rule.state,
            })
            .await;

        serde_json::to_value(ForwardAddResult {
            schema: lanfp_core::JSON_SCHEMA,
            local: listen_port,
            peer: peer.display(),
            target: target_port,
            state: rule.state,
        })
        .map_err(internal)
    }

    pub fn forward_list_json(&self) -> Result<serde_json::Value, IpcError> {
        let peers = self.db.list_peers().map_err(internal)?;
        let mut rules: Vec<RuleRecord> = self.rules.read().unwrap().values().cloned().collect();
        rules.sort_by_key(|r| r.listen_port);
        let forwards: Vec<ForwardInfo> = rules
            .iter()
            .map(|rule| {
                let peer = peers
                    .iter()
                    .find(|p| p.device_id == rule.peer_id)
                    .map(|p| p.display())
                    .unwrap_or_else(|| rule.peer_id.to_string());
                ForwardInfo {
                    local: rule.listen_port,
                    peer,
                    target: rule.target_port,
                    state: rule.state,
                    since: rule.created_at,
                    error: rule.last_error.clone(),
                }
            })
            .collect();
        serde_json::to_value(ForwardListResult {
            schema: lanfp_core::JSON_SCHEMA,
            forwards,
        })
        .map_err(internal)
    }

    pub async fn forward_remove_json(
        self: &Arc<Self>,
        local_port: u16,
    ) -> Result<serde_json::Value, IpcError> {
        let rule = self
            .rules
            .read()
            .unwrap()
            .get(&local_port)
            .cloned()
            .or_else(|| self.db.get_rule(local_port).ok().flatten());
        let Some(rule) = rule else {
            return Err(ipc_err(
                ExitCode::DeviceNotFound,
                format!("no forwarding rule on local port {local_port}"),
            ));
        };

        if let Some(listener) = self.listeners.lock().unwrap().remove(&local_port) {
            listener.cancel.cancel();
            listener.task.abort();
            let conns = listener.connections.lock().unwrap();
            for conn in conns.iter() {
                conn.abort();
            }
        }
        self.rules.write().unwrap().remove(&local_port);
        self.forward_ports.write().unwrap().remove(&local_port);
        if let Err(err) = self.db.delete_rule(local_port) {
            return Err(internal(err));
        }
        if let Some(handle) = self.sessions.get(rule.peer_id) {
            handle
                .send(ControlMessage::RuleRemove {
                    rule_id: rule.rule_id,
                })
                .await;
        }
        tracing::info!(
            "removed forwarding rule {local_port} -> {}",
            rule.target_port
        );
        serde_json::to_value(ForwardRemoveResult {
            schema: lanfp_core::JSON_SCHEMA,
            removed: local_port,
        })
        .map_err(internal)
    }
}

async fn map_bind_error(daemon: &Daemon, port: u16, err: &std::io::Error) -> IpcError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return ipc_err(
            ExitCode::Permission,
            format!("permission denied binding 127.0.0.1:{port}; use a port >= 1024"),
        );
    }
    // The cache may lag behind a listener that just appeared; refresh it so
    // the conflict report can name the process holding the port.
    let _ = daemon.inventory.refresh().await;
    let occupant = daemon
        .inventory
        .all()
        .into_iter()
        .find(|e| e.port == port)
        .map(|e| {
            let bind = e
                .bind
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!(
                " by {} (pid {}) on {}",
                e.process.as_deref().unwrap_or("-"),
                e.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                bind
            )
        })
        .unwrap_or_default();
    ipc_err(
        ExitCode::ListenConflict,
        format!("cannot listen on 127.0.0.1:{port}: {err}{occupant}"),
    )
}

fn spawn_rule_listener(daemon: &Arc<Daemon>, port: u16, listener: TcpListener) {
    let cancel = CancellationToken::new();
    let connections = Arc::new(Mutex::new(Vec::new()));
    let task_daemon = daemon.clone();
    let task_cancel = cancel.clone();
    let task_connections = connections.clone();
    let task = tokio::spawn(async move {
        rule_accept_loop(task_daemon, port, listener, task_cancel, task_connections).await;
    });
    daemon.listeners.lock().unwrap().insert(
        port,
        RuleListener {
            cancel,
            task,
            connections,
        },
    );
}

async fn rule_accept_loop(
    daemon: Arc<Daemon>,
    port: u16,
    listener: TcpListener,
    cancel: CancellationToken,
    connections: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
) {
    tracing::info!("listening on 127.0.0.1:{port} for forwarding");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => {
                    stream.set_nodelay(true).ok();
                    let daemon = daemon.clone();
                    let child = cancel.child_token();
                    let handle = tokio::spawn(async move {
                        daemon.handle_forward_connection(stream, port, child).await;
                    });
                    let mut conns = connections.lock().unwrap();
                    conns.retain(|h| !h.is_finished());
                    conns.push(handle);
                }
                Err(err) => {
                    tracing::warn!("accept on 127.0.0.1:{port} failed: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    tracing::info!("stopped listening on 127.0.0.1:{port}");
}

impl Daemon {
    async fn handle_forward_connection(
        self: Arc<Self>,
        stream: TcpStream,
        listen_port: u16,
        cancel: CancellationToken,
    ) {
        let rule = self.rules.read().unwrap().get(&listen_port).cloned();
        let Some(rule) = rule else {
            return;
        };
        if !rule.enabled || rule.state != RuleState::Active {
            tracing::debug!(
                "rejecting connection on {listen_port}: rule is {}",
                rule.state
            );
            return;
        }
        let Some(handle) = self.sessions.get(rule.peer_id) else {
            tracing::debug!("rejecting connection on {listen_port}: peer offline");
            return;
        };
        let (yamux_stream, permit) = match handle.open_stream().await {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!("cannot open data stream for rule {listen_port}: {err:#}");
                return;
            }
        };
        let mut yamux_stream = yamux_stream.compat();
        let header = DataHeader::new(4, rule.target_port, rule.rule_id).encode();
        if let Err(err) = yamux_stream.write_all(&header).await {
            tracing::warn!("cannot write data stream header: {err}");
            return;
        }
        let (up, down) =
            proxy_streams(stream, yamux_stream, self.config().idle_timeout(), cancel).await;
        tracing::debug!(
            "forwarded connection on {listen_port} finished ({} sent, {} received)",
            human_bytes(up),
            human_bytes(down)
        );
        drop(permit);
    }
}

/// Restore rules from the database and bind their listeners.
pub async fn start_restored_rules(daemon: &Arc<Daemon>) {
    let rules = match daemon.db.list_rules() {
        Ok(rules) => rules,
        Err(err) => {
            tracing::error!("cannot load forwarding rules: {err:#}");
            return;
        }
    };
    for mut rule in rules {
        rule.state = RuleState::PeerOffline;
        rule.last_error = None;
        let _ = daemon
            .db
            .update_rule_state(rule.listen_port, rule.state, None, now_ts());
        daemon
            .rules
            .write()
            .unwrap()
            .insert(rule.listen_port, rule.clone());
        match TcpListener::bind(("127.0.0.1", rule.listen_port)).await {
            Ok(listener) => {
                spawn_rule_listener(daemon, rule.listen_port, listener);
            }
            Err(err) => {
                let message = format!(
                    "cannot restore listener 127.0.0.1:{}: {err}",
                    rule.listen_port
                );
                tracing::warn!("{message}");
                rule.state = RuleState::ListenError;
                rule.last_error = Some(message.clone());
                let _ = daemon.db.update_rule_state(
                    rule.listen_port,
                    rule.state,
                    Some(&message),
                    now_ts(),
                );
                daemon.rules.write().unwrap().insert(rule.listen_port, rule);
            }
        }
    }
}

use tokio::io::AsyncWriteExt;
