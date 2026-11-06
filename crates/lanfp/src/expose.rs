//! Exposure policy: which local Native ports authorized devices may access.
//!
//! The policy is machine-wide. An empty whitelist means "all Native listening
//! ports are exposed"; once the whitelist has entries, only those ports are
//! exposed. Ports in the whitelist do not have to be listening yet.

use crate::daemon::{internal, ipc_err, Daemon};
use crate::db::Db;
use crate::util::now_ts;
use lanfp_core::error::ExitCode;
use lanfp_core::ipc::*;
use lanfp_core::protocol::{ControlMessage, ExposeMode, ExposedPort, ExposureView, PortInfo};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

pub struct ExposeManager {
    db: Arc<Db>,
    ports: RwLock<HashSet<u16>>,
}

impl ExposeManager {
    pub fn load(db: Arc<Db>) -> anyhow::Result<Self> {
        let ports: HashSet<u16> = db.list_expose()?.into_iter().collect();
        Ok(Self {
            db,
            ports: RwLock::new(ports),
        })
    }

    pub fn is_all(&self) -> bool {
        self.ports.read().unwrap().is_empty()
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ports.read().unwrap().contains(&port)
    }

    pub fn is_exposed(&self, port: u16) -> bool {
        self.is_all() || self.contains(port)
    }

    pub fn ports(&self) -> HashSet<u16> {
        self.ports.read().unwrap().clone()
    }

    /// Add ports and return how many were new.
    pub fn add(&self, ports: &[u16]) -> anyhow::Result<usize> {
        let inserted = self.db.add_expose(ports)?;
        let mut current = self.ports.write().unwrap();
        for port in ports {
            current.insert(*port);
        }
        Ok(inserted)
    }

    /// Remove ports and return how many existed.
    pub fn remove(&self, ports: &[u16]) -> anyhow::Result<usize> {
        let removed = self.db.remove_expose(ports)?;
        let mut current = self.ports.write().unwrap();
        for port in ports {
            current.remove(port);
        }
        Ok(removed)
    }
}

impl Daemon {
    /// The exposure view advertised to sessions and printed by `expose list`.
    pub fn exposure_view(&self) -> ExposureView {
        let native = self.inventory.native();
        if self.expose.is_all() {
            let ports = native
                .into_iter()
                .map(|p| ExposedPort {
                    port: p.port,
                    listening: true,
                    bind: p.bind,
                    process: p.process,
                    user: p.user,
                })
                .collect();
            return ExposureView {
                mode: ExposeMode::All,
                ports,
            };
        }

        let by_port: HashMap<u16, PortInfo> = native.into_iter().map(|p| (p.port, p)).collect();
        let mut configured: Vec<u16> = self.expose.ports().into_iter().collect();
        configured.sort_unstable();
        let ports = configured
            .into_iter()
            .map(|port| match by_port.get(&port) {
                Some(p) => ExposedPort {
                    port,
                    listening: true,
                    bind: p.bind.clone(),
                    process: p.process.clone(),
                    user: p.user.clone(),
                },
                None => ExposedPort {
                    port,
                    listening: false,
                    bind: Vec::new(),
                    process: None,
                    user: None,
                },
            })
            .collect();
        ExposureView {
            mode: ExposeMode::Whitelist,
            ports,
        }
    }

    /// The listening, exposed subset of the Native inventory. This is what
    /// sessions receive as `Inventory` and what rule states are based on.
    pub fn exposed_inventory(&self) -> Vec<PortInfo> {
        let native = self.inventory.native();
        if self.expose.is_all() {
            return native;
        }
        native
            .into_iter()
            .filter(|p| self.expose.is_exposed(p.port))
            .collect()
    }

    /// Re-broadcast Inventory + Exposure and reject inbound references whose
    /// target port is no longer exposed.
    pub async fn broadcast_exposure(self: &Arc<Self>) {
        let ports = self.exposed_inventory();
        let view = self.exposure_view();
        let seq = self.inventory.seq();
        for session in self.sessions.online() {
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
                })
                .await;
        }

        let now = now_ts();
        if let Ok(rows) = self.db.list_inbound() {
            for row in rows {
                if self.expose.is_exposed(row.target_port) {
                    continue;
                }
                if let Some(handle) = self.sessions.get(row.peer_id) {
                    handle
                        .send(ControlMessage::RuleRejected {
                            rule_id: row.rule_id,
                            reason: format!(
                                "port {} is not exposed by this device",
                                row.target_port
                            ),
                        })
                        .await;
                }
                let _ = self.db.delete_inbound(row.peer_id, row.rule_id);
            }
        }
        self.refresh_rule_states().await;
        tracing::debug!("exposure policy changed at {now}: {:?}", view.mode);
    }

    pub async fn expose_list_json(self: &Arc<Self>) -> Result<serde_json::Value, IpcError> {
        self.inventory.refresh().await.map_err(internal)?;
        let view = self.exposure_view();
        let peers = self.db.list_trust().map_err(internal)?;
        let mut inbound_by_port: HashMap<u16, Vec<ExposeInbound>> = HashMap::new();
        for row in self.db.list_inbound().map_err(internal)? {
            if !self.inventory.is_native(row.target_port)
                || !self.expose.is_exposed(row.target_port)
            {
                continue;
            }
            let peer = peers
                .iter()
                .find(|p| p.device_id == row.peer_id)
                .map(|p| self.display_peer(p))
                .unwrap_or_else(|| row.peer_id.to_string());
            inbound_by_port
                .entry(row.target_port)
                .or_default()
                .push(ExposeInbound {
                    id: row.peer_id,
                    peer,
                    peer_listen: row.peer_listen_port,
                });
        }
        let ports = view
            .ports
            .into_iter()
            .map(|p| ExposePortInfo {
                port: p.port,
                listening: p.listening,
                bind: p.bind,
                process: p.process,
                user: p.user,
                inbound: inbound_by_port.remove(&p.port).unwrap_or_default(),
            })
            .collect();
        serde_json::to_value(ExposeListResult {
            schema: lanfp_core::JSON_SCHEMA,
            mode: view.mode,
            ports,
        })
        .map_err(internal)
    }

    pub async fn expose_add_json(
        self: &Arc<Self>,
        ports: Vec<u16>,
    ) -> Result<serde_json::Value, IpcError> {
        let ports = normalize_ports(ports)?;
        self.validate_expose_ports(&ports)?;
        let before = self.expose.is_all();
        self.expose.add(&ports).map_err(internal)?;
        let mode = if self.expose.is_all() {
            ExposeMode::All
        } else {
            ExposeMode::Whitelist
        };
        let mode_changed = before && mode == ExposeMode::Whitelist;
        self.broadcast_exposure().await;
        serde_json::to_value(ExposeAddResult {
            schema: lanfp_core::JSON_SCHEMA,
            ports,
            mode,
            mode_changed,
        })
        .map_err(internal)
    }

    pub async fn expose_remove_json(
        self: &Arc<Self>,
        ports: Vec<u16>,
    ) -> Result<serde_json::Value, IpcError> {
        let ports = normalize_ports(ports)?;
        let current = self.expose.ports();
        if let Some(missing) = ports.iter().find(|p| !current.contains(p)) {
            return Err(ipc_err(
                ExitCode::DeviceNotFound,
                format!("port {missing} is not in the expose list"),
            ));
        }
        let before = self.expose.is_all();
        self.expose.remove(&ports).map_err(internal)?;
        let mode = if self.expose.is_all() {
            ExposeMode::All
        } else {
            ExposeMode::Whitelist
        };
        let mode_changed = !before && mode == ExposeMode::All;
        self.broadcast_exposure().await;
        serde_json::to_value(ExposeRemoveResult {
            schema: lanfp_core::JSON_SCHEMA,
            ports,
            mode,
            mode_changed,
        })
        .map_err(internal)
    }

    fn validate_expose_ports(&self, ports: &[u16]) -> Result<(), IpcError> {
        let forward_ports = self.forward_ports.read().unwrap().clone();
        for port in ports {
            if *port == self.agent_port {
                return Err(ipc_err(
                    ExitCode::Usage,
                    format!("port {port} is lanfp's agent port and cannot be exposed"),
                ));
            }
            if forward_ports.contains(port) {
                return Err(ipc_err(
                    ExitCode::Usage,
                    format!("port {port} is a local forwarding listener and cannot be exposed"),
                ));
            }
        }
        Ok(())
    }
}

fn normalize_ports(ports: Vec<u16>) -> Result<Vec<u16>, IpcError> {
    let mut out = Vec::new();
    for port in ports {
        if port == 0 {
            return Err(ipc_err(ExitCode::Usage, "port must not be 0"));
        }
        if !out.contains(&port) {
            out.push(port);
        }
    }
    if out.is_empty() {
        return Err(ipc_err(ExitCode::Usage, "at least one port is required"));
    }
    Ok(out)
}
