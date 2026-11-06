//! Exposure policy: which local Native ports authorized devices may access.
//!
//! The policy is machine-wide and configured through `agent.expose_ports` in
//! `config.toml` (single ports and ranges such as `3000-4000`). An empty
//! whitelist means "all Native listening ports are exposed"; once the
//! whitelist has entries, only ports covered by it are exposed. Ports inside
//! the whitelist do not have to be listening yet.

use crate::daemon::Daemon;
use crate::util::now_ts;
use lanpf_core::protocol::{
    ControlMessage, ExposeMode, ExposedPort, ExposureView, PortInfo, PortRange,
};
use std::sync::{Arc, RwLock};

/// A sorted, non-overlapping list of ranges parsed from `agent.expose_ports`.
#[derive(Debug, Default)]
pub struct ExposeManager {
    ranges: RwLock<Vec<PortRange>>,
}

impl ExposeManager {
    pub fn load(ranges: Vec<PortRange>) -> Self {
        Self {
            ranges: RwLock::new(ranges),
        }
    }

    /// Replace the whitelist after a configuration reload.
    pub fn set_ranges(&self, ranges: Vec<PortRange>) {
        *self.ranges.write().unwrap() = ranges;
    }

    pub fn is_all(&self) -> bool {
        self.ranges.read().unwrap().is_empty()
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ranges
            .read()
            .unwrap()
            .binary_search_by(|r| {
                if r.hi < port {
                    std::cmp::Ordering::Less
                } else if r.lo > port {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn is_exposed(&self, port: u16) -> bool {
        self.is_all() || self.contains(port)
    }

    pub fn expose_ranges(&self) -> Vec<PortRange> {
        self.ranges.read().unwrap().clone()
    }
}

impl Daemon {
    /// The exposure view advertised to sessions and rendered by `remote` on
    /// the consumer side.
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
                ranges: Vec::new(),
            };
        }

        let ranges = self.expose.expose_ranges();
        let ports = native
            .into_iter()
            .filter(|p| self.expose.contains(p.port))
            .map(|p| ExposedPort {
                port: p.port,
                listening: true,
                bind: p.bind,
                process: p.process,
                user: p.user,
            })
            .collect();
        ExposureView {
            mode: ExposeMode::Whitelist,
            ports,
            ranges,
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
            .filter(|p| self.expose.contains(p.port))
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
                    ranges: view.ranges.clone(),
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
}
