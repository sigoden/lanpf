//! Background port-inventory polling and the current Native port cache.

use anyhow::Result;
use lanfp_core::protocol::PortInfo;
use lanfp_core::protocol::PortKind;
use lanfp_inventory::{classify, Enumerator, ListenerEntry};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

pub struct InventoryService {
    enumerator: Mutex<Enumerator>,
    all: RwLock<Vec<ListenerEntry>>,
    native: RwLock<Vec<PortInfo>>,
    seq: AtomicU64,
    updates: broadcast::Sender<Arc<Vec<PortInfo>>>,
    self_pid: u32,
    agent_port: u16,
    forward_ports: Arc<RwLock<HashSet<u16>>>,
}

impl InventoryService {
    pub fn new(agent_port: u16, forward_ports: Arc<RwLock<HashSet<u16>>>) -> Result<Arc<Self>> {
        let (updates, _) = broadcast::channel(32);
        Ok(Arc::new(Self {
            enumerator: Mutex::new(Enumerator::new()?),
            all: RwLock::new(Vec::new()),
            native: RwLock::new(Vec::new()),
            seq: AtomicU64::new(0),
            updates,
            self_pid: std::process::id(),
            agent_port,
            forward_ports,
        }))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Vec<PortInfo>>> {
        self.updates.subscribe()
    }

    pub fn native(&self) -> Vec<PortInfo> {
        self.native.read().unwrap().clone()
    }

    pub fn is_native(&self, port: u16) -> bool {
        self.native.read().unwrap().iter().any(|p| p.port == port)
    }

    pub fn all(&self) -> Vec<ListenerEntry> {
        self.all.read().unwrap().clone()
    }

    /// Refresh the snapshot, update caches and notify subscribers on change.
    pub async fn refresh(self: &Arc<Self>) -> Result<Vec<ListenerEntry>> {
        let this = self.clone();
        let entries = tokio::task::spawn_blocking(move || {
            let mut en = this.enumerator.lock().unwrap_or_else(|e| e.into_inner());
            en.snapshot()
        })
        .await
        .map_err(|e| anyhow::anyhow!("inventory task failed: {e}"))??;
        self.apply(entries);
        Ok(self.all())
    }

    fn apply(&self, entries: Vec<ListenerEntry>) {
        let forward_ports = self.forward_ports.read().unwrap().clone();
        let native: Vec<PortInfo> = entries
            .iter()
            .filter(|e| {
                classify(e, self.self_pid, self.agent_port, &forward_ports) == PortKind::Native
            })
            .map(|e| e.to_port_info())
            .collect();

        let changed = {
            let current = self.native.read().unwrap();
            *current != native
        };
        *self.all.write().unwrap() = entries;
        if changed {
            *self.native.write().unwrap() = native.clone();
            self.seq.fetch_add(1, Ordering::Relaxed);
            let _ = self.updates.send(Arc::new(native));
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}
