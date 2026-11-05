//! Cross-platform TCP listening-port enumeration and classification.
//!
//! `netstat2` provides the socket table (address family, bind address, port,
//! state, owning PIDs); `sysinfo` resolves process name and user. Ports are
//! merged across IPv4/IPv6 so a dual-stack listener appears once.
//!
//! Blind spots (documented): sockets inside other network namespaces
//! (Docker containers, WSL2) and sockets whose owner is not visible to the
//! current user. In those cases the port is still listed and the ownership
//! columns show `-`.

use lanfp_core::protocol::{PortInfo, PortKind};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use sysinfo::{ProcessesToUpdate, System, UpdateKind, Users};

/// One merged listening socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerEntry {
    pub port: u16,
    pub bind: Vec<IpAddr>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub user: Option<String>,
}

impl ListenerEntry {
    pub fn to_port_info(&self) -> PortInfo {
        PortInfo {
            port: self.port,
            bind: self.bind.iter().map(|ip| ip.to_string()).collect(),
            pid: self.pid,
            process: self.process.clone(),
            user: self.user.clone(),
        }
    }
}

/// Enumerates TCP listeners and enriches them with process ownership.
pub struct Enumerator {
    sys: System,
    users: Option<Users>,
    users_age: u32,
}

impl Enumerator {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            sys: System::new()?,
            users: Users::new_with_refreshed_list().ok(),
            users_age: 0,
        })
    }

    /// Enumerate all TCP `LISTEN` sockets, merged by port and sorted by port.
    pub fn snapshot(&mut self) -> anyhow::Result<Vec<ListenerEntry>> {
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let sockets = get_sockets_info(af_flags, ProtocolFlags::TCP)?;

        let mut merged: BTreeMap<u16, ListenerEntry> = BTreeMap::new();
        let mut pids: BTreeSet<u32> = BTreeSet::new();

        for sock in sockets {
            let ProtocolSocketInfo::Tcp(tcp) = &sock.protocol_socket_info else {
                continue;
            };
            if tcp.state != TcpState::Listen || tcp.local_port == 0 {
                continue;
            }
            let pid = sock.associated_pids.iter().copied().find(|p| *p != 0);
            if let Some(pid) = pid {
                pids.insert(pid);
            }
            let entry = merged
                .entry(tcp.local_port)
                .or_insert_with(|| ListenerEntry {
                    port: tcp.local_port,
                    bind: Vec::new(),
                    pid: None,
                    process: None,
                    user: None,
                });
            if !entry.bind.contains(&tcp.local_addr) {
                entry.bind.push(tcp.local_addr);
            }
            if entry.pid.is_none() {
                entry.pid = pid;
            }
        }

        // Refresh only the processes that own listeners.
        let pid_list: Vec<sysinfo::Pid> = pids.iter().map(|p| sysinfo::Pid::from_u32(*p)).collect();
        if !pid_list.is_empty() {
            self.sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&pid_list),
                false,
                sysinfo::ProcessRefreshKind::nothing()
                    .with_user(UpdateKind::OnlyIfNotSet)
                    .without_tasks(),
            );
        }

        self.users_age += 1;
        if self.users_age >= 30 {
            self.users_age = 0;
            self.users = Users::new_with_refreshed_list().ok();
        }

        for entry in merged.values_mut() {
            if let Some(pid) = entry.pid {
                if let Some(process) = self.sys.process(sysinfo::Pid::from_u32(pid)) {
                    let name = process.name().to_string_lossy();
                    if !name.is_empty() {
                        entry.process = Some(name.into_owned());
                    }
                    if let Some(uid) = process.user_id() {
                        if let Some(user) = self
                            .users
                            .as_ref()
                            .and_then(|users| users.get_user_by_id(uid))
                        {
                            entry.user = Some(user.name().to_string());
                        }
                    }
                }
            }
            entry.bind.sort_by_key(|ip| match ip {
                IpAddr::V4(v4) => (0, v4.octets().to_vec()),
                IpAddr::V6(v6) => (1, v6.octets().to_vec()),
            });
        }

        Ok(merged.into_values().collect())
    }
}

/// Classify a listener relative to the running lanfp instance.
///
/// * agent port (or any listener owned by our PID that is not a rule) -> `Self`
/// * ports registered as forwarding listeners -> `Forward`
/// * everything else -> `Native`
pub fn classify(
    entry: &ListenerEntry,
    self_pid: u32,
    agent_port: u16,
    forward_ports: &HashSet<u16>,
) -> PortKind {
    if entry.port == agent_port {
        return PortKind::SelfPort;
    }
    if forward_ports.contains(&entry.port) {
        return PortKind::Forward;
    }
    if entry.pid == Some(self_pid) {
        return PortKind::SelfPort;
    }
    PortKind::Native
}

/// Return the entries that are neither lanfp's own agent listener nor a
/// forwarding listener.
pub fn native_entries(
    entries: &[ListenerEntry],
    self_pid: u32,
    agent_port: u16,
    forward_ports: &HashSet<u16>,
) -> Vec<ListenerEntry> {
    entries
        .iter()
        .filter(|e| classify(e, self_pid, agent_port, forward_ports) == PortKind::Native)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn finds_our_own_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut en = Enumerator::new().unwrap();
        let entries = en.snapshot().unwrap();
        let found = entries.iter().find(|e| e.port == port).expect("listener");
        assert!(found.bind.contains(&IpAddr::from([127, 0, 0, 1])));
        assert_eq!(found.pid, Some(std::process::id()));
        assert!(found.process.is_some(), "process name should be resolved");
    }

    #[test]
    fn classifies_ports() {
        let entry = |port, pid| ListenerEntry {
            port,
            bind: vec![IpAddr::from([127, 0, 0, 1])],
            pid,
            process: None,
            user: None,
        };
        let mut forwards = HashSet::new();
        forwards.insert(3000u16);
        assert_eq!(
            classify(&entry(47811, Some(1)), 1, 47811, &forwards),
            PortKind::SelfPort
        );
        assert_eq!(
            classify(&entry(3000, Some(2)), 1, 47811, &forwards),
            PortKind::Forward
        );
        assert_eq!(
            classify(&entry(8080, Some(2)), 1, 47811, &forwards),
            PortKind::Native
        );
        // Unknown ownership but a registered forward listener.
        assert_eq!(
            classify(&entry(3000, None), 1, 47811, &forwards),
            PortKind::Forward
        );
        // Other listener owned by lanfp itself (should not normally happen).
        assert_eq!(
            classify(&entry(9999, Some(1)), 1, 47811, &forwards),
            PortKind::SelfPort
        );
    }

    #[test]
    fn native_entries_filter() {
        let mk = |port, pid| ListenerEntry {
            port,
            bind: vec![IpAddr::from([0, 0, 0, 0])],
            pid,
            process: None,
            user: None,
        };
        let entries = vec![mk(47811, Some(1)), mk(3000, Some(1)), mk(8080, Some(2))];
        let mut forwards = HashSet::new();
        forwards.insert(3000u16);
        let native = native_entries(&entries, 1, 47811, &forwards);
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].port, 8080);
    }
}
