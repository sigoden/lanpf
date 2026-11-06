//! mDNS discovery: advertise `_lanfp._tcp.local.` and maintain a cache of
//! discovered devices.
//!
//! If mDNS is blocked by a firewall, manual `lanfp peer grant <ip>[:port]` remains
//! the primary fallback.

use anyhow::{Context, Result};
use lanfp_core::{sanitize_device_name, DEFAULT_AGENT_PORT, MDNS_SERVICE_TYPE, PROTOCOL_VERSION};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// How often the advertised address set is re-checked. A change (Wi-Fi to
/// Ethernet, DHCP renewal, VPN flap) unregisters and re-registers the record,
/// which also withdraws the stale A/AAAA records on the peers.
const ADVERTISE_REFRESH: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub uuid: Uuid,
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    /// Public key published in the mDNS TXT record. Unauthenticated, but used
    /// to bind a live grant/identity proof to the advertised device.
    pub pubkey: Option<[u8; 32]>,
    pub version: u16,
    pub last_seen: Instant,
}

impl DiscoveredPeer {
    /// Preferred address: IPv4 before IPv6, non-loopback first.
    pub fn best_addr(&self) -> Option<SocketAddr> {
        let pick = self
            .addresses
            .iter()
            .find(|ip| ip.is_ipv4() && !ip.is_loopback())
            .or_else(|| self.addresses.iter().find(|ip| ip.is_ipv4()))
            .or_else(|| self.addresses.iter().find(|ip| !ip.is_loopback()))
            .or_else(|| self.addresses.first())?;
        Some(SocketAddr::new(*pick, self.port))
    }

    pub fn display(&self) -> String {
        match self.best_addr() {
            Some(addr) => lanfp_core::format_peer(&self.name, &addr.ip().to_string(), self.port),
            None => format!("{}@?", self.name),
        }
    }
}

struct Advertised {
    fullname: String,
    addrs: Vec<IpAddr>,
}

pub struct Discovery {
    enabled: bool,
    cache: Arc<RwLock<HashMap<Uuid, DiscoveredPeer>>>,
    fullname_index: Arc<RwLock<HashMap<String, Uuid>>>,
    daemon: Mutex<Option<ServiceDaemon>>,
    self_uuid: Uuid,
    self_pubkey: [u8; 32],
    /// Address the agent listener is bound to; mDNS must only advertise
    /// addresses that this socket can actually answer on.
    agent_ip: IpAddr,
    /// What is currently advertised, used to detect address changes.
    advertised: Mutex<Option<Advertised>>,
    stop: Mutex<bool>,
    stop_cv: Condvar,
}

impl Discovery {
    pub fn new(
        self_uuid: Uuid,
        self_pubkey: [u8; 32],
        enabled: bool,
        agent_ip: IpAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            cache: Arc::new(RwLock::new(HashMap::new())),
            fullname_index: Arc::new(RwLock::new(HashMap::new())),
            daemon: Mutex::new(None),
            self_uuid,
            self_pubkey,
            agent_ip,
            advertised: Mutex::new(None),
            stop: Mutex::new(false),
            stop_cv: Condvar::new(),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Start advertising and browsing. Returns an error only for fatal setup
    /// problems; a missing non-loopback address simply disables advertising
    /// until one appears.
    pub fn start(self: &Arc<Self>, name: &str, agent_port: u16) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let daemon = ServiceDaemon::new().context("start mDNS daemon")?;

        let addresses = local_advertise_addresses(self.agent_ip);
        if addresses.is_empty() {
            tracing::warn!(
                "no non-loopback address found; mDNS advertising will start once one appears"
            );
        } else {
            match self.service_info(name, agent_port, &addresses) {
                Ok(info) => {
                    let fullname = info.get_fullname().to_string();
                    match daemon.register(info) {
                        Ok(()) => {
                            tracing::info!(
                                "advertising {} on port {} ({} address(es))",
                                MDNS_SERVICE_TYPE,
                                agent_port,
                                addresses.len()
                            );
                            *self.advertised.lock().unwrap() = Some(Advertised {
                                fullname,
                                addrs: addresses.clone(),
                            });
                        }
                        Err(err) => tracing::warn!("cannot register mDNS service: {err}"),
                    }
                }
                Err(err) => tracing::warn!("cannot build mDNS service info: {err:#}"),
            }
        }

        let receiver = daemon
            .browse(MDNS_SERVICE_TYPE)
            .context("browse mDNS service")?;
        let cache = self.cache.clone();
        let index = self.fullname_index.clone();
        let self_uuid = self.self_uuid;
        std::thread::Builder::new()
            .name("lanfp-mdns".into())
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    apply_event(&cache, &index, self_uuid, event);
                }
            })
            .context("spawn mDNS thread")?;

        *self.daemon.lock().unwrap() = Some(daemon);

        // Re-advertise after network changes: the address set is re-read on a
        // fixed interval, and re-registration withdraws the stale records.
        let discovery = self.clone();
        let device_name = name.to_string();
        std::thread::Builder::new()
            .name("lanfp-mdns-adv".into())
            .spawn(move || discovery.maintain_advertisement(&device_name, agent_port))
            .context("spawn mDNS advertisement thread")?;

        Ok(())
    }

    pub fn shutdown(&self) {
        *self.stop.lock().unwrap() = true;
        self.stop_cv.notify_all();
        if let Some(daemon) = self.daemon.lock().unwrap().take() {
            let _ = daemon.shutdown();
        }
    }

    fn maintain_advertisement(&self, name: &str, agent_port: u16) {
        loop {
            let stop = self.stop.lock().unwrap();
            let (stop, _) = self
                .stop_cv
                .wait_timeout(stop, ADVERTISE_REFRESH)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *stop {
                return;
            }
            drop(stop);
            self.refresh_advertisement(name, agent_port);
        }
    }

    fn refresh_advertisement(&self, name: &str, agent_port: u16) {
        if *self.stop.lock().unwrap() {
            return;
        }
        let addrs = local_advertise_addresses(self.agent_ip);
        {
            let advertised = self.advertised.lock().unwrap();
            let unchanged = match advertised.as_ref() {
                Some(current) => current.addrs == addrs,
                None => addrs.is_empty(),
            };
            if unchanged {
                return;
            }
        }

        let Some(daemon) = self.daemon.lock().unwrap().clone() else {
            return;
        };
        if let Some(old) = self.advertised.lock().unwrap().take() {
            if let Ok(status) = daemon.unregister(&old.fullname) {
                let _ = status.recv_timeout(Duration::from_secs(2));
            }
        }
        if addrs.is_empty() {
            tracing::warn!("no non-loopback address left; mDNS advertising stopped");
            return;
        }

        let info = match self.service_info(name, agent_port, &addrs) {
            Ok(info) => info,
            Err(err) => {
                tracing::warn!("cannot rebuild mDNS service info: {err:#}");
                return;
            }
        };
        let fullname = info.get_fullname().to_string();
        match daemon.register(info) {
            Ok(()) => {
                let shown: Vec<String> = addrs.iter().map(|ip| ip.to_string()).collect();
                tracing::info!(
                    "mDNS address changed; re-advertising on {}",
                    shown.join(", ")
                );
                *self.advertised.lock().unwrap() = Some(Advertised { fullname, addrs });
            }
            Err(err) => tracing::warn!("cannot re-register mDNS service: {err}"),
        }
    }

    fn service_info(
        &self,
        name: &str,
        agent_port: u16,
        addresses: &[IpAddr],
    ) -> Result<ServiceInfo> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "lanfp".into());
        let host_name = format!(
            "{}.local.",
            hostname.trim_end_matches('.').trim_end_matches(".local")
        );
        let instance = format!(
            "{}-{}",
            sanitize_device_name(name),
            &self.self_uuid.simple().to_string()[..8]
        );
        let id = self.self_uuid.to_string();
        let port = agent_port.to_string();
        let version = PROTOCOL_VERSION.to_string();
        let pubkey = hex::encode(self.self_pubkey);
        let props = [
            ("id", id.as_str()),
            ("nm", name),
            ("v", version.as_str()),
            ("p", port.as_str()),
            ("pk", pubkey.as_str()),
        ];
        ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &instance,
            &host_name,
            addresses,
            agent_port,
            &props[..],
        )
        .context("build mDNS service info")
    }

    pub fn snapshot(&self) -> Vec<DiscoveredPeer> {
        let mut peers: Vec<DiscoveredPeer> = self.cache.read().unwrap().values().cloned().collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name).then(a.uuid.cmp(&b.uuid)));
        peers
    }

    /// Drop a cached peer, e.g. after `lanfp peer set-address` so the explicit
    /// address wins over a stale mDNS result.
    pub fn forget(&self, uuid: Uuid) {
        self.cache.write().unwrap().remove(&uuid);
        self.fullname_index
            .write()
            .unwrap()
            .retain(|_, cached| *cached != uuid);
    }

    /// Freshest mDNS address of a peer, if it was resolved within `max_age`.
    pub fn fresh_addr(&self, uuid: Uuid, max_age: Duration) -> Option<SocketAddr> {
        self.cache
            .read()
            .unwrap()
            .get(&uuid)
            .filter(|peer| peer.last_seen.elapsed() < max_age)
            .and_then(|peer| peer.best_addr())
    }

    /// Run a fresh browse for `timeout` and return the merged cache.
    pub async fn scan(&self, timeout: Duration) -> Vec<DiscoveredPeer> {
        if !self.enabled {
            return self.snapshot();
        }
        let daemon = self.daemon.lock().unwrap().clone();
        let Some(daemon) = daemon else {
            return self.snapshot();
        };
        let cache = self.cache.clone();
        let index = self.fullname_index.clone();
        let self_uuid = self.self_uuid;
        let scan = tokio::task::spawn_blocking(move || {
            if let Ok(receiver) = daemon.browse(MDNS_SERVICE_TYPE) {
                let deadline = Instant::now() + timeout;
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match receiver.recv_timeout(remaining) {
                        Ok(event) => apply_event(&cache, &index, self_uuid, event),
                        Err(_) => break,
                    }
                }
            }
        });
        let _ = tokio::time::timeout(timeout + Duration::from_secs(1), scan).await;
        self.snapshot()
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        if let Some(daemon) = self.daemon.get_mut().unwrap().take() {
            let _ = daemon.shutdown();
        }
    }
}

fn apply_event(
    cache: &RwLock<HashMap<Uuid, DiscoveredPeer>>,
    index: &RwLock<HashMap<String, Uuid>>,
    self_uuid: Uuid,
    event: ServiceEvent,
) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            let Some(id) = info.get_property_val_str("id") else {
                return;
            };
            let Ok(uuid) = Uuid::parse_str(id) else {
                return;
            };
            if uuid == self_uuid {
                return;
            }
            let name = info
                .get_property_val_str("nm")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    info.get_fullname()
                        .split('.')
                        .next()
                        .unwrap_or("lanfp")
                        .to_string()
                });
            let port = info
                .get_property_val_str("p")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(DEFAULT_AGENT_PORT);
            let version = info
                .get_property_val_str("v")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(1);
            let pubkey = parse_pubkey(info.get_property_val_str("pk"));
            let addresses: Vec<IpAddr> = info
                .get_addresses()
                .iter()
                .map(|a| a.to_ip_addr())
                .collect();
            if addresses.is_empty() {
                return;
            }
            let fullname = info.get_fullname().to_string();
            let mut cache = cache.write().unwrap();
            match cache.get_mut(&uuid) {
                Some(existing) => {
                    // A resolver may report the A and AAAA records in separate
                    // events; merge instead of replacing so a later IPv6-only
                    // event does not discard the reachable IPv4 address.
                    merge_addresses(&mut existing.addresses, addresses);
                    existing.name = sanitize_device_name(&name);
                    existing.port = port;
                    existing.pubkey = pubkey;
                    existing.version = version;
                    existing.last_seen = Instant::now();
                }
                None => {
                    cache.insert(
                        uuid,
                        DiscoveredPeer {
                            uuid,
                            name: sanitize_device_name(&name),
                            addresses,
                            port,
                            pubkey,
                            version,
                            last_seen: Instant::now(),
                        },
                    );
                }
            }
            drop(cache);
            index.write().unwrap().insert(fullname, uuid);
        }
        ServiceEvent::ServiceRemoved(_ty, fullname) => {
            if let Some(uuid) = index.write().unwrap().remove(&fullname) {
                cache.write().unwrap().remove(&uuid);
            }
        }
        _ => {}
    }
}

fn parse_pubkey(raw: Option<&str>) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw?).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

fn local_advertise_addresses(agent_ip: IpAddr) -> Vec<IpAddr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out: Vec<IpAddr> = interfaces
        .into_iter()
        .map(|iface| iface.addr.ip())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .filter(|ip| match ip {
            IpAddr::V6(v6) => !v6.is_unicast_link_local(),
            IpAddr::V4(_) => true,
        })
        .collect();
    out = filter_advertise_addresses(out, agent_ip);
    out.sort();
    out.dedup();
    out
}

/// Keep only addresses the agent listener can answer on. Binding `0.0.0.0`
/// opens an IPv4-only socket, so advertising AAAA records would send peers to
/// an address that cannot connect; a specific bind address advertises itself.
fn filter_advertise_addresses(addrs: Vec<IpAddr>, agent_ip: IpAddr) -> Vec<IpAddr> {
    match agent_ip {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            addrs.into_iter().filter(IpAddr::is_ipv4).collect()
        }
        IpAddr::V4(ip) => vec![IpAddr::V4(ip)],
        IpAddr::V6(ip) if ip.is_unspecified() => addrs,
        IpAddr::V6(ip) => vec![IpAddr::V6(ip)],
    }
}

fn merge_addresses(existing: &mut Vec<IpAddr>, incoming: Vec<IpAddr>) {
    for addr in incoming {
        if !existing.contains(&addr) {
            existing.push(addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_wildcard_advertises_ipv4_only() {
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 8, 14)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let kept = filter_advertise_addresses(addrs, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(kept, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 8, 14))]);
    }

    #[test]
    fn specific_bind_advertises_exactly_that_address() {
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 8, 14)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let kept = filter_advertise_addresses(addrs, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(kept, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]);
    }

    #[test]
    fn ipv6_wildcard_keeps_both_families() {
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 8, 14)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let kept = filter_advertise_addresses(addrs.clone(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(kept, addrs);
    }

    #[test]
    fn merge_keeps_earlier_families_without_duplicates() {
        let mut existing = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 8, 8))];
        merge_addresses(
            &mut existing,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 8, 8)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        );
        assert_eq!(
            existing,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 8, 8)),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
    }

    #[test]
    fn parses_only_thirty_two_byte_hex_keys() {
        let key = [7u8; 32];
        assert_eq!(parse_pubkey(Some(&hex::encode(key))), Some(key));
        assert_eq!(parse_pubkey(Some("not-hex")), None);
        assert_eq!(parse_pubkey(Some("00")), None);
        assert_eq!(parse_pubkey(None), None);
    }
}
