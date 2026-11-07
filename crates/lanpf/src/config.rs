//! Configuration file (`config.toml`).

use anyhow::{bail, Context, Result};
use lanpf_core::protocol::PortRange;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_AGENT_LISTEN: &str = "0.0.0.0:47811";

/// A yamux connection carries the control stream plus the data streams. yamux
/// rejects the 513th stream with `TooManyStreams`, which lanpf treats as a
/// connection error, so keep one slot for the control stream.
pub const MAX_STREAMS_PER_SESSION: usize = 511;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub agent: AgentConfig,
    pub discovery: DiscoveryConfig,
    pub inventory: InventoryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub listen: String,
    pub max_streams: usize,
    pub max_new_streams_per_sec: u32,
    pub idle_timeout_secs: u64,
    /// Whitelist of ports forwarded peers may reach on this machine: single
    /// ports (`"80"`) and inclusive ranges (`"3000-4000"`). Empty or missing
    /// exposes every Native listening port.
    pub expose_ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    pub mdns: bool,
    pub scan_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryConfig {
    pub interval_ms: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_AGENT_LISTEN.to_string(),
            max_streams: 256,
            max_new_streams_per_sec: 100,
            idle_timeout_secs: 1800,
            expose_ports: Vec::new(),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mdns: true,
            scan_timeout_secs: 3,
        }
    }
}

impl Default for InventoryConfig {
    fn default() -> Self {
        Self { interval_ms: 2000 }
    }
}

impl Config {
    /// Load the configuration, creating a default file when it is missing.
    pub fn load_or_create(path: &Path) -> Result<Config> {
        if !path.exists() {
            let config = Config::default();
            config.save(path)?;
            return Ok(config);
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self).context("serialize config")?;
        std::fs::write(path, text).with_context(|| format!("write config {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.agent.listen_addr()?;
        self.agent.expose_ranges()?;
        if self.agent.max_streams == 0 {
            bail!("agent.max_streams must be greater than zero");
        }
        if self.agent.max_streams > MAX_STREAMS_PER_SESSION {
            bail!(
                "agent.max_streams must be at most {MAX_STREAMS_PER_SESSION} (one yamux stream slot is reserved for the control stream)"
            );
        }
        if self.agent.max_new_streams_per_sec == 0 {
            bail!("agent.max_new_streams_per_sec must be greater than zero");
        }
        if self.inventory.interval_ms < 100 {
            bail!("inventory.interval_ms must be at least 100");
        }
        Ok(())
    }

    pub fn scan_timeout(&self) -> Duration {
        Duration::from_secs(self.discovery.scan_timeout_secs.max(1))
    }

    pub fn inventory_interval(&self) -> Duration {
        Duration::from_millis(self.inventory.interval_ms.max(100))
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.agent.idle_timeout_secs.max(1))
    }
}

impl AgentConfig {
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen
            .parse()
            .with_context(|| format!("invalid agent.listen address `{}`", self.listen))
    }

    /// Parse and normalize `expose_ports` into sorted, non-overlapping ranges.
    pub fn expose_ranges(&self) -> Result<Vec<PortRange>> {
        let mut ranges: Vec<PortRange> = Vec::new();
        for item in &self.expose_ports {
            let item = item.trim();
            if item.is_empty() {
                bail!("agent.expose_ports must not contain empty entries");
            }
            let range =
                match item.split_once('-') {
                    Some((lo, hi)) => {
                        let lo: u16 = lo.trim().parse().with_context(|| {
                            format!("invalid agent.expose_ports entry `{item}`")
                        })?;
                        let hi: u16 = hi.trim().parse().with_context(|| {
                            format!("invalid agent.expose_ports entry `{item}`")
                        })?;
                        if lo > hi {
                            bail!("agent.expose_ports entry `{item}` has a reversed port range");
                        }
                        PortRange::new(lo, hi)
                    }
                    None => {
                        let port: u16 = item.parse().with_context(|| {
                            format!("invalid agent.expose_ports entry `{item}`")
                        })?;
                        PortRange::new(port, port)
                    }
                };
            if range.lo == 0 {
                bail!("agent.expose_ports entry `{item}`: port 0 is not a valid expose target");
            }
            ranges.push(range);
        }
        ranges.sort_unstable();
        let mut merged: Vec<PortRange> = Vec::new();
        for range in ranges {
            match merged.last_mut() {
                // Overlapping or directly adjacent ranges are folded together.
                Some(last) if range.lo <= last.hi.saturating_add(1) => {
                    if range.hi > last.hi {
                        last.hi = range.hi;
                    }
                }
                _ => merged.push(range),
            }
        }
        Ok(merged)
    }
}

/// Parse a human duration such as `3s`, `500ms`, `2m` or `1h`.
pub fn parse_duration(input: &str) -> Result<Duration> {
    let s = input.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    let (num, unit) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1e-3)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1.0)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60.0)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3600.0)
    } else {
        (s, 1.0)
    };
    let value: f64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid duration `{input}`"))?;
    if !value.is_finite() || value < 0.0 {
        bail!("invalid duration `{input}`");
    }
    Ok(Duration::from_secs_f64(value * unit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        c.validate().unwrap();
        assert_eq!(c.agent.listen, "0.0.0.0:47811");
        assert_eq!(c.agent.max_streams, 256);
        assert_eq!(c.agent.max_new_streams_per_sec, 100);
        assert_eq!(c.scan_timeout(), Duration::from_secs(3));
        assert_eq!(c.inventory_interval(), Duration::from_millis(2000));
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("3").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn ignores_legacy_pairing_section() {
        let c: Config =
            toml::from_str("[agent]\nlisten = \"127.0.0.1:1\"\n[pairing]\ncode_ttl_secs = 1\n")
                .unwrap();
        assert_eq!(c.agent.listen, "127.0.0.1:1");
    }

    #[test]
    fn rejects_bad_listen_address() {
        let mut c = Config::default();
        c.agent.listen = "not-an-address".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_out_of_range_stream_limits() {
        let mut c = Config::default();
        c.agent.max_streams = 0;
        assert!(c.validate().is_err());

        c.agent.max_streams = MAX_STREAMS_PER_SESSION + 1;
        assert!(c.validate().is_err());

        c.agent.max_streams = MAX_STREAMS_PER_SESSION;
        c.agent.max_new_streams_per_sec = 0;
        assert!(c.validate().is_err());

        c.agent.max_new_streams_per_sec = 100;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn parses_expose_ports_ranges() {
        let mut c = Config::default();
        c.agent.expose_ports = vec![
            "80".into(),
            "3000-4000".into(),
            "1024".into(),
            "3002 - 3999".into(),
            "2000-5000".into(),
        ];
        let ranges = c.agent.expose_ranges().unwrap();
        // Single ports, trimmed ranges, overlaps and adjacency merged.
        assert_eq!(
            ranges,
            vec![
                PortRange::new(80, 80),
                PortRange::new(1024, 1024),
                PortRange::new(2000, 5000),
            ]
        );
    }

    #[test]
    fn default_expose_ports_is_empty() {
        let c = Config::default();
        assert!(c.agent.expose_ranges().unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_expose_ports() {
        for bad in [
            ["0"],
            ["3000-2000"],
            ["abc"],
            ["80.5"],
            [""],
            ["  "],
            ["-"],
            ["3000-x"],
            ["3000-"],
            ["65536"],
            ["3000-4000-5000"],
        ] {
            let mut c = Config::default();
            c.agent.expose_ports = bad.iter().map(|s| s.to_string()).collect();
            assert!(
                c.agent.expose_ranges().is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn maximum_range_is_allowed() {
        let mut c = Config::default();
        c.agent.expose_ports = vec!["1024-65535".into()];
        assert_eq!(
            c.agent.expose_ranges().unwrap(),
            vec![PortRange::new(1024, 65535)]
        );
    }

    #[test]
    fn round_trips_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let c = Config::default();
        c.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.agent.listen, c.agent.listen);
        assert_eq!(
            loaded.discovery.scan_timeout_secs,
            c.discovery.scan_timeout_secs
        );
    }
}
