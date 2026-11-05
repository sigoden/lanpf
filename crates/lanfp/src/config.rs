//! Configuration file (`config.toml`).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_AGENT_LISTEN: &str = "0.0.0.0:47811";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub agent: AgentConfig,
    pub discovery: DiscoveryConfig,
    pub inventory: InventoryConfig,
    pub pairing: PairingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub listen: String,
    pub max_streams: usize,
    pub idle_timeout_secs: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PairingConfig {
    pub code_ttl_secs: u64,
    pub max_attempts: u32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_AGENT_LISTEN.to_string(),
            max_streams: 256,
            idle_timeout_secs: 1800,
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

impl Default for PairingConfig {
    fn default() -> Self {
        Self {
            code_ttl_secs: 300,
            max_attempts: 5,
        }
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
        if self.agent.max_streams == 0 {
            bail!("agent.max_streams must be greater than zero");
        }
        if self.inventory.interval_ms < 100 {
            bail!("inventory.interval_ms must be at least 100");
        }
        if self.pairing.max_attempts == 0 {
            bail!("pairing.max_attempts must be greater than zero");
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

    pub fn pairing_ttl(&self) -> Duration {
        Duration::from_secs(self.pairing.code_ttl_secs.max(1))
    }
}

impl AgentConfig {
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen
            .parse()
            .with_context(|| format!("invalid agent.listen address `{}`", self.listen))
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
        assert_eq!(c.scan_timeout(), Duration::from_secs(3));
        assert_eq!(c.inventory_interval(), Duration::from_millis(2000));
        assert_eq!(c.pairing_ttl(), Duration::from_secs(300));
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
    fn rejects_bad_listen_address() {
        let mut c = Config::default();
        c.agent.listen = "not-an-address".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn round_trips_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let c = Config::default();
        c.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.agent.listen, c.agent.listen);
        assert_eq!(loaded.pairing.max_attempts, 5);
    }
}
