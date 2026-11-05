//! Peer identifiers (`<name>@<address>[:port]`) and device-name sanitising.
//!
//! The user-visible device identifier is always `<name>@<address>`; internal
//! identity uses UUIDs which are never displayed.

use crate::DEFAULT_AGENT_PORT;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Maximum length of a sanitised device name.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddr {
    /// Optional display name. `None` for a bare address such as `192.168.8.10`.
    pub name: Option<String>,
    /// Host part; IPv6 addresses are stored without brackets.
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerParseError {
    #[error("peer identifier is empty")]
    Empty,
    #[error("invalid port `{0}`")]
    InvalidPort(String),
    #[error("invalid peer address `{0}`")]
    InvalidAddress(String),
    #[error("missing host in `{0}`")]
    MissingHost(String),
    #[error("unterminated IPv6 address in `{0}`")]
    UnterminatedIpv6(String),
}

impl PeerAddr {
    /// Parse a peer identifier.
    ///
    /// Accepted forms:
    ///
    /// * `name@192.168.8.10`
    /// * `name@192.168.8.10:47811`
    /// * `name@[fe80::1]`
    /// * `name@[fe80::1]:47811`
    /// * `192.168.8.10`, `192.168.8.10:47811`
    /// * `[fe80::1]`, `[fe80::1]:47811`
    /// * `fe80::1` (bare IPv6 without a port)
    pub fn parse(input: &str) -> Result<PeerAddr, PeerParseError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(PeerParseError::Empty);
        }
        if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(PeerParseError::InvalidAddress(s.to_string()));
        }

        let (name, rest) = match s.rsplit_once('@') {
            Some((name, rest)) => {
                let name = name.trim();
                if name.is_empty() {
                    return Err(PeerParseError::InvalidAddress(s.to_string()));
                }
                (Some(sanitize_device_name(name)), rest)
            }
            None => (None, s),
        };
        if rest.is_empty() {
            return Err(PeerParseError::MissingHost(s.to_string()));
        }

        let (host, port) = if let Some(after_open) = rest.strip_prefix('[') {
            let end = after_open
                .find(']')
                .ok_or_else(|| PeerParseError::UnterminatedIpv6(s.to_string()))?;
            let host = &after_open[..end];
            if host.is_empty() {
                return Err(PeerParseError::MissingHost(s.to_string()));
            }
            let after = &after_open[end + 1..];
            let port = if after.is_empty() {
                DEFAULT_AGENT_PORT
            } else if let Some(p) = after.strip_prefix(':') {
                parse_port(p)?
            } else {
                return Err(PeerParseError::InvalidAddress(s.to_string()));
            };
            (host.to_string(), port)
        } else if rest.matches(':').count() == 1 {
            let (host, p) = rest.rsplit_once(':').expect("one colon");
            if host.is_empty() {
                return Err(PeerParseError::MissingHost(s.to_string()));
            }
            (host.to_string(), parse_port(p)?)
        } else {
            // Either a plain host name, an IPv4 address, or a bare IPv6
            // address without a port.
            (rest.to_string(), DEFAULT_AGENT_PORT)
        };

        if host.is_empty() {
            return Err(PeerParseError::MissingHost(s.to_string()));
        }
        // A bare IPv6 address is fine; anything else must not contain colons.
        if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(PeerParseError::InvalidAddress(s.to_string()));
        }
        Ok(PeerAddr { name, host, port })
    }

    /// Render the identifier, omitting the default agent port and bracketing
    /// IPv6 hosts.
    pub fn display(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let port = if self.port == DEFAULT_AGENT_PORT {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        match &self.name {
            Some(name) => format!("{}@{}{}", name, host, port),
            None => format!("{}{}", host, port),
        }
    }

    /// Render `host:port` suitable for `TcpStream::connect`.
    pub fn connect_addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolve the address into a `SocketAddr` when the host is a literal IP.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let ip: IpAddr = self.host.parse().ok()?;
        Some(SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

fn parse_port(raw: &str) -> Result<u16, PeerParseError> {
    let port: u16 = raw
        .parse()
        .map_err(|_| PeerParseError::InvalidPort(raw.to_string()))?;
    if port == 0 {
        return Err(PeerParseError::InvalidPort(raw.to_string()));
    }
    Ok(port)
}

/// Sanitise a device name so that it can be embedded in `<name>@<address>`.
///
/// `@`, whitespace and control characters become `-`; leading/trailing `-`
/// are trimmed and the result is capped at [`MAX_DEVICE_NAME_LEN`] bytes.
pub fn sanitize_device_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch == '@' || ch.is_whitespace() || ch.is_control() {
            out.push('-');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim_matches('-');
    let mut result: String = trimmed.chars().take(MAX_DEVICE_NAME_LEN).collect();
    if result.is_empty() {
        result.push_str("lanfp");
    }
    result
}

/// Format a device identifier from its parts.
pub fn format_peer(name: &str, host: &str, port: u16) -> String {
    PeerAddr {
        name: Some(sanitize_device_name(name)),
        host: host.to_string(),
        port,
    }
    .display()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PeerAddr {
        PeerAddr::parse(s).unwrap()
    }

    #[test]
    fn parses_named_ipv4_with_default_port() {
        let a = p("mac-mini@192.168.8.10");
        assert_eq!(a.name.as_deref(), Some("mac-mini"));
        assert_eq!(a.host, "192.168.8.10");
        assert_eq!(a.port, DEFAULT_AGENT_PORT);
        assert_eq!(a.display(), "mac-mini@192.168.8.10");
        assert_eq!(a.connect_addr(), "192.168.8.10:47811");
    }

    #[test]
    fn parses_named_ipv4_with_explicit_port() {
        let a = p("mac-mini@192.168.8.10:5000");
        assert_eq!(a.port, 5000);
        assert_eq!(a.display(), "mac-mini@192.168.8.10:5000");
    }

    #[test]
    fn parses_bare_address() {
        let a = p("192.168.8.10");
        assert_eq!(a.name, None);
        assert_eq!(a.display(), "192.168.8.10");
        let a = p("192.168.8.10:5000");
        assert_eq!(a.port, 5000);
        assert_eq!(a.display(), "192.168.8.10:5000");
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let a = p("mac-mini@[fe80::1]");
        assert_eq!(a.name.as_deref(), Some("mac-mini"));
        assert_eq!(a.host, "fe80::1");
        assert_eq!(a.port, DEFAULT_AGENT_PORT);
        assert_eq!(a.display(), "mac-mini@[fe80::1]");

        let a = p("mac-mini@[fe80::1]:5000");
        assert_eq!(a.port, 5000);
        assert_eq!(a.connect_addr(), "[fe80::1]:5000");
        assert_eq!(a.display(), "mac-mini@[fe80::1]:5000");
    }

    #[test]
    fn parses_bare_ipv6_without_port() {
        let a = p("fe80::1");
        assert_eq!(a.host, "fe80::1");
        assert_eq!(a.port, DEFAULT_AGENT_PORT);
        assert_eq!(a.display(), "[fe80::1]");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(PeerAddr::parse("").is_err());
        assert!(PeerAddr::parse("name@").is_err());
        assert!(PeerAddr::parse("host:0").is_err());
        assert!(PeerAddr::parse("host:99999").is_err());
        assert!(PeerAddr::parse("host:abc").is_err());
        assert!(PeerAddr::parse("[fe80::1").is_err());
        assert!(PeerAddr::parse("mac mini@1.2.3.4").is_err());
    }

    #[test]
    fn sanitizes_device_names() {
        assert_eq!(sanitize_device_name("my mac"), "my-mac");
        assert_eq!(sanitize_device_name("a@b"), "a-b");
        assert_eq!(sanitize_device_name("  "), "lanfp");
        assert_eq!(sanitize_device_name("@x@"), "x");
        assert!(sanitize_device_name(&"x".repeat(200)).len() <= MAX_DEVICE_NAME_LEN);
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "mac-mini@192.168.8.10",
            "mac-mini@192.168.8.10:5000",
            "mac-mini@[fe80::1]",
            "mac-mini@[fe80::1]:5000",
            "192.168.8.10",
            "192.168.8.10:5000",
        ] {
            let a = PeerAddr::parse(s).unwrap();
            let b = PeerAddr::parse(&a.display()).unwrap();
            assert_eq!(a, b, "round trip failed for {s}");
        }
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn display_parse_roundtrip(
            name in "[A-Za-z0-9-]{1,20}",
            a in 1u8..=254u8,
            b in 0u8..=255u8,
            c in 0u8..=255u8,
            d in 1u8..=254u8,
            port in 1u16..=65535u16,
        ) {
            let host = format!("{a}.{b}.{c}.{d}");
            let input = format!("{name}@{host}:{port}");
            let parsed = PeerAddr::parse(&input).unwrap();
            let reparsed = PeerAddr::parse(&parsed.display()).unwrap();
            prop_assert_eq!(parsed, reparsed);
        }

        #[test]
        fn bare_address_roundtrip(
            a in 1u8..=254u8,
            b in 0u8..=255u8,
            c in 0u8..=255u8,
            d in 1u8..=254u8,
            port in 1u16..=65535u16,
        ) {
            let input = format!("{a}.{b}.{c}.{d}:{port}");
            let parsed = PeerAddr::parse(&input).unwrap();
            prop_assert!(parsed.name.is_none());
            prop_assert_eq!(PeerAddr::parse(&parsed.display()).unwrap(), parsed);
        }
    }

    #[test]
    fn format_peer_uses_sanitized_name() {
        assert_eq!(format_peer("my mac", "10.0.0.2", 47811), "my-mac@10.0.0.2");
        assert_eq!(format_peer("x", "10.0.0.2", 5000), "x@10.0.0.2:5000");
    }
}
