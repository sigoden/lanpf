//! Shared types for lanpf: identifiers, protocol messages, IPC payloads and
//! framing helpers.
//!
//! The crate deliberately contains no I/O beyond the generic async framing
//! helpers, so both the daemon and the short-lived CLI client can depend on it.

pub mod error;
pub mod frame;
pub mod ipc;
pub mod peer;
pub mod protocol;

pub use error::ExitCode;
pub use peer::{
    format_peer, has_explicit_port, sanitize_device_name, short_id, short_ids, PeerAddr,
    PeerParseError,
};

/// Protocol version carried by `Hello`, the grant handshake and the
/// exposure/inventory control messages.
pub const PROTOCOL_VERSION: u16 = 2;

/// Version of the `--json` output envelope (`schema` field).
pub const JSON_SCHEMA: u32 = 2;

/// Default agent port. Also the port omitted from `PEER` display.
pub const DEFAULT_AGENT_PORT: u16 = 47811;

/// mDNS service type.
pub const MDNS_SERVICE_TYPE: &str = "_lanpf._tcp.local.";

/// Magic prefix for the one-way grant channel (sent right after connecting to
/// the agent port).
pub const GRANT_MAGIC: &[u8; 4] = b"FPG1";

/// Magic prefix for the read-only identity query used by a consumer that wants
/// to pin a server it was granted access to.
pub const IDENTITY_MAGIC: &[u8; 4] = b"FPID";

/// Magic prefix of the 25-byte data-stream header.
pub const DATA_MAGIC: &[u8; 4] = b"LAND";

/// Length of the data-stream header.
pub const DATA_HEADER_LEN: usize = 25;

/// Build number reported in `Hello` (compile-time).
pub fn build_id() -> String {
    format!("lanpf/{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_strings_use_the_project_name() {
        assert_eq!(MDNS_SERVICE_TYPE, "_lanpf._tcp.local.");
        assert!(
            build_id().starts_with("lanpf/"),
            "build id lost the project name: {}",
            build_id()
        );
    }
}
