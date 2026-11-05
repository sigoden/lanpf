//! Shared types for lanfp: identifiers, protocol messages, IPC payloads and
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

/// Protocol version carried by `Hello` and the pairing handshake.
pub const PROTOCOL_VERSION: u16 = 1;

/// Version of the `--json` output envelope (`schema` field).
pub const JSON_SCHEMA: u32 = 1;

/// Default agent port. Also the port omitted from `PEER` display.
pub const DEFAULT_AGENT_PORT: u16 = 47811;

/// mDNS service type.
pub const MDNS_SERVICE_TYPE: &str = "_lanfp._tcp.local.";

/// Magic prefix for the pairing channel (sent right after connecting to the
/// agent port).
pub const PAIR_MAGIC: &[u8; 4] = b"FPP1";

/// Magic prefix of the 25-byte data-stream header.
pub const DATA_MAGIC: &[u8; 4] = b"LAND";

/// Length of the data-stream header.
pub const DATA_HEADER_LEN: usize = 25;

/// Build number reported in `Hello` (compile-time).
pub fn build_id() -> String {
    format!("lanfp/{}", env!("CARGO_PKG_VERSION"))
}
