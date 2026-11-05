//! Identity, TLS pinning, SPAKE2 pairing and pairing payload encryption.

pub mod identity;
pub mod pair;
pub mod spake;
pub mod tls;

pub use identity::{verify_signature, Identity};
pub use spake::{generate_code, validate_code, SpakeSession};
pub use tls::{client_config, install_crypto_provider, server_config, ALPN};

/// Default TLS server name used by the client (the certificate is pinned by
/// public key, so the name is only a placeholder).
pub const TLS_SERVER_NAME: &str = "lanfp.invalid";
