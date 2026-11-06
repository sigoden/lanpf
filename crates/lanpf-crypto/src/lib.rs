//! Device identity, TLS pinning, the one-way grant transcript and fingerprints.

pub mod grant;
pub mod identity;
pub mod tls;

pub use grant::{fingerprint, grant_transcript, identity_transcript};
pub use identity::{verify_signature, Identity};
pub use tls::{client_config, install_crypto_provider, server_config, ALPN};

/// Default TLS server name used by the client (the certificate is pinned by
/// public key, so the name is only a placeholder).
pub const TLS_SERVER_NAME: &str = "lanpf.invalid";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_identity_uses_the_project_name() {
        assert_eq!(std::str::from_utf8(ALPN).unwrap(), "lanpf/1");
        assert_eq!(TLS_SERVER_NAME, "lanpf.invalid");
    }
}
