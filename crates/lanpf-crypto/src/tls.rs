//! TLS 1.3 configuration with Ed25519 public-key pinning.
//!
//! Both sides use self-signed certificates. Instead of a PKI, each side pins
//! the Ed25519 public key of its peer: the server accepts a client certificate
//! whose key is in the known-peer set, and the client requires the exact key of
//! the peer it intends to reach.

use crate::identity::Identity;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// ALPN protocol identifier for the lanpf session protocol.
pub const ALPN: &[u8] = b"lanpf/1";

/// Extract the Ed25519 public key from a DER-encoded X.509 certificate.
pub fn ed25519_pubkey_from_cert(cert_der: &[u8]) -> Result<[u8; 32]> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der).context("parse X.509 certificate")?;
    let spki = &cert.tbs_certificate.subject_pki;
    if spki.algorithm.algorithm != x509_parser::oid_registry::OID_SIG_ED25519 {
        bail!("certificate public key is not Ed25519");
    }
    let raw = spki.subject_public_key.data.as_ref();
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key has unexpected length {}", raw.len()))?;
    Ok(key)
}

/// Verify an Ed25519 signature using a raw public key.
fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(message, &Signature::from_bytes(&sig))
        .is_ok()
}

fn verify_handshake_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ));
    }
    let pubkey = ed25519_pubkey_from_cert(cert.as_ref())
        .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    if verify_ed25519(&pubkey, message, dss.signature()) {
        Ok(HandshakeSignatureValid::assertion())
    } else {
        Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
    }
}

/// Client-side verifier that pins one peer's Ed25519 key.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected_pubkey: [u8; 32],
}

impl PinnedServerVerifier {
    pub fn new(expected_pubkey: [u8; 32]) -> Self {
        Self { expected_pubkey }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match ed25519_pubkey_from_cert(end_entity.as_ref()) {
            Ok(pk) if pk == self.expected_pubkey => Ok(ServerCertVerified::assertion()),
            Ok(_) => Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            )),
            Err(_) => Err(TlsError::InvalidCertificate(CertificateError::BadEncoding)),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Server-side verifier that accepts any certificate whose Ed25519 key is in
/// the shared known-peer set.
#[derive(Debug)]
pub struct KnownPeersVerifier {
    known: Arc<RwLock<HashSet<[u8; 32]>>>,
}

impl KnownPeersVerifier {
    pub fn new(known: Arc<RwLock<HashSet<[u8; 32]>>>) -> Self {
        Self { known }
    }
}

impl ClientCertVerifier for KnownPeersVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let pk = ed25519_pubkey_from_cert(end_entity.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        let known = self
            .known
            .read()
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::UnknownIssuer))?;
        if known.contains(&pk) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn cert_chain(identity: &Identity) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from(identity.cert_der().to_vec())]
}

/// Build the TLS server configuration used by the agent listener.
pub fn server_config(
    identity: &Identity,
    known_peers: Arc<RwLock<HashSet<[u8; 32]>>>,
) -> Result<Arc<rustls::ServerConfig>> {
    let verifier = KnownPeersVerifier::new(known_peers);
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(cert_chain(identity), identity.private_key_der())
            .context("build TLS server config")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Build a TLS client configuration that pins `expected_pubkey`.
pub fn client_config(
    identity: &Identity,
    expected_pubkey: [u8; 32],
) -> Result<Arc<rustls::ClientConfig>> {
    let verifier = PinnedServerVerifier::new(expected_pubkey);
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(cert_chain(identity), identity.private_key_der())
            .context("build TLS client config")?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Install the ring crypto provider once per process.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ed25519_key_from_certificate() {
        let id = Identity::generate().unwrap();
        let pk = ed25519_pubkey_from_cert(id.cert_der()).unwrap();
        assert_eq!(pk, id.public_key_bytes());
    }

    #[test]
    fn rejects_non_certificate_bytes() {
        assert!(ed25519_pubkey_from_cert(b"not a cert").is_err());
    }

    #[test]
    fn known_peer_verifier_accepts_and_rejects() {
        let id = Identity::generate().unwrap();
        let known = Arc::new(RwLock::new(HashSet::new()));
        let verifier = KnownPeersVerifier::new(known.clone());
        let cert = CertificateDer::from(id.cert_der().to_vec());
        assert!(verifier
            .verify_client_cert(&cert, &[], UnixTime::now())
            .is_err());
        known.write().unwrap().insert(id.public_key_bytes());
        assert!(verifier
            .verify_client_cert(&cert, &[], UnixTime::now())
            .is_ok());
    }
}
