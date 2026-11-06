//! Device identity: a long-lived Ed25519 key pair and a self-signed
//! certificate carrying the same key.
//!
//! The certificate is regenerated whenever the key is loaded without a stored
//! certificate; peers pin the *public key*, not the certificate, so
//! regeneration is harmless.

use anyhow::{bail, Context, Result};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, PKCS_ED25519};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const KEY_FILE: &str = "identity.key";
pub const CERT_FILE: &str = "identity.crt";

/// Ed25519 identity used for TLS, grant and identity-query signatures.
pub struct Identity {
    signing: SigningKey,
    key_der: Vec<u8>,
    cert_der: Vec<u8>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("pubkey", &hex::encode(self.public_key_bytes()))
            .finish()
    }
}

impl Identity {
    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        let signing = SigningKey::generate(&mut OsRng);
        let key_der = signing
            .to_pkcs8_der()
            .context("encode Ed25519 key as PKCS#8")?
            .as_bytes()
            .to_vec();
        Self::from_key_der(&key_der)
    }

    /// Rebuild an identity from a PKCS#8 key, generating a new certificate.
    pub fn from_key_der(key_der: &[u8]) -> Result<Self> {
        let signing = SigningKey::from_pkcs8_der(key_der).context("parse PKCS#8 Ed25519 key")?;
        let cert_der = make_certificate(key_der)?;
        Ok(Self {
            signing,
            key_der: key_der.to_vec(),
            cert_der,
        })
    }

    /// Rebuild an identity from a key and a previously issued certificate.
    /// The certificate must carry the same public key.
    pub fn from_key_and_cert(key_der: &[u8], cert_der: &[u8]) -> Result<Self> {
        let signing = SigningKey::from_pkcs8_der(key_der).context("parse PKCS#8 Ed25519 key")?;
        let expected = signing.verifying_key().to_bytes();
        let actual =
            crate::tls::ed25519_pubkey_from_cert(cert_der).context("parse stored certificate")?;
        if expected != actual {
            bail!("stored certificate does not match the stored private key");
        }
        Ok(Self {
            signing,
            key_der: key_der.to_vec(),
            cert_der: cert_der.to_vec(),
        })
    }

    /// Load `<dir>/identity.key` and `<dir>/identity.crt`, creating them on
    /// first use. The private key is written with mode 0600 on Unix.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        let key_path = dir.join(KEY_FILE);
        let cert_path = dir.join(CERT_FILE);
        if key_path.exists() {
            let key_der =
                fs::read(&key_path).with_context(|| format!("read {}", key_path.display()))?;
            if cert_path.exists() {
                let cert_der = fs::read(&cert_path)
                    .with_context(|| format!("read {}", cert_path.display()))?;
                match Self::from_key_and_cert(&key_der, &cert_der) {
                    Ok(identity) => return Ok(identity),
                    Err(err) => {
                        tracing::warn!(
                            "stored identity certificate is unusable ({err}); regenerating it"
                        );
                    }
                }
            }
            let identity = Self::from_key_der(&key_der)?;
            identity.save(dir)?;
            return Ok(identity);
        }

        let identity = Self::generate()?;
        identity.save(dir)?;
        Ok(identity)
    }

    /// Persist key and certificate into `dir`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        write_private(&dir.join(KEY_FILE), &self.key_der)?;
        fs::write(dir.join(CERT_FILE), &self.cert_der)
            .with_context(|| format!("write {}", dir.join(CERT_FILE).display()))?;
        Ok(())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// TLS private key in the form rustls expects.
    pub fn private_key_der(&self) -> rustls::pki_types::PrivateKeyDer<'static> {
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            self.key_der.clone(),
        ))
    }
}

/// Verify an Ed25519 signature against a raw public key.
pub fn verify_signature(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok()
}

fn make_certificate(key_der: &[u8]) -> Result<Vec<u8>> {
    let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec());
    let keypair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
        .context("load Ed25519 key into rcgen")?;
    let mut params = CertificateParams::new(vec!["lanpf".to_string()])
        .context("create certificate parameters")?;
    params
        .distinguished_name
        .push(DnType::CommonName, "lanpf device");
    params.is_ca = IsCa::NoCa;
    let cert = params
        .self_signed(&keypair)
        .context("self-sign device certificate")?;
    Ok(cert.der().to_vec())
}

fn write_private(path: &PathBuf, data: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_sign_and_verify() {
        let id = Identity::generate().unwrap();
        let msg = b"hello grant";
        let sig = id.sign(msg);
        assert!(verify_signature(&id.public_key_bytes(), msg, &sig));
        assert!(!verify_signature(&id.public_key_bytes(), b"other", &sig));
        assert_eq!(
            crate::tls::ed25519_pubkey_from_cert(id.cert_der()).unwrap(),
            id.public_key_bytes()
        );
    }

    #[test]
    fn persistence_round_trip() {
        let dir = TempDir::new().unwrap();
        let a = Identity::load_or_generate(dir.path()).unwrap();
        let b = Identity::load_or_generate(dir.path()).unwrap();
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(a.cert_der(), b.cert_der());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn rejects_mismatched_cert() {
        let dir = TempDir::new().unwrap();
        let a = Identity::load_or_generate(dir.path()).unwrap();
        let b = Identity::generate().unwrap();
        assert!(Identity::from_key_and_cert(a.key_der(), b.cert_der()).is_err());
    }
}
