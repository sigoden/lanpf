//! Pairing transcript, key derivation and AEAD helpers.

use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

const TRANSCRIPT_DOMAIN: &[u8] = b"lanfp-pair-v1";

/// Canonical pairing transcript signed by both sides.
///
/// Roles are fixed: A is the initiator (types the code), B the responder
/// (displays the code). Both sides must build the same byte string.
pub fn pairing_transcript(
    initiator_id: Uuid,
    responder_id: Uuid,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    initiator_pubkey: &[u8],
    responder_pubkey: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + 16 * 2 + 32 * 4);
    out.extend_from_slice(TRANSCRIPT_DOMAIN);
    out.extend_from_slice(initiator_id.as_bytes());
    out.extend_from_slice(responder_id.as_bytes());
    out.extend_from_slice(initiator_nonce);
    out.extend_from_slice(responder_nonce);
    out.extend_from_slice(initiator_pubkey);
    out.extend_from_slice(responder_pubkey);
    out
}

/// Derive directional AEAD keys from the SPAKE2 shared key and transcript.
///
/// Returns `(initiator_to_responder, responder_to_initiator)`.
pub fn derive_pair_keys(shared: &[u8; 32], transcript: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut a2b = [0u8; 32];
    let mut b2a = [0u8; 32];
    hk.expand(b"lanfp-pair-v1/a2b", &mut a2b)
        .expect("32 bytes is a valid HKDF output length");
    hk.expand(b"lanfp-pair-v1/b2a", &mut b2a)
        .expect("32 bytes is a valid HKDF output length");
    (a2b, b2a)
}

/// Encrypt `plaintext` with ChaCha20-Poly1305. Returns `(nonce, ciphertext)`.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rand::RngCore;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("pairing payload encryption failed"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt a payload produced by [`seal`].
pub fn open(key: &[u8; 32], aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        bail!("invalid pairing nonce length");
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("pairing payload authentication failed"))
}

/// Sign and encrypt this device's pairing info.
pub fn seal_device_info(
    key: &[u8; 32],
    transcript: &[u8],
    identity: &crate::identity::Identity,
    uuid: Uuid,
    name: &str,
    agent_port: u16,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let signature = identity.sign(transcript);
    let info = lanfp_core::protocol::PairDeviceInfo {
        uuid,
        name: name.to_string(),
        agent_port,
        pubkey: identity.public_key_bytes().to_vec(),
        cert_der: identity.cert_der().to_vec(),
        signature: signature.to_vec(),
    };
    let plaintext = serde_json::to_vec(&info).context("encode pairing device info")?;
    seal(key, transcript, &plaintext)
}

/// Decrypt and verify the peer's pairing info.
pub fn open_device_info(
    key: &[u8; 32],
    transcript: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<lanfp_core::protocol::PairDeviceInfo> {
    let plaintext = open(key, transcript, nonce, ciphertext)?;
    let info: lanfp_core::protocol::PairDeviceInfo =
        serde_json::from_slice(&plaintext).context("decode pairing device info")?;
    if !crate::identity::verify_signature(&info.pubkey, transcript, &info.signature) {
        bail!("pairing device signature verification failed");
    }
    let cert_pubkey = crate::tls::ed25519_pubkey_from_cert(&info.cert_der)
        .context("peer pairing certificate is invalid")?;
    if cert_pubkey != info.pubkey.as_slice() {
        bail!("pairing certificate does not match the advertised public key");
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn transcript() -> Vec<u8> {
        pairing_transcript(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            &[7u8; 32],
            &[8u8; 32],
            &[9u8; 32],
            &[10u8; 32],
        )
    }

    #[test]
    fn keys_are_directional_and_deterministic() {
        let t = transcript();
        let (a1, b1) = derive_pair_keys(&[5u8; 32], &t);
        let (a2, b2) = derive_pair_keys(&[5u8; 32], &t);
        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
        assert_ne!(a1, b1);
        assert_ne!(a1, [5u8; 32]);
    }

    #[test]
    fn aead_round_trip_and_tamper() {
        let key = [3u8; 32];
        let aad = b"aad";
        let (nonce, ct) = seal(&key, aad, b"secret").unwrap();
        assert_eq!(open(&key, aad, &nonce, &ct).unwrap(), b"secret");
        assert!(open(&key, b"other", &nonce, &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&key, aad, &nonce, &bad).is_err());
    }

    #[test]
    fn device_info_round_trip() {
        let id = Identity::generate().unwrap();
        let t = transcript();
        let key = [1u8; 32];
        let (nonce, ct) =
            seal_device_info(&key, &t, &id, Uuid::from_u128(3), "box", 47811).unwrap();
        let info = open_device_info(&key, &t, &nonce, &ct).unwrap();
        assert_eq!(info.uuid, Uuid::from_u128(3));
        assert_eq!(info.name, "box");
        assert_eq!(info.pubkey, id.public_key_bytes().to_vec());
    }

    #[test]
    fn wrong_key_rejected() {
        let id = Identity::generate().unwrap();
        let t = transcript();
        let (nonce, ct) = seal_device_info(&[1u8; 32], &t, &id, Uuid::nil(), "box", 1).unwrap();
        assert!(open_device_info(&[2u8; 32], &t, &nonce, &ct).is_err());
    }
}
