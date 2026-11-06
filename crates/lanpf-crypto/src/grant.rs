//! Transcripts for the one-way grant handshake and the read-only identity
//! query, plus the device key fingerprint shown to users.

use sha2::{Digest, Sha256};
use uuid::Uuid;

const GRANT_DOMAIN: &[u8] = b"lanpf-grant-v1";
const IDENTITY_DOMAIN: &[u8] = b"lanpf-identity-v1";

fn push(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Transcript signed by both sides of a grant handshake.
///
/// It binds both UUIDs, both nonces and both public keys, so a proof cannot be
/// replayed for a different pair of devices or a different handshake.
pub fn grant_transcript(
    initiator: Uuid,
    responder: Uuid,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    initiator_pubkey: &[u8],
    responder_pubkey: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    push(&mut out, GRANT_DOMAIN);
    push(&mut out, initiator.as_bytes());
    push(&mut out, responder.as_bytes());
    push(&mut out, initiator_nonce);
    push(&mut out, responder_nonce);
    push(&mut out, initiator_pubkey);
    push(&mut out, responder_pubkey);
    out
}

/// Transcript signed by the responder of a read-only identity query.
pub fn identity_transcript(nonce: &[u8], uuid: Uuid, agent_port: u16, pubkey: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    push(&mut out, IDENTITY_DOMAIN);
    push(&mut out, nonce);
    push(&mut out, uuid.as_bytes());
    push(&mut out, &agent_port.to_be_bytes());
    push(&mut out, pubkey);
    out
}

/// SHA-256 of an Ed25519 public key, lowercase hex.
pub fn fingerprint(pubkey: &[u8]) -> String {
    hex::encode(Sha256::digest(pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_transcript_binds_every_field() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let base = grant_transcript(a, b, b"n1", b"n2", b"p1", b"p2");
        assert_ne!(base, grant_transcript(b, a, b"n1", b"n2", b"p1", b"p2"));
        assert_ne!(base, grant_transcript(a, b, b"n2", b"n1", b"p1", b"p2"));
        assert_ne!(base, grant_transcript(a, b, b"n1", b"n2", b"p2", b"p1"));
    }

    #[test]
    fn identity_transcript_binds_nonce_and_identity() {
        let id = Uuid::new_v4();
        let base = identity_transcript(b"nonce", id, 47811, b"key");
        assert_ne!(base, identity_transcript(b"other", id, 47811, b"key"));
        assert_ne!(base, identity_transcript(b"nonce", id, 47812, b"key"));
    }

    #[test]
    fn fingerprint_is_stable_sha256_hex() {
        let fp = fingerprint(b"abc");
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, fingerprint(b"abc"));
        assert_ne!(fp, fingerprint(b"abd"));
    }
}
