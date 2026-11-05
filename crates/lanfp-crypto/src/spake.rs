//! SPAKE2 wrapper used by the pairing handshake.
//!
//! The 6-digit pairing code is the password. The code is shown only on the
//! waiting side's terminal; the initiator has to type it in. The exchanged
//! SPAKE2 messages are bound to both device identities (UUIDs), so a
//! man-in-the-middle cannot transplant a transcript between sessions.

use anyhow::{bail, Result};
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// Domain separation prefix for the SPAKE2 password.
const PASSWORD_DOMAIN: &str = "lanfp-pair-v1:";

pub struct SpakeSession {
    inner: Spake2<Ed25519Group>,
}

impl SpakeSession {
    /// Start as the initiator (the side that types the code).
    pub fn start_a(code: &str, initiator_id: &[u8], responder_id: &[u8]) -> (Self, Vec<u8>) {
        let password = Password::new(format!("{PASSWORD_DOMAIN}{code}"));
        let (inner, msg) = Spake2::<Ed25519Group>::start_a(
            &password,
            &Identity::new(initiator_id),
            &Identity::new(responder_id),
        );
        (Self { inner }, msg)
    }

    /// Start as the responder (the side that displays the code).
    pub fn start_b(code: &str, initiator_id: &[u8], responder_id: &[u8]) -> (Self, Vec<u8>) {
        let password = Password::new(format!("{PASSWORD_DOMAIN}{code}"));
        let (inner, msg) = Spake2::<Ed25519Group>::start_b(
            &password,
            &Identity::new(initiator_id),
            &Identity::new(responder_id),
        );
        (Self { inner }, msg)
    }

    /// Consume the peer's SPAKE2 message and derive the shared key.
    ///
    /// With a wrong code the key differs; the subsequent AEAD check fails,
    /// which is the explicit key confirmation.
    pub fn finish(self, peer_msg: &[u8]) -> Result<[u8; 32]> {
        let key = self
            .inner
            .finish(peer_msg)
            .map_err(|e| anyhow::anyhow!("SPAKE2 exchange failed: {e:?}"))?;
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("SPAKE2 produced a key of unexpected length"))?;
        Ok(key)
    }
}

/// Generate a random 6-digit pairing code.
pub fn generate_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000u32))
}

/// Validate a user-supplied pairing code.
pub fn validate_code(code: &str) -> Result<()> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        bail!("pairing code must be 6 digits");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_codes_derive_same_key() {
        let (a, msg_a) = SpakeSession::start_a("418302", b"alice", b"bob");
        let (b, msg_b) = SpakeSession::start_b("418302", b"alice", b"bob");
        let ka = a.finish(&msg_b).unwrap();
        let kb = b.finish(&msg_a).unwrap();
        assert_eq!(ka, kb);
    }

    #[test]
    fn wrong_codes_derive_different_keys() {
        let (a, msg_a) = SpakeSession::start_a("111111", b"alice", b"bob");
        let (b, msg_b) = SpakeSession::start_b("222222", b"alice", b"bob");
        let ka = a.finish(&msg_b).unwrap();
        let kb = b.finish(&msg_a).unwrap();
        assert_ne!(ka, kb);
    }

    #[test]
    fn identities_are_bound() {
        let (a, msg_a) = SpakeSession::start_a("418302", b"alice", b"bob");
        let (b, msg_b) = SpakeSession::start_b("418302", b"alice", b"mallory");
        let ka = a.finish(&msg_b).unwrap();
        let kb = b.finish(&msg_a).unwrap();
        assert_ne!(ka, kb);
    }

    #[test]
    fn code_format() {
        for _ in 0..100 {
            let code = generate_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            validate_code(&code).unwrap();
        }
        assert!(validate_code("12345").is_err());
        assert!(validate_code("12345a").is_err());
    }
}
