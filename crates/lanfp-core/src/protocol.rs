//! Wire protocol: port inventory entries, control messages, the data-stream
//! header and the pairing handshake messages.

use crate::{DATA_HEADER_LEN, DATA_MAGIC};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One TCP listening port as observed by the inventory enumerator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    /// Bind addresses, e.g. `["127.0.0.1"]` or `["0.0.0.0", "::"]`.
    #[serde(default)]
    pub bind: Vec<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

impl PortInfo {
    pub fn bind_display(&self) -> String {
        if self.bind.is_empty() {
            "-".to_string()
        } else {
            self.bind.join(",")
        }
    }

    pub fn process_display(&self) -> &str {
        self.process.as_deref().unwrap_or("-")
    }

    pub fn user_display(&self) -> &str {
        self.user.as_deref().unwrap_or("-")
    }

    pub fn pid_display(&self) -> String {
        self.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into())
    }

    /// All concrete (non-wildcard) addresses this port is bound to.
    pub fn concrete_binds(&self) -> Vec<String> {
        self.bind
            .iter()
            .filter(|b| *b != "0.0.0.0" && *b != "::")
            .cloned()
            .collect()
    }
}

/// Classification of a listening port relative to lanfp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortKind {
    /// Any listening port not owned by lanfp.
    Native,
    /// A listener created by lanfp for a forwarding rule.
    Forward,
    /// lanfp's own agent port (and any other lanfp-owned listener).
    SelfPort,
}

impl PortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PortKind::Native => "native",
            PortKind::Forward => "forward",
            PortKind::SelfPort => "self",
        }
    }
}

/// State of a forwarding rule (stored on the listening side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleState {
    Active,
    PeerOffline,
    TargetGone,
    ListenError,
}

impl RuleState {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleState::Active => "active",
            RuleState::PeerOffline => "peer_offline",
            RuleState::TargetGone => "target_gone",
            RuleState::ListenError => "listen_error",
        }
    }

    pub fn parse(s: &str) -> RuleState {
        match s {
            "active" => RuleState::Active,
            "target_gone" => RuleState::TargetGone,
            "listen_error" => RuleState::ListenError,
            _ => RuleState::PeerOffline,
        }
    }
}

impl std::fmt::Display for RuleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Control-stream message (framed as `u32 BE length + JSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Hello {
        version: u16,
        uuid: Uuid,
        name: String,
        agent_port: u16,
        build: String,
    },
    Inventory {
        seq: u64,
        ports: Vec<PortInfo>,
    },
    RuleUpsert {
        rule_id: Uuid,
        target_port: u16,
        listen_port: u16,
        state: RuleState,
    },
    RuleRemove {
        rule_id: Uuid,
    },
    /// Sent after the initial RuleUpsert burst; the serving side drops stale
    /// inbound references that are not in this snapshot.
    RuleSnapshot {
        rule_ids: Vec<Uuid>,
    },
    RuleRejected {
        rule_id: Uuid,
        reason: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Error {
        code: i32,
        message: String,
    },
}

/// 25-byte header written at the start of every forwarded data stream.
///
/// ```text
/// 0..4    "LAND"
/// 4       version = 1
/// 5       family (4 | 6)
/// 6..8    u16 BE target_port
/// 8..24   rule_id [16]
/// 24      reserved
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    pub family: u8,
    pub target_port: u16,
    pub rule_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DataHeaderError {
    #[error("data stream magic mismatch")]
    BadMagic,
    #[error("unsupported data stream version {0}")]
    BadVersion(u8),
    #[error("invalid address family {0}")]
    BadFamily(u8),
    #[error("data stream header too short")]
    TooShort,
}

impl DataHeader {
    pub const VERSION: u8 = 1;

    pub fn new(family: u8, target_port: u16, rule_id: Uuid) -> Self {
        Self {
            family,
            target_port,
            rule_id,
        }
    }

    pub fn encode(&self) -> [u8; DATA_HEADER_LEN] {
        let mut buf = [0u8; DATA_HEADER_LEN];
        buf[0..4].copy_from_slice(DATA_MAGIC);
        buf[4] = Self::VERSION;
        buf[5] = self.family;
        buf[6..8].copy_from_slice(&self.target_port.to_be_bytes());
        buf[8..24].copy_from_slice(self.rule_id.as_bytes());
        buf[24] = 0;
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<DataHeader, DataHeaderError> {
        if buf.len() < DATA_HEADER_LEN {
            return Err(DataHeaderError::TooShort);
        }
        if &buf[0..4] != DATA_MAGIC {
            return Err(DataHeaderError::BadMagic);
        }
        if buf[4] != Self::VERSION {
            return Err(DataHeaderError::BadVersion(buf[4]));
        }
        if buf[5] != 4 && buf[5] != 6 {
            return Err(DataHeaderError::BadFamily(buf[5]));
        }
        let target_port = u16::from_be_bytes([buf[6], buf[7]]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&buf[8..24]);
        Ok(DataHeader {
            family: buf[5],
            target_port,
            rule_id: Uuid::from_bytes(id),
        })
    }
}

/// Pairing handshake message (sent on the agent port after `FPP1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairMessage {
    Hello {
        version: u16,
        uuid: Uuid,
        name: String,
        agent_port: u16,
        /// 32-byte random nonce chosen by the initiator.
        nonce: Vec<u8>,
        /// 32-byte Ed25519 public key.
        pubkey: Vec<u8>,
    },
    Challenge {
        /// 32-byte random nonce chosen by the responder.
        nonce: Vec<u8>,
        /// Responder identity, bound into the SPAKE2 transcript.
        uuid: Uuid,
        name: String,
        agent_port: u16,
        /// 32-byte Ed25519 public key of the responder.
        pubkey: Vec<u8>,
    },
    SpakeA {
        msg: Vec<u8>,
    },
    SpakeB {
        msg: Vec<u8>,
    },
    /// AEAD-encrypted device info (see [`PairDeviceInfo`]).
    Secure {
        nonce: Vec<u8>,
        payload: Vec<u8>,
    },
    Reject {
        reason: String,
        code: i32,
    },
    Failed {
        reason: String,
        code: i32,
    },
    Done,
}

/// Payload encrypted with the SPAKE2-derived key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairDeviceInfo {
    pub uuid: Uuid,
    pub name: String,
    pub agent_port: u16,
    pub pubkey: Vec<u8>,
    /// Self-signed certificate carrying `pubkey`.
    pub cert_der: Vec<u8>,
    /// Ed25519 signature over the pairing transcript.
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_header_round_trip() {
        let rule = Uuid::new_v4();
        let h = DataHeader::new(4, 3000, rule);
        let bytes = h.encode();
        assert_eq!(&bytes[0..4], DATA_MAGIC);
        assert_eq!(bytes.len(), 25);
        let d = DataHeader::decode(&bytes).unwrap();
        assert_eq!(d, h);
        assert_eq!(d.target_port, 3000);
        assert_eq!(d.family, 4);
    }

    #[test]
    fn data_header_rejects_garbage() {
        assert_eq!(
            DataHeader::decode(b"LAND").unwrap_err(),
            DataHeaderError::TooShort
        );
        let mut bytes = DataHeader::new(4, 80, Uuid::nil()).encode();
        bytes[0] = b'X';
        assert_eq!(
            DataHeader::decode(&bytes).unwrap_err(),
            DataHeaderError::BadMagic
        );
        let mut bytes = DataHeader::new(4, 80, Uuid::nil()).encode();
        bytes[4] = 9;
        assert_eq!(
            DataHeader::decode(&bytes).unwrap_err(),
            DataHeaderError::BadVersion(9)
        );
        let mut bytes = DataHeader::new(4, 80, Uuid::nil()).encode();
        bytes[5] = 7;
        assert_eq!(
            DataHeader::decode(&bytes).unwrap_err(),
            DataHeaderError::BadFamily(7)
        );
    }

    #[test]
    fn control_message_round_trip() {
        let msgs = vec![
            ControlMessage::Hello {
                version: 1,
                uuid: Uuid::new_v4(),
                name: "box".into(),
                agent_port: 47811,
                build: "lanfp/0.1.0".into(),
            },
            ControlMessage::Inventory {
                seq: 3,
                ports: vec![PortInfo {
                    port: 3000,
                    bind: vec!["127.0.0.1".into()],
                    pid: Some(42),
                    process: Some("node".into()),
                    user: Some("sigo".into()),
                }],
            },
            ControlMessage::RuleUpsert {
                rule_id: Uuid::new_v4(),
                target_port: 3000,
                listen_port: 3000,
                state: RuleState::Active,
            },
            ControlMessage::RuleRemove {
                rule_id: Uuid::new_v4(),
            },
            ControlMessage::RuleSnapshot {
                rule_ids: vec![Uuid::new_v4()],
            },
            ControlMessage::RuleRejected {
                rule_id: Uuid::new_v4(),
                reason: "target gone".into(),
            },
            ControlMessage::Ping { nonce: 7 },
            ControlMessage::Pong { nonce: 7 },
            ControlMessage::Error {
                code: 8,
                message: "nope".into(),
            },
        ];
        for msg in msgs {
            let json = serde_json::to_string(&msg).unwrap();
            let back: ControlMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(msg, back);
        }
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn data_header_prop_roundtrip(
            family in prop::sample::select(vec![4u8, 6u8]),
            target_port in any::<u16>(),
            id in any::<[u8; 16]>(),
        ) {
            let header = DataHeader::new(family, target_port, Uuid::from_bytes(id));
            let decoded = DataHeader::decode(&header.encode()).unwrap();
            prop_assert_eq!(header, decoded);
        }
    }

    #[test]
    fn rule_state_round_trip() {
        for s in [
            RuleState::Active,
            RuleState::PeerOffline,
            RuleState::TargetGone,
            RuleState::ListenError,
        ] {
            assert_eq!(RuleState::parse(s.as_str()), s);
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
    }
}
