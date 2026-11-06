//! Local IPC between the short-lived CLI and the background daemon.
//!
//! Frames are `u32 BE length + JSON` (see [`crate::frame`]). Every request
//! carries an `id` which is echoed in the response.

use crate::error::ExitCode;
use crate::protocol::{ExposeMode, PortInfo, RuleState};
use crate::JSON_SCHEMA;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub type RequestId = u64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: RequestId,
    pub cmd: Command,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Liveness probe used by the auto-spawn logic.
    Ping,
    Status,
    Local,
    Scan {
        timeout_ms: u64,
    },
    Remote {
        peer: Option<String>,
    },
    ForwardAdd {
        peer: String,
        target_port: u16,
        listen: Option<u16>,
    },
    ForwardList,
    ForwardRemove {
        local_port: u16,
    },
    Inbound,
    /// Authorize one or more devices to connect to this machine. The grant
    /// handshake also lets the grantee learn this machine as a server.
    PeerGrant {
        peers: Vec<String>,
        force: bool,
    },
    /// Revoke the authorization of one or more devices.
    PeerRevoke {
        peers: Vec<String>,
    },
    /// List devices authorized to access this machine.
    PeerList,
    /// Override the address used to reach a known device.
    PeerSetAddress {
        peer: String,
        address: String,
    },
    /// Read the effective exposure view of this machine.
    ExposeList,
    ExposeAdd {
        ports: Vec<u16>,
    },
    ExposeRemove {
        ports: Vec<u16>,
    },
    DaemonStop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcError {
    pub code: i32,
    pub message: String,
}

impl IpcError {
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            code: code.code(),
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from_code(self.code).unwrap_or(ExitCode::DaemonUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub id: RequestId,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

impl Response {
    pub fn ok<T: Serialize>(id: RequestId, data: &T) -> Self {
        Self {
            id,
            ok: true,
            data: Some(serde_json::to_value(data).unwrap_or(Value::Null)),
            error: None,
        }
    }

    pub fn raw_ok(id: RequestId, data: Value) -> Self {
        Self {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(id: RequestId, code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            error: Some(IpcError::new(code, message)),
        }
    }
}

// ---------------------------------------------------------------------------
// Response payloads (also the shape of `--json` output, with `schema: 2`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub schema: u32,
    pub pid: u32,
    pub uptime_secs: u64,
    pub agent_addr: String,
    pub ipc_path: String,
    pub log_path: String,
    pub device: String,
    /// Stable UUID of this device.
    pub device_id: Uuid,
    /// SHA-256 of the device public key, hex encoded.
    pub fingerprint: String,
    pub version: String,
    /// Devices this machine authorized to connect.
    pub allowed: usize,
    /// Devices this machine may dial (servers that authorized it).
    pub servers: usize,
    pub online: usize,
    pub rules: usize,
}

impl StatusInfo {
    pub const SCHEMA: u32 = JSON_SCHEMA;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPeer {
    /// `<name>@<address>` selector.
    pub peer: String,
    /// Stable device UUID reported over mDNS (unverified until grant).
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: u16,
    /// Protocol version reported over mDNS.
    pub version: u16,
    /// This machine authorized the device to connect.
    pub authorized: bool,
    /// This machine knows the device as a server it may dial.
    pub known: bool,
    pub online: bool,
    /// SHA-256 of the mDNS public key, when advertised.
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema: u32,
    pub peers: Vec<ScanPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalResult {
    pub schema: u32,
    pub ports: Vec<PortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePort {
    pub port: u16,
    /// Whether the port is currently listening on the peer.
    pub listening: bool,
    pub bind: Vec<String>,
    pub process: Option<String>,
    pub user: Option<String>,
    /// Local listen ports of rules forwarding to this remote port.
    pub forwarded: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePeer {
    pub peer: String,
    /// Stable device UUID.
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub online: bool,
    /// Exposure policy of the peer.
    pub mode: ExposeMode,
    /// SHA-256 of the peer's public key, hex encoded.
    pub fingerprint: String,
    pub ports: Vec<RemotePort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRef {
    pub id: Uuid,
    pub peer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteResult {
    pub schema: u32,
    pub peers: Vec<RemotePeer>,
    /// Paired devices that were skipped because they are offline.
    #[serde(default)]
    pub offline: Vec<String>,
    /// Same set as `offline`, with the stable IDs.
    #[serde(default)]
    pub offline_peers: Vec<PeerRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardInfo {
    pub local: u16,
    pub peer: String,
    /// Stable UUID of the peer this rule belongs to.
    pub peer_id: Uuid,
    pub target: u16,
    pub state: RuleState,
    pub since: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardListResult {
    pub schema: u32,
    pub forwards: Vec<ForwardInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardAddResult {
    pub schema: u32,
    pub local: u16,
    pub peer: String,
    pub target: u16,
    pub state: RuleState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRemoveResult {
    pub schema: u32,
    pub removed: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundInfo {
    pub peer: String,
    /// Stable UUID of the peer that owns the forward.
    pub id: Uuid,
    pub my_port: u16,
    pub peer_listen: u16,
    pub since: i64,
    pub last_seen: i64,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundResult {
    pub schema: u32,
    pub inbound: Vec<InboundInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedPeer {
    /// `<name>@<address>` of the authorized device.
    pub peer: String,
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub fingerprint: String,
    /// The device was already authorized with the same key.
    pub already_granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGrantFailure {
    /// The selector as supplied by the caller.
    pub peer: String,
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGrantResult {
    pub schema: u32,
    pub granted: Vec<GrantedPeer>,
    #[serde(default)]
    pub failed: Vec<PeerGrantFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedPeer {
    /// `<name>@<address>` of the revoked device.
    pub peer: String,
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRevokeResult {
    pub schema: u32,
    pub revoked: Vec<RevokedPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSetAddressResult {
    pub schema: u32,
    /// `<name>@<new address>` of the updated device.
    pub peer: String,
    /// Stable UUID of the updated device.
    pub id: Uuid,
    /// New `ip:port` used for future dials.
    pub address: String,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListEntry {
    /// Full device UUID.
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub online: bool,
    pub since: i64,
    /// SHA-256 of the device public key, hex encoded.
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResult {
    pub schema: u32,
    pub peers: Vec<PeerListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposeInbound {
    /// Stable UUID of the peer that owns the forward.
    pub id: Uuid,
    pub peer: String,
    /// Local listening port on the forwarding device.
    pub peer_listen: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposePortInfo {
    pub port: u16,
    pub listening: bool,
    #[serde(default)]
    pub bind: Vec<String>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub inbound: Vec<ExposeInbound>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposeListResult {
    pub schema: u32,
    pub mode: ExposeMode,
    pub ports: Vec<ExposePortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposeAddResult {
    pub schema: u32,
    pub ports: Vec<u16>,
    pub mode: ExposeMode,
    /// The command switched the machine from "all" to "whitelist".
    pub mode_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposeRemoveResult {
    pub schema: u32,
    pub ports: Vec<u16>,
    pub mode: ExposeMode,
    /// The command emptied the whitelist and returned to "all".
    pub mode_changed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let cmds = vec![
            Command::Ping,
            Command::Status,
            Command::Local,
            Command::Scan { timeout_ms: 3000 },
            Command::Remote { peer: None },
            Command::Remote {
                peer: Some("mac-mini@192.168.8.10".into()),
            },
            Command::ForwardAdd {
                peer: "a@1.2.3.4".into(),
                target_port: 3000,
                listen: Some(3001),
            },
            Command::ForwardList,
            Command::ForwardRemove { local_port: 3000 },
            Command::Inbound,
            Command::PeerGrant {
                peers: vec!["a@1.2.3.4".into()],
                force: false,
            },
            Command::PeerRevoke {
                peers: vec!["a@1.2.3.4".into()],
            },
            Command::PeerList,
            Command::PeerSetAddress {
                peer: "a@1.2.3.4".into(),
                address: "10.0.0.2:47811".into(),
            },
            Command::ExposeList,
            Command::ExposeAdd {
                ports: vec![3000, 3001],
            },
            Command::ExposeRemove { ports: vec![3000] },
            Command::DaemonStop,
        ];
        for cmd in cmds {
            let req = Request { id: 7, cmd };
            let json = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn response_round_trip() {
        let resp = Response::ok(
            1,
            &ScanResult {
                schema: JSON_SCHEMA,
                peers: vec![ScanPeer {
                    peer: "mac-mini@192.168.8.10".into(),
                    id: Uuid::nil(),
                    name: "mac-mini".into(),
                    address: "192.168.8.10".into(),
                    port: 47811,
                    version: 2,
                    authorized: true,
                    known: false,
                    online: true,
                    fingerprint: Some("00".repeat(32)),
                }],
            },
        );
        let json = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);

        let err = Response::err(2, ExitCode::DeviceNotFound, "no such device");
        let json = serde_json::to_string(&err).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error.unwrap().exit_code(), ExitCode::DeviceNotFound);
    }

    #[test]
    fn grant_result_round_trip() {
        let result = PeerGrantResult {
            schema: JSON_SCHEMA,
            granted: vec![GrantedPeer {
                peer: "laptop@192.168.1.5".into(),
                id: Uuid::nil(),
                name: "laptop".into(),
                address: "192.168.1.5:47811".into(),
                fingerprint: "00".repeat(32),
                already_granted: false,
            }],
            failed: vec![PeerGrantFailure {
                peer: "missing".into(),
                code: 3,
                message: "not found".into(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: PeerGrantResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.granted.len(), 1);
        assert_eq!(back.failed.len(), 1);
    }
}
