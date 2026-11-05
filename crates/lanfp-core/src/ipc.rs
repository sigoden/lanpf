//! Local IPC between the short-lived CLI and the background daemon.
//!
//! Frames are `u32 BE length + JSON` (see [`crate::frame`]). Every request
//! carries an `id` which is echoed in the response.

use crate::error::ExitCode;
use crate::protocol::{PortInfo, RuleState};
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
    PairStart {
        peer: String,
    },
    PairFinish {
        token: Uuid,
        code: String,
        force: bool,
    },
    PairCancel {
        token: Uuid,
    },
    PairWaitStart {
        timeout_secs: u64,
    },
    PairWaitPoll {
        token: Uuid,
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
// Response payloads (also the shape of `--json` output, with `schema: 1`).
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
    pub version: String,
    pub peers_paired: usize,
    pub peers_online: usize,
    pub rules: usize,
}

impl StatusInfo {
    pub const SCHEMA: u32 = JSON_SCHEMA;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPeer {
    /// `<name>@<address>` selector.
    pub peer: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub paired: bool,
    pub online: bool,
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
    pub bind: Vec<String>,
    pub process: Option<String>,
    pub user: Option<String>,
    /// Local listen ports of rules forwarding to this remote port.
    pub forwarded: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePeer {
    pub peer: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub online: bool,
    pub ports: Vec<RemotePort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteResult {
    pub schema: u32,
    pub peers: Vec<RemotePeer>,
    /// Paired devices that were skipped because they are offline.
    #[serde(default)]
    pub offline: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardInfo {
    pub local: u16,
    pub peer: String,
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
pub struct PairWaitStartResult {
    pub schema: u32,
    pub token: Uuid,
    pub code: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairStartResult {
    pub schema: u32,
    pub token: Uuid,
    pub peer: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairFinishResult {
    pub schema: u32,
    pub peer: String,
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairWaitState {
    Waiting,
    Incoming,
    Paired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairWaitPollResult {
    pub schema: u32,
    pub state: PairWaitState,
    pub peer: Option<String>,
    pub code: Option<String>,
    pub attempts_left: Option<u32>,
    pub exit_code: Option<i32>,
    pub message: Option<String>,
    pub expires_in: Option<u64>,
}

impl PairWaitPollResult {
    pub fn new(state: PairWaitState) -> Self {
        Self {
            schema: JSON_SCHEMA,
            state,
            peer: None,
            code: None,
            attempts_left: None,
            exit_code: None,
            message: None,
            expires_in: None,
        }
    }
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
            Command::PairStart {
                peer: "a@1.2.3.4".into(),
            },
            Command::PairFinish {
                token: Uuid::nil(),
                code: "123456".into(),
                force: true,
            },
            Command::PairCancel { token: Uuid::nil() },
            Command::PairWaitStart { timeout_secs: 300 },
            Command::PairWaitPoll { token: Uuid::nil() },
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
                    name: "mac-mini".into(),
                    address: "192.168.8.10".into(),
                    port: 47811,
                    paired: true,
                    online: true,
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
}
