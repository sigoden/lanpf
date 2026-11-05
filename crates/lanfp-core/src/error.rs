//! Stable exit codes documented in PLAN.md section 4.5.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ExitCode {
    Ok = 0,
    Usage = 2,
    DeviceNotFound = 3,
    NotPairedOrOffline = 4,
    ListenConflict = 5,
    PeerNotWaiting = 6,
    Permission = 7,
    TargetNotInInventory = 8,
    PairingFailed = 9,
    DaemonUnavailable = 10,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ExitCode::Ok => "ok",
            ExitCode::Usage => "usage",
            ExitCode::DeviceNotFound => "device_not_found",
            ExitCode::NotPairedOrOffline => "not_paired_or_offline",
            ExitCode::ListenConflict => "listen_conflict",
            ExitCode::PeerNotWaiting => "peer_not_waiting",
            ExitCode::Permission => "permission_denied",
            ExitCode::TargetNotInInventory => "target_not_in_inventory",
            ExitCode::PairingFailed => "pairing_failed",
            ExitCode::DaemonUnavailable => "daemon_unavailable",
        }
    }

    /// Map a raw exit code back to the enum (used by IPC clients when the
    /// daemon reports a failure).
    pub fn from_code(code: i32) -> Option<ExitCode> {
        Some(match code {
            0 => ExitCode::Ok,
            2 => ExitCode::Usage,
            3 => ExitCode::DeviceNotFound,
            4 => ExitCode::NotPairedOrOffline,
            5 => ExitCode::ListenConflict,
            6 => ExitCode::PeerNotWaiting,
            7 => ExitCode::Permission,
            8 => ExitCode::TargetNotInInventory,
            9 => ExitCode::PairingFailed,
            10 => ExitCode::DaemonUnavailable,
            _ => return None,
        })
    }
}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
