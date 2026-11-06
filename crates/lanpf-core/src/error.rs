//! Stable exit codes, also documented in docs/usage.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ExitCode {
    Ok = 0,
    Usage = 2,
    DeviceNotFound = 3,
    NotAuthorizedOrOffline = 4,
    ListenConflict = 5,
    Permission = 7,
    TargetNotExposed = 8,
    AuthorizationFailed = 9,
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
            ExitCode::NotAuthorizedOrOffline => "not_authorized_or_offline",
            ExitCode::ListenConflict => "listen_conflict",
            ExitCode::Permission => "permission_denied",
            ExitCode::TargetNotExposed => "target_not_exposed",
            ExitCode::AuthorizationFailed => "authorization_failed",
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
            4 => ExitCode::NotAuthorizedOrOffline,
            5 => ExitCode::ListenConflict,
            7 => ExitCode::Permission,
            8 => ExitCode::TargetNotExposed,
            9 => ExitCode::AuthorizationFailed,
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
