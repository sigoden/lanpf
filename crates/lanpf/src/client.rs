//! IPC client used by every short-lived CLI command, including the
//! auto-start logic for the background daemon.

use crate::paths::Paths;
use lanpf_core::error::ExitCode;
use lanpf_core::frame::{read_json, write_json};
use lanpf_core::ipc::{Command, IpcError, Request, Response};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

#[derive(Debug)]
pub struct CliError {
    pub code: ExitCode,
    pub message: String,
}

impl CliError {
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        // `#` keeps anyhow context chains; plain values render unchanged.
        Self::new(ExitCode::DaemonUnavailable, format!("{err:#}"))
    }
}

impl From<IpcError> for CliError {
    fn from(err: IpcError) -> Self {
        Self {
            code: err.exit_code(),
            message: err.message,
        }
    }
}

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(unix)]
async fn connect_stream(paths: &Paths) -> std::io::Result<ClientStream> {
    tokio::net::UnixStream::connect(paths.socket_endpoint()).await
}

#[cfg(windows)]
async fn connect_stream(paths: &Paths) -> std::io::Result<ClientStream> {
    let name = paths.socket_endpoint().display().to_string();
    tokio::net::windows::named_pipe::ClientOptions::new().open(name)
}

async fn connect_or_spawn(paths: &Paths, autostart: bool) -> Result<ClientStream, CliError> {
    match connect_stream(paths).await {
        Ok(stream) => Ok(stream),
        Err(err) => {
            if !autostart {
                return Err(CliError::new(
                    ExitCode::DaemonUnavailable,
                    format!(
                        "lanpf daemon is not running ({}); start it with `lanpf daemon start`",
                        err
                    ),
                ));
            }
            paths.ensure().map_err(CliError::internal)?;
            spawn_daemon(paths)?;
            for _ in 0..50 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Ok(stream) = connect_stream(paths).await {
                    return Ok(stream);
                }
            }
            Err(CliError::new(
                ExitCode::DaemonUnavailable,
                format!(
                    "lanpf daemon did not start within 5s; see log {}",
                    paths.log_file().display()
                ),
            ))
        }
    }
}

/// Send a command to the daemon, starting it first when `autostart` is set.
pub async fn call(paths: &Paths, command: Command, autostart: bool) -> Result<Response, CliError> {
    let mut stream = connect_or_spawn(paths, autostart).await?;
    let request = Request {
        id: 1,
        cmd: command,
    };
    write_json(&mut stream, &request)
        .await
        .map_err(|e| CliError::internal(format!("cannot send request to daemon: {e}")))?;
    let response: Response = read_json(&mut stream)
        .await
        .map_err(|e| CliError::internal(format!("cannot read daemon response: {e}")))?;
    if !response.ok {
        if let Some(error) = response.error {
            return Err(error.into());
        }
        return Err(CliError::new(
            ExitCode::DaemonUnavailable,
            "daemon returned an error without details",
        ));
    }
    Ok(response)
}

/// Ensure a daemon is running; used by `lanpf daemon start`.
pub async fn ensure_running(paths: &Paths) -> Result<bool, CliError> {
    if connect_stream(paths).await.is_ok() {
        return Ok(false);
    }
    paths.ensure().map_err(CliError::internal)?;
    spawn_daemon(paths)?;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if connect_stream(paths).await.is_ok() {
            return Ok(true);
        }
    }
    Err(CliError::new(
        ExitCode::DaemonUnavailable,
        format!(
            "lanpf daemon did not start within 5s; see log {}",
            paths.log_file().display()
        ),
    ))
}

/// Clear the `HANDLE_FLAG_INHERIT` bit on our stdio handles so the daemon we
/// spawn cannot keep a caller's pipe open (see `spawn_daemon`).
#[cfg(windows)]
fn clear_stdio_inheritance() {
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(id) };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            unsafe {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

pub fn spawn_daemon(paths: &Paths) -> Result<(), CliError> {
    let exe = std::env::current_exe()
        .map_err(|e| CliError::internal(format!("cannot locate the lanpf executable: {e}")))?;
    paths.rotate_log(5 * 1024 * 1024);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_file())
        .map_err(|e| {
            CliError::internal(format!(
                "cannot open log file {}: {e}",
                paths.log_file().display()
            ))
        })?;
    let log_err = log
        .try_clone()
        .map_err(|e| CliError::internal(format!("cannot duplicate log handle: {e}")))?;

    let mut command = ProcessCommand::new(exe);
    command
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .env("LANPF_DAEMON", "1");
    if let Ok(home) = std::env::var("LANPF_HOME") {
        command.env("LANPF_HOME", home);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        // Every inheritable handle of this process is inherited by the child,
        // even when its own stdio is redirected. When the caller pipes our
        // stdout (a shell pipeline, sshd, a CI runner), the detached daemon
        // would keep that pipe open and the caller would never see EOF.
        clear_stdio_inheritance();
    }

    command.spawn().map_err(|e| {
        CliError::new(
            ExitCode::DaemonUnavailable,
            format!("cannot start lanpf serve: {e}"),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_keeps_the_context_chain() {
        let err = anyhow::anyhow!("expected `]`").context("parse config /tmp/config.toml");
        let err = CliError::internal(err);
        assert_eq!(err.code, ExitCode::DaemonUnavailable);
        assert!(err.message.contains("parse config"), "{}", err.message);
        assert!(err.message.contains("expected `]`"), "{}", err.message);
    }
}
