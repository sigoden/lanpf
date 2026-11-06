//! Platform-specific directories, IPC endpoint, lock and log paths.
//!
//! `LANPF_HOME` overrides every location with a self-contained directory
//! (`config/`, `data/`, `state/`, `run/`); this is what the test-suite uses to
//! run several isolated daemons.

use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        if let Ok(home) = std::env::var("LANPF_HOME") {
            if !home.is_empty() {
                let home = PathBuf::from(home);
                return Ok(Paths {
                    config_dir: home.join("config"),
                    data_dir: home.join("data"),
                    state_dir: home.join("state"),
                    runtime_dir: home.join("run"),
                });
            }
        }
        let config_dir = dirs::config_dir()
            .context("cannot determine the configuration directory")?
            .join("lanpf");
        let data_dir = dirs::data_dir()
            .context("cannot determine the data directory")?
            .join("lanpf");
        #[cfg(target_os = "linux")]
        let state_dir = dirs::state_dir()
            .unwrap_or_else(|| data_dir.clone())
            .join("lanpf");
        #[cfg(not(target_os = "linux"))]
        let state_dir = data_dir.join("logs");
        let runtime_dir = runtime_base().join("lanpf");
        Ok(Paths {
            config_dir,
            data_dir,
            state_dir,
            runtime_dir,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("lanpf.db")
    }

    pub fn identity_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("lanpf.log")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.runtime_dir.join("lanpf.lock")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.runtime_dir.join("lanpf.pid")
    }

    /// IPC endpoint: a Unix socket path on Unix, a named pipe name on Windows.
    pub fn socket_endpoint(&self) -> PathBuf {
        #[cfg(unix)]
        {
            let path = self.runtime_dir.join("ctl.sock");
            // sun_path is 104/108 bytes; fall back to /tmp when the runtime
            // directory is unusually deep.
            if path.as_os_str().len() > 100 {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                path.hash(&mut hasher);
                let suffix = format!("{:08x}", hasher.finish() as u32);
                return unix_tmp_dir().join(suffix).join("ctl.sock");
            }
            path
        }
        #[cfg(windows)]
        {
            // The pipe name must follow the runtime directory, otherwise every
            // `LANPF_HOME` on the machine would share one IPC endpoint and the
            // daemons would talk to each other's clients.
            use std::hash::{Hash, Hasher};
            let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            self.runtime_dir.hash(&mut hasher);
            PathBuf::from(format!(
                r"\\.\pipe\lanpf-{user}-{:08x}",
                hasher.finish() as u32
            ))
        }
    }

    /// Human-readable IPC address for `daemon status`.
    pub fn socket_display(&self) -> String {
        self.socket_endpoint().display().to_string()
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.state_dir] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create directory {}", dir.display()))?;
        }
        let runtime = self.runtime_dir.clone();
        std::fs::create_dir_all(&runtime)
            .with_context(|| format!("create runtime directory {}", runtime.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700));
        }
        #[cfg(unix)]
        {
            // If the socket fell back to /tmp, make sure that directory is
            // private as well.
            let endpoint = self.socket_endpoint();
            if let Some(parent) = endpoint.parent() {
                if parent != runtime {
                    std::fs::create_dir_all(parent)?;
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
                }
            }
        }
        Ok(())
    }

    /// Rotate the daemon log at startup when it grew beyond `max_bytes`.
    pub fn rotate_log(&self, max_bytes: u64) {
        let log = self.log_file();
        if let Ok(meta) = std::fs::metadata(&log) {
            if meta.len() > max_bytes {
                let rotated = log.with_extension("log.1");
                let _ = std::fs::remove_file(&rotated);
                let _ = std::fs::rename(&log, &rotated);
            }
        }
    }
}

#[cfg(unix)]
fn runtime_base() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        let tmp = PathBuf::from(tmp);
        if !tmp.as_os_str().is_empty() {
            return tmp;
        }
    }
    unix_tmp_dir()
}

#[cfg(unix)]
fn unix_tmp_dir() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/lanpf-{uid}"))
}

#[cfg(windows)]
fn runtime_base() -> PathBuf {
    std::env::temp_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_override_is_self_contained() {
        // The env var is process-global; this test only checks path joining
        // via a direct construction to avoid racing other tests.
        let home = PathBuf::from("/tmp/lanpf-test-home");
        let paths = Paths {
            config_dir: home.join("config"),
            data_dir: home.join("data"),
            state_dir: home.join("state"),
            runtime_dir: home.join("run"),
        };
        assert_eq!(paths.config_file(), home.join("config/config.toml"));
        assert_eq!(paths.db_file(), home.join("data/lanpf.db"));
        assert_eq!(paths.log_file(), home.join("state/lanpf.log"));
        assert_eq!(paths.lock_file(), home.join("run/lanpf.lock"));
    }

    #[cfg(windows)]
    #[test]
    fn pipe_name_follows_the_runtime_directory() {
        let base = Paths {
            config_dir: PathBuf::from(r"C:\tmp\a\config"),
            data_dir: PathBuf::from(r"C:\tmp\a\data"),
            state_dir: PathBuf::from(r"C:\tmp\a\state"),
            runtime_dir: PathBuf::from(r"C:\tmp\a\run"),
        };
        let other = Paths {
            runtime_dir: PathBuf::from(r"C:\tmp\b\run"),
            ..base.clone()
        };
        let endpoint = base.socket_endpoint().display().to_string();
        assert!(endpoint.starts_with(r"\\.\pipe\lanpf-"), "{endpoint}");
        assert_ne!(base.socket_endpoint(), other.socket_endpoint());
    }

    #[cfg(unix)]
    #[test]
    fn socket_endpoint_is_short_enough() {
        let paths = Paths::resolve().unwrap();
        let endpoint = paths.socket_endpoint();
        assert!(endpoint.as_os_str().len() <= 100, "{endpoint:?}");
    }
}
