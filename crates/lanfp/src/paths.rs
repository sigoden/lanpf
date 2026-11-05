//! Platform-specific directories, IPC endpoint, lock and log paths.
//!
//! `LANFP_HOME` overrides every location with a self-contained directory
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
        if let Ok(home) = std::env::var("LANFP_HOME") {
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
            .join("lanfp");
        let data_dir = dirs::data_dir()
            .context("cannot determine the data directory")?
            .join("lanfp");
        #[cfg(target_os = "linux")]
        let state_dir = dirs::state_dir()
            .unwrap_or_else(|| data_dir.clone())
            .join("lanfp");
        #[cfg(not(target_os = "linux"))]
        let state_dir = data_dir.join("logs");
        let runtime_dir = runtime_base().join("lanfp");
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
        self.data_dir.join("lanfp.db")
    }

    pub fn identity_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("lanfp.log")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.runtime_dir.join("lanfp.lock")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.runtime_dir.join("lanfp.pid")
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
            let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
            PathBuf::from(format!(r"\\.\pipe\lanfp-{user}"))
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
    PathBuf::from(format!("/tmp/lanfp-{uid}"))
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
        let home = PathBuf::from("/tmp/lanfp-test-home");
        let paths = Paths {
            config_dir: home.join("config"),
            data_dir: home.join("data"),
            state_dir: home.join("state"),
            runtime_dir: home.join("run"),
        };
        assert_eq!(paths.config_file(), home.join("config/config.toml"));
        assert_eq!(paths.db_file(), home.join("data/lanfp.db"));
        assert_eq!(paths.log_file(), home.join("state/lanfp.log"));
        assert_eq!(paths.lock_file(), home.join("run/lanfp.lock"));
    }

    #[cfg(unix)]
    #[test]
    fn socket_endpoint_is_short_enough() {
        let paths = Paths::resolve().unwrap();
        let endpoint = paths.socket_endpoint();
        assert!(endpoint.as_os_str().len() <= 100, "{endpoint:?}");
    }
}
