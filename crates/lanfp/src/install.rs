//! Optional login autostart registration (`lanfp daemon install`).

use crate::paths::Paths;
use anyhow::{bail, Context, Result};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
use std::process::Command;

/// Outcome of `lanfp daemon install`.
pub struct InstallOutcome {
    /// Path of the registered autostart entry.
    pub target: String,
    /// Whether the daemon was also started right now, not just at next login.
    pub started: bool,
}

#[cfg(target_os = "linux")]
pub fn install(_paths: &Paths) -> Result<InstallOutcome> {
    let exe = std::env::current_exe().context("locate lanfp executable")?;
    let home_env = std::env::var("LANFP_HOME").ok();

    if systemd_user_available() {
        let unit_path = systemd_unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let unit = systemd_unit_contents(&exe, home_env.as_deref());
        std::fs::write(&unit_path, unit)
            .with_context(|| format!("write {}", unit_path.display()))?;
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", "--now", "lanfp.service"])?;
        return Ok(InstallOutcome {
            target: unit_path.display().to_string(),
            started: true,
        });
    }

    let desktop_path = autostart_desktop_path()?;
    if let Some(parent) = desktop_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let desktop = desktop_entry_contents(&exe);
    std::fs::write(&desktop_path, desktop)
        .with_context(|| format!("write {}", desktop_path.display()))?;
    Ok(InstallOutcome {
        target: desktop_path.display().to_string(),
        started: false,
    })
}

#[cfg(target_os = "linux")]
pub fn uninstall(paths: &Paths) -> Result<String> {
    let _ = paths;
    let unit_path = systemd_unit_path()?;
    if unit_path.exists() {
        let _ = run(
            "systemctl",
            &["--user", "disable", "--now", "lanfp.service"],
        );
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("remove {}", unit_path.display()))?;
        let _ = run("systemctl", &["--user", "daemon-reload"]);
        return Ok(unit_path.display().to_string());
    }
    let desktop_path = autostart_desktop_path()?;
    if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)
            .with_context(|| format!("remove {}", desktop_path.display()))?;
        return Ok(desktop_path.display().to_string());
    }
    bail!("no lanfp autostart entry is installed")
}

#[cfg(target_os = "linux")]
fn systemd_unit_contents(exe: &Path, home_env: Option<&str>) -> String {
    let mut unit = String::from(
        "[Unit]\n\
         Description=lanfp LAN port forwarding agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n",
    );
    // Bare `lanfp` prints help and exits 2, so the unit must pass the daemon
    // subcommand explicitly.
    unit.push_str(&format!("ExecStart={} serve\n", quote_exec(exe)));
    unit.push_str("Restart=on-failure\nRestartSec=2\nEnvironment=RUST_LOG=info\n");
    if let Some(home) = home_env {
        unit.push_str(&format!("Environment=LANFP_HOME={home}\n"));
    }
    unit.push_str("\n[Install]\nWantedBy=default.target\n");
    unit
}

#[cfg(target_os = "linux")]
fn desktop_entry_contents(exe: &Path) -> String {
    let mut desktop = String::from(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=lanfp\n\
         Comment=LAN port forwarding agent\n\
         Terminal=false\n\
         Hidden=false\n\
         X-GNOME-Autostart-enabled=true\n",
    );
    // Same as the systemd unit: the desktop entry starts the daemon itself.
    desktop.push_str(&format!("Exec={} serve\n", quote_exec(exe)));
    desktop
}

#[cfg(target_os = "linux")]
fn systemd_user_available() -> bool {
    Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn systemd_unit_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("cannot determine the configuration directory")?;
    Ok(base.join("systemd/user/lanfp.service"))
}

#[cfg(target_os = "linux")]
fn autostart_desktop_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("cannot determine the configuration directory")?;
    Ok(base.join("autostart/lanfp.desktop"))
}

#[cfg(target_os = "macos")]
pub fn install(paths: &Paths) -> Result<InstallOutcome> {
    let exe = std::env::current_exe().context("locate lanfp executable")?;
    let plist_path = launch_agent_path()?;
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let home_env = std::env::var("LANFP_HOME").ok();
    let mut plist = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         <key>Label</key><string>com.lanfp.serve</string>\n\
         <key>ProgramArguments</key><array>\n",
    );
    plist.push_str(&format!(
        "<string>{}</string>\n<string>serve</string>\n",
        xml_escape(&exe.display().to_string())
    ));
    plist.push_str("</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><false/>\n");
    plist.push_str(&format!(
        "<key>StandardOutPath</key><string>{}</string>\n",
        xml_escape(&paths.log_file().display().to_string())
    ));
    plist.push_str(&format!(
        "<key>StandardErrorPath</key><string>{}</string>\n",
        xml_escape(&paths.log_file().display().to_string())
    ));
    if let Some(home) = home_env {
        plist.push_str("<key>EnvironmentVariables</key><dict><key>LANFP_HOME</key>");
        plist.push_str(&format!("<string>{}</string></dict>\n", xml_escape(&home)));
    }
    plist.push_str("</dict>\n</plist>\n");
    std::fs::write(&plist_path, plist)
        .with_context(|| format!("write {}", plist_path.display()))?;

    // The plist is registered; now try to activate it. `launchctl load` is
    // deprecated and fails silently on current macOS, so use bootstrap.
    // A GUI (Terminal) session can use the `gui/<uid>` domain; an SSH or other
    // background session can only try `user/<uid>`, and macOS 15 may reject
    // both with EIO. In that case the entry still starts at the next login.
    let uid = unsafe { libc::geteuid() };
    let label = "com.lanfp.serve";
    let plist_display = plist_path.display().to_string();
    let mut started = false;
    let mut last_error = None;
    for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
        let _ = run("launchctl", &["bootout", &format!("{domain}/{label}")]);
        match run("launchctl", &["bootstrap", &domain, &plist_display]) {
            Ok(()) => {
                let _ = run("launchctl", &["enable", &format!("{domain}/{label}")]);
                let _ = run(
                    "launchctl",
                    &["kickstart", "-k", &format!("{domain}/{label}")],
                );
                started = true;
                break;
            }
            Err(err) => last_error = Some(err),
        }
    }
    if !started {
        if let Some(err) = last_error {
            eprintln!(
                "warning: the LaunchAgent is installed but could not be started in this \
                 session ({err:#}); it will start at the next login"
            );
        }
    }
    Ok(InstallOutcome {
        target: plist_display,
        started,
    })
}

#[cfg(target_os = "macos")]
pub fn uninstall(paths: &Paths) -> Result<String> {
    let _ = paths;
    let plist_path = launch_agent_path()?;
    if !plist_path.exists() {
        bail!("no lanfp LaunchAgent is installed");
    }
    let uid = unsafe { libc::geteuid() };
    for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
        let _ = run(
            "launchctl",
            &["bootout", &format!("{domain}/com.lanfp.serve")],
        );
    }
    std::fs::remove_file(&plist_path)
        .with_context(|| format!("remove {}", plist_path.display()))?;
    Ok(plist_path.display().to_string())
}

#[cfg(target_os = "macos")]
fn launch_agent_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine the home directory")?;
    Ok(home.join("Library/LaunchAgents/com.lanfp.serve.plist"))
}

#[cfg(target_os = "macos")]
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "windows")]
pub fn install(_paths: &Paths) -> Result<InstallOutcome> {
    let exe = std::env::current_exe().context("locate lanfp executable")?;
    let command = format!("\"{}\" serve --hidden", exe.display());
    let status = Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "lanfp",
            "/t",
            "REG_SZ",
            "/d",
            &command,
            "/f",
        ])
        .status()
        .context("run reg.exe")?;
    if !status.success() {
        bail!("reg.exe failed with status {status}");
    }
    Ok(InstallOutcome {
        target: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\lanfp".to_string(),
        started: false,
    })
}

#[cfg(target_os = "windows")]
pub fn uninstall(_paths: &Paths) -> Result<String> {
    let status = Command::new("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "lanfp",
            "/f",
        ])
        .status()
        .context("run reg.exe")?;
    if !status.success() {
        bail!("no lanfp autostart entry is installed");
    }
    Ok(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\lanfp".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install(_paths: &Paths) -> Result<InstallOutcome> {
    bail!("login autostart is not supported on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn uninstall(_paths: &Paths) -> Result<String> {
    bail!("login autostart is not supported on this platform")
}

#[cfg(target_os = "linux")]
fn quote_exec(path: &Path) -> String {
    let text = path.display().to_string();
    if text.contains(' ') {
        format!("\"{text}\"")
    } else {
        text
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program} {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("{program} {} failed ({})", args.join(" "), output.status);
        }
        bail!("{program} {} failed: {stderr}", args.join(" "));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_starts_serve() {
        let exe = Path::new("/opt/lanfp/bin/lanfp");
        let unit = systemd_unit_contents(exe, None);
        assert!(
            unit.contains("ExecStart=/opt/lanfp/bin/lanfp serve\n"),
            "unit did not start the daemon: {unit}"
        );
    }

    #[test]
    fn systemd_unit_quotes_executable_with_spaces() {
        let exe = Path::new("/opt/lan fp/lanfp");
        let unit = systemd_unit_contents(exe, Some("/home/me/lanfp data"));
        assert!(
            unit.contains("ExecStart=\"/opt/lan fp/lanfp\" serve\n"),
            "unit did not quote the executable: {unit}"
        );
        assert!(unit.contains("Environment=LANFP_HOME=/home/me/lanfp data\n"));
    }

    #[test]
    fn desktop_entry_starts_serve() {
        let exe = Path::new("/usr/local/bin/lanfp");
        let desktop = desktop_entry_contents(exe);
        assert!(
            desktop.contains("Exec=/usr/local/bin/lanfp serve\n"),
            "desktop entry did not start the daemon: {desktop}"
        );
    }
}
