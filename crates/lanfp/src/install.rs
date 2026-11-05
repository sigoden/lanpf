//! Optional login autostart registration (`lanfp daemon install`).

use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
pub fn install(_paths: &Paths) -> Result<String> {
    let exe = std::env::current_exe().context("locate lanfp executable")?;
    let home_env = std::env::var("LANFP_HOME").ok();

    if systemd_user_available() {
        let unit_path = systemd_unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut unit = String::from(
            "[Unit]\n\
             Description=lanfp LAN port forwarding agent\n\
             After=network-online.target\n\
             Wants=network-online.target\n\n\
             [Service]\n\
             Type=simple\n",
        );
        unit.push_str(&format!("ExecStart={}\n", quote_exec(&exe)));
        unit.push_str("Restart=on-failure\nRestartSec=2\nEnvironment=RUST_LOG=info\n");
        if let Some(home) = &home_env {
            unit.push_str(&format!("Environment=LANFP_HOME={home}\n"));
        }
        unit.push_str("\n[Install]\nWantedBy=default.target\n");
        std::fs::write(&unit_path, unit)
            .with_context(|| format!("write {}", unit_path.display()))?;
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", "--now", "lanfp.service"])?;
        return Ok(unit_path.display().to_string());
    }

    let desktop_path = autostart_desktop_path()?;
    if let Some(parent) = desktop_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut desktop = String::from(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=lanfp\n\
         Comment=LAN port forwarding agent\n\
         Terminal=false\n\
         Hidden=false\n\
         X-GNOME-Autostart-enabled=true\n",
    );
    desktop.push_str(&format!("Exec={}\n", quote_exec(&exe)));
    std::fs::write(&desktop_path, desktop)
        .with_context(|| format!("write {}", desktop_path.display()))?;
    Ok(desktop_path.display().to_string())
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
pub fn install(paths: &Paths) -> Result<String> {
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
    let _ = run("launchctl", &["unload", &plist_path.display().to_string()]);
    run(
        "launchctl",
        &["load", "-w", &plist_path.display().to_string()],
    )?;
    Ok(plist_path.display().to_string())
}

#[cfg(target_os = "macos")]
pub fn uninstall(paths: &Paths) -> Result<String> {
    let _ = paths;
    let plist_path = launch_agent_path()?;
    if !plist_path.exists() {
        bail!("no lanfp LaunchAgent is installed");
    }
    let _ = run(
        "launchctl",
        &["unload", "-w", &plist_path.display().to_string()],
    );
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
pub fn install(_paths: &Paths) -> Result<String> {
    let exe = std::env::current_exe().context("locate lanfp executable")?;
    let command = format!("\"{}\" serve", exe.display());
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
    Ok(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\lanfp".to_string())
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
pub fn install(_paths: &Paths) -> Result<String> {
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
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
