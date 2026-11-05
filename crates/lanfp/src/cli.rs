//! Command-line definition.

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "lanfp",
    version,
    about = "LAN port-forwarding manager",
    long_about = "lanfp forwards TCP ports from this machine to services on paired devices in the same LAN.\n\n\
Pairing authorizes the other device to create forwards to any of your listening TCP ports. \
This version has no revoke or deny command; `lanfp inbound` is read-only. \
Forwarding listeners only bind 127.0.0.1 and the agent port is the only LAN-facing listener. \
On Linux/macOS a user-level process cannot listen on ports below 1024; use `--listen` with a high port. Process ownership for other users may be unavailable; ports are still listed and the owner columns show `-`."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan the LAN with mDNS and list discovered devices.
    Scan(ScanArgs),
    /// Pair with a device, or wait for an incoming pairing request.
    Pair(PairArgs),
    /// List this machine's Native listening ports.
    Local(JsonArgs),
    /// List Native ports of paired devices.
    Remote(RemoteArgs),
    /// Manage forwarding rules.
    #[command(subcommand)]
    Forward(ForwardCmd),
    /// Read-only view of who is forwarding this machine's ports.
    Inbound(JsonArgs),
    /// Run the daemon in the foreground (debugging).
    Serve(ServeArgs),
    /// Manage the background daemon.
    #[command(subcommand)]
    Daemon(DaemonCmd),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Detach from the console; used by the Windows login autostart entry.
    #[arg(long, hide = true)]
    pub hidden: bool,
}

#[derive(Debug, Args)]
pub struct JsonArgs {
    /// Print machine-readable JSON (`schema: 1`).
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// How long to wait for mDNS responses (e.g. 3s).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Peer selector (`<name>@<address>`, `<ip>[:port]`) or `wait`.
    #[arg(value_name = "PEER")]
    pub peer: Option<String>,
    /// Pairing code shown on the waiting device (skips the prompt).
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,
    /// Replace an existing trust entry when the device's key changed.
    #[arg(long)]
    pub force: bool,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
    /// Timeout for `pair wait` (e.g. 300s).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

#[derive(Debug, Args)]
pub struct RemoteArgs {
    /// Only list this peer.
    #[arg(value_name = "PEER")]
    pub peer: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ForwardCmd {
    /// Create a forwarding rule.
    Add(ForwardAddArgs),
    /// List forwarding rules.
    List(JsonArgs),
    /// Remove a forwarding rule by local listen port.
    Remove(ForwardRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ForwardAddArgs {
    /// Peer selector (`<name>@<address>` or `<ip>[:port]`).
    #[arg(value_name = "PEER")]
    pub peer: String,
    /// Native port on the peer.
    #[arg(value_name = "TARGET_PORT")]
    pub target_port: u16,
    /// Local loopback port (defaults to the target port).
    #[arg(long, value_name = "PORT")]
    pub listen: Option<u16>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ForwardRemoveArgs {
    /// Local listen port of the rule.
    #[arg(value_name = "LOCAL_PORT")]
    pub local_port: u16,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCmd {
    /// Start the background daemon.
    Start,
    /// Stop the background daemon.
    Stop,
    /// Show daemon status.
    Status(JsonArgs),
    /// Register login autostart (systemd user unit / LaunchAgent / HKCU Run).
    Install,
    /// Remove login autostart.
    Uninstall,
}
