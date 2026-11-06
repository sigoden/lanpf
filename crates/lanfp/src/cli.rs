//! Command-line definition.

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "lanfp", version, about = "LAN port-forwarding manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan the LAN with mDNS and list discovered devices.
    Scan(ScanArgs),
    /// Authorize devices to access this machine, or manage known devices.
    #[command(subcommand)]
    Peer(PeerCmd),
    /// List this machine's Native listening ports.
    Local(JsonArgs),
    /// List exposed ports of servers that authorized this machine.
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
    /// Print machine-readable JSON (`schema: 2`).
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
pub struct RemoteArgs {
    /// Only list this server.
    #[arg(value_name = "PEER")]
    pub peer: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum PeerCmd {
    /// List devices authorized to access this machine.
    List(JsonArgs),
    /// Authorize one or more devices; without PEER, pick from a scan.
    Grant(PeerGrantArgs),
    /// Revoke the authorization of one or more devices.
    Revoke(PeerRevokeArgs),
    /// Update the address used to reach a known device.
    SetAddress(PeerSetAddressArgs),
}

#[derive(Debug, Args)]
pub struct PeerGrantArgs {
    /// Peer selectors (`<name>`, `<uuid>`, `<ip>[:port]`). Omit to scan and pick.
    #[arg(value_name = "PEER", num_args = 0..)]
    pub peers: Vec<String>,
    /// Replace a device's key after a reinstall.
    #[arg(long)]
    pub force: bool,
    /// Print JSON instead of text (requires at least one PEER).
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PeerRevokeArgs {
    /// Peer selectors (`<name>`, `<uuid>`, `<ip>[:port]`).
    #[arg(value_name = "PEER", required = true, num_args = 1..)]
    pub peers: Vec<String>,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PeerSetAddressArgs {
    /// Peer selector (`<name>`, `<name>@<address>`, or `<uuid>`).
    #[arg(value_name = "PEER")]
    pub peer: String,
    /// New address as `<ip>[:port]`; the port defaults to 47811.
    #[arg(value_name = "ADDRESS")]
    pub address: String,
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
    /// Port exposed by the peer.
    #[arg(value_name = "TARGET_PORT")]
    pub target_port: u16,
    /// Local loopback port (defaults to the target port; 0 picks a free port).
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
