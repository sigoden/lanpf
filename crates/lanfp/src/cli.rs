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
    /// Pair with a device, or manage paired devices.
    #[command(subcommand)]
    Peer(PeerCmd),
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
pub struct RemoteArgs {
    /// Only list this peer.
    #[arg(value_name = "PEER")]
    pub peer: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum PeerCmd {
    /// Pair with a device (start the 6-digit handshake).
    Add(PeerAddArgs),
    /// Wait for an incoming pairing request and show the 6-digit code.
    Wait(PeerWaitArgs),
    /// List paired devices with their stable IDs.
    List(JsonArgs),
    /// Update the address used to reach a paired device.
    SetAddress(PeerSetAddressArgs),
}

#[derive(Debug, Args)]
pub struct PeerAddArgs {
    /// Peer selector (`<name>@<address>`, `<ip>[:port]`).
    #[arg(value_name = "PEER")]
    pub peer: String,
    /// Pairing code shown on the waiting device (skips the prompt).
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,
    /// Replace an existing trust entry when the device's key changed.
    #[arg(long)]
    pub force: bool,
    /// Print JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PeerWaitArgs {
    /// How long to wait for an incoming request (e.g. 300s).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
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
    /// Native port on the peer.
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
