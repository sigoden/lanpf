//! Implementation of the CLI subcommands (client side).

use crate::cli::{Commands, DaemonCmd, ForwardCmd, PeerCmd};
use crate::client::{self, CliError};
use crate::config::{parse_duration, Config};
use crate::daemon;
use crate::install;
use crate::output::{join_ports, print_table};
use crate::paths::Paths;
use crate::util::{format_uptime, print_json, relative_time};
use lanfp_core::error::ExitCode;
use lanfp_core::ipc::*;
use lanfp_core::{short_id, short_ids, PROTOCOL_VERSION};
use serde::de::DeserializeOwned;
use std::io::{IsTerminal, Write};

fn decode<T: DeserializeOwned>(value: Option<serde_json::Value>) -> Result<T, CliError> {
    let value = value.unwrap_or(serde_json::Value::Null);
    serde_json::from_value(value).map_err(|e| {
        CliError::new(
            ExitCode::DaemonUnavailable,
            format!("bad daemon response: {e}"),
        )
    })
}

fn paths() -> Result<Paths, CliError> {
    Paths::resolve().map_err(CliError::internal)
}

fn offline_notice(result: &RemoteResult) -> Option<String> {
    if result.offline_peers.is_empty() {
        if result.offline.is_empty() {
            return None;
        }
        return Some(format!(
            "skipping offline device(s): {}",
            result.offline.join(", ")
        ));
    }
    let list = result
        .offline_peers
        .iter()
        .map(|peer| format!("{} [{}]", peer.peer, short_id(peer.id)))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!("skipping offline device(s): {list}"))
}

pub async fn dispatch(command: Commands) -> Result<(), CliError> {
    match command {
        Commands::Scan(args) => scan(args).await,
        Commands::Peer(cmd) => match cmd {
            PeerCmd::List(args) => peer_list(args).await,
            PeerCmd::Grant(args) => peer_grant(args).await,
            PeerCmd::Revoke(args) => peer_revoke(args).await,
            PeerCmd::SetAddress(args) => peer_set_address(args).await,
        },
        Commands::Local(args) => local(args).await,
        Commands::Remote(args) => remote(args).await,
        Commands::Forward(cmd) => match cmd {
            ForwardCmd::Add(args) => forward_add(args).await,
            ForwardCmd::List(args) => forward_list(args).await,
            ForwardCmd::Remove(args) => forward_remove(args).await,
        },
        Commands::Inbound(args) => inbound(args).await,
        Commands::Serve(args) => serve(args).await,
        Commands::Daemon(cmd) => match cmd {
            DaemonCmd::Start => daemon_start().await,
            DaemonCmd::Stop => daemon_stop().await,
            DaemonCmd::Status(args) => daemon_status(args.json).await,
            DaemonCmd::Install => install_autostart(),
            DaemonCmd::Uninstall => uninstall_autostart(),
        },
    }
}

fn scan_state(peer: &ScanPeer) -> &'static str {
    if peer.version != PROTOCOL_VERSION {
        "incompatible"
    } else if peer.authorized {
        "authorized"
    } else if peer.known {
        "server"
    } else {
        "unknown"
    }
}

async fn scan(args: crate::cli::ScanArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let timeout_ms = match args.timeout.as_deref() {
        Some(raw) => parse_duration(raw)
            .map_err(|e| CliError::new(ExitCode::Usage, e.to_string()))?
            .as_millis() as u64,
        None => 0,
    };
    let response = client::call(&paths, Command::Scan { timeout_ms }, true).await?;
    let result: ScanResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    if result.peers.is_empty() {
        println!("no devices discovered");
        eprintln!(
            "hint: start `lanfp serve` on the other device, or use `lanfp peer grant <ip>[:port]`"
        );
        return Ok(());
    }
    let ids: Vec<_> = result.peers.iter().map(|p| p.id).collect();
    let short = short_ids(&ids);
    let rows: Vec<Vec<String>> = result
        .peers
        .iter()
        .zip(short)
        .map(|(p, id)| {
            vec![
                id,
                p.peer.clone(),
                p.port.to_string(),
                p.version.to_string(),
                scan_state(p).to_string(),
            ]
        })
        .collect();
    print_table(&["PEER ID", "PEER", "PORT", "VERSION", "STATE"], &rows);
    Ok(())
}

async fn peer_grant(args: crate::cli::PeerGrantArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let mut selectors = args.peers.clone();
    if selectors.is_empty() {
        if args.json {
            return Err(CliError::new(
                ExitCode::Usage,
                "`lanfp peer grant --json` requires at least one PEER",
            ));
        }
        if !std::io::stdin().is_terminal() {
            return Err(CliError::new(
                ExitCode::Usage,
                "stdin is not a terminal; pass a PEER: `lanfp peer grant <name|uuid|ip>`",
            ));
        }
        let Some(selector) = interactive_grant_target(&paths).await? else {
            println!("cancelled");
            return Ok(());
        };
        selectors.push(selector);
    }

    let response = client::call(
        &paths,
        Command::PeerGrant {
            peers: selectors,
            force: args.force,
        },
        true,
    )
    .await?;
    let result: PeerGrantResult = decode(response.data)?;
    if args.json {
        print_json(&result).map_err(CliError::internal)?;
    } else {
        for peer in &result.granted {
            if peer.already_granted {
                println!(
                    "already granted {} [{}] (refreshed)",
                    peer.peer,
                    short_id(peer.id)
                );
            } else {
                println!("granted {} [{}]", peer.peer, short_id(peer.id));
            }
            println!("key fingerprint: {}", peer.fingerprint);
            println!("this device may now connect and forward exposed ports on this machine");
        }
        for failure in &result.failed {
            eprintln!("failed to grant {}: {}", failure.peer, failure.message);
        }
    }
    if let Some(failure) = result.failed.first() {
        let code = ExitCode::from_code(failure.code).unwrap_or(ExitCode::AuthorizationFailed);
        return Err(CliError::new(code, ""));
    }
    Ok(())
}

async fn interactive_grant_target(paths: &Paths) -> Result<Option<String>, CliError> {
    let response = client::call(paths, Command::Scan { timeout_ms: 0 }, true).await?;
    let result: ScanResult = decode(response.data)?;
    let candidates: Vec<&ScanPeer> = result
        .peers
        .iter()
        .filter(|p| p.version == PROTOCOL_VERSION)
        .collect();
    if candidates.is_empty() {
        let incompatible = result.peers.len();
        let detail = if incompatible > 0 {
            format!(" ({incompatible} incompatible device(s) skipped)")
        } else {
            String::new()
        };
        return Err(CliError::new(
            ExitCode::DeviceNotFound,
            format!("no devices available to authorize{detail}; start `lanfp serve` on the other device or pass an address"),
        ));
    }
    println!("discovered devices:");
    for (index, peer) in candidates.iter().enumerate() {
        println!(
            "  {}. {:<10} {:<32} {}",
            index + 1,
            short_id(peer.id),
            peer.peer,
            if peer.authorized {
                "authorized"
            } else if peer.known {
                "server"
            } else {
                "unknown"
            }
        );
    }
    print!("select device [1-{}] (q to cancel): ", candidates.len());
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::new(ExitCode::Usage, format!("cannot read selection: {e}")))?;
    let line = line.trim();
    if line.eq_ignore_ascii_case("q") {
        return Ok(None);
    }
    let index: usize = line.parse().map_err(|_| {
        CliError::new(
            ExitCode::Usage,
            format!(
                "`{line}` is not a selection between 1 and {}",
                candidates.len()
            ),
        )
    })?;
    let Some(peer) = index.checked_sub(1).and_then(|i| candidates.get(i)) else {
        return Err(CliError::new(
            ExitCode::Usage,
            format!("selection must be between 1 and {}", candidates.len()),
        ));
    };
    Ok(Some(peer.id.to_string()))
}

async fn peer_revoke(args: crate::cli::PeerRevokeArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(&paths, Command::PeerRevoke { peers: args.peers }, true).await?;
    let result: PeerRevokeResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    for peer in &result.revoked {
        println!("revoked {} [{}]", peer.peer, short_id(peer.id));
    }
    Ok(())
}

async fn peer_list(args: crate::cli::JsonArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(&paths, Command::PeerList, true).await?;
    let result: PeerListResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    if result.peers.is_empty() {
        println!("no devices are authorized to access this machine");
        eprintln!("hint: use `lanfp peer grant` to authorize a device");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = result
        .peers
        .iter()
        .map(|p| {
            vec![
                p.id.to_string(),
                p.name.clone(),
                if p.address.is_empty() {
                    "-".into()
                } else {
                    p.address.clone()
                },
                p.port.to_string(),
                if p.online { "online" } else { "offline" }.to_string(),
                relative_time(p.since),
            ]
        })
        .collect();
    print_table(&["ID", "NAME", "ADDRESS", "PORT", "STATE", "SINCE"], &rows);
    Ok(())
}

async fn peer_set_address(args: crate::cli::PeerSetAddressArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(
        &paths,
        Command::PeerSetAddress {
            peer: args.peer,
            address: args.address,
        },
        true,
    )
    .await?;
    let result: PeerSetAddressResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    if result.online {
        println!("updated {} [{}] (online)", result.peer, short_id(result.id));
    } else {
        println!(
            "updated {} [{}] (offline; retrying in the background)",
            result.peer,
            short_id(result.id)
        );
    }
    Ok(())
}

async fn local(args: crate::cli::JsonArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(&paths, Command::Local, true).await?;
    let result: LocalResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    let rows: Vec<Vec<String>> = result
        .ports
        .iter()
        .map(|p| {
            vec![
                p.port.to_string(),
                p.bind_display(),
                p.process_display().to_string(),
                p.pid_display(),
                p.user_display().to_string(),
            ]
        })
        .collect();
    print_table(&["PORT", "BIND", "PROCESS", "PID", "USER"], &rows);
    Ok(())
}

async fn remote(args: crate::cli::RemoteArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(
        &paths,
        Command::Remote {
            peer: args.peer.clone(),
        },
        true,
    )
    .await?;
    let result: RemoteResult = decode(response.data)?;
    if let Some(note) = offline_notice(&result) {
        eprintln!("{note}");
    }
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    let mut ids = Vec::new();
    let mut rows = Vec::new();
    for peer in &result.peers {
        for port in &peer.ports {
            ids.push(peer.id);
            rows.push(vec![
                peer.peer.clone(),
                port.port.to_string(),
                if port.listening {
                    "listening".into()
                } else {
                    "not listening".into()
                },
                if port.bind.is_empty() {
                    "-".into()
                } else {
                    port.bind.join(",")
                },
                port.process.clone().unwrap_or_else(|| "-".into()),
                port.user.clone().unwrap_or_else(|| "-".into()),
                if port.forwarded.is_empty() {
                    "-".into()
                } else {
                    format!("-> {}", join_ports(&port.forwarded))
                },
            ]);
        }
        // Whitelist ranges may cover ports that are not listening; surface
        // them so the consumer learns the server's exposure policy. A single
        // port already listed above is not repeated as a one-port range.
        let listed_ports: Vec<u16> = peer.ports.iter().map(|p| p.port).collect();
        for range in &peer.ranges {
            if range.lo == range.hi && listed_ports.contains(&range.lo) {
                continue;
            }
            ids.push(peer.id);
            rows.push(vec![
                peer.peer.clone(),
                range.display(),
                "whitelisted".into(),
                "-".into(),
                "-".into(),
                "-".into(),
                "-".into(),
            ]);
        }
    }
    let short = short_ids(&ids);
    let rows: Vec<Vec<String>> = rows
        .into_iter()
        .zip(short)
        .map(|(mut row, id)| {
            row.insert(0, id);
            row
        })
        .collect();
    print_table(
        &[
            "PEER ID",
            "PEER",
            "PORT",
            "STATE",
            "BIND",
            "PROCESS",
            "USER",
            "FORWARDED",
        ],
        &rows,
    );
    Ok(())
}

async fn forward_add(args: crate::cli::ForwardAddArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(
        &paths,
        Command::ForwardAdd {
            peer: args.peer,
            target_port: args.target_port,
            listen: args.listen,
        },
        true,
    )
    .await?;
    let result: ForwardAddResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    println!(
        "created {} -> {}:{} ({})",
        result.local, result.peer, result.target, result.state
    );
    Ok(())
}

async fn forward_list(args: crate::cli::JsonArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(&paths, Command::ForwardList, true).await?;
    let result: ForwardListResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    let ids: Vec<_> = result.forwards.iter().map(|f| f.peer_id).collect();
    let short = short_ids(&ids);
    let rows: Vec<Vec<String>> = result
        .forwards
        .iter()
        .zip(short)
        .map(|(f, id)| {
            vec![
                f.local.to_string(),
                id,
                f.peer.clone(),
                f.target.to_string(),
                f.state.as_str().to_string(),
                relative_time(f.since),
            ]
        })
        .collect();
    print_table(
        &["LOCAL", "PEER ID", "PEER", "TARGET", "STATE", "SINCE"],
        &rows,
    );
    Ok(())
}

async fn forward_remove(args: crate::cli::ForwardRemoveArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(
        &paths,
        Command::ForwardRemove {
            local_port: args.local_port,
        },
        true,
    )
    .await?;
    let result: ForwardRemoveResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    println!("removed {}", result.removed);
    Ok(())
}

async fn inbound(args: crate::cli::JsonArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let response = client::call(&paths, Command::Inbound, true).await?;
    let result: InboundResult = decode(response.data)?;
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    let ids: Vec<_> = result.inbound.iter().map(|i| i.id).collect();
    let short = short_ids(&ids);
    let rows: Vec<Vec<String>> = result
        .inbound
        .iter()
        .zip(short)
        .map(|(i, id)| {
            vec![
                id,
                i.peer.clone(),
                i.my_port.to_string(),
                i.peer_listen.to_string(),
                relative_time(i.since),
                relative_time(i.last_seen),
                if i.online { "online" } else { "offline" }.to_string(),
            ]
        })
        .collect();
    print_table(
        &[
            "PEER ID",
            "PEER",
            "MY PORT",
            "PEER LISTEN",
            "SINCE",
            "LAST SEEN",
            "STATE",
        ],
        &rows,
    );
    Ok(())
}

async fn serve(args: crate::cli::ServeArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let config = Config::load_or_create(&paths.config_file()).map_err(CliError::internal)?;
    init_tracing();
    daemon::serve(paths, config, args.hidden)
        .await
        .map_err(|e| CliError::new(ExitCode::DaemonUnavailable, format!("{e:#}")))
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn daemon_status(json: bool) -> Result<(), CliError> {
    let paths = paths()?;
    let response = match client::call(&paths, Command::Status, false).await {
        Ok(response) => response,
        Err(err) if err.code == ExitCode::DaemonUnavailable => {
            if json {
                println!("{}", serde_json::json!({"schema": 2, "running": false}));
            } else {
                println!("lanfp is not running");
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    let status: StatusInfo = decode(response.data)?;
    if json {
        return print_json(&status).map_err(CliError::internal);
    }
    println!("pid: {}", status.pid);
    println!("uptime: {}", format_uptime(status.uptime_secs));
    println!("device: {}", status.device);
    println!("device id: {}", status.device_id);
    println!("fingerprint: {}", status.fingerprint);
    println!("agent: {}", status.agent_addr);
    println!("ipc: {}", status.ipc_path);
    println!("log: {}", status.log_path);
    println!("allowed: {} device(s)", status.allowed);
    println!("servers: {} device(s)", status.servers);
    println!("online: {}", status.online);
    println!("rules: {}", status.rules);
    Ok(())
}

async fn daemon_start() -> Result<(), CliError> {
    let paths = paths()?;
    let started = client::ensure_running(&paths).await?;
    if started {
        println!("lanfp daemon started");
    } else {
        println!("lanfp daemon is already running");
    }
    daemon_status(false).await
}

async fn daemon_stop() -> Result<(), CliError> {
    let paths = paths()?;
    match client::call(&paths, Command::DaemonStop, false).await {
        Ok(_) => {
            println!("lanfp daemon stopped");
            Ok(())
        }
        Err(err) if err.code == ExitCode::DaemonUnavailable => {
            println!("lanfp is not running");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn install_autostart() -> Result<(), CliError> {
    let paths = paths()?;
    let outcome = install::install(&paths).map_err(CliError::internal)?;
    println!("installed login autostart: {}", outcome.target);
    if outcome.started {
        println!("the daemon is running; check it with `lanfp daemon status`");
    } else {
        println!(
            "the daemon will start at the next login; run `lanfp daemon start` to start it now"
        );
    }
    Ok(())
}

fn uninstall_autostart() -> Result<(), CliError> {
    let paths = paths()?;
    let target = install::uninstall(&paths).map_err(CliError::internal)?;
    uninstall_result(target)
}

fn uninstall_result(target: Option<String>) -> Result<(), CliError> {
    match target {
        Some(target) => {
            println!("removed login autostart: {target}");
            Ok(())
        }
        None => Err(CliError::new(
            ExitCode::DeviceNotFound,
            "no login autostart entry is installed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_without_an_entry_is_not_found() {
        let err = uninstall_result(None).expect_err("missing autostart entry must fail");
        assert_eq!(err.code, ExitCode::DeviceNotFound);
        assert!(err.message.contains("no login autostart"));
    }

    #[test]
    fn uninstall_with_an_entry_succeeds() {
        uninstall_result(Some("unit".into())).expect("removing an entry succeeds");
    }
}
