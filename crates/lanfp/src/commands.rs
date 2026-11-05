//! Implementation of the CLI subcommands (client side).

use crate::cli::{Commands, DaemonCmd, ForwardCmd};
use crate::client::{self, CliError};
use crate::config::{parse_duration, Config};
use crate::daemon;
use crate::install;
use crate::output::{join_ports, print_table};
use crate::paths::Paths;
use crate::util::{format_uptime, print_json, relative_time};
use lanfp_core::error::ExitCode;
use lanfp_core::ipc::*;
use serde::de::DeserializeOwned;
use std::io::{IsTerminal, Write};
use std::time::Duration;

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

pub async fn dispatch(command: Commands) -> Result<(), CliError> {
    match command {
        Commands::Scan(args) => scan(args).await,
        Commands::Pair(args) => pair(args).await,
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
        eprintln!("hint: if mDNS is blocked, pair manually with `lanfp pair <ip>[:port]`");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = result
        .peers
        .iter()
        .map(|p| {
            vec![
                p.peer.clone(),
                p.port.to_string(),
                if p.paired { "paired" } else { "unpaired" }.to_string(),
            ]
        })
        .collect();
    print_table(&["PEER", "PORT", "STATE"], &rows);
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
    if let Some(note) = daemon::offline_notice(&result.offline) {
        eprintln!("{note}");
    }
    if args.json {
        return print_json(&result).map_err(CliError::internal);
    }
    let mut rows = Vec::new();
    for peer in &result.peers {
        for port in &peer.ports {
            rows.push(vec![
                peer.peer.clone(),
                port.port.to_string(),
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
    }
    print_table(
        &["PEER", "PORT", "BIND", "PROCESS", "USER", "FORWARDED"],
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
    let rows: Vec<Vec<String>> = result
        .forwards
        .iter()
        .map(|f| {
            vec![
                f.local.to_string(),
                f.peer.clone(),
                f.target.to_string(),
                f.state.as_str().to_string(),
                relative_time(f.since),
            ]
        })
        .collect();
    print_table(&["LOCAL", "PEER", "TARGET", "STATE", "SINCE"], &rows);
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
    let rows: Vec<Vec<String>> = result
        .inbound
        .iter()
        .map(|i| {
            vec![
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

async fn pair(args: crate::cli::PairArgs) -> Result<(), CliError> {
    match args.peer.clone() {
        None => Err(CliError::new(
            ExitCode::Usage,
            "usage: lanfp pair <peer> | lanfp pair wait",
        )),
        Some(selector) if selector == "wait" => pair_wait(args).await,
        Some(selector) => pair_initiate(args, selector).await,
    }
}

async fn pair_initiate(args: crate::cli::PairArgs, selector: String) -> Result<(), CliError> {
    let paths = paths()?;
    if !args.json {
        println!("connecting to {selector}...");
    }
    let response = client::call(
        &paths,
        Command::PairStart {
            peer: selector.clone(),
        },
        true,
    )
    .await?;
    let started: PairStartResult = decode(response.data)?;

    let code = match args.code.clone() {
        Some(code) => code,
        None => prompt_code(&started.peer)?,
    };
    if code.trim().is_empty() {
        return Err(CliError::new(
            ExitCode::PairingFailed,
            "no pairing code entered",
        ));
    }
    let response = client::call(
        &paths,
        Command::PairFinish {
            token: started.token,
            code: code.trim().to_string(),
            force: args.force,
        },
        false,
    )
    .await?;
    let finished: PairFinishResult = decode(response.data)?;
    if args.json {
        return print_json(&finished).map_err(CliError::internal);
    }
    println!("paired with {}", finished.peer);
    Ok(())
}

fn prompt_code(peer: &str) -> Result<String, CliError> {
    let prompt = format!("pairing code (shown on {peer}): ");
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)
            .map(|s| s.trim().to_string())
            .map_err(|e| CliError::new(ExitCode::PairingFailed, format!("cannot read code: {e}")))
    } else {
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map_err(|e| {
            CliError::new(ExitCode::PairingFailed, format!("cannot read code: {e}"))
        })?;
        Ok(line.trim().to_string())
    }
}

async fn pair_wait(args: crate::cli::PairArgs) -> Result<(), CliError> {
    let paths = paths()?;
    let timeout_secs = match args.timeout.as_deref() {
        Some(raw) => parse_duration(raw)
            .map_err(|e| CliError::new(ExitCode::Usage, e.to_string()))?
            .as_secs(),
        None => 0,
    };
    let response = client::call(&paths, Command::PairWaitStart { timeout_secs }, true).await?;
    let started: PairWaitStartResult = decode(response.data)?;
    println!("waiting for pairing request (Ctrl-C to cancel)...");

    let mut announced = false;
    let mut last_attempts: Option<u32> = Some(started.max_attempts);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = client::call(&paths, Command::PairCancel { token: started.token }, false).await;
                println!();
                println!("cancelled");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
        let response = client::call(
            &paths,
            Command::PairWaitPoll {
                token: started.token,
            },
            false,
        )
        .await?;
        let poll: PairWaitPollResult = decode(response.data)?;
        match poll.state {
            PairWaitState::Waiting => {
                if let Some(left) = poll.attempts_left {
                    if last_attempts.map(|last| left < last).unwrap_or(false) {
                        eprintln!("pairing attempt rejected; {left} attempt(s) left");
                    }
                    last_attempts = Some(left);
                }
            }
            PairWaitState::Incoming => {
                if !announced {
                    println!("incoming: {}", poll.peer.clone().unwrap_or_default());
                    println!(
                        "pairing code: {}   expires in {}s",
                        poll.code.clone().unwrap_or_else(|| started.code.clone()),
                        poll.expires_in.unwrap_or(started.timeout_secs)
                    );
                    announced = true;
                }
            }
            PairWaitState::Paired => {
                println!("paired with {}", poll.peer.unwrap_or_default());
                return Ok(());
            }
            PairWaitState::Failed => {
                let code = ExitCode::from_code(poll.exit_code.unwrap_or(9))
                    .unwrap_or(ExitCode::PairingFailed);
                return Err(CliError::new(
                    code,
                    poll.message.unwrap_or_else(|| "pairing failed".into()),
                ));
            }
        }
    }
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
                println!("{}", serde_json::json!({"schema": 1, "running": false}));
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
    println!("agent: {}", status.agent_addr);
    println!("ipc: {}", status.ipc_path);
    println!("log: {}", status.log_path);
    println!(
        "peers: {} paired, {} online",
        status.peers_paired, status.peers_online
    );
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
    println!("removed login autostart: {target}");
    Ok(())
}
