//! lanfp — LAN port-forwarding manager.

mod cli;
mod client;
mod commands;
mod config;
mod daemon;
mod db;
mod discovery;
mod forward;
mod install;
mod inventory_svc;
mod output;
mod pairing;
mod paths;
mod session;
mod util;

use clap::Parser;

#[tokio::main]
async fn main() {
    // Behave like a conventional Unix tool when stdout is closed early (for
    // example `lanfp remote | head`): terminate quietly instead of panicking
    // on a failed `println!`.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = cli::Cli::parse();
    if let Err(err) = commands::dispatch(cli.command).await {
        if !err.message.is_empty() {
            eprintln!("lanfp: {}", err.message);
        }
        std::process::exit(err.code.code());
    }
}
