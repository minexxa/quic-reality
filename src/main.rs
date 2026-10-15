mod auth;
mod cert;
mod cid;
mod client;
mod config;
mod initial;
mod protocol;
mod reality_socket;
mod salamander;
mod server;
mod tls;
mod util;

#[cfg(test)]
mod e2e;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{Config, Mode};
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "quic-reality", about = "QUIC + REALITY-style stealth proxy")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a server or client from a TOML config.
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Generate an X25519 key pair.
    Keygen,
    /// Print an example config.
    Example {
        #[arg(long)]
        client: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Keygen => {
            let kp = auth::KeyPair::generate();
            println!("private_key = \"{}\"", kp.private_hex());
            println!("public_key  = \"{}\"", kp.public_hex());
        }
        Commands::Example { client } => {
            if client {
                println!("{}", Config::example_client("YOUR_PUBLIC_KEY_HEX", "YOUR_SERVER:443"));
            } else {
                println!("{}", Config::example_server());
            }
        }
        Commands::Run { config } => {
            let cfg = Config::load(&config)?;
            let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));
            tracing_subscriber::fmt().with_env_filter(filter).init();
            if cfg.quic.chrome_parrot.is_some() {
                warn!("quic.chrome_parrot is deprecated and ignored");
            }
            match cfg.mode {
                Mode::Server => {
                    info!("quic-reality server {}", env!("CARGO_PKG_VERSION"));
                    server::run(cfg).await?;
                }
                Mode::Client => {
                    info!("quic-reality client {}", env!("CARGO_PKG_VERSION"));
                    client::run(cfg).await?;
                }
            }
        }
    }
    Ok(())
}
