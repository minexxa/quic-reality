//! quic-reality: QUIC transport with Xray-grade REALITY authentication.
//!
//! Topology:
//!
//! ```text
//! client                gateway (server)                dest
//!   |  UDP salamander?    |                                |
//!   |--QUIC Initial------>| decrypt Initial, extract CH,   |
//!   |                     | verify REALITY session id       |
//!   |                     |-- admit: feed to quinn endpoint |
//!   |                     |-- reject: 4-tuple NAT relay -->| real TLS site
//! ```

mod client;
mod config;
mod congestion;
mod gate;
mod protocol;
mod quic_initial;
mod reality;
mod salamander;
mod server;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::{Config, Mode};
use ring::digest;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "quic-reality", about = "QUIC + REALITY stealth proxy v0.4")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Generate an X25519 key pair for REALITY authentication.
    Keygen,
    /// Print an example configuration.
    Example {
        #[arg(long)]
        client: bool,
    },
    /// Print the SHA-256 fingerprint of a PEM certificate file.
    Fingerprint {
        #[arg(long)]
        cert: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => {
            let kp = reality::KeyPair::generate();
            println!("private_key = \"{}\"", kp.private_hex());
            println!("public_key  = \"{}\"", kp.public_hex());
        }
        Commands::Example { client } => {
            if client {
                println!(
                    "{}",
                    Config::example_client("YOUR_PUBLIC_KEY_HEX", "YOUR_SERVER:8443")
                );
            } else {
                println!("{}", Config::example_server());
            }
        }
        Commands::Fingerprint { cert } => {
            let pem = std::fs::read_to_string(&cert)?;
            let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()?;
            let Some(first) = certs.first() else {
                bail!("no certificate found in {}", cert.display());
            };
            let d = digest::digest(&digest::SHA256, first.as_ref());
            println!("{}", hex::encode(d.as_ref()));
        }
        Commands::Run { config } => {
            let cfg = Config::load(&config)?;
            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));
            tracing_subscriber::fmt().with_env_filter(filter).init();
            match cfg.mode {
                Mode::Server => {
                    if cfg.reality.private_key.is_empty() {
                        bail!("server needs reality.private_key");
                    }
                    info!("quic-reality server v0.4");
                    server::run(cfg).await?;
                }
                Mode::Client => {
                    if cfg.reality.public_key.is_empty() || cfg.server.is_empty() {
                        bail!("client needs public_key and server");
                    }
                    info!("quic-reality client v0.4");
                    client::run(cfg).await?;
                }
            }
        }
    }
    Ok(())
}
