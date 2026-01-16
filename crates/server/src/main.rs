mod approval;
mod claude_process;
mod tls;

use anyhow::Result;
use clap::Parser;
use claude_remote_common::Config;
use rustls::crypto::ring::default_provider;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "claude-remote-server")]
#[command(about = "Remote control server for Claude Code")]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0")]
    address: String,

    /// Listen port
    #[arg(short, long, default_value = "7433")]
    port: u16,

    /// Config directory
    #[arg(long)]
    config_dir: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider
    default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();

    let config = match &args.config_dir {
        Some(dir) => Config::with_dir(dir.into()),
        None => Config::new(),
    };

    tracing::info!("Config directory: {:?}", config.config_dir());

    // Channel for approval requests from connection handlers to GUI
    let (approval_tx, approval_rx) = mpsc::channel::<approval::ApprovalRequest>(16);

    // Channel for activity messages from connection handlers to GUI
    let (activity_tx, activity_rx) = mpsc::channel::<approval::Activity>(256);

    // Start TLS server
    let server = tls::Server::new(&config, &args.address, args.port, approval_tx, activity_tx).await?;
    let server = Arc::new(server);

    // Spawn server accept loop
    let server_clone = server.clone();
    tokio::spawn(async move {
        if let Err(e) = server_clone.run().await {
            tracing::error!("Server error: {}", e);
        }
    });

    // Run GUI for approval dialogs (blocks main thread)
    approval::run_gui(approval_rx, activity_rx, config)?;

    Ok(())
}
