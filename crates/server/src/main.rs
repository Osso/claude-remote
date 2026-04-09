mod approval;
mod claude_process;
mod tls;

use anyhow::Result;
use clap::Parser;
use claude_remote_common::Config;
use rustls::crypto::ring::default_provider;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

/// Server runtime info
pub struct ServerInfo {
    /// When the server started
    pub started_at: std::time::SystemTime,
    /// Instant for uptime calculation
    pub start_instant: Instant,
    /// Binary version hash (first 8 chars of SHA256)
    pub version: String,
}

impl ServerInfo {
    fn new() -> Self {
        let version = Self::compute_binary_hash();
        Self {
            started_at: std::time::SystemTime::now(),
            start_instant: Instant::now(),
            version,
        }
    }

    fn compute_binary_hash() -> String {
        use std::io::Read;

        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return "unknown".to_string(),
        };

        let mut file = match std::fs::File::open(&exe_path) {
            Ok(f) => f,
            Err(_) => return "unknown".to_string(),
        };

        // Read first 64KB for fast hashing
        let mut buffer = vec![0u8; 64 * 1024];
        let n = file.read(&mut buffer).unwrap_or(0);
        buffer.truncate(n);

        // Simple hash using ring
        use ring::digest::{Context, SHA256};
        let mut context = Context::new(&SHA256);
        context.update(&buffer);
        let digest = context.finish();

        // Return first 8 hex chars
        digest.as_ref()[..4]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_instant.elapsed().as_secs()
    }

    pub fn started_at_iso(&self) -> String {
        use std::time::UNIX_EPOCH;
        let duration = self
            .started_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        // Return Unix timestamp as string (simple, no external deps)
        format!("{}", duration.as_secs())
    }
}

#[derive(Parser)]
#[command(name = "claude-remote-server")]
#[command(about = "Remote control server for Claude Code")]
struct Args {
    /// Listen address (ignored if --socket is used)
    #[arg(short, long, default_value = "0.0.0.0")]
    address: String,

    /// Listen port (ignored if --socket is used)
    #[arg(short, long, default_value = "7433")]
    port: u16,

    /// Unix socket path (alternative to address:port)
    #[arg(long)]
    socket: Option<String>,

    /// Config directory
    #[arg(long)]
    config_dir: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_rustls_provider();
    init_logging()?;
    let args = Args::parse();
    let config = load_config(&args);
    tracing::info!("Config directory: {:?}", config.config_dir());
    let server_info = Arc::new(ServerInfo::new());
    tracing::info!("Server version: {}", server_info.version);
    let (approval_tx, approval_rx) = mpsc::channel::<approval::ApprovalRequest>(16);
    let (activity_tx, activity_rx) = mpsc::channel::<approval::Activity>(256);
    let server = create_server(&args, &config, approval_tx, activity_tx, server_info).await?;
    let server = Arc::new(server);
    spawn_server_loop(server.clone());
    approval::run_gui(approval_rx, activity_rx, config)?;
    Ok(())
}

fn install_rustls_provider() {
    default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
}

fn init_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    Ok(())
}

fn load_config(args: &Args) -> Config {
    match &args.config_dir {
        Some(dir) => Config::with_dir(dir.into()),
        None => Config::new(),
    }
}

async fn create_server(
    args: &Args,
    config: &Config,
    approval_tx: mpsc::Sender<approval::ApprovalRequest>,
    activity_tx: mpsc::Sender<approval::Activity>,
    server_info: Arc<ServerInfo>,
) -> Result<tls::Server> {
    if let Some(socket_path) = &args.socket {
        return create_server_unix(config, socket_path, approval_tx, activity_tx, server_info)
            .await;
    }
    tls::Server::new(
        config,
        &args.address,
        args.port,
        approval_tx,
        activity_tx,
        server_info,
    )
    .await
}

#[cfg(unix)]
async fn create_server_unix(
    config: &Config,
    socket_path: &str,
    approval_tx: mpsc::Sender<approval::ApprovalRequest>,
    activity_tx: mpsc::Sender<approval::Activity>,
    server_info: Arc<ServerInfo>,
) -> Result<tls::Server> {
    tls::Server::new_unix(config, socket_path, approval_tx, activity_tx, server_info).await
}

#[cfg(not(unix))]
async fn create_server_unix(
    _config: &Config,
    _socket_path: &str,
    _approval_tx: mpsc::Sender<approval::ApprovalRequest>,
    _activity_tx: mpsc::Sender<approval::Activity>,
    _server_info: Arc<ServerInfo>,
) -> Result<tls::Server> {
    anyhow::bail!("Unix sockets are not supported on this platform");
}

fn spawn_server_loop(server: Arc<tls::Server>) {
    tokio::spawn(async move {
        if let Err(error) = server.run().await {
            tracing::error!("Server error: {}", error);
        }
    });
}
