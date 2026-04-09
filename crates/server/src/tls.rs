//! TLS server implementation with mTLS support

use anyhow::{Context, Result};
use claude_remote_common::{CertManager, Config, Fingerprint};
use std::sync::Arc;
use tofu_mtls::AcceptAnyClientCert;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

#[cfg(unix)]
use tokio::net::UnixListener;

use crate::ServerInfo;
use crate::approval::{Activity, ApprovalRequest};

mod connection;
use connection::handle_connection;

/// Listener that can be either TCP or Unix socket
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl Listener {
    pub async fn bind_tcp(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;
        Ok(Listener::Tcp(listener))
    }

    #[cfg(unix)]
    pub async fn bind_unix(path: &str) -> Result<Self> {
        // Remove existing socket file if it exists
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).context(format!("Failed to bind to Unix socket {}", path))?;
        Ok(Listener::Unix(listener))
    }

    pub fn _local_addr_string(&self) -> String {
        match self {
            Listener::Tcp(l) => l.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            #[cfg(unix)]
            Listener::Unix(l) => l
                .local_addr()
                .map(|a| {
                    a.as_pathname()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
        }
    }
}

pub struct Server {
    listener: Listener,
    acceptor: TlsAcceptor,
    config: Config,
    approval_tx: mpsc::Sender<ApprovalRequest>,
    activity_tx: mpsc::Sender<Activity>,
    server_info: Arc<ServerInfo>,
}

impl Server {
    /// Create a new server listening on TCP
    pub async fn new(
        config: &Config,
        address: &str,
        port: u16,
        approval_tx: mpsc::Sender<ApprovalRequest>,
        activity_tx: mpsc::Sender<Activity>,
        server_info: Arc<ServerInfo>,
    ) -> Result<Self> {
        let addr = format!("{}:{}", address, port);
        let listener = Listener::bind_tcp(&addr).await?;
        tracing::info!("Listening on {}", addr);
        Self::with_listener(config, listener, approval_tx, activity_tx, server_info)
    }

    /// Create a new server listening on a Unix socket
    #[cfg(unix)]
    pub async fn new_unix(
        config: &Config,
        socket_path: &str,
        approval_tx: mpsc::Sender<ApprovalRequest>,
        activity_tx: mpsc::Sender<Activity>,
        server_info: Arc<ServerInfo>,
    ) -> Result<Self> {
        let listener = Listener::bind_unix(socket_path).await?;
        tracing::info!("Listening on Unix socket {}", socket_path);
        Self::with_listener(config, listener, approval_tx, activity_tx, server_info)
    }

    fn with_listener(
        config: &Config,
        listener: Listener,
        approval_tx: mpsc::Sender<ApprovalRequest>,
        activity_tx: mpsc::Sender<Activity>,
        server_info: Arc<ServerInfo>,
    ) -> Result<Self> {
        // Load or generate server certificate
        let cert_mgr = CertManager::new(config.config_dir(), "server");
        let (cert_pem, key_pem) = cert_mgr
            .load_or_generate("claude-remote-server")
            .context("Failed to load/generate server certificate")?;

        let fingerprint = cert_mgr.fingerprint()?;
        tracing::info!("Server certificate fingerprint: {}", fingerprint);

        // Parse certificate and key
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate")?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("Failed to parse private key")?
            .context("No private key found")?;

        // Build TLS config with client certificate verification using tofu-mtls
        let client_verifier = Arc::new(AcceptAnyClientCert::new());
        let tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .context("Failed to build TLS config")?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        Ok(Self {
            listener,
            acceptor,
            config: Config::with_dir(config.config_dir().to_path_buf()),
            approval_tx,
            activity_tx,
            server_info,
        })
    }

    pub async fn run(&self) -> Result<()> {
        loop {
            match &self.listener {
                Listener::Tcp(tcp_listener) => {
                    let (stream, peer_addr) = tcp_listener.accept().await?;
                    tracing::info!("Connection from {}", peer_addr);
                    self.handle_stream(stream).await;
                }
                #[cfg(unix)]
                Listener::Unix(unix_listener) => {
                    let (stream, _) = unix_listener.accept().await?;
                    tracing::info!("Connection from Unix socket");
                    self.handle_stream(stream).await;
                }
            }
        }
    }

    async fn handle_stream<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let acceptor = self.acceptor.clone();
        let config = Config::with_dir(self.config.config_dir().to_path_buf());
        let approval_tx = self.approval_tx.clone();
        let activity_tx = self.activity_tx.clone();
        let server_info = self.server_info.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::error!("TLS handshake failed: {}", error);
                    return;
                }
            };

            let fingerprint = extract_client_fingerprint_generic(&tls_stream);
            tracing::info!("Client fingerprint: {}", fingerprint);

            if let Err(error) = handle_connection(
                tls_stream,
                fingerprint,
                config,
                approval_tx,
                activity_tx,
                server_info,
            )
            .await
            {
                tracing::error!("Connection error: {}", error);
            }
        });
    }
}

/// Extract client certificate fingerprint from TLS stream (generic version)
fn extract_client_fingerprint_generic<S>(stream: &TlsStream<S>) -> Fingerprint
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (_, server_conn) = stream.get_ref();

    if let Some(certs) = server_conn.peer_certificates() {
        if let Some(cert) = certs.first() {
            return Fingerprint::from_rustls_cert(cert);
        }
    }

    // Fallback if no certificate (shouldn't happen with mandatory client auth)
    Fingerprint("no-certificate".to_string())
}
