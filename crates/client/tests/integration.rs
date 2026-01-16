//! Integration tests for client-server communication

use anyhow::Result;
use claude_remote_common::{CertManager, Config};
use rustls::crypto::ring::default_provider;
use std::sync::Once;

static INIT: Once = Once::new();

fn init_crypto() {
    INIT.call_once(|| {
        default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}
use claude_remote_protocol::wire;
use claude_remote_protocol::{Request, Response};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tofu_mtls::AcceptAnyClientCert;

/// Test server that auto-approves all clients
struct TestServer {
    port: u16,
    acceptor: TlsAcceptor,
    listener: TcpListener,
    #[allow(dead_code)]
    config_dir: TempDir,
}

impl TestServer {
    async fn new() -> Result<Self> {
        let config_dir = TempDir::new()?;
        let config = Config::with_dir(config_dir.path().to_path_buf());

        // Generate server certificate
        let cert_mgr = CertManager::new(config.config_dir(), "server");
        let (cert_pem, key_pem) = cert_mgr.load_or_generate("test-server")?;

        // Parse certificate and key
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

        // Build TLS config with client certificate verification
        let client_verifier = Arc::new(AcceptAnyClientCert::new());
        let tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        Ok(Self {
            port,
            acceptor,
            listener,
            config_dir,
        })
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Accept one connection and handle requests
    async fn accept_one<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: FnOnce(Box<dyn TestStream>) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let (stream, _) = self.listener.accept().await?;
        let tls_stream = self.acceptor.accept(stream).await?;
        handler(Box::new(tls_stream)).await
    }
}

/// Trait object wrapper for the TLS stream
trait TestStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestStream for T {}

/// Handle requests on a stream - simple echo/response handler
async fn handle_test_requests<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    stop_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        _ = async {
            loop {
                let request: Request = match wire::read_message(&mut reader).await {
                    Ok(req) => req,
                    Err(_) => break,
                };

                match request {
                    Request::Ping => {
                        wire::write_message(&mut writer, &Response::Pong).await?;
                    }
                    Request::Status => {
                        wire::write_message(&mut writer, &Response::StatusInfo {
                            uptime_secs: 42,
                            version: "test123".to_string(),
                            started_at: "1234567890".to_string(),
                        }).await?;
                    }
                    Request::ListSessions => {
                        wire::write_message(&mut writer, &Response::Sessions {
                            sessions: vec![],
                        }).await?;
                    }
                    Request::Exec { command, .. } => {
                        wire::write_message(&mut writer, &Response::ExecResult {
                            exit_code: Some(0),
                            stdout: format!("executed: {}", command),
                            stderr: String::new(),
                        }).await?;
                    }
                    _ => {
                        wire::write_message(&mut writer, &Response::Error {
                            message: "Not implemented in test".to_string(),
                        }).await?;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        } => {}
        _ = stop_rx => {}
    }

    Ok(())
}

/// Create a client config in a temp directory
fn create_client_config() -> Result<(TempDir, Config)> {
    let dir = TempDir::new()?;
    let config = Config::with_dir(dir.path().to_path_buf());
    Ok((dir, config))
}

mod connection_tests {
    use super::*;
    use claude_remote_client::Connection;

    #[tokio::test]
    async fn connect_to_server() {
        init_crypto();
        let server = TestServer::new().await.unwrap();
        let server_addr = server.addr();

        // Server task
        let server_handle = tokio::spawn(async move {
            let (stop_tx, stop_rx) = oneshot::channel();
            server.accept_one(|stream| async move {
                // Just accept and immediately close
                drop(stop_tx);
                handle_test_requests(stream, stop_rx).await
            }).await
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client connects
        let (_dir, config) = create_client_config().unwrap();
        let result = Connection::connect(&config, &server_addr).await;

        // Connection should succeed (new server, TOFU will accept)
        assert!(result.is_ok(), "Connection failed: {:?}", result.err());

        // Clean up
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn ping_pong() {
        init_crypto();
        let server = TestServer::new().await.unwrap();
        let server_addr = server.addr();

        let (stop_tx, stop_rx) = oneshot::channel();

        // Server task
        let server_handle = tokio::spawn(async move {
            server.accept_one(|stream| async move {
                handle_test_requests(stream, stop_rx).await
            }).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (_dir, config) = create_client_config().unwrap();
        let mut conn = Connection::connect(&config, &server_addr).await.unwrap();

        // Send ping
        conn.send(&Request::Ping).await.unwrap();

        // Receive pong
        let response: Response = conn.receive().await.unwrap();
        assert!(matches!(response, Response::Pong));

        // Stop server
        let _ = stop_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn status_request() {
        init_crypto();
        let server = TestServer::new().await.unwrap();
        let server_addr = server.addr();

        let (stop_tx, stop_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move {
            server.accept_one(|stream| async move {
                handle_test_requests(stream, stop_rx).await
            }).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (_dir, config) = create_client_config().unwrap();
        let mut conn = Connection::connect(&config, &server_addr).await.unwrap();

        conn.send(&Request::Status).await.unwrap();

        let response: Response = conn.receive().await.unwrap();
        match response {
            Response::StatusInfo { uptime_secs, version, .. } => {
                assert_eq!(uptime_secs, 42);
                assert_eq!(version, "test123");
            }
            _ => panic!("Expected StatusInfo, got {:?}", response),
        }

        let _ = stop_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn exec_request() {
        init_crypto();
        let server = TestServer::new().await.unwrap();
        let server_addr = server.addr();

        let (stop_tx, stop_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move {
            server.accept_one(|stream| async move {
                handle_test_requests(stream, stop_rx).await
            }).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (_dir, config) = create_client_config().unwrap();
        let mut conn = Connection::connect(&config, &server_addr).await.unwrap();

        conn.send(&Request::Exec {
            command: "echo hello".to_string(),
            cwd: None,
        }).await.unwrap();

        let response: Response = conn.receive().await.unwrap();
        match response {
            Response::ExecResult { exit_code, stdout, .. } => {
                assert_eq!(exit_code, Some(0));
                assert!(stdout.contains("echo hello"));
            }
            _ => panic!("Expected ExecResult, got {:?}", response),
        }

        let _ = stop_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn multiple_requests() {
        init_crypto();
        let server = TestServer::new().await.unwrap();
        let server_addr = server.addr();

        let (stop_tx, stop_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move {
            server.accept_one(|stream| async move {
                handle_test_requests(stream, stop_rx).await
            }).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (_dir, config) = create_client_config().unwrap();
        let mut conn = Connection::connect(&config, &server_addr).await.unwrap();

        // Multiple ping/pong
        for _ in 0..5 {
            conn.send(&Request::Ping).await.unwrap();
            let response: Response = conn.receive().await.unwrap();
            assert!(matches!(response, Response::Pong));
        }

        // Then status
        conn.send(&Request::Status).await.unwrap();
        let response: Response = conn.receive().await.unwrap();
        assert!(matches!(response, Response::StatusInfo { .. }));

        let _ = stop_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn tofu_remembers_server() {
        init_crypto();
        let server = TestServer::new().await.unwrap();
        let server_addr = server.addr();

        // Keep server alive for multiple connections
        let server_handle = tokio::spawn({
            async move {
                // Accept first connection
                let (stream1, _) = server.listener.accept().await.unwrap();
                let tls1 = server.acceptor.accept(stream1).await.unwrap();
                let (mut reader1, mut writer1) = split(tls1);

                // Handle one ping
                let _: Request = wire::read_message(&mut reader1).await.unwrap();
                wire::write_message(&mut writer1, &Response::Pong).await.unwrap();
                drop(reader1);
                drop(writer1);

                // Accept second connection
                let (stream2, _) = server.listener.accept().await.unwrap();
                let tls2 = server.acceptor.accept(stream2).await.unwrap();
                let (mut reader2, mut writer2) = split(tls2);

                // Handle one ping
                let _: Request = wire::read_message(&mut reader2).await.unwrap();
                wire::write_message(&mut writer2, &Response::Pong).await.unwrap();

                Ok::<_, anyhow::Error>(())
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Use same config dir for both connections
        let (_dir, config) = create_client_config().unwrap();

        // First connection - new server
        {
            let mut conn = Connection::connect(&config, &server_addr).await.unwrap();
            conn.send(&Request::Ping).await.unwrap();
            let _: Response = conn.receive().await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second connection - known server (TOFU should remember)
        {
            let mut conn = Connection::connect(&config, &server_addr).await.unwrap();
            conn.send(&Request::Ping).await.unwrap();
            let _: Response = conn.receive().await.unwrap();
        }

        let _ = server_handle.await;
    }
}
