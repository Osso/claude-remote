//! TLS client connection with TOFU server verification

use anyhow::{Context, Result};
use claude_remote_common::{CertManager, Config, Fingerprint};
use claude_remote_protocol::wire;
use rustls::pki_types::ServerName;
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tofu_mtls::{AcceptAnyServerCert, KnownHosts, TofuVerification};

#[cfg(unix)]
use tokio::net::UnixStream;

/// A boxed async reader
type BoxedRead = Pin<Box<dyn AsyncRead + Send + Unpin>>;
/// A boxed async writer
type BoxedWrite = Pin<Box<dyn AsyncWrite + Send + Unpin>>;

pub struct Connection {
    reader: BoxedRead,
    writer: BoxedWrite,
}

/// Result of server verification
pub enum ServerVerification {
    /// Server was already known and fingerprint matched
    Known,
    /// New server - fingerprint was saved
    NewServer { fingerprint: Fingerprint },
    /// Server fingerprint changed - potential MITM
    FingerprintMismatch {
        expected: Fingerprint,
        actual: Fingerprint,
    },
}

impl Connection {
    pub async fn connect(config: &Config, server_addr: &str) -> Result<Self> {
        let (conn, verification) = Self::connect_with_verification(config, server_addr).await?;

        match verification {
            ServerVerification::Known => {
                tracing::info!("Connected to known server");
            }
            ServerVerification::NewServer { fingerprint } => {
                tracing::warn!(
                    "Connected to new server. Fingerprint: {}",
                    fingerprint
                );
                tracing::warn!("The server fingerprint has been saved for future connections.");
            }
            ServerVerification::FingerprintMismatch { expected, actual } => {
                return Err(anyhow::anyhow!(
                    "SERVER FINGERPRINT MISMATCH!\n\
                     Expected: {}\n\
                     Actual:   {}\n\
                     This could indicate a man-in-the-middle attack.\n\
                     If you trust this server, delete the entry from your config.",
                    expected, actual
                ));
            }
        }

        Ok(conn)
    }

    /// Connect with explicit verification result
    pub async fn connect_with_verification(
        config: &Config,
        server_addr: &str,
    ) -> Result<(Self, ServerVerification)> {
        // Check if this is a Unix socket path
        #[cfg(unix)]
        if is_unix_socket_path(server_addr) {
            return Self::connect_unix_with_verification(config, server_addr).await;
        }

        Self::connect_tcp_with_verification(config, server_addr).await
    }

    /// Connect via TCP
    async fn connect_tcp_with_verification(
        config: &Config,
        server_addr: &str,
    ) -> Result<(Self, ServerVerification)> {
        let connector = build_tls_connector(config)?;

        // Parse server address
        let (host, port) = parse_address(server_addr)?;

        // Connect
        let addr = format!("{}:{}", host, port);
        tracing::info!("Connecting to {}", addr);

        let stream = TcpStream::connect(&addr)
            .await
            .context(format!("Failed to connect to {}", addr))?;

        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        // Extract server certificate fingerprint
        let server_fingerprint = extract_server_fingerprint(&tls_stream);
        tracing::debug!("Server fingerprint: {}", server_fingerprint);

        // TOFU verification using tofu-mtls
        let known_hosts_path = config.config_dir().join("known_servers.toml");
        let verification = verify_server(&known_hosts_path, server_addr, &server_fingerprint)?;

        let (reader, writer) = tokio::io::split(tls_stream);
        let conn = Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
        };

        Ok((conn, verification))
    }

    /// Connect via Unix socket
    #[cfg(unix)]
    async fn connect_unix_with_verification(
        config: &Config,
        socket_path: &str,
    ) -> Result<(Self, ServerVerification)> {
        let connector = build_tls_connector(config)?;

        tracing::info!("Connecting to Unix socket {}", socket_path);

        let stream = UnixStream::connect(socket_path)
            .await
            .context(format!("Failed to connect to Unix socket {}", socket_path))?;

        // Use "localhost" as server name for Unix sockets
        let server_name = ServerName::try_from("localhost".to_string())
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        // Extract server certificate fingerprint
        let server_fingerprint = extract_server_fingerprint_generic(&tls_stream);
        tracing::debug!("Server fingerprint: {}", server_fingerprint);

        // TOFU verification using socket path as identifier
        let known_hosts_path = config.config_dir().join("known_servers.toml");
        let verification = verify_server(&known_hosts_path, socket_path, &server_fingerprint)?;

        let (reader, writer) = tokio::io::split(tls_stream);
        let conn = Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
        };

        Ok((conn, verification))
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        wire::write_message(&mut self.writer, msg)
            .await
            .map_err(|e| anyhow::anyhow!("Send error: {}", e))
    }

    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        wire::read_message(&mut self.reader)
            .await
            .map_err(|e| anyhow::anyhow!("Receive error: {}", e))
    }
}

/// Build TLS connector with client certificate
fn build_tls_connector(config: &Config) -> Result<TlsConnector> {
    let cert_mgr = CertManager::new(config.config_dir(), "client");
    let (cert_pem, key_pem) = cert_mgr
        .load_or_generate("claude-remote-client")
        .context("Failed to load/generate client certificate")?;

    let fingerprint = cert_mgr.fingerprint()?;
    tracing::info!("Client certificate fingerprint: {}", fingerprint);

    // Parse certificate and key
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate")?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("Failed to parse private key")?
        .context("No private key found")?;

    // Build TLS config - accept any cert, we verify fingerprint after handshake
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(certs, key)
        .context("Failed to build TLS config")?;

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

/// Check if the address looks like a Unix socket path
#[cfg(unix)]
fn is_unix_socket_path(addr: &str) -> bool {
    // Unix socket if it starts with / or ./
    addr.starts_with('/') || addr.starts_with("./")
}

fn parse_address(addr: &str) -> Result<(&str, u16)> {
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str
            .parse()
            .context(format!("Invalid port: {}", port_str))?;
        Ok((host, port))
    } else {
        Ok((addr, 7433))
    }
}

/// Extract server certificate fingerprint from TLS stream over TCP
fn extract_server_fingerprint(stream: &TlsStream<TcpStream>) -> Fingerprint {
    let (_, client_conn) = stream.get_ref();

    if let Some(certs) = client_conn.peer_certificates() {
        if let Some(cert) = certs.first() {
            return Fingerprint::from_rustls_cert(cert);
        }
    }

    Fingerprint("no-certificate".to_string())
}

/// Extract server certificate fingerprint from TLS stream (generic)
#[cfg(unix)]
fn extract_server_fingerprint_generic<S>(stream: &TlsStream<S>) -> Fingerprint
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (_, client_conn) = stream.get_ref();

    if let Some(certs) = client_conn.peer_certificates() {
        if let Some(cert) = certs.first() {
            return Fingerprint::from_rustls_cert(cert);
        }
    }

    Fingerprint("no-certificate".to_string())
}

/// Verify server fingerprint using TOFU model
fn verify_server(
    known_hosts_path: &PathBuf,
    server_addr: &str,
    actual_fingerprint: &Fingerprint,
) -> Result<ServerVerification> {
    let known_hosts = KnownHosts::new(known_hosts_path);

    match known_hosts.verify(server_addr, actual_fingerprint)? {
        TofuVerification::Known => Ok(ServerVerification::Known),
        TofuVerification::NewHost { fingerprint } => {
            Ok(ServerVerification::NewServer { fingerprint })
        }
        TofuVerification::FingerprintMismatch { expected, actual } => {
            Ok(ServerVerification::FingerprintMismatch { expected, actual })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // parse_address tests
    #[test]
    fn parse_address_with_port() {
        let (host, port) = parse_address("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_address_default_port() {
        let (host, port) = parse_address("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 7433);
    }

    #[test]
    fn parse_address_ipv4_with_port() {
        let (host, port) = parse_address("192.168.1.1:9999").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 9999);
    }

    #[test]
    fn parse_address_ipv4_default_port() {
        let (host, port) = parse_address("192.168.1.1").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 7433);
    }

    #[test]
    fn parse_address_localhost() {
        let (host, port) = parse_address("localhost:7433").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 7433);
    }

    #[test]
    fn parse_address_invalid_port() {
        let result = parse_address("example.com:notaport");
        assert!(result.is_err());
    }

    #[test]
    fn parse_address_port_out_of_range() {
        let result = parse_address("example.com:99999");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn is_unix_socket_absolute_path() {
        assert!(is_unix_socket_path("/tmp/test.sock"));
        assert!(is_unix_socket_path("/var/run/claude.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn is_unix_socket_relative_path() {
        assert!(is_unix_socket_path("./test.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn is_not_unix_socket() {
        assert!(!is_unix_socket_path("localhost:7433"));
        assert!(!is_unix_socket_path("192.168.1.1:7433"));
        assert!(!is_unix_socket_path("example.com"));
    }

    // TOFU verification tests using tofu-mtls
    #[test]
    fn verify_server_new_server() {
        let dir = TempDir::new().unwrap();
        let known_hosts_path = dir.path().join("known_servers.toml");

        let fingerprint = Fingerprint("abc123".to_string());
        let result = verify_server(&known_hosts_path, "newserver.com:7433", &fingerprint).unwrap();

        match result {
            ServerVerification::NewServer { fingerprint: fp } => {
                assert_eq!(fp.0, "abc123");
            }
            _ => panic!("Expected NewServer"),
        }
    }

    #[test]
    fn verify_server_known_server_matches() {
        let dir = TempDir::new().unwrap();
        let known_hosts_path = dir.path().join("known_servers.toml");
        let known_hosts = KnownHosts::new(&known_hosts_path);

        // Pre-save a known server
        let fingerprint = Fingerprint("expected_fp".to_string());
        known_hosts.add("knownserver.com:7433", &fingerprint).unwrap();

        // Verify with matching fingerprint
        let result = verify_server(&known_hosts_path, "knownserver.com:7433", &fingerprint).unwrap();

        assert!(matches!(result, ServerVerification::Known));
    }

    #[test]
    fn verify_server_fingerprint_mismatch() {
        let dir = TempDir::new().unwrap();
        let known_hosts_path = dir.path().join("known_servers.toml");
        let known_hosts = KnownHosts::new(&known_hosts_path);

        // Pre-save a known server
        known_hosts.add("knownserver.com:7433", &Fingerprint("expected_fp".to_string())).unwrap();

        // Verify with different fingerprint
        let fingerprint = Fingerprint("different_fp".to_string());
        let result = verify_server(&known_hosts_path, "knownserver.com:7433", &fingerprint).unwrap();

        match result {
            ServerVerification::FingerprintMismatch { expected, actual } => {
                assert_eq!(expected.0, "expected_fp");
                assert_eq!(actual.0, "different_fp");
            }
            _ => panic!("Expected FingerprintMismatch"),
        }
    }
}
