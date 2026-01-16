//! Configuration management

use crate::Fingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// Path to claude binary
    #[serde(default)]
    pub claude_path: Option<String>,

    /// Trusted client fingerprints with optional names
    #[serde(default)]
    pub trusted_clients: HashMap<String, TrustedClient>,
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    7433 // "CLDE" on phone keypad
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedClient {
    /// Human-readable name for this client
    pub name: String,

    /// When was this client approved
    #[serde(default)]
    pub approved_at: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            port: default_port(),
            claude_path: None,
            trusted_clients: HashMap::new(),
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Default server to connect to
    #[serde(default)]
    pub default_server: Option<String>,

    /// Known servers with their fingerprints
    #[serde(default)]
    pub known_servers: HashMap<String, KnownServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownServer {
    /// Server's certificate fingerprint
    pub fingerprint: String,

    /// When was this server first seen
    #[serde(default)]
    pub first_seen: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            default_server: None,
            known_servers: HashMap::new(),
        }
    }
}

/// Configuration manager
pub struct Config {
    config_dir: PathBuf,
}

impl Config {
    /// Create config manager using platform-appropriate directory
    pub fn new() -> Self {
        let config_dir = directories::ProjectDirs::from("com", "claude-remote", "claude-remote")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".claude-remote"));

        Self { config_dir }
    }

    /// Create config manager with specific directory
    pub fn with_dir(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Load server configuration
    pub fn load_server(&self) -> Result<ServerConfig, ConfigError> {
        let path = self.config_dir.join("server.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(ServerConfig::default())
        }
    }

    /// Save server configuration
    pub fn save_server(&self, config: &ServerConfig) -> Result<(), ConfigError> {
        std::fs::create_dir_all(&self.config_dir)?;
        let path = self.config_dir.join("server.toml");
        let content = toml::to_string_pretty(config)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load client configuration
    pub fn load_client(&self) -> Result<ClientConfig, ConfigError> {
        let path = self.config_dir.join("client.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(ClientConfig::default())
        }
    }

    /// Save client configuration
    pub fn save_client(&self, config: &ClientConfig) -> Result<(), ConfigError> {
        std::fs::create_dir_all(&self.config_dir)?;
        let path = self.config_dir.join("client.toml");
        let content = toml::to_string_pretty(config)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a trusted client to server config
    pub fn add_trusted_client(
        &self,
        fingerprint: &Fingerprint,
        name: &str,
    ) -> Result<(), ConfigError> {
        let mut config = self.load_server()?;
        config.trusted_clients.insert(
            fingerprint.0.clone(),
            TrustedClient {
                name: name.to_string(),
                approved_at: Some(chrono_now()),
            },
        );
        self.save_server(&config)
    }

    /// Check if a client is trusted
    pub fn is_client_trusted(&self, fingerprint: &Fingerprint) -> Result<bool, ConfigError> {
        let config = self.load_server()?;
        Ok(config.trusted_clients.contains_key(&fingerprint.0))
    }
}

fn chrono_now() -> String {
    // Simple ISO 8601 timestamp without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ServerConfig tests
    #[test]
    fn server_config_defaults() {
        let config = ServerConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0");
        assert_eq!(config.port, 7433);
        assert!(config.claude_path.is_none());
        assert!(config.trusted_clients.is_empty());
    }

    #[test]
    fn server_config_roundtrip() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let mut server = ServerConfig::default();
        server.port = 8080;
        server.listen_addr = "127.0.0.1".to_string();
        server.claude_path = Some("/usr/bin/claude".to_string());
        server.trusted_clients.insert(
            "abc123".to_string(),
            TrustedClient {
                name: "Test Client".to_string(),
                approved_at: Some("1234567890".to_string()),
            },
        );

        config.save_server(&server).unwrap();
        let loaded = config.load_server().unwrap();

        assert_eq!(loaded.port, 8080);
        assert_eq!(loaded.listen_addr, "127.0.0.1");
        assert_eq!(loaded.claude_path, Some("/usr/bin/claude".to_string()));
        assert!(loaded.trusted_clients.contains_key("abc123"));
        assert_eq!(loaded.trusted_clients["abc123"].name, "Test Client");
    }

    #[test]
    fn server_config_load_nonexistent_returns_default() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let loaded = config.load_server().unwrap();
        assert_eq!(loaded.port, 7433); // default
    }

    // ClientConfig tests
    #[test]
    fn client_config_defaults() {
        let config = ClientConfig::default();
        assert!(config.default_server.is_none());
        assert!(config.known_servers.is_empty());
    }

    #[test]
    fn client_config_roundtrip() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let mut client = ClientConfig::default();
        client.default_server = Some("server.example.com:7433".to_string());
        client.known_servers.insert(
            "server.example.com:7433".to_string(),
            KnownServer {
                fingerprint: "abc123def456".to_string(),
                first_seen: Some("1234567890".to_string()),
            },
        );

        config.save_client(&client).unwrap();
        let loaded = config.load_client().unwrap();

        assert_eq!(loaded.default_server, Some("server.example.com:7433".to_string()));
        assert!(loaded.known_servers.contains_key("server.example.com:7433"));
        assert_eq!(loaded.known_servers["server.example.com:7433"].fingerprint, "abc123def456");
    }

    #[test]
    fn client_config_load_nonexistent_returns_default() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let loaded = config.load_client().unwrap();
        assert!(loaded.default_server.is_none());
        assert!(loaded.known_servers.is_empty());
    }

    #[test]
    fn client_config_multiple_servers() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let mut client = ClientConfig::default();
        client.known_servers.insert(
            "server1.example.com:7433".to_string(),
            KnownServer {
                fingerprint: "fp1".to_string(),
                first_seen: None,
            },
        );
        client.known_servers.insert(
            "server2.example.com:7433".to_string(),
            KnownServer {
                fingerprint: "fp2".to_string(),
                first_seen: None,
            },
        );

        config.save_client(&client).unwrap();
        let loaded = config.load_client().unwrap();

        assert_eq!(loaded.known_servers.len(), 2);
        assert_eq!(loaded.known_servers["server1.example.com:7433"].fingerprint, "fp1");
        assert_eq!(loaded.known_servers["server2.example.com:7433"].fingerprint, "fp2");
    }

    // Trusted client management tests
    #[test]
    fn add_trusted_client() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let fp = Fingerprint("abc123".to_string());
        config.add_trusted_client(&fp, "My Laptop").unwrap();

        let loaded = config.load_server().unwrap();
        assert!(loaded.trusted_clients.contains_key("abc123"));
        assert_eq!(loaded.trusted_clients["abc123"].name, "My Laptop");
        assert!(loaded.trusted_clients["abc123"].approved_at.is_some());
    }

    #[test]
    fn is_client_trusted_true() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let fp = Fingerprint("trusted_fp".to_string());
        config.add_trusted_client(&fp, "Trusted").unwrap();

        assert!(config.is_client_trusted(&fp).unwrap());
    }

    #[test]
    fn is_client_trusted_false() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let fp = Fingerprint("unknown_fp".to_string());
        assert!(!config.is_client_trusted(&fp).unwrap());
    }

    #[test]
    fn add_multiple_trusted_clients() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        config.add_trusted_client(&Fingerprint("fp1".to_string()), "Client 1").unwrap();
        config.add_trusted_client(&Fingerprint("fp2".to_string()), "Client 2").unwrap();
        config.add_trusted_client(&Fingerprint("fp3".to_string()), "Client 3").unwrap();

        assert!(config.is_client_trusted(&Fingerprint("fp1".to_string())).unwrap());
        assert!(config.is_client_trusted(&Fingerprint("fp2".to_string())).unwrap());
        assert!(config.is_client_trusted(&Fingerprint("fp3".to_string())).unwrap());
        assert!(!config.is_client_trusted(&Fingerprint("fp4".to_string())).unwrap());
    }

    #[test]
    fn config_creates_directory() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("nested").join("config");
        let config = Config::with_dir(subdir.clone());

        assert!(!subdir.exists());

        config.save_server(&ServerConfig::default()).unwrap();

        assert!(subdir.exists());
        assert!(subdir.join("server.toml").exists());
    }

    #[test]
    fn config_dir_accessor() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        assert_eq!(config.config_dir(), dir.path());
    }

    // TOML format tests
    #[test]
    fn server_config_toml_format() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let mut server = ServerConfig::default();
        server.port = 9999;
        config.save_server(&server).unwrap();

        let content = std::fs::read_to_string(dir.path().join("server.toml")).unwrap();
        assert!(content.contains("port = 9999"));
        assert!(content.contains("listen_addr"));
    }

    #[test]
    fn client_config_toml_format() {
        let dir = TempDir::new().unwrap();
        let config = Config::with_dir(dir.path().to_path_buf());

        let mut client = ClientConfig::default();
        client.default_server = Some("myserver:7433".to_string());
        config.save_client(&client).unwrap();

        let content = std::fs::read_to_string(dir.path().join("client.toml")).unwrap();
        assert!(content.contains("default_server"));
        assert!(content.contains("myserver:7433"));
    }
}
