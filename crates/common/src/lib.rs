pub mod config;

// Re-export from tofu-mtls for convenience
pub use config::Config;
pub use tofu_mtls::{CertManager, Fingerprint};
