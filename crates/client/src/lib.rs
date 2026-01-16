//! Claude Remote Client Library
//!
//! Provides TLS connection with TOFU server verification.

mod connection;

pub use connection::{Connection, ServerVerification};
