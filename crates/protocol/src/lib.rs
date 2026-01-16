//! Protocol messages for claude-remote
//!
//! Defines the wire format between client and server, as well as
//! types for interacting with Claude Code's stream-json API.

pub mod claude;
pub mod wire;

pub use claude::{ClaudeInput, ClaudeOutput};
pub use wire::{Request, Response};
