# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

claude-remote enables remote access to Claude Code over mTLS with TOFU (Trust-On-First-Use) authentication.

- **claude-remote** (client): CLI that connects to a remote server and sends prompts
- **claude-remote-server**: Server that spawns Claude Code processes and streams responses, with iced GUI for client approval

## Build Commands

```bash
cargo build --release                    # Build all
cargo build --release -p claude-remote-client   # Build client only
cargo build --release -p claude-remote-server   # Build server only
cargo test                               # Run all tests
cargo test -p claude-remote-protocol     # Test specific crate
```

## Architecture

```
┌─────────────────┐         mTLS          ┌──────────────────┐
│  claude-remote  │◄───────────────────►  │ claude-remote-   │
│    (client)     │   TOFU verification   │     server       │
└─────────────────┘                       └────────┬─────────┘
                                                   │
                                          stream-json API
                                                   │
                                                   ▼
                                          ┌───────────────┐
                                          │  claude CLI   │
                                          └───────────────┘
```

### Crate Structure

- **common**: `Config`, re-exports `CertManager`/`Fingerprint` from tofu-mtls
- **protocol**: `Request`/`Response` wire types, `ClaudeInput`/`ClaudeOutput` for Claude's stream-json format
- **client**: Connection handling with TOFU server verification
- **server**: TLS listener, client approval GUI, Claude process spawning

### External Dependency

Uses `tofu-mtls` library (at `../lib/tofu-mtls`) for:
- Certificate generation and management
- Length-prefixed wire protocol
- TOFU known-hosts verification
- rustls verifiers that accept any cert (verification done post-handshake)

### Config Location

`~/.config/claude-remote/` containing:
- `client.crt`/`client.key` - Client certificate
- `server.crt`/`server.key` - Server certificate
- `known_servers.toml` - TOFU trusted servers
- `server.toml` - Trusted clients list

## Claude Code Integration

The server uses Claude's `--input-format stream-json --output-format stream-json` mode. Messages are newline-delimited JSON. Key types in `protocol/src/claude.rs`:
- `ClaudeOutput::Assistant` - Streaming text chunks
- `ClaudeOutput::Result` - Final result with cost info
- `ClaudeOutput::ToolUse`/`ToolResult` - Tool interactions
