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

## Windows Support

The server runs on Windows with these adaptations:

- **Claude spawning**: Uses `cmd /c claude` to handle the npm wrapper (`.cmd` file)
- **Detached process spawning**: Uses `Start-Process` via cmd for update restarts
- **Path handling**: Windows paths work transparently through the file transfer commands

## File Transfer

Large file support with automatic chunking:

- Files ≤8MB: Single `GetFile`/`PutFile` request
- Files >8MB: Chunked via `GetFileChunk`/`PutFileChunk` (8MB chunks)
- 8MB chunk size chosen to stay under 16MB wire protocol limit after base64 encoding (~33% overhead)
- `StatFile` request checks size before transfer to choose strategy

## Remote Commands

Available commands beyond prompts:

| Command | Description |
|---------|-------------|
| `status` | Server uptime, version hash, start time |
| `exec <cmd>` | Execute shell command without Claude |
| `shutdown` | Graceful server termination |
| `update` | Git pull, build, restart with new binary |
| `get <remote> <local>` | Download file from server |
| `put <local> <remote>` | Upload file to server |

## Self-Update Mechanism

The `update` command performs:
1. `git pull` in the project directory
2. `cargo build --release -p claude-remote-server`
3. Verify new binary exists at expected path
4. Spawn new server process (detached)
5. Send `UpdateComplete` response
6. Exit old process

On Windows, detached spawn uses: `cmd /c start "" <binary>`
On Unix: Spawn with stdin/stdout/stderr set to null

## Version Tracking

Server computes a version hash at startup:
- SHA256 of first 64KB of the running binary
- Returns first 8 hex characters (4 bytes)
- Useful for verifying updates took effect

## Known Issues

- **npm wrapper on Windows**: Claude installed via npm creates a `.cmd` wrapper. Direct `Command::new("claude")` fails; must use `cmd /c claude`
- **Detached processes**: Windows `Start-Process` via cmd is the reliable way to spawn a process that survives parent exit
- **Connection resets on update**: Client gets connection reset when server restarts; this is expected
