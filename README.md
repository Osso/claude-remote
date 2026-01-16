# claude-remote

Remote access to Claude Code over mTLS with TOFU (Trust-On-First-Use) authentication.

## Overview

- **claude-remote** - CLI client that connects to a remote server and sends prompts
- **claude-remote-server** - Server with GUI for client approval, spawns Claude Code and streams responses

## Installation

```bash
cargo install --git https://github.com/Osso/claude-remote claude-remote-client
cargo install --git https://github.com/Osso/claude-remote claude-remote-server
```

Or build from source:

```bash
git clone https://github.com/Osso/claude-remote
cd claude-remote
cargo build --release
```

Binaries will be in `target/release/`.

## Usage

### Server

Start the server on the machine with Claude Code installed:

```bash
claude-remote-server
```

The server listens on `0.0.0.0:7433` by default. A GUI window shows connection requests and activity.

Options:
- `--address` / `-a` - Bind address (default: 0.0.0.0)
- `--port` / `-p` - Port (default: 7433)

### Client

```bash
# Send a single prompt
claude-remote -p "your prompt here"

# Interactive mode
claude-remote

# Specify server
claude-remote -s hostname:7433 -p "prompt"

# Set default server
claude-remote config --server hostname:7433

# Test connection
claude-remote ping

# File transfer
claude-remote get /remote/path ./local/path
claude-remote put ./local/path /remote/path
```

## First Connection

On first connection to a new server:

1. Client generates a certificate automatically
2. Server shows approval dialog with client fingerprint
3. Once approved, client is trusted for future connections

This is similar to SSH's known_hosts - you verify the fingerprint once, then connections are automatic.

## Configuration

Config is stored in `~/.config/claude-remote/`:

- `client.crt` / `client.key` - Client certificate
- `server.crt` / `server.key` - Server certificate
- `known_servers.toml` - Trusted servers (client)
- `server.toml` - Trusted clients (server)

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

The server uses Claude's `--input-format stream-json --output-format stream-json` mode to stream responses back to the client in real-time.

## License

MIT
