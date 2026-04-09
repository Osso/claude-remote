use anyhow::Result;
use claude_remote_common::{Config, Fingerprint};
use claude_remote_protocol::{Request, Response, wire};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, split};
use tokio::sync::mpsc;

use crate::ServerInfo;
use crate::approval::{Activity, ApprovalRequest};
use crate::claude_process::ClaudeProcess;

/// Shared context for request handlers within a connection.
struct ConnectionCtx {
    activity_tx: mpsc::Sender<Activity>,
    server_info: Arc<ServerInfo>,
    fingerprint_str: String,
}

pub(super) async fn handle_connection<S>(
    stream: S,
    client_fingerprint: Fingerprint,
    config: Config,
    approval_tx: mpsc::Sender<ApprovalRequest>,
    activity_tx: mpsc::Sender<Activity>,
    server_info: Arc<ServerInfo>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = split(stream);
    let fp_str = client_fingerprint.0.clone();

    let _ = activity_tx
        .send(Activity::Connected {
            fingerprint: fp_str.clone(),
        })
        .await;

    if !authorize_client(&client_fingerprint, &config, &approval_tx, &mut writer).await? {
        let _ = activity_tx
            .send(Activity::Disconnected {
                fingerprint: fp_str,
            })
            .await;
        return Ok(());
    }

    let ctx = ConnectionCtx {
        activity_tx,
        server_info,
        fingerprint_str: fp_str.clone(),
    };

    dispatch_loop(&mut reader, &mut writer, &ctx).await?;

    let _ = ctx
        .activity_tx
        .send(Activity::Disconnected {
            fingerprint: fp_str,
        })
        .await;

    Ok(())
}

/// Check if client is trusted; if not, request approval via GUI.
/// Returns false if rejected (rejection response already sent).
async fn authorize_client<W: AsyncWrite + Unpin>(
    fingerprint: &Fingerprint,
    config: &Config,
    approval_tx: &mpsc::Sender<ApprovalRequest>,
    writer: &mut W,
) -> Result<bool> {
    let is_trusted = config.is_client_trusted(fingerprint).unwrap_or(false);
    if is_trusted {
        return Ok(true);
    }

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let request = ApprovalRequest {
        fingerprint: fingerprint.clone(),
        response: response_tx,
    };

    if approval_tx.send(request).await.is_err() {
        tracing::error!("Failed to send approval request");
        return Ok(false);
    }

    match response_rx.await {
        Ok(true) => {
            tracing::info!("Client {} approved", fingerprint);
            Ok(true)
        }
        _ => {
            tracing::info!("Client {} rejected", fingerprint);
            send_error(writer, "Connection rejected").await?;
            Ok(false)
        }
    }
}

/// Main request dispatch loop.
async fn dispatch_loop<R, W>(reader: &mut R, writer: &mut W, ctx: &ConnectionCtx) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut active_process: Option<ClaudeProcess> = None;

    loop {
        let request: Request = match wire::read_message(reader).await {
            Ok(req) => req,
            Err(claude_remote_protocol::wire::ProtocolError::ConnectionClosed) => {
                tracing::info!("Client disconnected");
                break;
            }
            Err(claude_remote_protocol::wire::ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                tracing::info!("Client disconnected (reset)");
                break;
            }
            Err(e) => {
                tracing::error!("Protocol error: {}", e);
                break;
            }
        };

        match request {
            Request::Prompt {
                content,
                session_id,
            } => {
                handle_prompt(writer, ctx, &content, session_id, &mut active_process).await?;
            }
            Request::Abort => {
                if let Some(process) = active_process.take() {
                    process.abort().await;
                }
            }
            Request::Ping => {
                wire::write_message(writer, &Response::Pong).await?;
            }
            Request::Status => {
                wire::write_message(
                    writer,
                    &Response::StatusInfo {
                        uptime_secs: ctx.server_info.uptime_secs(),
                        version: ctx.server_info.version.clone(),
                        started_at: ctx.server_info.started_at_iso(),
                    },
                )
                .await?;
            }
            Request::ListSessions => {
                wire::write_message(
                    writer,
                    &Response::Sessions {
                        sessions: Vec::new(),
                    },
                )
                .await?;
            }
            Request::Shutdown => {
                tracing::info!("Shutdown requested by client");
                wire::write_message(writer, &Response::ShuttingDown).await?;
                std::process::exit(0);
            }
            Request::Update { project_dir } => {
                handle_update(writer, &project_dir).await?;
            }
            Request::Exec { command, cwd } => {
                handle_exec(writer, &command, cwd.as_deref()).await?;
            }
            Request::StatFile { path } => {
                handle_stat_file(writer, &path).await?;
            }
            Request::GetFile { path } => {
                handle_get_file(writer, ctx, &path).await?;
            }
            Request::GetFileChunk {
                path,
                offset,
                length,
            } => {
                handle_get_file_chunk(writer, &path, offset, length).await?;
            }
            Request::PutFile { path, content } => {
                handle_put_file(writer, ctx, &path, &content).await?;
            }
            Request::PutFileChunk {
                path,
                offset,
                total_size: _,
                content,
            } => {
                handle_put_file_chunk(writer, &path, offset, &content).await?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Request handlers
// ---------------------------------------------------------------------------

async fn handle_prompt<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ctx: &ConnectionCtx,
    content: &str,
    session_id: Option<String>,
    active_process: &mut Option<ClaudeProcess>,
) -> Result<()> {
    tracing::info!("Received prompt: {}...", &content[..content.len().min(50)]);
    let _ = ctx
        .activity_tx
        .send(Activity::Prompt {
            fingerprint: ctx.fingerprint_str.clone(),
            content: content.to_string(),
        })
        .await;

    let (process, mut rx) = match ClaudeProcess::spawn(content, session_id).await {
        Ok(pair) => pair,
        Err(e) => {
            return send_error(writer, &format!("Failed to start Claude: {}", e)).await;
        }
    };
    *active_process = Some(process);

    while let Some(output) = rx.recv().await {
        let is_result = output.is_result();
        if let Some(text) = output.text() {
            if !text.is_empty() && !is_result {
                let _ = ctx
                    .activity_tx
                    .send(Activity::Response {
                        text: text.to_string(),
                    })
                    .await;
            }
        }

        wire::write_message(writer, &Response::Claude { output }).await?;
        if is_result {
            let _ = ctx.activity_tx.send(Activity::Completed).await;
            break;
        }
    }

    *active_process = None;
    Ok(())
}

async fn handle_update<W: AsyncWrite + Unpin>(writer: &mut W, project_dir: &str) -> Result<()> {
    send_progress(writer, "Pulling latest changes...").await?;
    if !run_build_step(writer, "git", &["pull"], project_dir, "Git pull").await? {
        return Ok(());
    }

    send_progress(writer, "Building release...").await?;
    let build_args = ["build", "--release", "-p", "claude-remote-server"];
    if !run_build_step(writer, "cargo", &build_args, project_dir, "Build").await? {
        return Ok(());
    }

    let new_binary = release_binary_path(project_dir);
    if !std::path::Path::new(&new_binary).exists() {
        send_error(writer, &format!("Binary not found: {}", new_binary)).await?;
        return Ok(());
    }

    send_progress(writer, "Starting new server...").await?;
    spawn_new_server(&new_binary);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    wire::write_message(
        writer,
        &Response::UpdateComplete {
            new_binary: new_binary.clone(),
        },
    )
    .await?;

    tracing::info!("Update complete, shutting down old server");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    std::process::exit(0);
}

/// Run a shell command as a build step; returns true on success.
async fn run_build_step<W: AsyncWrite + Unpin>(
    writer: &mut W,
    program: &str,
    args: &[&str],
    cwd: &str,
    label: &str,
) -> Result<bool> {
    use std::process::Command;

    let result = Command::new(program).args(args).current_dir(cwd).output();
    match result {
        Ok(output) if output.status.success() => {
            let msg = String::from_utf8_lossy(&output.stdout);
            send_progress(writer, &format!("{}: {}", label, msg.trim())).await?;
            Ok(true)
        }
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr);
            send_error(writer, &format!("{} failed: {}", label, err)).await?;
            Ok(false)
        }
        Err(e) => {
            send_error(writer, &format!("Failed to run {}: {}", program, e)).await?;
            Ok(false)
        }
    }
}

fn release_binary_path(project_dir: &str) -> String {
    #[cfg(windows)]
    {
        format!("{}\\target\\release\\claude-remote-server.exe", project_dir)
    }
    #[cfg(not(windows))]
    {
        format!("{}/target/release/claude-remote-server", project_dir)
    }
}

fn spawn_new_server(binary: &str) {
    use std::process::{Command, Stdio};

    #[cfg(windows)]
    {
        let _ = Command::new("cmd")
            .args(["/c", "start", "", binary])
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new(binary)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

async fn handle_exec<W: AsyncWrite + Unpin>(
    writer: &mut W,
    command: &str,
    cwd: Option<&str>,
) -> Result<()> {
    tracing::info!("Executing command: {}", command);

    let result = run_shell_command(command, cwd);
    match result {
        Ok(output) => {
            wire::write_message(
                writer,
                &Response::ExecResult {
                    exit_code: output.status.code(),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                },
            )
            .await?;
        }
        Err(e) => {
            send_error(writer, &format!("Failed to execute command: {}", e)).await?;
        }
    }
    Ok(())
}

fn run_shell_command(command: &str, cwd: Option<&str>) -> std::io::Result<std::process::Output> {
    use std::process::Command;

    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/c", command]);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", command]);
        c
    };

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.output()
}

async fn handle_stat_file<W: AsyncWrite + Unpin>(writer: &mut W, path: &str) -> Result<()> {
    match tokio::fs::metadata(path).await {
        Ok(meta) if meta.is_dir() => {
            send_error(
                writer,
                &format!("Path is a directory, not a file: {}", path),
            )
            .await
        }
        Ok(meta) => {
            wire::write_message(writer, &Response::FileStat { size: meta.len() }).await?;
            Ok(())
        }
        Err(e) => send_error(writer, &format!("Failed to stat file: {}", e)).await,
    }
}

async fn handle_get_file<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ctx: &ConnectionCtx,
    path: &str,
) -> Result<()> {
    use base64::Engine;

    let _ = ctx
        .activity_tx
        .send(Activity::FileGet {
            fingerprint: ctx.fingerprint_str.clone(),
            path: path.to_string(),
        })
        .await;

    if let Err(msg) = validate_file_path(path).await {
        return send_error(writer, &msg).await;
    }

    match tokio::fs::read(path).await {
        Ok(content) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&content);
            wire::write_message(writer, &Response::FileContent { content: encoded }).await?;
            Ok(())
        }
        Err(e) => send_error(writer, &format!("Failed to read file: {}", e)).await,
    }
}

async fn handle_get_file_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    path: &str,
    offset: u64,
    length: u64,
) -> Result<()> {
    use base64::Engine;
    if let Err(msg) = validate_file_path(path).await {
        return send_error(writer, &msg).await;
    }

    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => return send_error(writer, &format!("Failed to open file: {}", e)).await,
    };

    if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
        return send_error(writer, &format!("Failed to seek: {}", e)).await;
    }

    let buffer = read_chunk(&mut file, offset, length).await?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
    wire::write_message(writer, &Response::FileChunk { content: encoded }).await?;
    Ok(())
}

/// Read a chunk from a file. Falls back to partial read if exact read fails.
async fn read_chunk(file: &mut tokio::fs::File, offset: u64, length: u64) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; length as usize];
    match file.read_exact(&mut buffer).await {
        Ok(_) => Ok(buffer),
        Err(_) => {
            // Partial read fallback (e.g. near end of file)
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buffer = vec![0u8; length as usize];
            let n = file.read(&mut buffer).await?;
            buffer.truncate(n);
            Ok(buffer)
        }
    }
}

async fn handle_put_file<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ctx: &ConnectionCtx,
    path: &str,
    content: &str,
) -> Result<()> {
    use base64::Engine;

    let _ = ctx
        .activity_tx
        .send(Activity::FilePut {
            fingerprint: ctx.fingerprint_str.clone(),
            path: path.to_string(),
        })
        .await;

    let decoded = match base64::engine::general_purpose::STANDARD.decode(content) {
        Ok(d) => d,
        Err(e) => return send_error(writer, &format!("Invalid base64: {}", e)).await,
    };

    match tokio::fs::write(path, &decoded).await {
        Ok(()) => {
            wire::write_message(writer, &Response::FileOk).await?;
            Ok(())
        }
        Err(e) => send_error(writer, &format!("Failed to write file: {}", e)).await,
    }
}

async fn handle_put_file_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    path: &str,
    offset: u64,
    content: &str,
) -> Result<()> {
    use base64::Engine;

    let decoded = match base64::engine::general_purpose::STANDARD.decode(content) {
        Ok(d) => d,
        Err(e) => return send_error(writer, &format!("Invalid base64: {}", e)).await,
    };

    let mut file = if offset == 0 {
        match tokio::fs::File::create(path).await {
            Ok(f) => f,
            Err(e) => return send_error(writer, &format!("Failed to open file: {}", e)).await,
        }
    } else {
        match tokio::fs::OpenOptions::new().write(true).open(path).await {
            Ok(f) => f,
            Err(e) => return send_error(writer, &format!("Failed to open file: {}", e)).await,
        }
    };

    if offset > 0 {
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
            return send_error(writer, &format!("Failed to seek: {}", e)).await;
        }
    }

    match file.write_all(&decoded).await {
        Ok(()) => {
            wire::write_message(writer, &Response::FileOk).await?;
            Ok(())
        }
        Err(e) => send_error(writer, &format!("Failed to write chunk: {}", e)).await,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate that a path exists and is not a directory.
async fn validate_file_path(path: &str) -> std::result::Result<(), String> {
    match tokio::fs::metadata(path).await {
        Ok(meta) if meta.is_dir() => Err(format!("Path is a directory, not a file: {}", path)),
        Err(e) => Err(format!("Failed to access path: {}", e)),
        Ok(_) => Ok(()),
    }
}

async fn send_error<W: AsyncWrite + Unpin>(writer: &mut W, message: &str) -> Result<()> {
    wire::write_message(
        writer,
        &Response::Error {
            message: message.to_string(),
        },
    )
    .await?;
    Ok(())
}

async fn send_progress<W: AsyncWrite + Unpin>(writer: &mut W, msg: &str) -> Result<()> {
    wire::write_message(
        writer,
        &Response::UpdateProgress {
            message: msg.to_string(),
        },
    )
    .await?;
    Ok(())
}
