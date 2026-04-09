use anyhow::Result;
use claude_remote_common::{Config, Fingerprint};
use claude_remote_protocol::{Request, Response, wire};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, split};
use tokio::sync::mpsc;

use crate::ServerInfo;
use crate::approval::{Activity, ApprovalRequest};
use crate::claude_process::ClaudeProcess;

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

    let is_trusted = config
        .is_client_trusted(&client_fingerprint)
        .unwrap_or(false);

    if !is_trusted {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let request = ApprovalRequest {
            fingerprint: client_fingerprint.clone(),
            response: response_tx,
        };

        if approval_tx.send(request).await.is_err() {
            tracing::error!("Failed to send approval request");
            return Ok(());
        }

        match response_rx.await {
            Ok(approved) if approved => {
                tracing::info!("Client {} approved", client_fingerprint);
            }
            _ => {
                tracing::info!("Client {} rejected", client_fingerprint);
                let response = Response::Error {
                    message: "Connection rejected".to_string(),
                };
                wire::write_message(&mut writer, &response).await?;
                let _ = activity_tx
                    .send(Activity::Disconnected {
                        fingerprint: fp_str,
                    })
                    .await;
                return Ok(());
            }
        }
    }

    let mut active_process: Option<ClaudeProcess> = None;

    loop {
        let request: Request = match wire::read_message(&mut reader).await {
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
                tracing::info!("Received prompt: {}...", &content[..content.len().min(50)]);
                let _ = activity_tx
                    .send(Activity::Prompt {
                        fingerprint: fp_str.clone(),
                        content: content.clone(),
                    })
                    .await;

                match ClaudeProcess::spawn(&content, session_id).await {
                    Ok((process, mut rx)) => {
                        active_process = Some(process);

                        while let Some(output) = rx.recv().await {
                            let is_result = output.is_result();
                            if let Some(text) = output.text() {
                                if !text.is_empty() && !is_result {
                                    let _ = activity_tx
                                        .send(Activity::Response {
                                            text: text.to_string(),
                                        })
                                        .await;
                                }
                            }

                            let response = Response::Claude { output };
                            wire::write_message(&mut writer, &response).await?;
                            if is_result {
                                let _ = activity_tx.send(Activity::Completed).await;
                                break;
                            }
                        }

                        active_process = None;
                    }
                    Err(e) => {
                        let response = Response::Error {
                            message: format!("Failed to start Claude: {}", e),
                        };
                        wire::write_message(&mut writer, &response).await?;
                    }
                }
            }

            Request::Abort => {
                if let Some(process) = active_process.take() {
                    process.abort().await;
                }
            }

            Request::Ping => {
                wire::write_message(&mut writer, &Response::Pong).await?;
            }

            Request::Status => {
                wire::write_message(
                    &mut writer,
                    &Response::StatusInfo {
                        uptime_secs: server_info.uptime_secs(),
                        version: server_info.version.clone(),
                        started_at: server_info.started_at_iso(),
                    },
                )
                .await?;
            }

            Request::ListSessions => {
                wire::write_message(
                    &mut writer,
                    &Response::Sessions {
                        sessions: Vec::new(),
                    },
                )
                .await?;
            }

            Request::Shutdown => {
                tracing::info!("Shutdown requested by client");
                wire::write_message(&mut writer, &Response::ShuttingDown).await?;
                std::process::exit(0);
            }

            Request::Update { project_dir } => {
                use std::process::Command;

                async fn send_progress<W: tokio::io::AsyncWrite + Unpin>(
                    writer: &mut W,
                    msg: &str,
                ) -> anyhow::Result<()> {
                    wire::write_message(
                        writer,
                        &Response::UpdateProgress {
                            message: msg.to_string(),
                        },
                    )
                    .await?;
                    Ok(())
                }

                send_progress(&mut writer, "Pulling latest changes...").await?;

                let pull_result = Command::new("git")
                    .args(["pull"])
                    .current_dir(&project_dir)
                    .output();

                match pull_result {
                    Ok(output) if output.status.success() => {
                        let msg = String::from_utf8_lossy(&output.stdout);
                        send_progress(&mut writer, &format!("Git pull: {}", msg.trim())).await?;
                    }
                    Ok(output) => {
                        let err = String::from_utf8_lossy(&output.stderr);
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Git pull failed: {}", err),
                            },
                        )
                        .await?;
                        continue;
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to run git: {}", e),
                            },
                        )
                        .await?;
                        continue;
                    }
                }

                send_progress(&mut writer, "Building release...").await?;

                let build_result = Command::new("cargo")
                    .args(["build", "--release", "-p", "claude-remote-server"])
                    .current_dir(&project_dir)
                    .output();

                match build_result {
                    Ok(output) if output.status.success() => {
                        send_progress(&mut writer, "Build complete").await?;
                    }
                    Ok(output) => {
                        let err = String::from_utf8_lossy(&output.stderr);
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Build failed: {}", err),
                            },
                        )
                        .await?;
                        continue;
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to run cargo: {}", e),
                            },
                        )
                        .await?;
                        continue;
                    }
                }

                #[cfg(windows)]
                let new_binary =
                    format!("{}\\target\\release\\claude-remote-server.exe", project_dir);
                #[cfg(not(windows))]
                let new_binary = format!("{}/target/release/claude-remote-server", project_dir);

                if !std::path::Path::new(&new_binary).exists() {
                    wire::write_message(
                        &mut writer,
                        &Response::Error {
                            message: format!("Binary not found: {}", new_binary),
                        },
                    )
                    .await?;
                    continue;
                }

                send_progress(&mut writer, "Starting new server...").await?;

                #[cfg(windows)]
                {
                    let _ = Command::new("cmd")
                        .args(["/c", "start", "", &new_binary])
                        .spawn();
                }
                #[cfg(not(windows))]
                {
                    let _ = Command::new(&new_binary)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn();
                }

                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                wire::write_message(
                    &mut writer,
                    &Response::UpdateComplete {
                        new_binary: new_binary.clone(),
                    },
                )
                .await?;

                tracing::info!("Update complete, shutting down old server");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                std::process::exit(0);
            }

            Request::Exec { command, cwd } => {
                use std::process::Command;

                tracing::info!("Executing command: {}", command);

                #[cfg(windows)]
                let result = {
                    let mut cmd = Command::new("cmd");
                    cmd.args(["/c", &command]);
                    if let Some(dir) = &cwd {
                        cmd.current_dir(dir);
                    }
                    cmd.output()
                };

                #[cfg(not(windows))]
                let result = {
                    let mut cmd = Command::new("sh");
                    cmd.args(["-c", &command]);
                    if let Some(dir) = &cwd {
                        cmd.current_dir(dir);
                    }
                    cmd.output()
                };

                match result {
                    Ok(output) => {
                        wire::write_message(
                            &mut writer,
                            &Response::ExecResult {
                                exit_code: output.status.code(),
                                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                            },
                        )
                        .await?;
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to execute command: {}", e),
                            },
                        )
                        .await?;
                    }
                }
            }

            Request::StatFile { path } => match tokio::fs::metadata(&path).await {
                Ok(meta) => {
                    if meta.is_dir() {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Path is a directory, not a file: {}", path),
                            },
                        )
                        .await?;
                    } else {
                        wire::write_message(&mut writer, &Response::FileStat { size: meta.len() })
                            .await?;
                    }
                }
                Err(e) => {
                    wire::write_message(
                        &mut writer,
                        &Response::Error {
                            message: format!("Failed to stat file: {}", e),
                        },
                    )
                    .await?;
                }
            },

            Request::GetFile { path } => {
                use base64::Engine;

                let _ = activity_tx
                    .send(Activity::FileGet {
                        fingerprint: fp_str.clone(),
                        path: path.clone(),
                    })
                    .await;

                match tokio::fs::metadata(&path).await {
                    Ok(meta) if meta.is_dir() => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Path is a directory, not a file: {}", path),
                            },
                        )
                        .await?;
                        continue;
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to access path: {}", e),
                            },
                        )
                        .await?;
                        continue;
                    }
                    _ => {}
                }

                match tokio::fs::read(&path).await {
                    Ok(content) => {
                        let encoded = base64::engine::general_purpose::STANDARD.encode(&content);
                        wire::write_message(
                            &mut writer,
                            &Response::FileContent { content: encoded },
                        )
                        .await?;
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to read file: {}", e),
                            },
                        )
                        .await?;
                    }
                }
            }

            Request::GetFileChunk {
                path,
                offset,
                length,
            } => {
                use base64::Engine;
                use tokio::io::{AsyncReadExt, AsyncSeekExt};

                match tokio::fs::metadata(&path).await {
                    Ok(meta) if meta.is_dir() => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Path is a directory, not a file: {}", path),
                            },
                        )
                        .await?;
                        continue;
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to access path: {}", e),
                            },
                        )
                        .await?;
                        continue;
                    }
                    _ => {}
                }

                match tokio::fs::File::open(&path).await {
                    Ok(mut file) => {
                        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
                            wire::write_message(
                                &mut writer,
                                &Response::Error {
                                    message: format!("Failed to seek: {}", e),
                                },
                            )
                            .await?;
                            continue;
                        }

                        let mut buffer = vec![0u8; length as usize];
                        match file.read_exact(&mut buffer).await {
                            Ok(_) => {
                                let encoded =
                                    base64::engine::general_purpose::STANDARD.encode(&buffer);
                                wire::write_message(
                                    &mut writer,
                                    &Response::FileChunk { content: encoded },
                                )
                                .await?;
                            }
                            Err(e) => {
                                let mut buffer = vec![0u8; length as usize];
                                if file.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                                    match file.read(&mut buffer).await {
                                        Ok(n) => {
                                            buffer.truncate(n);
                                            let encoded = base64::engine::general_purpose::STANDARD
                                                .encode(&buffer);
                                            wire::write_message(
                                                &mut writer,
                                                &Response::FileChunk { content: encoded },
                                            )
                                            .await?;
                                        }
                                        Err(e) => {
                                            wire::write_message(
                                                &mut writer,
                                                &Response::Error {
                                                    message: format!("Failed to read chunk: {}", e),
                                                },
                                            )
                                            .await?;
                                        }
                                    }
                                } else {
                                    wire::write_message(
                                        &mut writer,
                                        &Response::Error {
                                            message: format!("Failed to read chunk: {}", e),
                                        },
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Failed to open file: {}", e),
                            },
                        )
                        .await?;
                    }
                }
            }

            Request::PutFile { path, content } => {
                use base64::Engine;

                let _ = activity_tx
                    .send(Activity::FilePut {
                        fingerprint: fp_str.clone(),
                        path: path.clone(),
                    })
                    .await;

                match base64::engine::general_purpose::STANDARD.decode(&content) {
                    Ok(decoded) => match tokio::fs::write(&path, &decoded).await {
                        Ok(()) => {
                            wire::write_message(&mut writer, &Response::FileOk).await?;
                        }
                        Err(e) => {
                            wire::write_message(
                                &mut writer,
                                &Response::Error {
                                    message: format!("Failed to write file: {}", e),
                                },
                            )
                            .await?;
                        }
                    },
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Invalid base64: {}", e),
                            },
                        )
                        .await?;
                    }
                }
            }

            Request::PutFileChunk {
                path,
                offset,
                total_size,
                content,
            } => {
                use base64::Engine;
                use tokio::io::{AsyncSeekExt, AsyncWriteExt};

                match base64::engine::general_purpose::STANDARD.decode(&content) {
                    Ok(decoded) => {
                        let file_result = if offset == 0 {
                            tokio::fs::File::create(&path).await
                        } else {
                            tokio::fs::OpenOptions::new().write(true).open(&path).await
                        };

                        match file_result {
                            Ok(mut file) => {
                                if offset > 0 {
                                    if let Err(e) =
                                        file.seek(std::io::SeekFrom::Start(offset)).await
                                    {
                                        wire::write_message(
                                            &mut writer,
                                            &Response::Error {
                                                message: format!("Failed to seek: {}", e),
                                            },
                                        )
                                        .await?;
                                        continue;
                                    }
                                }

                                match file.write_all(&decoded).await {
                                    Ok(()) => {
                                        wire::write_message(&mut writer, &Response::FileOk).await?;
                                    }
                                    Err(e) => {
                                        wire::write_message(
                                            &mut writer,
                                            &Response::Error {
                                                message: format!("Failed to write chunk: {}", e),
                                            },
                                        )
                                        .await?;
                                    }
                                }
                            }
                            Err(e) => {
                                wire::write_message(
                                    &mut writer,
                                    &Response::Error {
                                        message: format!("Failed to open file: {}", e),
                                    },
                                )
                                .await?;
                            }
                        }
                    }
                    Err(e) => {
                        wire::write_message(
                            &mut writer,
                            &Response::Error {
                                message: format!("Invalid base64: {}", e),
                            },
                        )
                        .await?;
                    }
                }

                let _ = total_size;
            }
        }
    }

    let _ = activity_tx
        .send(Activity::Disconnected {
            fingerprint: fp_str,
        })
        .await;

    Ok(())
}
