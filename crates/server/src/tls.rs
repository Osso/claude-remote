//! TLS server implementation with mTLS support

use anyhow::{Context, Result};
use claude_remote_common::{CertManager, Config, Fingerprint};
use claude_remote_protocol::{wire, Request, Response};
use std::sync::Arc;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tofu_mtls::AcceptAnyClientCert;

use crate::approval::{Activity, ApprovalRequest};
use crate::claude_process::ClaudeProcess;

pub struct Server {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: Config,
    approval_tx: mpsc::Sender<ApprovalRequest>,
    activity_tx: mpsc::Sender<Activity>,
}

impl Server {
    pub async fn new(
        config: &Config,
        address: &str,
        port: u16,
        approval_tx: mpsc::Sender<ApprovalRequest>,
        activity_tx: mpsc::Sender<Activity>,
    ) -> Result<Self> {
        // Load or generate server certificate
        let cert_mgr = CertManager::new(config.config_dir(), "server");
        let (cert_pem, key_pem) = cert_mgr
            .load_or_generate("claude-remote-server")
            .context("Failed to load/generate server certificate")?;

        let fingerprint = cert_mgr.fingerprint()?;
        tracing::info!("Server certificate fingerprint: {}", fingerprint);

        // Parse certificate and key
        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate")?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("Failed to parse private key")?
            .context("No private key found")?;

        // Build TLS config with client certificate verification using tofu-mtls
        let client_verifier = Arc::new(AcceptAnyClientCert::new());
        let tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .context("Failed to build TLS config")?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // Bind to address
        let addr = format!("{}:{}", address, port);
        let listener = TcpListener::bind(&addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;

        tracing::info!("Listening on {}", addr);

        Ok(Self {
            listener,
            acceptor,
            config: Config::with_dir(config.config_dir().to_path_buf()),
            approval_tx,
            activity_tx,
        })
    }

    pub async fn run(&self) -> Result<()> {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            tracing::info!("Connection from {}", peer_addr);

            let acceptor = self.acceptor.clone();
            let config = Config::with_dir(self.config.config_dir().to_path_buf());
            let approval_tx = self.approval_tx.clone();
            let activity_tx = self.activity_tx.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        // Extract client certificate fingerprint
                        let fingerprint = extract_client_fingerprint(&tls_stream);
                        tracing::info!("Client fingerprint: {}", fingerprint);

                        if let Err(e) =
                            handle_connection(tls_stream, fingerprint, config, approval_tx, activity_tx).await
                        {
                            tracing::error!("Connection error: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("TLS handshake failed: {}", e);
                    }
                }
            });
        }
    }
}

/// Extract client certificate fingerprint from TLS stream
fn extract_client_fingerprint(stream: &TlsStream<TcpStream>) -> Fingerprint {
    let (_, server_conn) = stream.get_ref();

    if let Some(certs) = server_conn.peer_certificates() {
        if let Some(cert) = certs.first() {
            return Fingerprint::from_rustls_cert(cert);
        }
    }

    // Fallback if no certificate (shouldn't happen with mandatory client auth)
    Fingerprint("no-certificate".to_string())
}

async fn handle_connection<S>(
    stream: S,
    client_fingerprint: Fingerprint,
    config: Config,
    approval_tx: mpsc::Sender<ApprovalRequest>,
    activity_tx: mpsc::Sender<Activity>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = split(stream);
    let fp_str = client_fingerprint.0.clone();

    // Send connected activity
    let _ = activity_tx
        .send(Activity::Connected {
            fingerprint: fp_str.clone(),
        })
        .await;

    // Check if client is trusted
    let is_trusted = config
        .is_client_trusted(&client_fingerprint)
        .unwrap_or(false);

    if !is_trusted {
        // Request approval via GUI
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

    // Handle requests
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
            Request::Prompt { content, session_id } => {
                tracing::info!("Received prompt: {}...", &content[..content.len().min(50)]);

                // Log the prompt
                let _ = activity_tx
                    .send(Activity::Prompt {
                        fingerprint: fp_str.clone(),
                        content: content.clone(),
                    })
                    .await;

                // Spawn Claude process with the prompt
                match ClaudeProcess::spawn(&content, session_id).await {
                    Ok((process, mut rx)) => {
                        // Store process for potential abort
                        active_process = Some(process);

                        // Stream responses
                        while let Some(output) = rx.recv().await {
                            let is_result = output.is_result();

                            // Log response text
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

                        // Process completed
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

            Request::ListSessions => {
                // TODO: implement session listing
                wire::write_message(
                    &mut writer,
                    &Response::Sessions {
                        sessions: Vec::new(),
                    },
                )
                .await?;
            }

            Request::StatFile { path } => {
                match tokio::fs::metadata(&path).await {
                    Ok(meta) => {
                        wire::write_message(&mut writer, &Response::FileStat { size: meta.len() })
                            .await?;
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
                }
            }

            Request::GetFile { path } => {
                use base64::Engine;

                let _ = activity_tx
                    .send(Activity::FileGet {
                        fingerprint: fp_str.clone(),
                        path: path.clone(),
                    })
                    .await;

                match tokio::fs::read(&path).await {
                    Ok(content) => {
                        let encoded = base64::engine::general_purpose::STANDARD.encode(&content);
                        wire::write_message(&mut writer, &Response::FileContent { content: encoded })
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

            Request::GetFileChunk { path, offset, length } => {
                use base64::Engine;
                use tokio::io::{AsyncReadExt, AsyncSeekExt};

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
                                let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
                                wire::write_message(&mut writer, &Response::FileChunk { content: encoded })
                                    .await?;
                            }
                            Err(e) => {
                                // Try reading what's available (for last chunk)
                                let mut buffer = vec![0u8; length as usize];
                                if file.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                                    match file.read(&mut buffer).await {
                                        Ok(n) => {
                                            buffer.truncate(n);
                                            let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
                                            wire::write_message(&mut writer, &Response::FileChunk { content: encoded })
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

            Request::PutFileChunk { path, offset, total_size, content } => {
                use base64::Engine;
                use tokio::io::{AsyncSeekExt, AsyncWriteExt};

                match base64::engine::general_purpose::STANDARD.decode(&content) {
                    Ok(decoded) => {
                        // For first chunk (offset 0), create/truncate file
                        let file_result = if offset == 0 {
                            tokio::fs::File::create(&path).await
                        } else {
                            tokio::fs::OpenOptions::new()
                                .write(true)
                                .open(&path)
                                .await
                        };

                        match file_result {
                            Ok(mut file) => {
                                if offset > 0 {
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

                // Log on last chunk
                let _ = total_size; // suppress unused warning, used for potential future progress
            }
        }
    }

    // Send disconnected activity
    let _ = activity_tx
        .send(Activity::Disconnected {
            fingerprint: fp_str,
        })
        .await;

    Ok(())
}
