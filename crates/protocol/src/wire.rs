//! Wire protocol between client and server
//!
//! Defines Request/Response message types and re-exports the
//! length-prefixed wire protocol from tofu-mtls.

use crate::claude::ClaudeOutput;
use serde::{Deserialize, Serialize};

// Re-export wire protocol from tofu-mtls
pub use tofu_mtls::{read_message, write_message, WireError as ProtocolError, MAX_MESSAGE_SIZE};

/// Request from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Send a prompt to Claude
    Prompt {
        /// The prompt text
        content: String,
        /// Optional session ID to continue
        #[serde(default)]
        session_id: Option<String>,
    },

    /// Abort current request
    Abort,

    /// List active sessions
    ListSessions,

    /// Ping/keepalive
    Ping,

    /// Graceful shutdown
    Shutdown,

    /// Update server: pull, build, restart with new binary
    Update {
        /// Path to the project directory
        project_dir: String,
    },

    /// Get file metadata (size)
    StatFile {
        /// Path to the file
        path: String,
    },

    /// Get a file from the server (for small files < 10MB)
    GetFile {
        /// Path to the file on the server
        path: String,
    },

    /// Get a chunk of a file (for large files)
    GetFileChunk {
        /// Path to the file on the server
        path: String,
        /// Offset in bytes
        offset: u64,
        /// Length to read
        length: u64,
    },

    /// Put a file to the server (for small files < 10MB)
    PutFile {
        /// Path to save the file on the server
        path: String,
        /// File contents (base64 encoded)
        content: String,
    },

    /// Put a chunk of a file (for large files)
    PutFileChunk {
        /// Path to save the file on the server
        path: String,
        /// Offset in bytes
        offset: u64,
        /// Total file size (used for first chunk to create file)
        total_size: u64,
        /// Chunk contents (base64 encoded)
        content: String,
    },
}

/// Response from server to client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Claude output (forwarded from Claude Code)
    Claude { output: ClaudeOutput },

    /// Session list
    Sessions { sessions: Vec<SessionInfo> },

    /// Pong response
    Pong,

    /// Shutdown acknowledged - server will exit after sending this
    ShuttingDown,

    /// Update progress
    UpdateProgress { message: String },

    /// Update complete - server will restart after sending this
    UpdateComplete { new_binary: String },

    /// Error response
    Error { message: String },

    /// Request completed
    Done { session_id: Option<String> },

    /// File metadata
    FileStat { size: u64 },

    /// File content (base64 encoded)
    FileContent { content: String },

    /// File chunk content (base64 encoded)
    FileChunk { content: String },

    /// File operation success
    FileOk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub started_at: String,
    pub last_active: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude::ResultMessage;
    use std::io::Cursor;

    #[tokio::test]
    async fn roundtrip_request_prompt() {
        let req = Request::Prompt {
            content: "Hello".to_string(),
            session_id: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        match decoded {
            Request::Prompt { content, .. } => assert_eq!(content, "Hello"),
            _ => panic!("Wrong request type"),
        }
    }

    #[tokio::test]
    async fn roundtrip_request_prompt_with_session() {
        let req = Request::Prompt {
            content: "Continue".to_string(),
            session_id: Some("session-123".to_string()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        match decoded {
            Request::Prompt {
                content,
                session_id,
            } => {
                assert_eq!(content, "Continue");
                assert_eq!(session_id, Some("session-123".to_string()));
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[tokio::test]
    async fn roundtrip_request_abort() {
        let req = Request::Abort;

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        assert!(matches!(decoded, Request::Abort));
    }

    #[tokio::test]
    async fn roundtrip_request_ping() {
        let req = Request::Ping;

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        assert!(matches!(decoded, Request::Ping));
    }

    #[tokio::test]
    async fn roundtrip_request_list_sessions() {
        let req = Request::ListSessions;

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        assert!(matches!(decoded, Request::ListSessions));
    }

    #[tokio::test]
    async fn roundtrip_response_error() {
        let resp = Response::Error {
            message: "Test error".to_string(),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &resp).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Response = read_message(&mut cursor).await.unwrap();

        match decoded {
            Response::Error { message } => assert_eq!(message, "Test error"),
            _ => panic!("Wrong response type"),
        }
    }

    #[tokio::test]
    async fn roundtrip_response_pong() {
        let resp = Response::Pong;

        let mut buf = Vec::new();
        write_message(&mut buf, &resp).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Response = read_message(&mut cursor).await.unwrap();

        assert!(matches!(decoded, Response::Pong));
    }

    #[tokio::test]
    async fn roundtrip_response_done() {
        let resp = Response::Done {
            session_id: Some("sess-456".to_string()),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &resp).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Response = read_message(&mut cursor).await.unwrap();

        match decoded {
            Response::Done { session_id } => assert_eq!(session_id, Some("sess-456".to_string())),
            _ => panic!("Wrong response type"),
        }
    }

    #[tokio::test]
    async fn roundtrip_response_sessions() {
        let resp = Response::Sessions {
            sessions: vec![
                SessionInfo {
                    id: "s1".to_string(),
                    started_at: "2024-01-01".to_string(),
                    last_active: "2024-01-02".to_string(),
                },
                SessionInfo {
                    id: "s2".to_string(),
                    started_at: "2024-01-03".to_string(),
                    last_active: "2024-01-04".to_string(),
                },
            ],
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &resp).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Response = read_message(&mut cursor).await.unwrap();

        match decoded {
            Response::Sessions { sessions } => {
                assert_eq!(sessions.len(), 2);
                assert_eq!(sessions[0].id, "s1");
                assert_eq!(sessions[1].id, "s2");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[tokio::test]
    async fn roundtrip_response_claude() {
        let resp = Response::Claude {
            output: ClaudeOutput::Result(ResultMessage {
                subtype: "success".to_string(),
                is_error: false,
                result: Some("42".to_string()),
                session_id: None,
                total_cost_usd: Some(0.01),
                extra: serde_json::Value::Null,
            }),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &resp).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Response = read_message(&mut cursor).await.unwrap();

        match decoded {
            Response::Claude { output } => {
                assert!(output.is_result());
                assert_eq!(output.text(), Some("42"));
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[tokio::test]
    async fn read_empty_stream_returns_connection_closed() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let result: Result<Request, _> = read_message(&mut cursor).await;

        assert!(matches!(result, Err(ProtocolError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn large_prompt_roundtrip() {
        let large_content = "x".repeat(1024 * 1024);
        let req = Request::Prompt {
            content: large_content.clone(),
            session_id: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        match decoded {
            Request::Prompt { content, .. } => {
                assert_eq!(content.len(), 1024 * 1024);
                assert_eq!(content, large_content);
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[tokio::test]
    async fn unicode_content_roundtrip() {
        let req = Request::Prompt {
            content: "Hello 世界 🌍 émoji".to_string(),
            session_id: None,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).await.unwrap();

        match decoded {
            Request::Prompt { content, .. } => assert_eq!(content, "Hello 世界 🌍 émoji"),
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_serialization_format() {
        let req = Request::Prompt {
            content: "test".to_string(),
            session_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""type":"prompt""#));
        assert!(json.contains(r#""content":"test""#));
    }

    #[test]
    fn response_serialization_format() {
        let resp = Response::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""type":"pong""#));
    }
}
