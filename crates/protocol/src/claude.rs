//! Claude Code stream-json protocol types
//!
//! These types match Claude Code's `--input-format stream-json` and
//! `--output-format stream-json` formats.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Input message to Claude Code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaudeInput {
    /// User message
    User {
        message: UserMessage,
    },
    /// Control message (e.g., abort)
    Control {
        #[serde(flatten)]
        control: ControlMessage,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMessage {
    pub role: String,
    pub content: String,
}

impl ClaudeInput {
    pub fn user(content: impl Into<String>) -> Self {
        Self::User {
            message: UserMessage {
                role: "user".to_string(),
                content: content.into(),
            },
        }
    }

    pub fn abort() -> Self {
        Self::Control {
            control: ControlMessage::Abort,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "subtype", rename_all = "snake_case")]
pub enum ControlMessage {
    Abort,
}

/// Output message from Claude Code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaudeOutput {
    /// System initialization message
    System(SystemMessage),

    /// Assistant response (streaming chunks)
    Assistant(AssistantMessage),

    /// Tool use request
    ToolUse(ToolUseMessage),

    /// Tool result
    ToolResult(ToolResultMessage),

    /// Final result
    Result(ResultMessage),

    /// Error
    Error(ErrorMessage),

    /// Unknown message type (for forward compatibility)
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMessage {
    pub subtype: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantMessage {
    pub message: AssistantContent,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantContent {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text { text: String },
    ToolUse { id: String, name: String, input: Value },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseMessage {
    pub tool_use_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub input: Value,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultMessage {
    pub tool_use_id: String,
    #[serde(default)]
    pub output: Option<String>,
    #[serde(default)]
    pub is_error: Option<bool>,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMessage {
    pub subtype: String,
    #[serde(default)]
    pub is_error: bool,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub total_cost_usd: Option<f64>,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(flatten)]
    pub extra: Value,
}

impl ClaudeOutput {
    /// Extract text content from assistant messages
    pub fn text(&self) -> Option<&str> {
        match self {
            ClaudeOutput::Assistant(msg) => {
                for block in &msg.message.content {
                    if let ContentBlock::Text { text } = block {
                        return Some(text);
                    }
                }
                None
            }
            ClaudeOutput::Result(msg) => msg.result.as_deref(),
            _ => None,
        }
    }

    /// Check if this is a final result
    pub fn is_result(&self) -> bool {
        matches!(self, ClaudeOutput::Result(_))
    }

    /// Check if this is an error
    pub fn is_error(&self) -> bool {
        matches!(self, ClaudeOutput::Error(_))
            || matches!(self, ClaudeOutput::Result(r) if r.is_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ClaudeInput tests
    #[test]
    fn serialize_user_input() {
        let input = ClaudeInput::user("What is 2+2?");
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains(r#""type":"user""#));
        assert!(json.contains(r#""role":"user""#));
        assert!(json.contains("What is 2+2?"));
    }

    #[test]
    fn serialize_abort_input() {
        let input = ClaudeInput::abort();
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains(r#""type":"control""#));
        assert!(json.contains(r#""subtype":"abort""#));
    }

    #[test]
    fn user_input_format() {
        let input = ClaudeInput::user("test prompt");
        let json = serde_json::to_string(&input).unwrap();
        // Should match Claude Code's expected format
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "user");
        assert_eq!(parsed["message"]["role"], "user");
        assert_eq!(parsed["message"]["content"], "test prompt");
    }

    // ClaudeOutput parsing tests
    #[test]
    fn parse_system_init() {
        let json = r#"{"type":"system","subtype":"init","cwd":"/tmp","session_id":"abc"}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::System(msg) => {
                assert_eq!(msg.subtype, "init");
                assert_eq!(msg.cwd, Some("/tmp".to_string()));
                assert_eq!(msg.session_id, Some("abc".to_string()));
            }
            _ => panic!("Expected System message"),
        }
    }

    #[test]
    fn parse_system_with_tools() {
        let json = r#"{"type":"system","subtype":"init","tools":["Read","Write","Bash"]}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::System(msg) => {
                assert_eq!(msg.tools, Some(vec!["Read".to_string(), "Write".to_string(), "Bash".to_string()]));
            }
            _ => panic!("Expected System message"),
        }
    }

    #[test]
    fn parse_assistant_message() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Hello"}]}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.text(), Some("Hello"));
        assert!(!output.is_result());
        assert!(!output.is_error());
    }

    #[test]
    fn parse_assistant_with_multiple_content_blocks() {
        let json = r#"{"type":"assistant","message":{"content":[
            {"type":"text","text":"First"},
            {"type":"text","text":"Second"}
        ]}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        // text() returns first text block
        assert_eq!(output.text(), Some("First"));
    }

    #[test]
    fn parse_assistant_with_tool_use() {
        let json = r#"{"type":"assistant","message":{"content":[
            {"type":"text","text":"Let me read that file"},
            {"type":"tool_use","id":"tool_1","name":"Read","input":{"path":"/tmp/test"}}
        ]}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::Assistant(msg) => {
                assert_eq!(msg.message.content.len(), 2);
                match &msg.message.content[1] {
                    ContentBlock::ToolUse { id, name, input } => {
                        assert_eq!(id, "tool_1");
                        assert_eq!(name, "Read");
                        assert_eq!(input["path"], "/tmp/test");
                    }
                    _ => panic!("Expected ToolUse block"),
                }
            }
            _ => panic!("Expected Assistant message"),
        }
    }

    #[test]
    fn parse_tool_use_message() {
        let json = r#"{"type":"tool_use","tool_use_id":"t123","tool_name":"Bash","input":{"command":"ls"}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::ToolUse(msg) => {
                assert_eq!(msg.tool_use_id, "t123");
                assert_eq!(msg.tool_name, "Bash");
                assert_eq!(msg.input["command"], "ls");
            }
            _ => panic!("Expected ToolUse message"),
        }
    }

    #[test]
    fn parse_tool_result_message() {
        let json = r#"{"type":"tool_result","tool_use_id":"t123","output":"file1.txt\nfile2.txt"}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::ToolResult(msg) => {
                assert_eq!(msg.tool_use_id, "t123");
                assert_eq!(msg.output, Some("file1.txt\nfile2.txt".to_string()));
                assert_eq!(msg.is_error, None);
            }
            _ => panic!("Expected ToolResult message"),
        }
    }

    #[test]
    fn parse_tool_result_error() {
        let json = r#"{"type":"tool_result","tool_use_id":"t123","output":"command failed","is_error":true}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::ToolResult(msg) => {
                assert_eq!(msg.is_error, Some(true));
            }
            _ => panic!("Expected ToolResult message"),
        }
    }

    #[test]
    fn parse_result_success() {
        let json = r#"{"type":"result","subtype":"success","result":"42","session_id":"sess123","total_cost_usd":0.05}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert!(output.is_result());
        assert!(!output.is_error());
        assert_eq!(output.text(), Some("42"));
        match output {
            ClaudeOutput::Result(msg) => {
                assert_eq!(msg.subtype, "success");
                assert_eq!(msg.session_id, Some("sess123".to_string()));
                assert_eq!(msg.total_cost_usd, Some(0.05));
            }
            _ => panic!("Expected Result message"),
        }
    }

    #[test]
    fn parse_result_error() {
        let json = r#"{"type":"result","subtype":"error","is_error":true,"result":"Something went wrong"}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert!(output.is_result());
        assert!(output.is_error());
    }

    #[test]
    fn parse_error_message() {
        let json = r#"{"type":"error","error":"API rate limit exceeded","message":"Please try again"}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert!(output.is_error());
        match output {
            ClaudeOutput::Error(msg) => {
                assert_eq!(msg.error, Some("API rate limit exceeded".to_string()));
                assert_eq!(msg.message, Some("Please try again".to_string()));
            }
            _ => panic!("Expected Error message"),
        }
    }

    #[test]
    fn parse_unknown_type_gracefully() {
        let json = r#"{"type":"future_message_type","data":"something"}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert!(matches!(output, ClaudeOutput::Unknown));
    }

    #[test]
    fn parse_unknown_content_block_type() {
        let json = r#"{"type":"assistant","message":{"content":[
            {"type":"future_block_type","data":"something"}
        ]}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::Assistant(msg) => {
                assert!(matches!(msg.message.content[0], ContentBlock::Other));
            }
            _ => panic!("Expected Assistant message"),
        }
    }

    #[test]
    fn text_returns_none_for_non_text_messages() {
        let json = r#"{"type":"tool_use","tool_use_id":"t1","tool_name":"Read","input":{}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.text(), None);
    }

    #[test]
    fn text_returns_none_for_empty_content() {
        let json = r#"{"type":"assistant","message":{"content":[]}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.text(), None);
    }

    #[test]
    fn roundtrip_user_input() {
        let input = ClaudeInput::user("Hello Claude");
        let json = serde_json::to_string(&input).unwrap();
        let parsed: ClaudeInput = serde_json::from_str(&json).unwrap();
        match parsed {
            ClaudeInput::User { message } => {
                assert_eq!(message.role, "user");
                assert_eq!(message.content, "Hello Claude");
            }
            _ => panic!("Expected User input"),
        }
    }

    #[test]
    fn extra_fields_preserved() {
        let json = r#"{"type":"system","subtype":"init","custom_field":"custom_value"}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::System(msg) => {
                assert_eq!(msg.extra["custom_field"], "custom_value");
            }
            _ => panic!("Expected System message"),
        }
    }

    #[test]
    fn assistant_stop_reason() {
        let json = r#"{"type":"assistant","message":{"content":[],"stop_reason":"end_turn"}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::Assistant(msg) => {
                assert_eq!(msg.message.stop_reason, Some("end_turn".to_string()));
            }
            _ => panic!("Expected Assistant message"),
        }
    }

    #[test]
    fn assistant_model_info() {
        let json = r#"{"type":"assistant","message":{"id":"msg_123","model":"claude-3-opus","content":[]}}"#;
        let output: ClaudeOutput = serde_json::from_str(json).unwrap();
        match output {
            ClaudeOutput::Assistant(msg) => {
                assert_eq!(msg.message.id, Some("msg_123".to_string()));
                assert_eq!(msg.message.model, Some("claude-3-opus".to_string()));
            }
            _ => panic!("Expected Assistant message"),
        }
    }
}
