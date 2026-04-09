//! Claude Code process management

use anyhow::{Context, Result};
use claude_remote_protocol::claude::{ClaudeInput, ClaudeOutput};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// Handle to a running Claude Code process
pub struct ClaudeProcess {
    child: Child,
}

impl ClaudeProcess {
    /// Spawn a new Claude Code process and send a prompt
    ///
    /// Returns a receiver for streaming responses.
    pub async fn spawn(
        content: &str,
        session_id: Option<String>,
    ) -> Result<(Self, mpsc::Receiver<ClaudeOutput>)> {
        let mut child = claude_command(session_id)
            .spawn()
            .with_context(|| format!("Failed to spawn claude process. Is 'claude' in PATH?"))?;

        let stdin = child.stdin.take().context("Failed to get stdin")?;
        let stdout = child.stdout.take().context("Failed to get stdout")?;

        write_prompt(stdin, content).await?;

        let (tx, rx) = mpsc::channel::<ClaudeOutput>(256);
        spawn_output_reader(stdout, tx);

        Ok((Self { child }, rx))
    }

    /// Abort the current operation
    pub async fn abort(mut self) {
        let _ = self.child.kill().await;
    }
}

fn claude_command(session_id: Option<String>) -> Command {
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/c", "claude"]);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = Command::new("claude");

    cmd.args([
        "-p",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
    ]);
    if let Some(id) = session_id {
        cmd.args(["--session-id", &id]);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

async fn write_prompt(mut stdin: tokio::process::ChildStdin, content: &str) -> Result<()> {
    let input = ClaudeInput::user(content);
    let json = serde_json::to_string(&input)?;
    stdin.write_all(json.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    drop(stdin);
    Ok(())
}

fn spawn_output_reader(stdout: tokio::process::ChildStdout, tx: mpsc::Sender<ClaudeOutput>) {
    tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.is_empty() {
                continue;
            }
            if process_output_line(&line, &tx).await {
                break;
            }
        }
    });
}

async fn process_output_line(line: &str, tx: &mpsc::Sender<ClaudeOutput>) -> bool {
    let output = match serde_json::from_str::<ClaudeOutput>(line) {
        Ok(output) => output,
        Err(error) => {
            tracing::warn!("Failed to parse Claude output: {} - line: {}", error, line);
            return false;
        }
    };
    let is_result = output.is_result();
    if tx.send(output).await.is_err() {
        return true;
    }
    is_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires claude binary"]
    async fn test_simple_prompt() {
        let (_process, mut rx) =
            ClaudeProcess::spawn("What is 2+2? Answer with just the number.", None)
                .await
                .unwrap();

        let mut got_result = false;
        while let Some(output) = rx.recv().await {
            println!("Output: {:?}", output);
            if output.is_result() {
                got_result = true;
                break;
            }
        }

        assert!(got_result);
    }
}
