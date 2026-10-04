pub mod exec;
pub mod fs;
pub mod host;
pub mod image;
pub mod jobs;
pub mod screenshot;
pub mod service;
pub mod session;
pub mod sysinfo;
pub mod users;

use std::process::Stdio;
use tokio::io::AsyncWriteExt;

pub struct ToolOutput {
    pub text: String,
    /// (mime type, base64 data)
    pub image: Option<(String, String)>,
}

impl ToolOutput {
    pub fn text(text: impl Into<String>) -> Self {
        ToolOutput { text: text.into(), image: None }
    }
}

pub type ToolResult = Result<ToolOutput, String>;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runs argv to completion, optionally feeding stdin, and captures stdout and stderr.
pub async fn run_capture(argv: &[String], stdin: Option<&[u8]>) -> Result<std::process::Output, String> {
    let mut child = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
    let pipe = child.stdin.take();
    // Feed stdin while draining stdout: a child that echoes its input (tee) blocks on a
    // full stdout pipe, and writing all of stdin first would then deadlock.
    let feed = async {
        if let (Some(mut pipe), Some(data)) = (pipe, stdin) {
            // A child that exits early closes the pipe; its exit status tells the story.
            let _ = pipe.write_all(data).await;
            // Dropping the pipe here closes it, which is what lets the child see EOF.
        }
    };
    let (_, out) = tokio::join!(feed, child.wait_with_output());
    out.map_err(|e| format!("{}: {e}", argv[0]))
}

/// Like `run_capture`, but a non-zero exit becomes an error carrying stderr.
pub async fn run_ok(argv: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let out = run_capture(argv, stdin).await?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A child that echoes stdin (tee, cat) fills its stdout pipe long before a large
    // input is fully written; feeding stdin and draining stdout must happen together.
    #[tokio::test]
    async fn large_stdin_through_an_echoing_child_does_not_deadlock() {
        let argv: Vec<String> = if cfg!(windows) {
            vec!["findstr".into(), "^".into()]
        } else {
            vec!["cat".into()]
        };
        let input = "0123456789abcdef\r\n".repeat(60_000); // ~1 MB, far above a pipe buffer
        let run = run_ok(&argv, Some(input.as_bytes()));
        let out = tokio::time::timeout(std::time::Duration::from_secs(20), run)
            .await
            .expect("run_ok deadlocked")
            .unwrap();
        assert_eq!(out.len(), input.len());
    }
}
