//! Persistent interactive shells backed by tmux, one tmux server per user.

use super::{run_capture, run_ok, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::resolve;
use serde::Deserialize;
use std::time::Instant;
use vps_agent_core::output::wrap_untrusted;

const SESSION_PREFIX: &str = "va-";
const MAX_CAPTURE_LINES: u32 = 2000;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionOpenParams {
    /// Session name: lowercase letters, digits and dashes, at most 32 characters. Generated if omitted.
    pub name: Option<String>,
    /// Working directory of the shell. Defaults to the user's home.
    pub cwd: Option<String>,
    /// Managed user that owns the session. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionSendParams {
    /// Session name returned by session_open.
    pub name: String,
    /// Text to type, sent literally.
    pub text: Option<String>,
    /// Press Enter after the text. Default true when `text` is given.
    pub enter: Option<bool>,
    /// Special keys to press after the text, in tmux notation: Enter, Escape, Tab, Up, Down,
    /// Left, Right, BSpace, Space, PPage, NPage, Home, End, F1-F12, C-c, M-x.
    pub keys: Option<Vec<String>>,
    /// Managed user that owns the session. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionCaptureParams {
    /// Session name returned by session_open.
    pub name: String,
    /// Lines of scrollback to include above the visible screen, at most 2000. Default 0.
    pub scrollback: Option<u32>,
    /// Managed user that owns the session. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionCloseParams {
    /// Session name returned by session_open.
    pub name: String,
    /// Managed user that owns the session. Default: agent.
    pub as_user: Option<String>,
}

pub fn valid_session_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

pub fn valid_key(key: &str) -> bool {
    const NAMED: &[&str] = &[
        "Enter", "Escape", "Tab", "Up", "Down", "Left", "Right", "BSpace", "Space", "PPage",
        "NPage", "Home", "End", "DC", "IC",
    ];
    if NAMED.contains(&key) {
        return true;
    }
    if let Some(n) = key.strip_prefix('F') {
        return matches!(n.parse::<u8>(), Ok(1..=12));
    }
    match key.strip_prefix("C-").or_else(|| key.strip_prefix("M-")) {
        Some(rest) => rest.len() == 1 && rest.bytes().all(|b| b.is_ascii_alphanumeric()),
        None => false,
    }
}

/// tmux target for the session: `=` forces an exact name match, `:` selects its current window.
fn target(name: &str) -> Result<String, String> {
    if !valid_session_name(name) {
        return Err(format!("invalid session name {name:?}"));
    }
    Ok(format!("={SESSION_PREFIX}{name}:"))
}

pub async fn session_open(ctx: &Ctx, p: SessionOpenParams) -> ToolResult {
    let started = Instant::now();
    let name = p.name.unwrap_or_else(|| format!("s{:x}", super::now()));
    if !valid_session_name(&name) {
        return Err(format!("invalid session name {name:?}"));
    }
    if let Some(cwd) = &p.cwd {
        ctx.policy.check_path(cwd)?;
    }
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let full = format!("{SESSION_PREFIX}{name}");
    let mut argv = vec!["tmux", "new-session", "-d", "-s", &full, "-x", "200", "-y", "50"];
    if let Some(cwd) = &p.cwd {
        argv.extend(["-c", cwd.as_str()]);
    }
    run_ok(&run_as.argv(&argv), None).await?;
    audit("session_open", run_as.name(), serde_json::json!({"name": name, "cwd": p.cwd}), Some(0), started.elapsed().as_millis());
    Ok(ToolOutput::text(format!("name: {name}\nsize: 200x50")))
}

pub async fn session_send_keys(ctx: &Ctx, p: SessionSendParams) -> ToolResult {
    let started = Instant::now();
    let target = target(&p.name)?;
    let keys = p.keys.unwrap_or_default();
    if let Some(bad) = keys.iter().find(|k| !valid_key(k)) {
        return Err(format!("unsupported key {bad:?}"));
    }
    if let Some(text) = &p.text {
        ctx.policy.check_command(text)?;
    }
    if p.text.is_none() && keys.is_empty() {
        return Err("nothing to send: give `text` or `keys`".into());
    }
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    if let Some(text) = &p.text {
        // -l sends the text literally; without it tmux would read words like "Enter" as keys.
        run_ok(&run_as.argv(&["tmux", "send-keys", "-t", &target, "-l", "--", text]), None).await?;
        if p.enter != Some(false) {
            run_ok(&run_as.argv(&["tmux", "send-keys", "-t", &target, "Enter"]), None).await?;
        }
    }
    for key in &keys {
        run_ok(&run_as.argv(&["tmux", "send-keys", "-t", &target, key]), None).await?;
    }
    audit(
        "session_send_keys",
        run_as.name(),
        serde_json::json!({"name": p.name, "text": p.text, "keys": keys}),
        Some(0),
        started.elapsed().as_millis(),
    );
    Ok(ToolOutput::text("sent; use session_capture to see the screen"))
}

pub async fn session_capture(ctx: &Ctx, p: SessionCaptureParams) -> ToolResult {
    let target = target(&p.name)?;
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let start = format!("-{}", p.scrollback.unwrap_or(0).min(MAX_CAPTURE_LINES));
    let out = run_ok(&run_as.argv(&["tmux", "capture-pane", "-p", "-t", &target, "-S", &start]), None).await?;
    let screen = String::from_utf8_lossy(&out);
    Ok(ToolOutput::text(wrap_untrusted(
        &format!("session:{}", p.name),
        &ctx.policy.redact(screen.trim_end()),
    )))
}

pub async fn session_close(ctx: &Ctx, p: SessionCloseParams) -> ToolResult {
    let started = Instant::now();
    let target = target(&p.name)?;
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let out = run_capture(&run_as.argv(&["tmux", "kill-session", "-t", &target]), None).await?;
    audit("session_close", run_as.name(), serde_json::json!({"name": p.name}), out.status.code(), started.elapsed().as_millis());
    if out.status.success() {
        Ok(ToolOutput::text(format!("closed {}", p.name)))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names_are_strictly_shaped() {
        for ok in ["a", "deploy", "build-2", "s18c2a9f3"] {
            assert!(valid_session_name(ok), "{ok}");
        }
        for bad in ["", "-x", "A", "a b", "a:b", "a.b", "a;b", "$(id)", &"x".repeat(33)] {
            assert!(!valid_session_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn target_is_an_exact_match_on_the_prefixed_name() {
        assert_eq!(target("deploy").unwrap(), "=va-deploy:");
        assert!(target("a:b").is_err());
    }

    #[test]
    fn only_known_keys_are_accepted() {
        for ok in ["Enter", "Escape", "Up", "F1", "F12", "C-c", "C-d", "M-x", "BSpace"] {
            assert!(valid_key(ok), "{ok}");
        }
        for bad in ["", "enter", "F13", "F0", "C-", "C-cc", "C-;", "-t", "rm -rf", "Enter;id"] {
            assert!(!valid_key(bad), "{bad:?}");
        }
    }
}
