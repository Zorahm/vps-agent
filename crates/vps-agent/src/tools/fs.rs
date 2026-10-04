use super::{run_ok, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::{resolve, RunAs};
use base64::Engine;
use serde::Deserialize;
use std::time::Instant;
use vps_agent_core::output::wrap_untrusted;

pub const MAX_READ_LINES: usize = 2000;
pub const MAX_TRANSFER: usize = 20 * 1024 * 1024;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsReadParams {
    /// Absolute path of the file.
    pub path: String,
    /// First line to return, 1-based. Default 1.
    pub start_line: Option<usize>,
    /// Number of lines to return, at most 2000. Default 2000.
    pub limit: Option<usize>,
    /// Managed user to read as. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsEditParams {
    /// Absolute path of the file.
    pub path: String,
    /// Exact text to replace. Must occur exactly once unless replace_all is set.
    pub old: String,
    /// Replacement text.
    pub new: String,
    /// Replace every occurrence of `old`.
    pub replace_all: Option<bool>,
    /// Managed user to edit as. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsWriteParams {
    /// Absolute path of the file. The parent directory must exist.
    pub path: String,
    /// Full new content of the file.
    pub content: String,
    /// Managed user to write as. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsUploadParams {
    /// Absolute destination path on the server.
    pub path: String,
    /// File content, base64-encoded. At most 20 MB after decoding.
    pub content_base64: String,
    /// Managed user to write as. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FsDownloadParams {
    /// Absolute path of the file on the server. At most 20 MB.
    pub path: String,
    /// Managed user to read as. Default: agent.
    pub as_user: Option<String>,
}

pub fn slice_lines(content: &str, start: usize, limit: usize) -> (String, usize) {
    let lines: Vec<&str> = content.lines().collect();
    let first = start.max(1);
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate().skip(first - 1).take(limit) {
        out.push_str(&format!("{:>6}\t{line}\n", i + 1));
    }
    (out, lines.len())
}

#[derive(Debug)]
pub enum EditError {
    NotFound,
    Ambiguous(usize),
    Identical,
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditError::NotFound => write!(f, "`old` was not found in the file"),
            EditError::Ambiguous(n) => {
                write!(f, "`old` matches {n} times; add context or set replace_all")
            }
            EditError::Identical => write!(f, "`old` and `new` are identical"),
        }
    }
}

pub fn apply_edit(content: &str, old: &str, new: &str, replace_all: bool) -> Result<String, EditError> {
    if old.is_empty() {
        return Err(EditError::NotFound);
    }
    if old == new {
        return Err(EditError::Identical);
    }
    match content.matches(old).count() {
        0 => Err(EditError::NotFound),
        1 => Ok(content.replacen(old, new, 1)),
        _ if replace_all => Ok(content.replace(old, new)),
        n => Err(EditError::Ambiguous(n)),
    }
}

/// Checks the path against the deny list both as written and after symlink resolution.
pub async fn resolve_path(ctx: &Ctx, run_as: &RunAs, path: &str) -> Result<String, String> {
    ctx.policy.check_path(path)?;
    let out = run_ok(&run_as.argv(&["realpath", "-m", "--", path]), None).await?;
    let real = String::from_utf8_lossy(&out).trim_end_matches('\n').to_string();
    ctx.policy.check_path(&real)?;
    Ok(real)
}

pub async fn read_bytes(run_as: &RunAs, real_path: &str, max: usize) -> Result<Vec<u8>, String> {
    let limit = (max + 1).to_string();
    let data = run_ok(&run_as.argv(&["head", "-c", &limit, "--", real_path]), None).await?;
    if data.len() > max {
        return Err(format!("file is larger than {max} bytes"));
    }
    Ok(data)
}

pub async fn write_bytes(run_as: &RunAs, real_path: &str, data: &[u8]) -> Result<(), String> {
    // tee echoes its input; the copy on stdout is discarded by run_ok's caller.
    run_ok(&run_as.argv(&["tee", "--", real_path]), Some(data)).await.map(|_| ())
}

pub async fn fs_read(ctx: &Ctx, p: FsReadParams) -> ToolResult {
    let started = Instant::now();
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let real = resolve_path(ctx, &run_as, &p.path).await?;
    let data = read_bytes(&run_as, &real, MAX_TRANSFER).await?;
    let limit = p.limit.unwrap_or(MAX_READ_LINES).min(MAX_READ_LINES);
    let (slice, total) = slice_lines(&String::from_utf8_lossy(&data), p.start_line.unwrap_or(1), limit);
    audit("fs_read", run_as.name(), serde_json::json!({"path": real}), Some(0), started.elapsed().as_millis());
    Ok(ToolOutput::text(format!(
        "total_lines: {total}\n{}",
        wrap_untrusted(&format!("file:{real}"), &ctx.policy.redact(&slice))
    )))
}

pub async fn fs_edit(ctx: &Ctx, p: FsEditParams) -> ToolResult {
    let started = Instant::now();
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let real = resolve_path(ctx, &run_as, &p.path).await?;
    let data = read_bytes(&run_as, &real, MAX_TRANSFER).await?;
    let content = String::from_utf8(data).map_err(|_| "file is not valid UTF-8".to_string())?;
    let edited = apply_edit(&content, &p.old, &p.new, p.replace_all == Some(true))
        .map_err(|e| e.to_string())?;
    write_bytes(&run_as, &real, edited.as_bytes()).await?;
    audit(
        "fs_edit",
        run_as.name(),
        serde_json::json!({"path": real, "old_bytes": p.old.len(), "new_bytes": p.new.len()}),
        Some(0),
        started.elapsed().as_millis(),
    );
    Ok(ToolOutput::text(format!("edited {real}")))
}

async fn write_tool(ctx: &Ctx, tool: &str, as_user: Option<&str>, path: &str, data: &[u8]) -> Result<String, String> {
    let started = Instant::now();
    let run_as = resolve(ctx, as_user).await?;
    let real = resolve_path(ctx, &run_as, path).await?;
    write_bytes(&run_as, &real, data).await?;
    audit(
        tool,
        run_as.name(),
        serde_json::json!({"path": real, "bytes": data.len()}),
        Some(0),
        started.elapsed().as_millis(),
    );
    Ok(real)
}

pub async fn fs_write(ctx: &Ctx, p: FsWriteParams) -> ToolResult {
    let real = write_tool(ctx, "fs_write", p.as_user.as_deref(), &p.path, p.content.as_bytes()).await?;
    Ok(ToolOutput::text(format!("wrote {} bytes to {real}", p.content.len())))
}

pub async fn fs_upload(ctx: &Ctx, p: FsUploadParams) -> ToolResult {
    let data = base64::engine::general_purpose::STANDARD
        .decode(p.content_base64.trim())
        .map_err(|e| format!("content_base64 is not valid base64: {e}"))?;
    if data.len() > MAX_TRANSFER {
        return Err(format!("upload is larger than {MAX_TRANSFER} bytes"));
    }
    let real = write_tool(ctx, "fs_upload", p.as_user.as_deref(), &p.path, &data).await?;
    Ok(ToolOutput::text(format!("uploaded {} bytes to {real}", data.len())))
}

pub async fn fs_download(ctx: &Ctx, p: FsDownloadParams) -> ToolResult {
    let started = Instant::now();
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let real = resolve_path(ctx, &run_as, &p.path).await?;
    let data = read_bytes(&run_as, &real, MAX_TRANSFER).await?;
    audit(
        "fs_download",
        run_as.name(),
        serde_json::json!({"path": real, "bytes": data.len()}),
        Some(0),
        started.elapsed().as_millis(),
    );
    let body = base64::engine::general_purpose::STANDARD.encode(&data);
    Ok(ToolOutput::text(format!(
        "size: {}\nencoding: base64\n{}",
        data.len(),
        wrap_untrusted(&format!("file:{real}"), &body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_and_numbers_lines() {
        let (t, total) = slice_lines("a\nb\nc\nd\n", 2, 2);
        assert_eq!(t, "     2\tb\n     3\tc\n");
        assert_eq!(total, 4);
    }

    #[test]
    fn slice_handles_out_of_range_and_no_trailing_newline() {
        assert_eq!(slice_lines("a\nb", 5, 10), (String::new(), 2));
        assert_eq!(slice_lines("a\nb", 2, 10).0, "     2\tb\n");
        assert_eq!(slice_lines("", 1, 10), (String::new(), 0));
        assert_eq!(slice_lines("a\n", 0, 10).0, "     1\ta\n");
    }

    #[test]
    fn edit_replaces_a_unique_match() {
        assert_eq!(
            apply_edit("port=80\nhost=a\n", "port=80", "port=8080", false).unwrap(),
            "port=8080\nhost=a\n"
        );
    }

    #[test]
    fn edit_refuses_missing_ambiguous_and_noop() {
        assert!(matches!(apply_edit("abc", "x", "y", false), Err(EditError::NotFound)));
        assert!(matches!(apply_edit("a a a", "a", "b", false), Err(EditError::Ambiguous(3))));
        assert!(matches!(apply_edit("abc", "b", "b", false), Err(EditError::Identical)));
        assert!(matches!(apply_edit("abc", "", "b", false), Err(EditError::NotFound)));
    }

    #[test]
    fn edit_replace_all() {
        assert_eq!(apply_edit("a a a", "a", "b", true).unwrap(), "b b b");
    }
}
