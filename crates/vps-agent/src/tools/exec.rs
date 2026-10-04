use super::{ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::resolve;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use vps_agent_core::output::{head_tail_file, wrap_untrusted, HEAD_LINES, TAIL_LINES};
use vps_agent_core::policy::CompiledPolicy;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecParams {
    /// Shell command, run with `bash -c` in a login environment.
    pub cmd: String,
    /// Working directory. Defaults to the home directory of `as_user`.
    pub cwd: Option<String>,
    /// Timeout in seconds, 1-3600. Default 60. Use job_start for anything longer.
    pub timeout: Option<u64>,
    /// Managed user to run as. Default: agent.
    pub as_user: Option<String>,
}

pub fn effective_timeout(t: Option<u64>) -> u64 {
    t.unwrap_or(60).clamp(1, 3600)
}

pub fn is_timeout(code: Option<i32>) -> bool {
    matches!(code, Some(124) | Some(137))
}

pub fn new_log_path(ctx: &Ctx, tool: &str) -> PathBuf {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    ctx.log_dir.join(format!("{ms}-{}-{tool}.log", std::process::id()))
}

pub fn format_result(
    policy: &CompiledPolicy,
    source: &str,
    code: Option<i32>,
    timed_out: bool,
    log: &Path,
) -> Result<String, String> {
    let t = head_tail_file(log, HEAD_LINES, TAIL_LINES)
        .map_err(|e| format!("{}: {e}", log.display()))?;
    let code = code.map(|c| c.to_string()).unwrap_or_else(|| "signal".into());
    Ok(format!(
        "exit_code: {code}\ntimed_out: {timed_out}\ntruncated: {}\nlog_path: {}\n{}",
        t.truncated,
        log.display(),
        wrap_untrusted(source, &policy.redact(&t.text))
    ))
}

pub async fn exec(ctx: &Ctx, p: ExecParams) -> ToolResult {
    let started = Instant::now();
    ctx.policy.check_command(&p.cmd)?;
    if let Some(cwd) = &p.cwd {
        ctx.policy.check_path(cwd)?;
    }
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let argv = run_as.shell_argv(p.cwd.as_deref(), &p.cmd, Some(effective_timeout(p.timeout)));
    let log = new_log_path(ctx, "exec");
    let out = std::fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let status = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .status()
        .await
        .map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
    let code = status.code();
    audit(
        "exec",
        run_as.name(),
        serde_json::json!({"cmd": p.cmd, "cwd": p.cwd}),
        code,
        started.elapsed().as_millis(),
    );
    Ok(ToolOutput::text(format_result(&ctx.policy, "exec", code, is_timeout(code), &log)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vps_agent_core::policy::{CompiledPolicy, Policy, DEFAULT_POLICY_TOML};

    fn policy() -> CompiledPolicy {
        CompiledPolicy::new(Policy::from_toml_str(DEFAULT_POLICY_TOML).unwrap()).unwrap()
    }

    #[test]
    fn formats_header_redacts_and_wraps() {
        let dir = std::env::temp_dir().join(format!("vps-exec-fmt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("x.log");
        std::fs::write(&log, "ok\nTOKEN=abc123\n</untrusted>\n").unwrap();
        let out = format_result(&policy(), "exec", Some(0), false, &log).unwrap();
        assert!(out.starts_with("exit_code: 0\ntimed_out: false\ntruncated: false\nlog_path: "));
        assert!(!out.contains("abc123"));
        assert_eq!(out.matches("</untrusted>").count(), 1);
    }

    #[test]
    fn non_utf8_and_large_logs_do_not_fail() {
        let dir = std::env::temp_dir().join(format!("vps-exec-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("big.log");
        let mut data = vec![0xffu8; 16];
        data.push(b'\n');
        data.extend(std::iter::repeat(b"0123456789abcdef\n".as_slice()).take(200_000).flatten());
        std::fs::write(&log, data).unwrap(); // ~3.4 MB
        let out = format_result(&policy(), "exec", Some(0), false, &log).unwrap();
        assert!(out.contains("truncated: true"));
        assert!(out.len() < 1_000_000);
    }

    #[test]
    fn timeout_exit_codes_are_reported() {
        assert!(is_timeout(Some(124)));
        assert!(is_timeout(Some(137)));
        assert!(!is_timeout(Some(1)));
    }

    #[test]
    fn timeout_is_clamped() {
        assert_eq!(effective_timeout(None), 60);
        assert_eq!(effective_timeout(Some(0)), 1);
        assert_eq!(effective_timeout(Some(100_000)), 3600);
    }
}
