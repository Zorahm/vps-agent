use super::{now, run_ok, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::{parse_as_user, resolve};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use vps_agent_core::output::wrap_untrusted;

pub const PID_MARKER: &str = "__vps_agent_pid ";
// setsid gives the command its own session and process group, so job_kill can signal
// the whole tree with one `kill -- -PID`, whatever sudo does with ptys.
pub const JOB_WRAPPER: &str = r#"exec 2>&1; cd -- "${1:-$HOME}" || exit 126; exec setsid -w bash -c 'echo "__vps_agent_pid $$"; exec bash -c "$1"' _ "$2""#;
const CHUNK_MAX: u64 = 64 * 1024;
// A login shell may print a banner before the wrapper runs; look this far for the marker.
const PID_SCAN_LINES: usize = 100;

#[derive(Debug, Serialize, Deserialize)]
pub struct JobMeta {
    pub id: String,
    pub cmd: String,
    pub as_user: String,
    pub cwd: Option<String>,
    pub started_at: u64,
    pub runner_pid: Option<u32>,
    pub pid: Option<i32>,
    pub exit_code: Option<i32>,
    pub finished_at: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JobStartParams {
    /// Shell command to run in the background.
    pub cmd: String,
    /// Working directory. Defaults to the home directory of `as_user`.
    pub cwd: Option<String>,
    /// Managed user to run as. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JobIdParams {
    /// Job id returned by job_start.
    pub id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JobOutputParams {
    /// Job id returned by job_start.
    pub id: String,
    /// Byte offset to read from. Default 0; pass the previous next_offset to continue.
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JobKillParams {
    /// Job id returned by job_start.
    pub id: String,
    /// Send SIGKILL instead of SIGTERM.
    pub force: Option<bool>,
}

pub fn new_job_id() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("j{ms:x}{:04x}", std::process::id() & 0xffff)
}

pub fn valid_job_id(id: &str) -> bool {
    let Some(hex) = id.strip_prefix('j') else { return false };
    (8..=24).contains(&hex.len())
        && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn split_pid_line(first_line: &[u8]) -> Option<i32> {
    std::str::from_utf8(first_line).ok()?.strip_prefix(PID_MARKER)?.trim().parse().ok()
}

pub fn read_chunk(path: &Path, offset: u64, max: u64) -> std::io::Result<(Vec<u8>, u64, bool)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = offset.min(len);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf)?;
    let next = start + buf.len() as u64;
    Ok((buf, next, next >= len))
}

fn job_path(job_dir: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_job_id(id) {
        return Err(format!("invalid job id {id:?}"));
    }
    Ok(job_dir.join(id))
}

pub fn save_meta(job_dir: &Path, meta: &JobMeta) -> Result<(), String> {
    let dir = job_path(job_dir, &meta.id)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join("meta.json.tmp");
    let body = serde_json::to_string(meta).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| format!("{}: {e}", tmp.display()))?;
    // Rename so job_status never reads a half-written file.
    std::fs::rename(&tmp, dir.join("meta.json")).map_err(|e| e.to_string())
}

pub fn load_meta(job_dir: &Path, id: &str) -> Result<JobMeta, String> {
    let file = job_path(job_dir, id)?.join("meta.json");
    let body = std::fs::read_to_string(&file).map_err(|_| format!("no such job: {id}"))?;
    serde_json::from_str(&body).map_err(|e| format!("{}: {e}", file.display()))
}

pub async fn job_start(ctx: &Ctx, p: JobStartParams) -> ToolResult {
    let started = Instant::now();
    ctx.policy.check_command(&p.cmd)?;
    if let Some(cwd) = &p.cwd {
        ctx.policy.check_path(cwd)?;
    }
    let run_as = resolve(ctx, p.as_user.as_deref()).await?;
    let meta = JobMeta {
        id: new_job_id(),
        cmd: p.cmd,
        as_user: run_as.name().to_string(),
        cwd: p.cwd,
        started_at: now(),
        runner_pid: None,
        pid: None,
        exit_code: None,
        finished_at: None,
    };
    save_meta(&ctx.job_dir, &meta)?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // setsid -f detaches the runner so it survives the end of this SSH session.
    let status = tokio::process::Command::new("setsid")
        .arg("-f")
        .arg(exe)
        .args(["job-run", &meta.id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| format!("cannot start setsid: {e}"))?;
    if !status.success() {
        return Err(format!("setsid exited with {status}"));
    }
    audit(
        "job_start",
        run_as.name(),
        serde_json::json!({"id": meta.id, "cmd": meta.cmd, "cwd": meta.cwd}),
        None,
        started.elapsed().as_millis(),
    );
    let log = ctx.job_dir.join(&meta.id).join("output.log");
    Ok(ToolOutput::text(format!("id: {}\nlog_path: {}", meta.id, log.display())))
}

fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    -1
}

/// Body of the hidden `vps-agent job-run <id>` subcommand: runs the job to completion.
pub fn job_run(ctx: &Ctx, id: &str) -> Result<(), String> {
    let mut meta = load_meta(&ctx.job_dir, id)?;
    meta.runner_pid = Some(std::process::id());
    save_meta(&ctx.job_dir, &meta)?;

    // The managed-user check already ran in job_start.
    let run_as = parse_as_user(Some(&meta.as_user))?;
    let argv = run_as.argv(&[
        "bash", "-lc", JOB_WRAPPER, "_", meta.cwd.as_deref().unwrap_or(""), &meta.cmd,
    ]);
    let log_path = ctx.job_dir.join(id).join("output.log");
    let mut log = std::fs::File::create(&log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
    // The wrapper merges the command's stderr into stdout; this handle only catches what
    // fails before the wrapper runs (sudo refusing, bash missing), so it lands in the log.
    let early_errors = log.try_clone().map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(early_errors)
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
    let mut reader = std::io::BufReader::new(child.stdout.take().expect("stdout was piped"));

    let mut line = Vec::new();
    for _ in 0..PID_SCAN_LINES {
        line.clear();
        if reader.read_until(b'\n', &mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        if let Some(pid) = split_pid_line(&line) {
            meta.pid = Some(pid);
            save_meta(&ctx.job_dir, &meta)?;
            break;
        }
        log.write_all(&line).map_err(|e| e.to_string())?;
    }
    std::io::copy(&mut reader, &mut log).map_err(|e| e.to_string())?;

    let status = child.wait().map_err(|e| e.to_string())?;
    meta.exit_code = Some(exit_code_of(status));
    meta.finished_at = Some(now());
    save_meta(&ctx.job_dir, &meta)
}

pub async fn job_status(ctx: &Ctx, p: JobIdParams) -> ToolResult {
    let meta = load_meta(&ctx.job_dir, &p.id)?;
    let runner_alive =
        meta.runner_pid.is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists());
    let status = if meta.exit_code.is_some() {
        "finished"
    } else if runner_alive || meta.runner_pid.is_none() && now().saturating_sub(meta.started_at) < 5 {
        "running"
    } else {
        "lost"
    };
    let bytes = std::fs::metadata(ctx.job_dir.join(&p.id).join("output.log")).map(|m| m.len()).unwrap_or(0);
    let opt = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_else(|| "-".into());
    Ok(ToolOutput::text(format!(
        "id: {}\nstatus: {status}\nexit_code: {}\nas_user: {}\nstarted_at: {}\nfinished_at: {}\noutput_bytes: {bytes}",
        meta.id,
        opt(meta.exit_code.map(i64::from)),
        meta.as_user,
        meta.started_at,
        opt(meta.finished_at.map(|t| t as i64)),
    )))
}

pub async fn job_output(ctx: &Ctx, p: JobOutputParams) -> ToolResult {
    load_meta(&ctx.job_dir, &p.id)?;
    let log = ctx.job_dir.join(&p.id).join("output.log");
    let (bytes, next, eof) = match read_chunk(&log, p.offset.unwrap_or(0), CHUNK_MAX) {
        Ok(chunk) => chunk,
        // The runner has not created the log yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), 0, false),
        Err(e) => return Err(format!("{}: {e}", log.display())),
    };
    let text = ctx.policy.redact(&String::from_utf8_lossy(&bytes));
    Ok(ToolOutput::text(format!(
        "next_offset: {next}\neof: {eof}\n{}",
        wrap_untrusted(&format!("job:{}", p.id), &text)
    )))
}

pub async fn job_kill(ctx: &Ctx, p: JobKillParams) -> ToolResult {
    let started = Instant::now();
    let meta = load_meta(&ctx.job_dir, &p.id)?;
    if meta.exit_code.is_some() {
        return Err("job already finished".into());
    }
    let Some(pid) = meta.pid else {
        return Err("job has no recorded pid yet".into());
    };
    let run_as = parse_as_user(Some(&meta.as_user))?;
    let sig = if p.force == Some(true) { "-KILL" } else { "-TERM" };
    run_ok(&run_as.argv(&["kill", sig, "--", &format!("-{pid}")]), None).await?;
    audit(
        "job_kill",
        run_as.name(),
        serde_json::json!({"id": p.id, "signal": sig}),
        Some(0),
        started.elapsed().as_millis(),
    );
    Ok(ToolOutput::text(format!("{sig} sent to job {}", p.id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_ids_are_strictly_shaped() {
        assert!(valid_job_id("j18c2a9f3b1"));
        for bad in ["", "j", "x18c2a9f3", "j../../etc", "j18c2a9f3/..", "J18C2A9F3", "j18c2a9f3 "] {
            assert!(!valid_job_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn new_ids_are_valid_and_distinct() {
        let a = new_job_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = new_job_id();
        assert!(valid_job_id(&a) && valid_job_id(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn pid_marker_line_is_recognized() {
        assert_eq!(split_pid_line(b"__vps_agent_pid 4242\n"), Some(4242));
        assert_eq!(split_pid_line(b"hello\n"), None);
        assert_eq!(split_pid_line(b"__vps_agent_pid abc\n"), None);
    }

    #[test]
    fn chunks_page_through_a_file() {
        let p = std::env::temp_dir().join(format!("vps-job-chunk-{}", std::process::id()));
        std::fs::write(&p, b"0123456789").unwrap();
        assert_eq!(read_chunk(&p, 0, 4).unwrap(), (b"0123".to_vec(), 4, false));
        assert_eq!(read_chunk(&p, 4, 100).unwrap(), (b"456789".to_vec(), 10, true));
        assert_eq!(read_chunk(&p, 10, 4).unwrap(), (vec![], 10, true));
        assert_eq!(read_chunk(&p, 999, 4).unwrap(), (vec![], 10, true));
    }

    #[test]
    fn meta_round_trips_through_the_job_directory() {
        let dir = std::env::temp_dir().join(format!("vps-job-meta-{}", std::process::id()));
        let meta = JobMeta {
            id: "j18c2a9f3b1".into(),
            cmd: "sleep 1".into(),
            as_user: "agent".into(),
            cwd: None,
            started_at: 5,
            runner_pid: None,
            pid: Some(42),
            exit_code: None,
            finished_at: None,
        };
        save_meta(&dir, &meta).unwrap();
        let back = load_meta(&dir, "j18c2a9f3b1").unwrap();
        assert_eq!(back.pid, Some(42));
        assert_eq!(back.cmd, "sleep 1");
        assert!(load_meta(&dir, "../etc").is_err());
        assert!(load_meta(&dir, "jdeadbeef00").is_err());
    }
}
