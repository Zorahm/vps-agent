use super::{run_ok, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use std::time::Instant;
use vps_agent_core::output::wrap_untrusted;
use vps_agent_core::paths::AGENT_USER;

/// Returns (total_kb, available_kb).
pub fn parse_meminfo(s: &str) -> Option<(u64, u64)> {
    let field = |key: &str| -> Option<u64> {
        s.lines().find(|l| l.starts_with(key))?.split_whitespace().nth(1)?.parse().ok()
    };
    Some((field("MemTotal:")?, field("MemAvailable:")?))
}

// Each section fails soft: sysinfo is most useful exactly when the machine is unwell.
async fn section(argv: &[&str]) -> String {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    match run_ok(&argv, None).await {
        Ok(out) if !out.is_empty() => String::from_utf8_lossy(&out).trim_end().to_string(),
        Ok(_) => "none".into(),
        Err(_) => "unavailable".into(),
    }
}

pub async fn sysinfo(ctx: &Ctx) -> ToolResult {
    let started = Instant::now();
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "unavailable".into());
    let memory = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| parse_meminfo(&s))
        .map(|(total, avail)| format!("{} MiB total, {} MiB available", total / 1024, avail / 1024))
        .unwrap_or_else(|| "unavailable".into());
    let body = format!(
        "## load (1m 5m 15m), cpus\n{load}, {}\n\n## memory\n{memory}\n\n## disks\n{}\n\n## failed units\n{}\n\n## listening ports\n{}",
        section(&["nproc"]).await,
        section(&["df", "-P", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"]).await,
        section(&["systemctl", "--failed", "--no-legend", "--plain"]).await,
        section(&["ss", "-tlnH"]).await,
    );
    audit("sysinfo", AGENT_USER, serde_json::json!({}), Some(0), started.elapsed().as_millis());
    Ok(ToolOutput::text(wrap_untrusted("sysinfo", &ctx.policy.redact(&body))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo() {
        let s = "MemTotal:        2030000 kB\nMemFree:          100000 kB\nMemAvailable:    1500000 kB\n";
        assert_eq!(parse_meminfo(s), Some((2030000, 1500000)));
        assert_eq!(parse_meminfo("garbage"), None);
    }
}
