//! System services (not `systemctl --user`) that the administrator listed in
//! `[services] allow` of policy.toml. They run through the root helper.

use super::{run_capture, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use serde::Deserialize;
use std::time::Instant;
use vps_agent_core::output::{head_tail, wrap_untrusted, HEAD_LINES, TAIL_LINES};
use vps_agent_core::paths::AGENT_USER;
use vps_agent_core::policy::valid_service_unit;

const CONTROL_ACTIONS: &[&str] = &["start", "stop", "restart", "reload"];

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemServiceParams {
    /// Unit name with the .service suffix, as listed in the policy, for example "bot.service".
    pub unit: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemServiceControlParams {
    /// One of: start, stop, restart, reload.
    pub action: String,
    /// Unit name with the .service suffix, as listed in the policy.
    pub unit: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemServiceLogsParams {
    /// Unit name with the .service suffix, as listed in the policy.
    pub unit: String,
    /// Number of most recent journal lines, 1-1000. Default 100.
    pub lines: Option<u32>,
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Helper arguments for a call; the policy check itself happens in the helper, as root.
pub fn helper_args(verb: &str, unit: &str, lines: Option<u32>) -> Result<Vec<String>, String> {
    if !valid_service_unit(unit) {
        return Err(format!("invalid unit name {unit:?}: expected something like \"bot.service\""));
    }
    match verb {
        "logs" => Ok(strings(&["service", "logs", unit, &lines.unwrap_or(100).clamp(1, 1000).to_string()])),
        "status" => Ok(strings(&["service", "status", unit])),
        v if CONTROL_ACTIONS.contains(&v) => Ok(strings(&["service", v, unit])),
        other => Err(format!("action must be one of: {}; got {other:?}", CONTROL_ACTIONS.join(", "))),
    }
}

async fn call(ctx: &Ctx, tool: &str, args: Vec<String>) -> ToolResult {
    let started = Instant::now();
    let mut argv = ctx.helper.clone();
    argv.extend(args.iter().cloned());
    let out = run_capture(&argv, None).await?;
    audit(tool, AGENT_USER, serde_json::json!({"helper_args": args}), out.status.code(), started.elapsed().as_millis());
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("unexpected helper output: {e}"))?;
    let shown = head_tail(reply["output"].as_str().unwrap_or(""), HEAD_LINES, TAIL_LINES);
    Ok(ToolOutput::text(format!(
        "exit_code: {}\n{}",
        reply["exit_code"],
        wrap_untrusted(tool, &ctx.policy.redact(&shown.text))
    )))
}

pub async fn system_service_status(ctx: &Ctx, p: SystemServiceParams) -> ToolResult {
    call(ctx, "system_service_status", helper_args("status", &p.unit, None)?).await
}

pub async fn system_service_logs(ctx: &Ctx, p: SystemServiceLogsParams) -> ToolResult {
    call(ctx, "system_service_logs", helper_args("logs", &p.unit, p.lines)?).await
}

pub async fn system_service_control(ctx: &Ctx, p: SystemServiceControlParams) -> ToolResult {
    call(ctx, "system_service_control", helper_args(&p.action, &p.unit, None)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_helper_arguments() {
        assert_eq!(helper_args("restart", "bot.service", None).unwrap(), ["service", "restart", "bot.service"]);
        assert_eq!(helper_args("status", "bot.service", None).unwrap(), ["service", "status", "bot.service"]);
        assert_eq!(helper_args("logs", "bot.service", None).unwrap(), ["service", "logs", "bot.service", "100"]);
        assert_eq!(helper_args("logs", "bot.service", Some(9999)).unwrap()[3], "1000");
    }

    #[test]
    fn rejects_other_actions_and_malformed_units() {
        for action in ["enable", "disable", "mask", "edit", "daemon-reload", ""] {
            assert!(helper_args(action, "bot.service", None).is_err(), "{action:?}");
        }
        for unit in ["bot", "--now", "a b.service", "../x.service", ".service", ""] {
            assert!(helper_args("restart", unit, None).is_err(), "{unit:?}");
        }
    }
}
