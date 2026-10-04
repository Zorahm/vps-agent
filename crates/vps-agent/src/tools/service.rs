//! `systemctl --user` for managed users. Needs lingering (see user_linger) so the user's
//! service manager runs without a login session.

use super::{run_capture, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use crate::runas::{resolve, RunAs};
use serde::Deserialize;
use std::time::Instant;
use vps_agent_core::output::{head_tail, wrap_untrusted, HEAD_LINES, TAIL_LINES};

// sudo drops XDG_RUNTIME_DIR, and without it systemctl --user cannot find the user's bus.
const USER_BUS_WRAPPER: &str = r#"export XDG_RUNTIME_DIR="/run/user/$(id -u)"; exec "$@""#;
const CONTROL_ACTIONS: &[&str] =
    &["start", "stop", "restart", "reload", "enable", "disable", "daemon-reload"];
const MAX_LOG_LINES: u32 = 1000;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceStatusParams {
    /// Unit name, for example "shop.service".
    pub unit: String,
    /// Managed user that owns the unit. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceControlParams {
    /// One of: start, stop, restart, reload, enable, disable, daemon-reload.
    pub action: String,
    /// Unit name. Not needed for daemon-reload.
    pub unit: Option<String>,
    /// Managed user that owns the unit. Default: agent.
    pub as_user: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceLogsParams {
    /// Unit name, for example "shop.service".
    pub unit: String,
    /// Number of most recent journal lines, at most 1000. Default 100.
    pub lines: Option<u32>,
    /// Managed user that owns the unit. Default: agent.
    pub as_user: Option<String>,
}

pub fn valid_unit(unit: &str) -> bool {
    (1..=128).contains(&unit.len())
        && !unit.starts_with('-')
        && unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"@._:-".contains(&b))
}

pub fn control_args(action: &str, unit: Option<&str>) -> Result<Vec<String>, String> {
    if !CONTROL_ACTIONS.contains(&action) {
        return Err(format!("action must be one of: {}", CONTROL_ACTIONS.join(", ")));
    }
    let mut args = vec!["systemctl".to_string(), "--user".into(), action.into()];
    match (action, unit) {
        ("daemon-reload", _) => {}
        (_, Some(unit)) if valid_unit(unit) => args.push(unit.into()),
        (_, Some(unit)) => return Err(format!("invalid unit name {unit:?}")),
        (_, None) => return Err(format!("`unit` is required for {action}")),
    }
    Ok(args)
}

fn user_bus_argv(run_as: &RunAs, command: &[String]) -> Vec<String> {
    let mut inner = vec!["bash", "-c", USER_BUS_WRAPPER, "_"];
    inner.extend(command.iter().map(String::as_str));
    run_as.argv(&inner)
}

async fn run_user(ctx: &Ctx, tool: &str, as_user: Option<&str>, command: Vec<String>) -> ToolResult {
    let started = Instant::now();
    let run_as = resolve(ctx, as_user).await?;
    let out = run_capture(&user_bus_argv(&run_as, &command), None).await?;
    let code = out.status.code();
    audit(tool, run_as.name(), serde_json::json!({"command": command}), code, started.elapsed().as_millis());
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let shown = head_tail(&text, HEAD_LINES, TAIL_LINES);
    Ok(ToolOutput::text(format!(
        "exit_code: {}\n{}",
        code.map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
        wrap_untrusted(tool, &ctx.policy.redact(&shown.text))
    )))
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

pub async fn service_status(ctx: &Ctx, p: ServiceStatusParams) -> ToolResult {
    if !valid_unit(&p.unit) {
        return Err(format!("invalid unit name {:?}", p.unit));
    }
    // systemctl status exits 3 for an inactive unit; that is an answer, not a failure.
    let command = strings(&["systemctl", "--user", "status", "--no-pager", "-l", &p.unit]);
    run_user(ctx, "service_status", p.as_user.as_deref(), command).await
}

pub async fn service_control(ctx: &Ctx, p: ServiceControlParams) -> ToolResult {
    let command = control_args(&p.action, p.unit.as_deref())?;
    run_user(ctx, "service_control", p.as_user.as_deref(), command).await
}

pub async fn service_logs(ctx: &Ctx, p: ServiceLogsParams) -> ToolResult {
    if !valid_unit(&p.unit) {
        return Err(format!("invalid unit name {:?}", p.unit));
    }
    let lines = p.lines.unwrap_or(100).min(MAX_LOG_LINES).to_string();
    let command =
        strings(&["journalctl", "--user", "-u", &p.unit, "-n", &lines, "--no-pager", "-o", "short-iso"]);
    run_user(ctx, "service_logs", p.as_user.as_deref(), command).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_names_are_validated() {
        for ok in ["shop.service", "worker@1.service", "app.timer", "a"] {
            assert!(valid_unit(ok), "{ok}");
        }
        for bad in ["", "-f", "--user", "a b", "a;b", "a/b", "$(id)", &"x".repeat(129)] {
            assert!(!valid_unit(bad), "{bad:?}");
        }
    }

    #[test]
    fn control_builds_systemctl_arguments() {
        assert_eq!(
            control_args("restart", Some("shop.service")).unwrap(),
            ["systemctl", "--user", "restart", "shop.service"]
        );
        assert_eq!(control_args("daemon-reload", None).unwrap(), ["systemctl", "--user", "daemon-reload"]);
    }

    #[test]
    fn control_rejects_unknown_actions_and_missing_units() {
        assert!(control_args("poweroff", None).is_err());
        assert!(control_args("edit", Some("shop.service")).is_err());
        assert!(control_args("start", None).is_err());
        assert!(control_args("start", Some("--system")).is_err());
    }

    #[test]
    fn user_bus_wrapper_keeps_every_argument_separate() {
        let run_as = RunAs::Managed("shop".into());
        let v = user_bus_argv(&run_as, &strings(&["systemctl", "--user", "start", "a.service"]));
        assert_eq!(&v[..6], ["sudo", "-n", "-u", "shop", "-H", "--"]);
        assert_eq!(&v[6..10], ["bash", "-c", USER_BUS_WRAPPER, "_"]);
        assert_eq!(&v[10..], ["systemctl", "--user", "start", "a.service"]);
    }
}
