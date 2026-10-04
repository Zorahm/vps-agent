use super::{run_capture, ToolOutput, ToolResult};
use crate::audit::audit;
use crate::ctx::Ctx;
use serde::Deserialize;
use std::time::Instant;
use vps_agent_core::names::validate_user_name;
use vps_agent_core::paths::AGENT_USER;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserCreateParams {
    /// Name of the new user: lowercase letters, digits and dashes, 2-31 characters.
    pub name: String,
    /// Login shell: "bash" (default) or "nologin".
    pub shell: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserDeleteParams {
    /// Name of the managed user to delete.
    pub name: String,
    /// Keep a tarball of the home directory on the server.
    pub archive: Option<bool>,
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

pub fn helper_args_create(p: &UserCreateParams) -> Result<Vec<String>, String> {
    validate_user_name(&p.name).map_err(|e| format!("name {:?}: {e}", p.name))?;
    match p.shell.as_deref() {
        None => Ok(strings(&["user", "create", &p.name])),
        Some(shell @ ("bash" | "nologin")) => Ok(strings(&["user", "create", &p.name, "--shell", shell])),
        Some(other) => Err(format!("shell must be bash or nologin, not {other:?}")),
    }
}

pub fn helper_args_delete(p: &UserDeleteParams) -> Result<Vec<String>, String> {
    validate_user_name(&p.name).map_err(|e| format!("name {:?}: {e}", p.name))?;
    let mut args = strings(&["user", "delete", &p.name]);
    if p.archive == Some(true) {
        args.push("--archive".into());
    }
    Ok(args)
}

pub async fn call_helper(ctx: &Ctx, tool: &str, args: Vec<String>, stdin: Option<&[u8]>) -> ToolResult {
    let started = Instant::now();
    let mut argv = ctx.helper.clone();
    argv.extend(args.iter().cloned());
    let out = run_capture(&argv, stdin).await?;
    audit(
        tool,
        AGENT_USER,
        serde_json::json!({"helper_args": args}),
        out.status.code(),
        started.elapsed().as_millis(),
    );
    if out.status.success() {
        Ok(ToolOutput::text(String::from_utf8_lossy(&out.stdout).trim().to_string()))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub async fn user_create(ctx: &Ctx, p: UserCreateParams) -> ToolResult {
    call_helper(ctx, "user_create", helper_args_create(&p)?, None).await
}

pub async fn user_delete(ctx: &Ctx, p: UserDeleteParams) -> ToolResult {
    call_helper(ctx, "user_delete", helper_args_delete(&p)?, None).await
}

pub async fn user_list(ctx: &Ctx) -> ToolResult {
    call_helper(ctx, "user_list", strings(&["user", "list"]), None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_helper_arguments() {
        let c = UserCreateParams { name: "shop".into(), shell: None };
        assert_eq!(helper_args_create(&c).unwrap(), ["user", "create", "shop"]);
        let c = UserCreateParams { name: "shop".into(), shell: Some("nologin".into()) };
        assert_eq!(helper_args_create(&c).unwrap(), ["user", "create", "shop", "--shell", "nologin"]);
        let d = UserDeleteParams { name: "shop".into(), archive: Some(true) };
        assert_eq!(helper_args_delete(&d).unwrap(), ["user", "delete", "shop", "--archive"]);
    }

    #[test]
    fn rejects_bad_input_before_calling_the_helper() {
        assert!(helper_args_create(&UserCreateParams { name: "--shell".into(), shell: None }).is_err());
        assert!(helper_args_create(&UserCreateParams { name: "shop".into(), shell: Some("zsh".into()) })
            .is_err());
        assert!(helper_args_delete(&UserDeleteParams { name: "root".into(), archive: None }).is_err());
    }
}
