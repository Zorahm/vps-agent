//! Host-level actions that go through the privileged helper: lingering and nginx vhosts.

use super::users::call_helper;
use super::ToolResult;
use crate::ctx::Ctx;
use serde::Deserialize;
use vps_agent_core::names::validate_group_name;
use vps_agent_core::nginx::check_vhost;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserLingerParams {
    /// Managed user whose service manager should keep running without a login.
    pub name: String,
    /// true to enable lingering, false to disable it.
    pub enable: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NginxApplyParams {
    /// Vhost name: lowercase letters, digits and dashes. Stored as /etc/nginx/sites-agent/<name>.conf.
    pub name: String,
    /// Full content of the vhost file (one or more `server { ... }` blocks).
    pub content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NginxRemoveParams {
    /// Vhost name given to nginx_apply.
    pub name: String,
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

pub fn linger_args(p: &UserLingerParams) -> Result<Vec<String>, String> {
    validate_group_name(&p.name).map_err(|e| format!("name {:?}: {e}", p.name))?;
    Ok(strings(&["linger", if p.enable { "enable" } else { "disable" }, &p.name]))
}

pub fn nginx_args(verb: &str, name: &str) -> Result<Vec<String>, String> {
    validate_group_name(name).map_err(|e| format!("vhost name {name:?}: {e}"))?;
    Ok(strings(&["nginx", verb, name]))
}

pub async fn user_linger(ctx: &Ctx, p: UserLingerParams) -> ToolResult {
    call_helper(ctx, "user_linger", linger_args(&p)?, None).await
}

pub async fn nginx_apply(ctx: &Ctx, p: NginxApplyParams) -> ToolResult {
    // The helper checks again as root; failing here first gives the model a faster answer.
    check_vhost(&p.content)?;
    call_helper(ctx, "nginx_apply", nginx_args("apply", &p.name)?, Some(p.content.as_bytes())).await
}

pub async fn nginx_remove(ctx: &Ctx, p: NginxRemoveParams) -> ToolResult {
    call_helper(ctx, "nginx_remove", nginx_args("remove", &p.name)?, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_helper_arguments() {
        let p = UserLingerParams { name: "shop".into(), enable: true };
        assert_eq!(linger_args(&p).unwrap(), ["linger", "enable", "shop"]);
        let p = UserLingerParams { name: "shop".into(), enable: false };
        assert_eq!(linger_args(&p).unwrap(), ["linger", "disable", "shop"]);
        assert_eq!(nginx_args("apply", "shop").unwrap(), ["nginx", "apply", "shop"]);
    }

    #[test]
    fn rejects_names_that_could_be_flags_or_paths() {
        assert!(linger_args(&UserLingerParams { name: "--now".into(), enable: true }).is_err());
        assert!(nginx_args("apply", "../etc").is_err());
        assert!(nginx_args("remove", "a b").is_err());
    }
}
