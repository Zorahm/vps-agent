//! Privileged provisioning through the root helper: apt packages, TLS certificates and
//! PostgreSQL databases. Each is off until the administrator enables it in policy.toml,
//! and the helper checks the policy again as root.

use super::system_service::call as call_report;
use super::users::call_helper;
use super::ToolResult;
use crate::ctx::Ctx;
use serde::Deserialize;
use vps_agent_core::names::validate_group_name;
use vps_agent_core::policy::{valid_db_name, valid_domain, valid_package_name};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PkgInstallParams {
    /// apt package names, 1-20. Each must be listed under [packages] allow in policy.toml.
    pub packages: Vec<String>,
    /// Run `apt-get update` first. Default false.
    pub update: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CertIssueParams {
    /// Domain to get a Let's Encrypt certificate for. Its DNS must already point at this
    /// server, and it must be listed under [certs] domains in policy.toml.
    pub domain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DbCreateParams {
    /// Managed user that will own the database. A PostgreSQL role with the same name is created.
    pub user: String,
    /// Database name: lowercase letters, digits and underscores.
    pub database: String,
    /// Default false: peer authentication over the Unix socket, no password exists.
    /// true: a random password is set and written to a file in the user's home for apps
    /// that can only connect over TCP; the password is not returned.
    pub password: Option<bool>,
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

pub fn pkg_args(packages: &[String]) -> Result<Vec<String>, String> {
    if !(1..=20).contains(&packages.len()) {
        return Err("give 1 to 20 package names".into());
    }
    if let Some(bad) = packages.iter().find(|p| !valid_package_name(p)) {
        return Err(format!("{bad:?} is not a plain package name (no versions, paths or options)"));
    }
    let mut args = strings(&["pkg", "install"]);
    args.extend(packages.iter().cloned());
    Ok(args)
}

pub fn cert_args(domain: &str) -> Result<Vec<String>, String> {
    if !valid_domain(domain) {
        return Err(format!("{domain:?} is not a plain lowercase domain name"));
    }
    Ok(strings(&["cert", "issue", domain]))
}

pub fn db_args(p: &DbCreateParams) -> Result<Vec<String>, String> {
    validate_group_name(&p.user).map_err(|e| format!("user {:?}: {e}", p.user))?;
    if !valid_db_name(&p.database) {
        return Err(format!("database name {:?} must be lowercase letters, digits and underscores, and not a built-in database", p.database));
    }
    let mut args = strings(&["db", "create", &p.user, &p.database]);
    if p.password == Some(true) {
        args.push("--password".into());
    }
    Ok(args)
}

pub async fn pkg_install(ctx: &Ctx, p: PkgInstallParams) -> ToolResult {
    let args = pkg_args(&p.packages)?;
    if p.update == Some(true) {
        call_report(ctx, "pkg_install", strings(&["pkg", "update"])).await?;
    }
    call_report(ctx, "pkg_install", args).await
}

pub async fn cert_issue(ctx: &Ctx, p: CertIssueParams) -> ToolResult {
    call_report(ctx, "cert_issue", cert_args(&p.domain)?).await
}

pub async fn db_create(ctx: &Ctx, p: DbCreateParams) -> ToolResult {
    call_helper(ctx, "db_create", db_args(&p)?, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        strings(v)
    }

    #[test]
    fn builds_helper_arguments() {
        assert_eq!(pkg_args(&names(&["tmux", "python3-venv"])).unwrap(), ["pkg", "install", "tmux", "python3-venv"]);
        assert_eq!(cert_args("shop.example.com").unwrap(), ["cert", "issue", "shop.example.com"]);
        let p = DbCreateParams { user: "shop".into(), database: "shop_prod".into(), password: None };
        assert_eq!(db_args(&p).unwrap(), ["db", "create", "shop", "shop_prod"]);
        let p = DbCreateParams { user: "shop".into(), database: "shop_prod".into(), password: Some(true) };
        assert_eq!(db_args(&p).unwrap(), ["db", "create", "shop", "shop_prod", "--password"]);
    }

    #[test]
    fn rejects_anything_that_is_not_a_plain_name() {
        for bad in [&[][..], &["-y"], &["tmux=1.0"], &["./x.deb"], &["tmux", "--reinstall"]] {
            assert!(pkg_args(&names(bad)).is_err(), "{bad:?}");
        }
        assert!(pkg_args(&names(&["a1"; 21])).is_err());
        for bad in ["", "localhost", "--pre-hook", "a.example.com -d b.example.com", "*.example.com", "A.example.com"] {
            assert!(cert_args(bad).is_err(), "{bad:?}");
        }
        for (user, db) in [("--password", "x"), ("shop", "--password"), ("shop", "a-b"), ("shop", "postgres")] {
            let p = DbCreateParams { user: user.into(), database: db.into(), password: None };
            assert!(db_args(&p).is_err(), "{user} {db}");
        }
    }
}
