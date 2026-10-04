use crate::ctx::Ctx;
use vps_agent_core::names::validate_group_name;
use vps_agent_core::paths::AGENT_USER;

pub const SHELL_WRAPPER: &str = r#"cd -- "${1:-$HOME}" || exit 126; exec bash -c "$2""#;

#[derive(Debug, Clone)]
pub enum RunAs {
    Agent,
    Managed(String),
}

pub fn parse_as_user(as_user: Option<&str>) -> Result<RunAs, String> {
    match as_user {
        None | Some("") | Some(AGENT_USER) => Ok(RunAs::Agent),
        Some(name) => {
            // Shape only: adopted users may carry reserved names (ubuntu, www-data).
            // The helper's `user check` decides whether the user is really managed.
            validate_group_name(name).map_err(|e| format!("as_user {name:?}: {e}"))?;
            if name == "root" {
                return Err("as_user root is never allowed".into());
            }
            Ok(RunAs::Managed(name.to_string()))
        }
    }
}

pub async fn resolve(ctx: &Ctx, as_user: Option<&str>) -> Result<RunAs, String> {
    let run_as = parse_as_user(as_user)?;
    if let RunAs::Managed(name) = &run_as {
        let out = tokio::process::Command::new(&ctx.helper[0])
            .args(&ctx.helper[1..])
            .args(["user", "check", name])
            .output()
            .await
            .map_err(|e| format!("cannot run the helper: {e}"))?;
        if !out.status.success() {
            return Err(format!("as_user {name}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    Ok(run_as)
}

impl RunAs {
    pub fn name(&self) -> &str {
        match self {
            RunAs::Agent => AGENT_USER,
            RunAs::Managed(n) => n,
        }
    }

    pub fn argv(&self, argv: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = match self {
            RunAs::Agent => vec![],
            RunAs::Managed(n) => {
                ["sudo", "-n", "-u", n, "-H", "--"].iter().map(|s| s.to_string()).collect()
            }
        };
        v.extend(argv.iter().map(|s| s.to_string()));
        v
    }

    pub fn shell_argv(&self, cwd: Option<&str>, cmd: &str, timeout_secs: Option<u64>) -> Vec<String> {
        let t = timeout_secs.map(|s| s.to_string());
        let mut inner: Vec<&str> = vec![];
        if let Some(t) = &t {
            inner.extend(["timeout", "-k", "5", t.as_str()]);
        }
        inner.extend(["bash", "-lc", SHELL_WRAPPER, "_", cwd.unwrap_or(""), cmd]);
        self.argv(&inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_agent_resolve_to_agent() {
        assert!(matches!(parse_as_user(None), Ok(RunAs::Agent)));
        assert!(matches!(parse_as_user(Some("")), Ok(RunAs::Agent)));
        assert!(matches!(parse_as_user(Some("agent")), Ok(RunAs::Agent)));
    }

    #[test]
    fn hostile_names_are_rejected_before_any_process_is_spawned() {
        for n in ["root", "-rf", "a;b", "$(id)", "shop extra", "../x", "#0", "-u#0"] {
            assert!(parse_as_user(Some(n)).is_err(), "{n:?}");
        }
    }

    #[test]
    fn agent_argv_is_direct() {
        assert_eq!(RunAs::Agent.argv(&["cat", "--", "/x"]), ["cat", "--", "/x"]);
    }

    #[test]
    fn managed_argv_goes_through_sudo_without_a_shell() {
        let v = RunAs::Managed("shop".into()).argv(&["cat", "--", "/x"]);
        assert_eq!(v, ["sudo", "-n", "-u", "shop", "-H", "--", "cat", "--", "/x"]);
    }

    #[test]
    fn shell_argv_passes_cmd_as_one_argument() {
        let cmd = r#"echo "$HOME"; rm -rf "a b" && echo 'x'"#;
        let v = RunAs::Managed("shop".into()).shell_argv(Some("/srv/apps/shop/app"), cmd, Some(60));
        assert_eq!(&v[..6], ["sudo", "-n", "-u", "shop", "-H", "--"]);
        assert_eq!(&v[6..10], ["timeout", "-k", "5", "60"]);
        assert_eq!(&v[10..12], ["bash", "-lc"]);
        assert_eq!(v[12], SHELL_WRAPPER);
        assert_eq!(&v[13..], ["_", "/srv/apps/shop/app", cmd]);
    }

    #[test]
    fn shell_argv_without_timeout_or_cwd() {
        let v = RunAs::Agent.shell_argv(None, "ls", None);
        assert_eq!(v, ["bash", "-lc", SHELL_WRAPPER, "_", "", "ls"]);
    }
}
