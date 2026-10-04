use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    ReadOnly,
    #[default]
    Ask,
    Auto,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Deny {
    pub commands: Vec<String>,
    pub paths: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Redact {
    pub patterns: Vec<String>,
}

/// System services (not `systemctl --user`) the agent may control through the helper.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Services {
    pub allow: Vec<String>,
}

fn default_uid_range() -> (u32, u32) {
    (20000, 29999)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub mode: Mode,
    pub uid_range: (u32, u32),
    pub deny: Deny,
    pub redact: Redact,
    pub services: Services,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Ask,
            uid_range: default_uid_range(),
            deny: Deny::default(),
            redact: Redact::default(),
            services: Services::default(),
        }
    }
}

pub const BUILTIN_DENY_GROUPS: &[&str] =
    &["root", "sudo", "wheel", "adm", "docker", "lxd", "disk", "shadow", "systemd-journal"];

pub const DEFAULT_POLICY_TOML: &str = r#"mode = "ask"            # read-only | ask | auto
uid_range = [20000, 29999]

[deny]
commands = ['rm\s+-rf\s+/(\s|$)', 'mkfs', 'dd\s+.*of=/dev/']
paths    = ["/etc/shadow", "/root", "/etc/vps-agent"]
groups   = []

[redact]
patterns = ['(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*\S+', '-----BEGIN [A-Z ]*PRIVATE KEY-----']
"#;

impl Policy {
    pub fn from_toml_str(s: &str) -> Result<Policy, String> {
        let p: Policy = toml::from_str(s).map_err(|e| format!("policy.toml: {e}"))?;
        let (lo, hi) = p.uid_range;
        // 1000..60000 keeps the range clear of system accounts and of nobody (65534).
        if lo < 1000 || hi >= 60000 || lo > hi {
            return Err(format!(
                "policy.toml: uid_range [{lo}, {hi}] must satisfy 1000 <= lo <= hi < 60000"
            ));
        }
        Ok(p)
    }

    pub fn load(path: &str) -> Result<Policy, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Policy::from_toml_str(&s)
    }

    pub fn group_denied(&self, group: &str) -> bool {
        BUILTIN_DENY_GROUPS.contains(&group) || self.deny.groups.iter().any(|g| g == group)
    }

    /// True for a well-formed `.service` unit that the administrator listed by exact name.
    pub fn service_allowed(&self, unit: &str) -> bool {
        valid_service_unit(unit) && self.services.allow.iter().any(|u| u == unit)
    }
}

pub fn valid_service_unit(unit: &str) -> bool {
    unit.len() <= 128
        && unit.strip_suffix(".service").is_some_and(|stem| !stem.is_empty())
        && !unit.starts_with('-')
        && unit.bytes().all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
}

pub fn normalize_lexical(path: &str) -> Result<String, String> {
    if !path.starts_with('/') {
        return Err(format!("path must be absolute: {path:?}"));
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

pub struct CompiledPolicy {
    pub policy: Policy,
    deny_commands: Vec<Regex>,
    deny_paths: Vec<String>,
    redact: Vec<Regex>,
}

impl CompiledPolicy {
    pub fn new(policy: Policy) -> Result<Self, String> {
        let compile = |v: &[String], what: &str| -> Result<Vec<Regex>, String> {
            v.iter()
                .map(|p| Regex::new(p).map_err(|e| format!("{what} pattern {p:?}: {e}")))
                .collect()
        };
        let deny_commands = compile(&policy.deny.commands, "deny.commands")?;
        let redact = compile(&policy.redact.patterns, "redact")?;
        let deny_paths =
            policy.deny.paths.iter().map(|p| normalize_lexical(p)).collect::<Result<_, _>>()?;
        Ok(CompiledPolicy { policy, deny_commands, deny_paths, redact })
    }

    pub fn check_command(&self, cmd: &str) -> Result<(), String> {
        match self.deny_commands.iter().find(|r| r.is_match(cmd)) {
            Some(r) => Err(format!("command denied by policy pattern {:?}", r.as_str())),
            None => Ok(()),
        }
    }

    pub fn check_path(&self, abs_path: &str) -> Result<(), String> {
        let p = normalize_lexical(abs_path)?;
        for d in &self.deny_paths {
            if p == *d || p.starts_with(&format!("{d}/")) {
                return Err(format!("path denied by policy: {d}"));
            }
        }
        Ok(())
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for r in &self.redact {
            out = r.replace_all(&out, "[REDACTED]").into_owned();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled() -> CompiledPolicy {
        CompiledPolicy::new(Policy::from_toml_str(DEFAULT_POLICY_TOML).unwrap()).unwrap()
    }

    #[test]
    fn default_policy_parses() {
        let p = Policy::from_toml_str(DEFAULT_POLICY_TOML).unwrap();
        assert_eq!(p.mode, Mode::Ask);
        assert_eq!(p.uid_range, (20000, 29999));
    }

    #[test]
    fn empty_file_gets_defaults() {
        let p = Policy::from_toml_str("").unwrap();
        assert_eq!(p.mode, Mode::Ask);
        assert_eq!(p.uid_range, (20000, 29999));
        assert!(p.deny.commands.is_empty());
    }

    #[test]
    fn rejects_inverted_or_low_uid_range() {
        assert!(Policy::from_toml_str("uid_range = [30000, 20000]").is_err());
        assert!(Policy::from_toml_str("uid_range = [0, 100]").is_err());
        assert!(Policy::from_toml_str("uid_range = [500, 2000]").is_err());
    }

    #[test]
    fn bad_regex_is_an_error_not_a_panic() {
        let p = Policy::from_toml_str("[deny]\ncommands = ['(']").unwrap();
        assert!(CompiledPolicy::new(p).is_err());
    }

    #[test]
    fn denies_dangerous_commands() {
        let c = compiled();
        assert!(c.check_command("rm -rf /").is_err());
        assert!(c.check_command("sudo rm  -rf  / ").is_err());
        assert!(c.check_command("mkfs.ext4 /dev/sda1").is_err());
        assert!(c.check_command("dd if=/dev/zero of=/dev/sda").is_err());
        assert!(c.check_command("rm -rf /srv/apps/shop/tmp").is_ok());
        assert!(c.check_command("ls -la").is_ok());
    }

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize_lexical("/a/b/../c").unwrap(), "/a/c");
        assert_eq!(normalize_lexical("//etc//shadow").unwrap(), "/etc/shadow");
        assert_eq!(normalize_lexical("/a/./b/").unwrap(), "/a/b");
        assert_eq!(normalize_lexical("/../..").unwrap(), "/");
        assert!(normalize_lexical("etc/shadow").is_err());
        assert!(normalize_lexical("").is_err());
    }

    #[test]
    fn denies_paths_after_normalization() {
        let c = compiled();
        for p in ["/etc/shadow", "//etc/shadow", "/etc/vps-agent/policy.toml",
                  "/etc/vps-agent/../vps-agent/policy.toml", "/root", "/root/.ssh/id_ed25519"] {
            assert!(c.check_path(p).is_err(), "{p}");
        }
        for p in ["/etc/shadow-backup-notes", "/rootfs/a", "/srv/apps/shop/.env", "/etc/hosts"] {
            assert!(c.check_path(p).is_ok(), "{p}");
        }
    }

    #[test]
    fn redacts_secrets() {
        let c = compiled();
        let out = c.redact("DB_PASSWORD=hunter2\napi-key: abc123\nplain line");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("abc123"));
        assert!(out.contains("[REDACTED]"));
        assert!(out.contains("plain line"));
        assert!(c.redact("-----BEGIN OPENSSH PRIVATE KEY-----").contains("[REDACTED]"));
    }

    #[test]
    fn only_listed_service_units_are_allowed() {
        let p = Policy::from_toml_str("[services]
allow = ['bot.service', '../evil.service', 'nginx']").unwrap();
        assert!(p.service_allowed("bot.service"));
        for no in ["nginx.service", "bot", "nginx", "../evil.service", "bot.service extra", "--now", ""] {
            assert!(!p.service_allowed(no), "{no:?}");
        }
        assert!(!Policy::from_toml_str("").unwrap().service_allowed("bot.service"));
    }

    #[test]
    fn builtin_and_configured_groups_are_denied() {
        let p = Policy::from_toml_str("[deny]\ngroups = ['backup']").unwrap();
        assert!(p.group_denied("docker"));
        assert!(p.group_denied("backup"));
        assert!(!p.group_denied("www-data"));
    }
}
