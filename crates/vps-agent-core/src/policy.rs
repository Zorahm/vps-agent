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

/// apt packages the agent may install through the helper, by exact name.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Packages {
    pub allow: Vec<String>,
}

/// Let's Encrypt certificates. Off until the administrator gives an email, accepts the
/// terms of service and lists the domains.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Certs {
    pub email: String,
    pub agree_tos: bool,
    /// Exact names, or `*.example.com` for any name under example.com.
    pub domains: Vec<String>,
    /// Failed attempts count too: they are what exhausts Let's Encrypt rate limits.
    pub max_per_day: u32,
}

impl Default for Certs {
    fn default() -> Self {
        Certs { email: String::new(), agree_tos: false, domains: Vec::new(), max_per_day: 5 }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Databases {
    /// Allow creating PostgreSQL roles and databases for managed users.
    pub postgres: bool,
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
    pub packages: Packages,
    pub certs: Certs,
    pub databases: Databases,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Ask,
            uid_range: default_uid_range(),
            deny: Deny::default(),
            redact: Redact::default(),
            services: Services::default(),
            packages: Packages::default(),
            certs: Certs::default(),
            databases: Databases::default(),
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
patterns = ['(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*\S+', '-----BEGIN [A-Z ]*PRIVATE KEY-----', '://[^/\s:@]+:[^/\s@]+@']

# System services the agent may start, stop, restart and read logs of, by exact unit name.
[services]
allow = []

# apt packages the agent may install, by exact name. Package scripts run as root and
# dependencies are pulled in automatically: list only what you would install yourself.
[packages]
allow = []

# Let's Encrypt certificates. Disabled until email, agree_tos and domains are all set.
# A domain is an exact name or "*.example.com" for any name under example.com.
[certs]
email = ""
agree_tos = false
domains = []
max_per_day = 5

# PostgreSQL roles and databases for managed users (peer authentication by default).
[databases]
postgres = false
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

    pub fn package_allowed(&self, name: &str) -> bool {
        valid_package_name(name) && self.packages.allow.iter().any(|p| p == name)
    }

    /// Ok when certificates are fully configured and the domain is on the list.
    pub fn cert_request_allowed(&self, domain: &str) -> Result<(), String> {
        let c = &self.certs;
        if !valid_email(&c.email) || !c.agree_tos || c.domains.is_empty() {
            return Err("certificates are not enabled: set email, agree_tos and domains under [certs] in policy.toml".into());
        }
        if !valid_domain(domain) {
            return Err(format!("{domain:?} is not a plain lowercase domain name"));
        }
        let listed = c.domains.iter().any(|entry| match entry.strip_prefix("*.") {
            Some(parent) => domain.strip_suffix(parent).is_some_and(|head| head.ends_with('.')),
            None => entry == domain,
        });
        if listed {
            Ok(())
        } else {
            Err(format!("{domain} is not in [certs] domains of policy.toml"))
        }
    }
}

/// Debian package name: no versions, releases, paths or options can ride along.
pub fn valid_package_name(name: &str) -> bool {
    let b = name.as_bytes();
    (2..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+.-".contains(c))
        && !name.contains("..")
}

pub fn valid_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_email(email: &str) -> bool {
    let ok_char = |b: u8| b.is_ascii_alphanumeric() || b"._+-".contains(&b);
    match email.split_once('@') {
        Some((local, host)) => {
            !local.is_empty() && !local.starts_with('-') && local.bytes().all(ok_char) && valid_domain(host)
        }
        None => false,
    }
}

/// PostgreSQL database name that needs no quoting and is not one of the built-in databases.
pub fn valid_db_name(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=63).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        && !["postgres", "template0", "template1"].contains(&name)
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

#[cfg(test)]
mod privileged_ops_tests {
    use super::*;

    #[test]
    fn everything_is_off_by_default() {
        let p = Policy::from_toml_str("").unwrap();
        assert!(!p.package_allowed("python3-venv"));
        assert!(p.cert_request_allowed("shop.example.com").is_err());
        assert!(!p.databases.postgres);
        let d = Policy::from_toml_str(DEFAULT_POLICY_TOML).unwrap();
        assert!(!d.package_allowed("python3-venv"));
        assert!(d.cert_request_allowed("shop.example.com").is_err());
        assert!(!d.databases.postgres);
    }

    #[test]
    fn packages_match_by_exact_plain_name() {
        let p = Policy::from_toml_str("[packages]\nallow = ['python3-venv', 'libstdc++6', 'evil=1.0', '../x']").unwrap();
        assert!(p.package_allowed("python3-venv"));
        assert!(p.package_allowed("libstdc++6"));
        for no in ["python3", "python3-venv=3.12", "python3-venv/noble", "./python3-venv.deb", "-y",
                   "evil=1.0", "../x", "python3-venv ", "Python3-venv", "a", ""] {
            assert!(!p.package_allowed(no), "{no:?}");
        }
    }

    fn certs(domains: &str) -> Policy {
        Policy::from_toml_str(&format!(
            "[certs]\nemail = 'ops@example.com'\nagree_tos = true\ndomains = {domains}"
        ))
        .unwrap()
    }

    #[test]
    fn cert_domains_match_exactly_or_under_a_wildcard_entry() {
        let p = certs("['shop.example.com', '*.apps.example.com']");
        for ok in ["shop.example.com", "a.apps.example.com", "a.b.apps.example.com"] {
            assert_eq!(p.cert_request_allowed(ok), Ok(()), "{ok}");
        }
        for no in ["example.com", "evilshop.example.com", "apps.example.com", "xapps.example.com",
                   "shop.example.com.evil.net", "*.apps.example.com", "SHOP.example.com",
                   "shop.example.com --pre-hook id", "-d", "localhost", "a..b.com", "-a.example.com", ""] {
            assert!(p.cert_request_allowed(no).is_err(), "{no:?}");
        }
    }

    #[test]
    fn certs_need_an_email_the_terms_and_a_domain_list() {
        let ok = "[certs]\nemail = 'ops@example.com'\nagree_tos = true\ndomains = ['a.example.com']";
        assert!(Policy::from_toml_str(ok).unwrap().cert_request_allowed("a.example.com").is_ok());
        for broken in [
            "[certs]\nagree_tos = true\ndomains = ['a.example.com']",
            "[certs]\nemail = 'ops@example.com'\ndomains = ['a.example.com']",
            "[certs]\nemail = 'ops@example.com'\nagree_tos = true",
            "[certs]\nemail = '--pre-hook=id'\nagree_tos = true\ndomains = ['a.example.com']",
            "[certs]\nemail = 'no-at-sign'\nagree_tos = true\ndomains = ['a.example.com']",
        ] {
            assert!(Policy::from_toml_str(broken).unwrap().cert_request_allowed("a.example.com").is_err(), "{broken}");
        }
    }

    #[test]
    fn database_names_are_plain_identifiers() {
        for ok in ["shop", "shop_prod", "a1", "x"] {
            assert!(valid_db_name(ok), "{ok}");
        }
        for no in ["", "1shop", "Shop", "shop-prod", "shop;drop", "shop db", "postgres", "template0",
                   "template1", &"a".repeat(64)] {
            assert!(!valid_db_name(no), "{no:?}");
        }
    }
}
