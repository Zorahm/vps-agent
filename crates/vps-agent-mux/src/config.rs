//! hosts.toml: the servers the multiplexer can reach, and how.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// ssh destination: an alias from ~/.ssh/config or user@host.
    pub ssh: String,
    /// Private key used for this host. Required when `ca_key` is set.
    pub identity: Option<String>,
    /// Private key of the user CA. When set, a short-lived certificate for `identity`
    /// is signed before every connection instead of relying on authorized_keys.
    pub ca_key: Option<String>,
    /// Certificate lifetime in minutes. Default 5.
    pub cert_minutes: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub hosts: BTreeMap<String, Host>,
}

fn valid_host_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

pub fn parse_config(text: &str) -> Result<Config, String> {
    let cfg: Config = toml::from_str(text).map_err(|e| format!("hosts.toml: {e}"))?;
    if cfg.hosts.is_empty() {
        return Err("hosts.toml: no [hosts.<name>] entries".into());
    }
    for (name, host) in &cfg.hosts {
        if !valid_host_name(name) {
            return Err(format!("hosts.toml: host name {name:?} must be lowercase letters, digits and dashes"));
        }
        // An ssh destination starting with a dash would be read by ssh as an option.
        if host.ssh.is_empty() || host.ssh.starts_with('-') || host.ssh.contains(char::is_whitespace) {
            return Err(format!("hosts.toml: [hosts.{name}] ssh = {:?} is not a destination", host.ssh));
        }
        if host.ca_key.is_some() && host.identity.is_none() {
            return Err(format!("hosts.toml: [hosts.{name}] ca_key needs identity"));
        }
    }
    Ok(cfg)
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

pub fn default_config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("VPS_AGENT_HOSTS") {
        return Some(PathBuf::from(p));
    }
    Some(home_dir()?.join(".config").join("vps-agent").join("hosts.toml"))
}

pub fn expand_home(path: &str, home: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home.trim_end_matches(['/', '\\'])),
        None => path.to_string(),
    }
}

pub fn ssh_argv(host: &Host, home: &str) -> Vec<String> {
    let mut v: Vec<String> = [
        "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(identity) = &host.identity {
        let identity = expand_home(identity, home);
        v.extend(["-i".into(), identity.clone(), "-o".into(), "IdentitiesOnly=yes".into()]);
        if host.ca_key.is_some() {
            v.extend(["-o".into(), format!("CertificateFile={identity}-cert.pub")]);
        }
    }
    v.extend([host.ssh.clone(), "vps-agent".into(), "serve".into()]);
    v
}

/// The ssh-keygen call that signs a fresh certificate, or None when the host uses a plain key.
pub fn keygen_argv(host: &Host, home: &str) -> Option<Vec<String>> {
    let ca = expand_home(host.ca_key.as_ref()?, home);
    let identity = expand_home(host.identity.as_ref()?, home);
    let minutes = host.cert_minutes.unwrap_or(5).clamp(1, 60);
    Some(vec![
        "ssh-keygen".into(), "-q".into(), "-s".into(), ca, "-I".into(), "vps-agent-mux".into(),
        "-n".into(), "agent".into(),
        // A minute of backdating absorbs clock skew between this machine and the server.
        "-V".into(), format!("-1m:+{minutes}m"),
        format!("{identity}.pub"),
    ])
}

/// Takes `host` out of a tool call's arguments. With one configured host it may be omitted.
pub fn split_host(mut args: Map<String, Value>, cfg: &Config) -> Result<(String, Map<String, Value>), String> {
    let names: Vec<&String> = cfg.hosts.keys().collect();
    let host = match args.remove("host") {
        Some(Value::String(h)) => h,
        Some(other) => return Err(format!("`host` must be a string, not {other}")),
        None if names.len() == 1 => names[0].clone(),
        None => return Err(format!("`host` is required: one of {}", list(&names))),
    };
    if !cfg.hosts.contains_key(&host) {
        return Err(format!("unknown host {host:?}: configured hosts are {}", list(&names)));
    }
    Ok((host, args))
}

fn list(names: &[&String]) -> String {
    names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ")
}

/// Adds a `host` property to a remote tool's input schema.
pub fn inject_host(mut schema: Map<String, Value>, cfg: &Config) -> Map<String, Value> {
    let names: Vec<&String> = cfg.hosts.keys().collect();
    let props = schema.entry("properties").or_insert_with(|| json!({}));
    if let Value::Object(props) = props {
        props.insert(
            "host".into(),
            json!({"type": "string", "enum": names, "description": "Which server to run this on."}),
        );
    }
    if names.len() > 1 {
        let required = schema.entry("required").or_insert_with(|| json!([]));
        if let Value::Array(required) = required {
            required.push(json!("host"));
        }
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO: &str = r#"
[hosts.prod]
ssh = "vps-agent-prod"

[hosts.stage]
ssh = "agent@10.0.0.5"
identity = "~/.ssh/vps-agent_stage"
ca_key = "~/.ssh/vps-agent_ca"
cert_minutes = 10
"#;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn parses_hosts() {
        let cfg = parse_config(TWO).unwrap();
        assert_eq!(cfg.hosts.len(), 2);
        assert_eq!(cfg.hosts["stage"].cert_minutes, Some(10));
    }

    #[test]
    fn rejects_bad_configs() {
        for bad in [
            "",
            "[hosts]",
            "[hosts.Prod]\nssh = \"a\"",
            "[hosts.prod]\nssh = \"-oProxyCommand=evil\"",
            "[hosts.prod]\nssh = \"a b\"",
            "[hosts.prod]\nssh = \"a\"\nca_key = \"~/ca\"",
            "[hosts.prod]\nssh = \"a\"\ntypo = 1",
        ] {
            assert!(parse_config(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn plain_host_uses_ssh_config() {
        let cfg = parse_config(TWO).unwrap();
        let v = ssh_argv(&cfg.hosts["prod"], "/home/me");
        assert_eq!(v[0], "ssh");
        assert_eq!(&v[v.len() - 3..], ["vps-agent-prod", "vps-agent", "serve"]);
        assert!(!v.iter().any(|a| a == "-i"));
        assert!(keygen_argv(&cfg.hosts["prod"], "/home/me").is_none());
    }

    #[test]
    fn cert_host_signs_a_short_lived_certificate_and_presents_it() {
        let cfg = parse_config(TWO).unwrap();
        let k = keygen_argv(&cfg.hosts["stage"], "/home/me").unwrap();
        assert_eq!(k, [
            "ssh-keygen", "-q", "-s", "/home/me/.ssh/vps-agent_ca", "-I", "vps-agent-mux", "-n",
            "agent", "-V", "-1m:+10m", "/home/me/.ssh/vps-agent_stage.pub",
        ]);
        let v = ssh_argv(&cfg.hosts["stage"], "/home/me");
        assert!(v.windows(2).any(|w| w == ["-i", "/home/me/.ssh/vps-agent_stage"]));
        assert!(v.contains(&"CertificateFile=/home/me/.ssh/vps-agent_stage-cert.pub".to_string()));
    }

    #[test]
    fn certificate_lifetime_is_clamped() {
        let mut host = parse_config(TWO).unwrap().hosts["stage"].clone();
        host.cert_minutes = Some(100_000);
        assert!(keygen_argv(&host, "/h").unwrap().contains(&"-1m:+60m".to_string()));
    }

    #[test]
    fn host_is_split_from_arguments() {
        let cfg = parse_config(TWO).unwrap();
        let (h, rest) = split_host(obj(json!({"host": "prod", "cmd": "ls"})), &cfg).unwrap();
        assert_eq!(h, "prod");
        assert_eq!(Value::Object(rest), json!({"cmd": "ls"}));
        assert!(split_host(obj(json!({"cmd": "ls"})), &cfg).is_err());
        assert!(split_host(obj(json!({"host": "nope"})), &cfg).is_err());
        assert!(split_host(obj(json!({"host": 5})), &cfg).is_err());
    }

    #[test]
    fn single_host_is_the_default() {
        let cfg = parse_config("[hosts.only]\nssh = \"a\"").unwrap();
        assert_eq!(split_host(obj(json!({"cmd": "ls"})), &cfg).unwrap().0, "only");
    }

    #[test]
    fn schema_gets_a_host_property() {
        let cfg = parse_config(TWO).unwrap();
        let schema = obj(json!({"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}));
        let out = inject_host(schema, &cfg);
        assert_eq!(out["properties"]["host"]["enum"], json!(["prod", "stage"]));
        assert_eq!(out["required"], json!(["cmd", "host"]));

        // A tool without parameters still gets the property; one host keeps it optional.
        let one = parse_config("[hosts.only]\nssh = \"a\"").unwrap();
        let out = inject_host(obj(json!({"type": "object"})), &one);
        assert_eq!(out["properties"]["host"]["enum"], json!(["only"]));
        assert!(out.get("required").is_none());
    }

    #[test]
    fn home_is_expanded_only_for_tilde_slash() {
        assert_eq!(expand_home("~/.ssh/k", "C:\\Users\\me"), "C:\\Users\\me/.ssh/k");
        assert_eq!(expand_home("/abs/k", "/home/me"), "/abs/k");
        assert_eq!(expand_home("~other/k", "/home/me"), "~other/k");
    }
}
