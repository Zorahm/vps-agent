use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use vps_agent_core::names::validate_group_name;
use vps_agent_core::paths::{
    AGENT_USER, HELPER_BIN, JOB_DIR, LOG_DIR, MANAGED_GROUP, POLICY_FILE, PRIV_DIR, REGISTRY_FILE,
    SUDOERS_DISABLED, SUDOERS_FILE,
};
use vps_agent_core::policy::{CompiledPolicy, Policy};
use vps_agent_core::registry::{lock, Registry, UserEntry};

pub fn adopt_check(user: &str, uid: Option<u32>, reg: &Registry) -> Result<u32, String> {
    validate_group_name(user).map_err(|e| format!("{user:?}: {e}"))?;
    if user == AGENT_USER {
        return Err("the agent user cannot be adopted".into());
    }
    let uid = uid.ok_or_else(|| format!("user {user} does not exist"))?;
    if uid == 0 {
        return Err("UID 0 is never adopted".into());
    }
    if reg.users.contains_key(user) {
        return Err(format!("{user} is already in the registry"));
    }
    Ok(uid)
}

fn capture(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn require_root() -> Result<(), String> {
    if capture("id", &["-u"]).as_deref() == Some("0") {
        Ok(())
    } else {
        Err("this command must be run as root".into())
    }
}

fn uid_of(user: &str) -> Option<u32> {
    capture("id", &["-u", "--", user])?.parse().ok()
}

fn authorized_keys() -> Option<PathBuf> {
    let passwd = capture("getent", &["passwd", AGENT_USER])?;
    let home = passwd.split(':').nth(5)?.to_string();
    Some(Path::new(&home).join(".ssh").join("authorized_keys"))
}

fn disabled(path: &Path) -> PathBuf {
    path.with_extension("disabled")
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn adopt(user: &str) -> Result<(), String> {
    require_root()?;
    let _guard = lock(Path::new(PRIV_DIR))?;
    let mut reg = Registry::load(Path::new(REGISTRY_FILE))?;
    let uid = adopt_check(user, uid_of(user), &reg)?;
    run("usermod", &["-aG", MANAGED_GROUP, user])?;
    reg.users.insert(user.to_string(), UserEntry { uid, adopted: true, created_at: now() });
    reg.save(Path::new(REGISTRY_FILE))?;
    println!("adopted {user} (uid {uid})");
    Ok(())
}

pub fn off() -> Result<(), String> {
    require_root()?;
    if Path::new(SUDOERS_FILE).exists() {
        run("mv", &["-f", SUDOERS_FILE, SUDOERS_DISABLED])?;
        println!("sudoers rule removed");
    }
    if let Some(keys) = authorized_keys().filter(|k| k.exists()) {
        std::fs::rename(&keys, disabled(&keys)).map_err(|e| format!("{}: {e}", keys.display()))?;
        println!("SSH key disabled");
    }
    let reg = Registry::load(Path::new(REGISTRY_FILE))?;
    for user in std::iter::once(AGENT_USER).chain(reg.users.keys().map(String::as_str)) {
        // pkill exits 1 when the user has no processes.
        let _ = Command::new("pkill").args(["-KILL", "-u", user]).status();
    }
    println!("processes of {AGENT_USER} and {} managed user(s) killed", reg.users.len());
    println!("vps-agent is off; run `vps-agent on` to restore access");
    Ok(())
}

pub fn on() -> Result<(), String> {
    require_root()?;
    if Path::new(SUDOERS_DISABLED).exists() {
        run("visudo", &["-cf", SUDOERS_DISABLED])?;
        run("install", &["-m", "0440", "-o", "root", "-g", "root", SUDOERS_DISABLED, SUDOERS_FILE])?;
        std::fs::remove_file(SUDOERS_DISABLED).map_err(|e| e.to_string())?;
        println!("sudoers rule restored");
    }
    if let Some(keys) = authorized_keys() {
        let off = disabled(&keys);
        if off.exists() {
            std::fs::rename(&off, &keys).map_err(|e| format!("{}: {e}", off.display()))?;
            println!("SSH key restored");
        }
    }
    println!("vps-agent is on");
    Ok(())
}

pub fn selftest() -> Result<(), String> {
    let mut failed = 0;
    let mut check = |label: &str, result: Result<(), String>| match result {
        Ok(()) => println!("ok    {label}"),
        Err(e) => {
            println!("FAIL  {label}: {e}");
            failed += 1;
        }
    };

    check(
        "running as agent",
        match capture("id", &["-un"]).as_deref() {
            Some(AGENT_USER) => Ok(()),
            other => Err(format!("running as {}", other.unwrap_or("unknown"))),
        },
    );
    check("policy loads", Policy::load(POLICY_FILE).and_then(CompiledPolicy::new).map(|_| ()));
    for dir in [LOG_DIR, JOB_DIR] {
        let probe = Path::new(dir).join(format!(".selftest-{}", std::process::id()));
        let result = std::fs::create_dir_all(dir)
            .and_then(|_| std::fs::write(&probe, b""))
            .and_then(|_| std::fs::remove_file(&probe))
            .map_err(|e| e.to_string());
        check(&format!("{dir} is writable"), result);
    }
    check(
        "helper answers through sudo",
        match capture("sudo", &["-n", HELPER_BIN, "user", "list"]) {
            Some(out) if out.starts_with('[') => Ok(()),
            Some(out) => Err(format!("unexpected output: {out}")),
            None => Err("sudo -n vps-agent-priv user list failed".into()),
        },
    );
    for tool in ["timeout", "setsid", "realpath", "logger", "head", "tee"] {
        let found = capture("sh", &["-c", &format!("command -v {tool}")]).is_some();
        check(&format!("{tool} is on PATH"), if found { Ok(()) } else { Err("not found".into()) });
    }

    if failed == 0 {
        Ok(())
    } else {
        Err(format!("{failed} check(s) failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adopt_rules() {
        let mut reg = Registry::default();
        assert_eq!(adopt_check("legacy", Some(1001), &reg), Ok(1001));
        assert!(adopt_check("root", Some(0), &reg).is_err());
        assert!(adopt_check("toor", Some(0), &reg).is_err()); // UID 0 under another name
        assert!(adopt_check("agent", Some(999), &reg).is_err());
        assert!(adopt_check("ghost", None, &reg).is_err());
        assert!(adopt_check("-x", Some(1001), &reg).is_err());
        reg.users.insert("legacy".into(), UserEntry { uid: 1001, adopted: true, created_at: 0 });
        assert!(adopt_check("legacy", Some(1001), &reg).is_err());
    }
}
