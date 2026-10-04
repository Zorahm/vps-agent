use std::process::{Command, Stdio};

pub trait System {
    fn uid_of(&self, user: &str) -> Option<u32>;
    fn uid_taken(&self, uid: u32) -> bool;
    fn groups_of(&self, user: &str) -> Vec<String>;
    fn group_exists(&self, group: &str) -> bool;
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String>;
    fn now(&self) -> u64;
    fn path_exists(&self, path: &str) -> bool;
    fn read_file(&self, path: &str) -> Option<Vec<u8>>;
    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), String>;
    fn remove_file(&self, path: &str) -> Result<(), String>;
}

pub struct RealSystem;

// A fixed PATH and an empty environment: the helper must not inherit anything from its caller.
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

impl RealSystem {
    pub fn uid_of_self(&self) -> u32 {
        output("id", &["-u"]).and_then(|s| s.parse().ok()).unwrap_or(u32::MAX)
    }
}

impl System for RealSystem {
    fn uid_of(&self, user: &str) -> Option<u32> {
        output("id", &["-u", "--", user])?.parse().ok()
    }

    fn uid_taken(&self, uid: u32) -> bool {
        output("getent", &["passwd", &uid.to_string()]).is_some()
    }

    fn groups_of(&self, user: &str) -> Vec<String> {
        output("id", &["-nG", "--", user])
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default()
    }

    fn group_exists(&self, group: &str) -> bool {
        output("getent", &["group", group]).is_some()
    }

    fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
        let out = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{program} exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn path_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), String> {
        std::fs::write(path, data).map_err(|e| format!("{path}: {e}"))
    }

    fn remove_file(&self, path: &str) -> Result<(), String> {
        std::fs::remove_file(path).map_err(|e| format!("{path}: {e}"))
    }
}
