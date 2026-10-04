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
    /// Runs a command and returns its exit code with stdout and stderr combined.
    fn capture(&self, program: &str, args: &[&str]) -> Result<(i32, String), String>;
    /// Like `capture`, feeding `input` on stdin. Secrets go this way, never through arguments.
    fn capture_input(&self, program: &str, args: &[&str], input: &[u8]) -> Result<(i32, String), String>;
    fn home_of(&self, user: &str) -> Option<String>;
    /// 48 hex characters from the kernel's random source.
    fn random_hex(&self) -> Result<String, String>;
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

    fn capture(&self, program: &str, args: &[&str]) -> Result<(i32, String), String> {
        let out = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            // apt and its package scripts must never stop to ask a question.
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((out.status.code().unwrap_or(-1), text))
    }

    fn capture_input(&self, program: &str, args: &[&str], input: &[u8]) -> Result<(i32, String), String> {
        use std::io::Write;
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        // Inputs here are a line or two, far below a pipe buffer, so writing first cannot block.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }
        let out = child.wait_with_output().map_err(|e| format!("{program}: {e}"))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((out.status.code().unwrap_or(-1), text))
    }

    fn home_of(&self, user: &str) -> Option<String> {
        let passwd = output("getent", &["passwd", user])?;
        passwd.split(':').nth(5).filter(|h| h.starts_with('/')).map(String::from)
    }

    fn random_hex(&self) -> Result<String, String> {
        use std::io::Read;
        let mut buf = [0u8; 24];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .map_err(|e| format!("/dev/urandom: {e}"))?;
        Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
    }
}
