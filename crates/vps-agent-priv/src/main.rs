mod actions;
mod cli;
mod sys;

use actions::{execute, ActionError, Env};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use sys::RealSystem;
use vps_agent_core::paths::{APPS_DIR, ARCHIVE_DIR, POLICY_FILE, REGISTRY_FILE};
use vps_agent_core::policy::Policy;

fn audit(line: &str) {
    let _ = Command::new("/usr/bin/logger")
        .args(["-t", "vps-agent-priv", "--", line])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn fail(code: u8, args: &[String], msg: &str) -> ExitCode {
    eprintln!("vps-agent-priv: {msg}");
    audit(&serde_json::json!({"args": args, "result": "error", "code": code, "error": msg}).to_string());
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sys = RealSystem;
    if sys.uid_of_self() != 0 {
        eprintln!("vps-agent-priv: must run as root (through sudo)");
        return ExitCode::from(4);
    }
    let action = match cli::parse(&args) {
        Ok(a) => a,
        Err(usage) => return fail(2, &args, &usage),
    };
    let policy = match Policy::load(POLICY_FILE) {
        Ok(p) => p,
        Err(e) => return fail(4, &args, &e),
    };
    let env = Env {
        sys: &sys,
        policy: &policy,
        registry_path: Path::new(REGISTRY_FILE),
        archive_dir: Path::new(ARCHIVE_DIR),
        apps_dir: APPS_DIR,
    };
    match execute(&env, &action) {
        Ok(v) => {
            println!("{v}");
            audit(&serde_json::json!({"args": args, "result": "ok"}).to_string());
            ExitCode::SUCCESS
        }
        Err(ActionError::Denied(m)) => fail(3, &args, &m),
        Err(ActionError::System(m)) => fail(4, &args, &m),
    }
}
