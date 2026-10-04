use std::process::Stdio;

pub fn audit(tool: &str, as_user: &str, args: serde_json::Value, exit_code: Option<i32>, millis: u128) {
    let line = serde_json::json!({
        "tool": tool, "as_user": as_user, "args": args, "exit_code": exit_code, "ms": millis as u64,
    })
    .to_string();
    // Failing to audit must not fail the tool call; journald may be unavailable in a container.
    let _ = std::process::Command::new("logger")
        .args(["-t", "vps-agent", "--", &line])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
