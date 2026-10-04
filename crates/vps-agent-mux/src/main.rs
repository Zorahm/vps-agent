mod config;
mod proxy;

use std::process::ExitCode;

const USAGE: &str = "usage: vps-agent-mux [serve|check] [--config <hosts.toml>]";

fn load(explicit: Option<String>) -> Result<(config::Config, String), String> {
    let path = match explicit {
        Some(p) => std::path::PathBuf::from(p),
        None => config::default_config_path().ok_or("cannot find the home directory")?,
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let home = config::home_dir().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default();
    Ok((config::parse_config(&text)?, home))
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut command = "serve".to_string();
    let mut config_path = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "serve" | "check" => command = arg,
            "--config" => config_path = args.next(),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let result = match load(config_path) {
        Err(e) => Err(e),
        Ok((cfg, home)) => {
            let mux = proxy::Mux::new(cfg, home);
            if command == "check" {
                let report = mux.hosts_report().await;
                println!("{report}");
                if report.contains("unreachable") { Err("some hosts are unreachable".into()) } else { Ok(()) }
            } else {
                proxy::serve(mux).await
            }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // stdout belongs to the MCP transport; diagnostics go to stderr only.
            eprintln!("vps-agent-mux: {e}");
            ExitCode::FAILURE
        }
    }
}
