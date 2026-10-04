mod admin;
mod audit;
mod ctx;
mod runas;
mod server;
mod tools;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "vps-agent", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the MCP server over stdio (default).
    Serve,
    /// Hand an existing user over to the agent. Root only.
    Adopt { user: String },
    /// Re-enable the agent after `off`. Root only.
    On,
    /// Kill switch: revoke sudo, kill agent processes, disable its SSH key. Root only.
    Off,
    /// Check that the installation works. Run as the agent user.
    Selftest,
    #[command(hide = true)]
    JobRun { id: String },
}

fn main() -> ExitCode {
    let result: Result<(), String> = match Cli::parse().cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => ctx::Ctx::load().and_then(|c| {
            tokio::runtime::Runtime::new().map_err(|e| e.to_string())?.block_on(server::serve(c))
        }),
        Cmd::JobRun { id } => ctx::Ctx::load().and_then(|c| tools::jobs::job_run(&c, &id)),
        Cmd::Adopt { user } => admin::adopt(&user),
        Cmd::On => admin::on(),
        Cmd::Off => admin::off(),
        Cmd::Selftest => admin::selftest(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // stdout belongs to the MCP transport; diagnostics go to stderr only.
            eprintln!("vps-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
