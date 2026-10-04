use std::path::PathBuf;
use vps_agent_core::paths::{HELPER_BIN, JOB_DIR, LOG_DIR, POLICY_FILE};
use vps_agent_core::policy::{CompiledPolicy, Policy};

pub struct Ctx {
    pub policy: CompiledPolicy,
    pub log_dir: PathBuf,
    pub job_dir: PathBuf,
    /// argv prefix for calling the privileged helper
    pub helper: Vec<String>,
}

impl Ctx {
    pub fn load() -> Result<Ctx, String> {
        let policy = CompiledPolicy::new(Policy::load(POLICY_FILE)?)?;
        let ctx = Ctx {
            policy,
            log_dir: PathBuf::from(LOG_DIR),
            job_dir: PathBuf::from(JOB_DIR),
            helper: vec!["sudo".into(), "-n".into(), HELPER_BIN.into()],
        };
        for d in [&ctx.log_dir, &ctx.job_dir] {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        Ok(ctx)
    }
}
