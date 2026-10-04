use crate::cli::{Action, Shell};
use crate::sys::System;
use serde_json::{json, Value};
use std::path::Path;
use vps_agent_core::names::{validate_group_name, validate_user_name};
use vps_agent_core::nginx::{check_vhost, INCLUDE_FILE, INCLUDE_LINE, SITES_DIR};
use vps_agent_core::paths::MANAGED_GROUP;
use vps_agent_core::policy::{valid_db_name, Policy};
use vps_agent_core::registry::{lock, Registry, UserEntry};

#[derive(Debug)]
pub enum ActionError {
    Denied(String),
    System(String),
}

pub struct Env<'a> {
    pub sys: &'a dyn System,
    pub policy: &'a Policy,
    pub registry_path: &'a Path,
    pub archive_dir: &'a Path,
    pub apps_dir: &'a str,
}

fn denied<T>(msg: impl Into<String>) -> Result<T, ActionError> {
    Err(ActionError::Denied(msg.into()))
}

pub fn check_managed(env: &Env, reg: &Registry, name: &str) -> Result<(), ActionError> {
    validate_group_name(name).map_err(|e| ActionError::Denied(format!("{name:?}: {e}")))?;
    let Some(entry) = reg.users.get(name) else {
        return denied(format!("{name} is not in the vps-agent registry"));
    };
    let Some(uid) = env.sys.uid_of(name) else {
        return denied(format!("{name} does not exist on this system"));
    };
    if uid == 0 || uid != entry.uid {
        return denied(format!("{name}: live UID {uid} does not match the registry"));
    }
    let (lo, hi) = env.policy.uid_range;
    if !entry.adopted && !(lo..=hi).contains(&uid) {
        return denied(format!("{name}: UID {uid} is outside the managed range {lo}-{hi}"));
    }
    if !env.sys.groups_of(name).iter().any(|g| g == MANAGED_GROUP) {
        return denied(format!("{name} is not a member of {MANAGED_GROUP}"));
    }
    Ok(())
}

pub fn execute(env: &Env, action: &Action) -> Result<Value, ActionError> {
    let dir = env.registry_path.parent().unwrap_or(Path::new("."));
    let guard = lock(dir).map_err(ActionError::System)?;
    let mut reg = Registry::load(env.registry_path).map_err(ActionError::System)?;
    // Only actions that rewrite the registry keep the lock; apt and certbot run for minutes
    // and must not block every other helper call meanwhile.
    let _guard = matches!(action, Action::UserCreate { .. } | Action::UserDelete { .. }).then_some(guard);
    match action {
        Action::UserList => Ok(Value::Array(
            reg.users
                .iter()
                .map(|(n, u)| {
                    json!({"name": n, "uid": u.uid, "adopted": u.adopted, "created_at": u.created_at})
                })
                .collect(),
        )),
        Action::UserCheck { name } => {
            check_managed(env, &reg, name)?;
            Ok(json!({"ok": true}))
        }
        Action::UserCreate { name, shell } => {
            validate_user_name(name).map_err(|e| ActionError::Denied(format!("{name:?}: {e}")))?;
            if reg.users.contains_key(name) || env.sys.uid_of(name).is_some() {
                return denied(format!("user {name} already exists"));
            }
            let Some(uid) = reg.next_free_uid(env.policy.uid_range, &|u| env.sys.uid_taken(u))
            else {
                return denied("no free UID left in the managed range");
            };
            let home = format!("{}/{name}", env.apps_dir);
            let shell = match shell {
                Shell::Bash => "/bin/bash",
                Shell::Nologin => "/usr/sbin/nologin",
            };
            env.sys
                .run(
                    "useradd",
                    &[
                        "--uid", &uid.to_string(), "--user-group", "--create-home", "--home-dir",
                        &home, "--shell", shell, "--groups", MANAGED_GROUP, name,
                    ],
                )
                .map_err(ActionError::System)?;
            env.sys.run("chmod", &["0750", &home]).map_err(ActionError::System)?;
            reg.users
                .insert(name.clone(), UserEntry { uid, adopted: false, created_at: env.sys.now() });
            reg.save(env.registry_path).map_err(ActionError::System)?;
            Ok(json!({"name": name, "uid": uid, "home": home}))
        }
        Action::UserDelete { name, archive } => {
            check_managed(env, &reg, name)?;
            if reg.users[name].adopted {
                return denied(format!(
                    "{name} is an adopted user and cannot be deleted by the agent"
                ));
            }
            // pkill exits 1 when nothing matched; that is not a failure here.
            let _ = env.sys.run("pkill", &["-KILL", "-u", name]);
            let mut archive_path = Value::Null;
            if *archive {
                let file = env.archive_dir.join(format!("{name}-{}.tar.gz", env.sys.now()));
                let file = file.to_string_lossy().into_owned();
                env.sys
                    .run("tar", &["-czf", &file, "-C", env.apps_dir, name])
                    .map_err(ActionError::System)?;
                archive_path = json!(file);
            }
            env.sys.run("userdel", &["--remove", name]).map_err(ActionError::System)?;
            reg.users.remove(name);
            reg.save(env.registry_path).map_err(ActionError::System)?;
            Ok(json!({"deleted": name, "archive": archive_path}))
        }
        Action::GroupAdd { user, group } => {
            check_managed(env, &reg, user)?;
            validate_group_name(group)
                .map_err(|e| ActionError::Denied(format!("{group:?}: {e}")))?;
            if env.policy.group_denied(group) {
                return denied(format!("group {group} is on the deny list"));
            }
            if !env.sys.group_exists(group) {
                return denied(format!("group {group} does not exist"));
            }
            env.sys.run("usermod", &["-aG", group, user]).map_err(ActionError::System)?;
            Ok(json!({"ok": true}))
        }
        Action::Linger { user, enable } => {
            check_managed(env, &reg, user)?;
            let verb = if *enable { "enable-linger" } else { "disable-linger" };
            env.sys.run("loginctl", &[verb, user]).map_err(ActionError::System)?;
            Ok(json!({"ok": true}))
        }
        Action::NginxApply { name, content } => {
            let target = vhost_path(env, name)?;
            let text = std::str::from_utf8(content)
                .map_err(|_| ActionError::Denied("vhost is not valid UTF-8".into()))?;
            check_vhost(text).map_err(ActionError::Denied)?;
            env.sys
                .run("install", &["-d", "-m", "0755", "-o", "root", "-g", "root", SITES_DIR])
                .map_err(ActionError::System)?;
            let created_include = !env.sys.path_exists(INCLUDE_FILE);
            if created_include {
                env.sys.write_file(INCLUDE_FILE, INCLUDE_LINE.as_bytes()).map_err(ActionError::System)?;
            }
            let previous = env.sys.read_file(&target);
            env.sys.write_file(&target, content).map_err(ActionError::System)?;
            if let Err(e) = env.sys.run("nginx", &["-t"]) {
                // Put everything back exactly as it was; the running nginx was never touched.
                let restored = match &previous {
                    Some(old) => env.sys.write_file(&target, old),
                    None => env.sys.remove_file(&target),
                };
                if created_include {
                    let _ = env.sys.remove_file(INCLUDE_FILE);
                }
                restored.map_err(ActionError::System)?;
                return denied(format!("nginx -t failed, rolled back: {e}"));
            }
            env.sys.run("systemctl", &["reload", "nginx"]).map_err(ActionError::System)?;
            Ok(json!({"applied": target}))
        }
        Action::Service { verb, unit } => {
            check_service(env, unit)?;
            let args: Vec<&str> = if verb == "status" {
                vec!["status", "--no-pager", "-l", unit]
            } else {
                vec![verb, unit]
            };
            // A failed start or an inactive unit is an answer for the caller, not a helper error.
            let (code, output) = env.sys.capture("systemctl", &args).map_err(ActionError::System)?;
            Ok(json!({"exit_code": code, "output": output}))
        }
        Action::PkgUpdate => {
            if env.policy.packages.allow.is_empty() {
                return denied("package installation is not enabled: [packages] allow is empty in policy.toml");
            }
            let (code, output) = env.sys.capture("apt-get", &["update"]).map_err(ActionError::System)?;
            Ok(json!({"exit_code": code, "output": tail(&output)}))
        }
        Action::PkgInstall { names } => {
            if names.is_empty() {
                return denied("no packages given");
            }
            if let Some(bad) = names.iter().find(|n| !env.policy.package_allowed(n)) {
                return denied(format!("{bad:?} is not in [packages] allow of policy.toml"));
            }
            // --force-confold keeps existing config files instead of stopping to ask.
            let mut args = vec![
                "install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold", "--",
            ];
            args.extend(names.iter().map(String::as_str));
            let (code, output) = env.sys.capture("apt-get", &args).map_err(ActionError::System)?;
            Ok(json!({"exit_code": code, "output": tail(&output)}))
        }
        Action::CertIssue { domain } => {
            env.policy.cert_request_allowed(domain).map_err(ActionError::Denied)?;
            if !env.sys.path_exists("/usr/bin/certbot") {
                return denied("certbot is not installed on this server (packages: certbot, python3-certbot-nginx)");
            }
            let cert_dir = format!("/etc/letsencrypt/live/{domain}");
            if env.sys.path_exists(&format!("{cert_dir}/fullchain.pem")) {
                return Ok(json!({"already_present": true, "cert_dir": cert_dir}));
            }
            count_cert_attempt(env)?;
            // Every argument is fixed here: certbot's hook options run commands as root.
            let (code, output) = env
                .sys
                .capture(
                    "certbot",
                    &[
                        "certonly", "--nginx", "--non-interactive", "--agree-tos", "--keep-until-expiring",
                        "-m", &env.policy.certs.email, "-d", domain,
                    ],
                )
                .map_err(ActionError::System)?;
            Ok(json!({"exit_code": code, "output": tail(&output), "cert_dir": cert_dir}))
        }
        Action::DbCreate { user, name, password } => {
            if !env.policy.databases.postgres {
                return denied("databases are not enabled: set postgres = true under [databases] in policy.toml");
            }
            check_managed(env, &reg, user)?;
            if !valid_db_name(name) {
                return denied(format!("database name {name:?} must be lowercase letters, digits and underscores, and not a built-in database"));
            }
            if !env.sys.path_exists("/usr/bin/createuser") {
                return denied("PostgreSQL is not installed on this server");
            }
            let as_postgres = |args: &[&str]| {
                let mut full = vec!["-u", "postgres", "--"];
                full.extend_from_slice(args);
                env.sys.capture("runuser", &full).map_err(ActionError::System)
            };
            // The role carries the user's own name: that is what peer authentication matches on.
            // A second database for the same user finds the role already there.
            if !pg_exists(env, "SELECT 1 FROM pg_roles WHERE rolname = :'n';\n", user)? {
                let (code, out) =
                    as_postgres(&["createuser", "--no-superuser", "--no-createdb", "--no-createrole", "--", user])?;
                if code != 0 {
                    return Err(ActionError::System(format!("createuser: {}", out.trim())));
                }
            }
            if pg_exists(env, "SELECT 1 FROM pg_database WHERE datname = :'n';\n", name)? {
                return denied(format!("database {name} already exists"));
            }
            let (code, out) = as_postgres(&["createdb", "--owner", user, "--", name])?;
            if code != 0 {
                return Err(ActionError::System(format!("createdb: {}", out.trim())));
            }
            if !*password {
                return Ok(json!({
                    "database": name, "role": user, "auth": "peer",
                    "url": format!("postgresql:///{name}?host=/var/run/postgresql"),
                }));
            }
            let env_file = write_db_password(env, user, name)?;
            Ok(json!({"database": name, "role": user, "auth": "password", "env_file": env_file}))
        }
        Action::ServiceLogs { unit, lines } => {
            check_service(env, unit)?;
            let n = lines.to_string();
            let (code, output) = env
                .sys
                .capture("journalctl", &["-u", unit, "-n", &n, "--no-pager", "-o", "short-iso"])
                .map_err(ActionError::System)?;
            Ok(json!({"exit_code": code, "output": output}))
        }
        Action::NginxRemove { name } => {
            let target = vhost_path(env, name)?;
            let Some(previous) = env.sys.read_file(&target) else {
                return denied(format!("no such vhost: {name}"));
            };
            env.sys.remove_file(&target).map_err(ActionError::System)?;
            if let Err(e) = env.sys.run("nginx", &["-t"]) {
                env.sys.write_file(&target, &previous).map_err(ActionError::System)?;
                return denied(format!("nginx -t failed after removal, rolled back: {e}"));
            }
            env.sys.run("systemctl", &["reload", "nginx"]).map_err(ActionError::System)?;
            Ok(json!({"removed": target}))
        }
    }
}

/// The last lines of a long tool output; apt prints thousands.
fn tail(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    lines[lines.len().saturating_sub(60)..].join("\n")
}

/// Asks the PostgreSQL catalog whether a role or database exists. The name is bound as the
/// psql variable `n` and quoted by psql itself. Error text is never inspected: the server
/// words its messages in its own locale.
fn pg_exists(env: &Env, sql: &str, name: &str) -> Result<bool, ActionError> {
    let var = format!("n={name}");
    let (code, out) = env
        .sys
        .capture_input("runuser", &["-u", "postgres", "--", "psql", "-At", "-v", &var], sql.as_bytes())
        .map_err(ActionError::System)?;
    if code != 0 {
        return Err(ActionError::System(format!("cannot query PostgreSQL: {}", out.trim())));
    }
    Ok(out.trim() == "1")
}

/// Counts one certificate attempt for today and refuses once the daily cap is reached.
fn count_cert_attempt(env: &Env) -> Result<(), ActionError> {
    let file = env.registry_path.with_file_name("cert-attempts.json");
    let file = file.to_string_lossy();
    let today = env.sys.now() / 86_400;
    let saved: Value = env.sys.read_file(&file).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let count = if saved["day"] == today { saved["count"].as_u64().unwrap_or(0) } else { 0 };
    if count >= u64::from(env.policy.certs.max_per_day) {
        return denied(format!(
            "daily certificate limit reached ({} per day, see [certs] max_per_day)",
            env.policy.certs.max_per_day
        ));
    }
    env.sys
        .write_file(&file, json!({"day": today, "count": count + 1}).to_string().as_bytes())
        .map_err(ActionError::System)
}

/// Sets a random password on the role and stores the connection string in the user's home.
/// Returns the file's path; the password itself never leaves this function.
fn write_db_password(env: &Env, user: &str, name: &str) -> Result<String, ActionError> {
    let Some(home) = env.sys.home_of(user) else {
        return Err(ActionError::System(format!("cannot find the home directory of {user}")));
    };
    let secret = env.sys.random_hex().map_err(ActionError::System)?;
    // On stdin, not in arguments: argv is visible to every user through /proc.
    let sql = format!("ALTER ROLE \"{user}\" PASSWORD '{secret}';\n");
    let (code, out) = env
        .sys
        .capture_input("runuser", &["-u", "postgres", "--", "psql", "-q", "-v", "ON_ERROR_STOP=1"], sql.as_bytes())
        .map_err(ActionError::System)?;
    if code != 0 {
        return Err(ActionError::System(format!("setting the role password failed: {}", out.trim())));
    }
    let dir = format!("{home}/.vps-agent");
    let file = format!("db-{name}.env");
    let content = format!("DATABASE_URL=postgresql://{user}:{secret}@127.0.0.1:5432/{name}\n");
    // Written with the user's own privileges: its home is under its control, and root
    // following a symlink planted there would be a way to overwrite any file.
    let script = r#"umask 077 && mkdir -p -- "$1" && cat > "$1/$2""#;
    let (code, out) = env
        .sys
        .capture_input("runuser", &["-u", user, "--", "sh", "-c", script, "_", &dir, &file], content.as_bytes())
        .map_err(ActionError::System)?;
    if code != 0 {
        return Err(ActionError::System(format!("writing {dir}/{file} failed: {}", out.trim())));
    }
    Ok(format!("{dir}/{file}"))
}

fn check_service(env: &Env, unit: &str) -> Result<(), ActionError> {
    if env.policy.service_allowed(unit) {
        Ok(())
    } else {
        denied(format!("{unit:?} is not in [services] allow of policy.toml"))
    }
}

fn vhost_path(env: &Env, name: &str) -> Result<String, ActionError> {
    validate_group_name(name).map_err(|e| ActionError::Denied(format!("vhost name {name:?}: {e}")))?;
    if !env.sys.path_exists("/etc/nginx/nginx.conf") {
        return denied("nginx is not installed on this server");
    }
    Ok(format!("{SITES_DIR}/{name}.conf"))
}

#[cfg(test)]
mod tests_support {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct Fake {
        pub uids: RefCell<HashMap<String, u32>>,
        pub groups: RefCell<HashMap<String, Vec<String>>>,
        pub existing_groups: Vec<String>,
        pub calls: RefCell<Vec<String>>,
        pub fail_on: Option<&'static str>,
        pub files: RefCell<HashMap<String, Vec<u8>>>,
        /// Seconds added to the fake clock.
        pub clock: std::cell::Cell<u64>,
        /// What was fed to commands on stdin; kept apart from `calls` like a real argv is.
        pub inputs: RefCell<Vec<String>>,
        /// (substring of the call, exit code, output) for commands that should not just succeed.
        pub canned: RefCell<Vec<(String, i32, String)>>,
    }

    impl System for Fake {
        fn uid_of(&self, user: &str) -> Option<u32> {
            self.uids.borrow().get(user).copied()
        }
        fn uid_taken(&self, uid: u32) -> bool {
            self.uids.borrow().values().any(|u| *u == uid)
        }
        fn groups_of(&self, user: &str) -> Vec<String> {
            self.groups.borrow().get(user).cloned().unwrap_or_default()
        }
        fn group_exists(&self, g: &str) -> bool {
            self.existing_groups.iter().any(|x| x == g)
        }
        fn now(&self) -> u64 {
            1_700_000_000 + self.clock.get()
        }
        fn home_of(&self, user: &str) -> Option<String> {
            self.uids.borrow().contains_key(user).then(|| format!("/srv/apps/{user}"))
        }
        fn random_hex(&self) -> Result<String, String> {
            Ok("5ec2e7".repeat(8))
        }
        fn capture_input(&self, program: &str, args: &[&str], input: &[u8]) -> Result<(i32, String), String> {
            self.inputs.borrow_mut().push(String::from_utf8_lossy(input).into_owned());
            self.capture(program, args)
        }
        fn path_exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }
        fn read_file(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }
        fn write_file(&self, path: &str, data: &[u8]) -> Result<(), String> {
            self.files.borrow_mut().insert(path.to_string(), data.to_vec());
            Ok(())
        }
        fn remove_file(&self, path: &str) -> Result<(), String> {
            self.files.borrow_mut().remove(path);
            Ok(())
        }
        fn capture(&self, program: &str, args: &[&str]) -> Result<(i32, String), String> {
            let call = format!("{program} {}", args.join(" "));
            self.calls.borrow_mut().push(call.clone());
            let canned = self.canned.borrow();
            match canned.iter().find(|(key, _, _)| call.contains(key.as_str())) {
                Some((_, code, output)) => Ok((*code, output.clone())),
                None => Ok((0, "captured".into())),
            }
        }
        fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("{program} {}", args.join(" ")));
            if self.fail_on == Some(program) {
                return Err(format!("{program} failed"));
            }
            if program == "useradd" {
                let name = args.last().unwrap().to_string();
                let uid: u32 =
                    args[args.iter().position(|a| *a == "--uid").unwrap() + 1].parse().unwrap();
                self.uids.borrow_mut().insert(name.clone(), uid);
                self.groups.borrow_mut().insert(name, vec!["agent-managed".into()]);
            }
            Ok(())
        }
    }

    pub struct Fixture {
        pub dir: std::path::PathBuf,
        pub policy: Policy,
    }

    pub fn fixture(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("vps-priv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Fixture { dir, policy: Policy::from_toml_str("").unwrap() }
    }

    pub fn env<'a>(f: &'a Fixture, sys: &'a Fake, reg: &'a std::path::Path) -> Env<'a> {
        Env { sys, policy: &f.policy, registry_path: reg, archive_dir: &f.dir, apps_dir: "/srv/apps" }
    }

    pub fn create(e: &Env, name: &str) -> Result<serde_json::Value, ActionError> {
        execute(e, &Action::UserCreate { name: name.into(), shell: Shell::Bash })
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;

    #[test]
    fn create_allocates_uid_and_registers() {
        let f = fixture("create");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        let v = create(&e, "shop").unwrap();
        assert_eq!(v["uid"], 20000);
        assert_eq!(v["home"], "/srv/apps/shop");
        let call = sys.calls.borrow()[0].clone();
        assert!(call.starts_with("useradd "));
        assert!(call.contains("--home-dir /srv/apps/shop"));
        assert!(call.contains("--groups agent-managed"));
        assert!(!call.contains(" -o"));
        assert_eq!(Registry::load(&reg).unwrap().users["shop"].uid, 20000);
        assert_eq!(create(&e, "blog").unwrap()["uid"], 20001);
    }

    #[test]
    fn create_rejects_bad_reserved_and_existing_names() {
        let f = fixture("reject");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        sys.uids.borrow_mut().insert("deploy".into(), 1001);
        let e = env(&f, &sys, &reg);
        for n in ["root", "-rf", "a;b", "agent", "deploy"] {
            assert!(matches!(create(&e, n), Err(ActionError::Denied(_))), "{n}");
        }
        assert!(sys.calls.borrow().is_empty());
    }

    #[test]
    fn failed_useradd_leaves_registry_unchanged() {
        let f = fixture("fail");
        let reg = f.dir.join("users.json");
        let sys = Fake { fail_on: Some("useradd"), ..Default::default() };
        assert!(matches!(create(&env(&f, &sys, &reg), "shop"), Err(ActionError::System(_))));
        assert!(Registry::load(&reg).unwrap().users.is_empty());
    }

    #[test]
    fn check_requires_all_three_signs() {
        let f = fixture("check");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        let chk = |n: &str| execute(&e, &Action::UserCheck { name: n.into() });
        assert!(chk("shop").is_ok());

        // Not in the registry, though in the group and in range.
        sys.uids.borrow_mut().insert("ghost".into(), 20500);
        sys.groups.borrow_mut().insert("ghost".into(), vec!["agent-managed".into()]);
        assert!(chk("ghost").is_err());

        // Removed from the group.
        sys.groups.borrow_mut().insert("shop".into(), vec![]);
        assert!(chk("shop").is_err());
        sys.groups.borrow_mut().insert("shop".into(), vec!["agent-managed".into()]);

        // UID changed behind the helper's back.
        sys.uids.borrow_mut().insert("shop".into(), 0);
        assert!(chk("shop").is_err());
    }

    #[test]
    fn adopted_user_passes_check_outside_uid_range_but_is_not_deletable() {
        let f = fixture("adopt");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        sys.uids.borrow_mut().insert("legacy".into(), 1001);
        sys.groups.borrow_mut().insert("legacy".into(), vec!["agent-managed".into()]);
        let mut r = Registry::default();
        r.users.insert("legacy".into(), UserEntry { uid: 1001, adopted: true, created_at: 0 });
        r.save(&reg).unwrap();
        let e = env(&f, &sys, &reg);
        assert!(execute(&e, &Action::UserCheck { name: "legacy".into() }).is_ok());
        let del = execute(&e, &Action::UserDelete { name: "legacy".into(), archive: false });
        assert!(matches!(del, Err(ActionError::Denied(_))));
        assert!(sys.calls.borrow().is_empty());
    }

    #[test]
    fn delete_archives_then_removes() {
        let f = fixture("delete");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        sys.calls.borrow_mut().clear();
        let v = execute(&e, &Action::UserDelete { name: "shop".into(), archive: true }).unwrap();
        let calls = sys.calls.borrow().clone();
        let tar = calls.iter().position(|c| c.starts_with("tar ")).unwrap();
        let del = calls.iter().position(|c| c.starts_with("userdel ")).unwrap();
        assert!(tar < del);
        assert!(v["archive"].as_str().unwrap().ends_with(".tar.gz"));
        assert!(Registry::load(&reg).unwrap().users.is_empty());
    }

    #[test]
    fn group_add_enforces_deny_list_and_managed_check() {
        let f = fixture("group");
        let reg = f.dir.join("users.json");
        let sys =
            Fake { existing_groups: vec!["www-data".into(), "docker".into()], ..Default::default() };
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        let add = |u: &str, g: &str| execute(&e, &Action::GroupAdd { user: u.into(), group: g.into() });
        assert!(add("shop", "www-data").is_ok());
        assert!(matches!(add("shop", "docker"), Err(ActionError::Denied(_))));
        assert!(matches!(add("shop", "sudo"), Err(ActionError::Denied(_))));
        assert!(matches!(add("shop", "nosuchgroup"), Err(ActionError::Denied(_))));
        assert!(matches!(add("root", "www-data"), Err(ActionError::Denied(_))));
    }
}

#[cfg(test)]
mod v1_tests {
    use super::tests_support::*;
    use super::*;

    const VHOST: &[u8] = b"server { listen 8080; location / { proxy_pass http://127.0.0.1:3000; } }\n";
    const TARGET: &str = "/etc/nginx/sites-agent/shop.conf";

    fn with_nginx(sys: &Fake) {
        sys.write_file("/etc/nginx/nginx.conf", b"http {}").unwrap();
    }

    fn apply(e: &Env, content: &[u8]) -> Result<serde_json::Value, ActionError> {
        execute(e, &Action::NginxApply { name: "shop".into(), content: content.to_vec() })
    }

    #[test]
    fn linger_only_for_managed_users() {
        let f = fixture("linger");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        sys.calls.borrow_mut().clear();
        assert!(execute(&e, &Action::Linger { user: "shop".into(), enable: true }).is_ok());
        assert_eq!(sys.calls.borrow()[0], "loginctl enable-linger shop");
        assert!(execute(&e, &Action::Linger { user: "shop".into(), enable: false }).is_ok());
        assert_eq!(sys.calls.borrow()[1], "loginctl disable-linger shop");
        let other = execute(&e, &Action::Linger { user: "root".into(), enable: true });
        assert!(matches!(other, Err(ActionError::Denied(_))));
    }

    #[test]
    fn nginx_apply_writes_tests_and_reloads() {
        let f = fixture("ngx-ok");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        with_nginx(&sys);
        apply(&env(&f, &sys, &reg), VHOST).unwrap();
        assert_eq!(sys.read_file(TARGET).unwrap(), VHOST);
        assert!(sys.path_exists("/etc/nginx/conf.d/vps-agent.conf"));
        let calls = sys.calls.borrow().clone();
        let test = calls.iter().position(|c| c == "nginx -t").unwrap();
        let reload = calls.iter().position(|c| c == "systemctl reload nginx").unwrap();
        assert!(test < reload);
    }

    #[test]
    fn nginx_apply_rolls_back_when_the_config_test_fails() {
        let f = fixture("ngx-bad");
        let reg = f.dir.join("users.json");
        let sys = Fake { fail_on: Some("nginx"), ..Default::default() };
        with_nginx(&sys);
        sys.write_file(TARGET, b"old").unwrap();
        let r = apply(&env(&f, &sys, &reg), VHOST);
        assert!(matches!(r, Err(ActionError::Denied(_))));
        assert_eq!(sys.read_file(TARGET).unwrap(), b"old");
        assert!(!sys.calls.borrow().iter().any(|c| c.starts_with("systemctl reload")));

        // A brand-new file is removed again, not left behind.
        sys.remove_file(TARGET).unwrap();
        assert!(apply(&env(&f, &sys, &reg), VHOST).is_err());
        assert!(!sys.path_exists(TARGET));
    }

    #[test]
    fn nginx_apply_rejects_dangerous_config_bad_names_and_missing_nginx() {
        let f = fixture("ngx-deny");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        assert!(matches!(apply(&e, VHOST), Err(ActionError::Denied(_)))); // nginx not installed
        with_nginx(&sys);
        assert!(matches!(apply(&e, b"server { access_log /etc/cron.d/x; }"), Err(ActionError::Denied(_))));
        assert!(matches!(apply(&e, &[0xff, 0xfe]), Err(ActionError::Denied(_))));
        let bad_name = execute(&e, &Action::NginxApply { name: "../x".into(), content: VHOST.to_vec() });
        assert!(matches!(bad_name, Err(ActionError::Denied(_))));
        assert!(!sys.calls.borrow().iter().any(|c| c.starts_with("nginx")));
    }

    #[test]
    fn system_services_are_limited_to_the_allow_list() {
        let mut f = fixture("svc");
        f.policy = Policy::from_toml_str("[services]\nallow = ['bot.service']").unwrap();
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        let svc = |verb: &str, unit: &str| execute(&e, &Action::Service { verb: verb.into(), unit: unit.into() });

        let v = svc("restart", "bot.service").unwrap();
        assert_eq!(v["exit_code"], 0);
        svc("status", "bot.service").unwrap();
        execute(&e, &Action::ServiceLogs { unit: "bot.service".into(), lines: 20 }).unwrap();
        assert_eq!(
            *sys.calls.borrow(),
            [
                "systemctl restart bot.service",
                "systemctl status --no-pager -l bot.service",
                "journalctl -u bot.service -n 20 --no-pager -o short-iso",
            ]
        );

        sys.calls.borrow_mut().clear();
        for unit in ["ssh.service", "nginx.service", "bot", "--now", "bot.service --now"] {
            assert!(matches!(svc("restart", unit), Err(ActionError::Denied(_))), "{unit}");
        }
        let logs = execute(&e, &Action::ServiceLogs { unit: "ssh.service".into(), lines: 20 });
        assert!(matches!(logs, Err(ActionError::Denied(_))));
        assert!(sys.calls.borrow().is_empty());
    }

    #[test]
    fn nginx_remove_deletes_and_reloads() {
        let f = fixture("ngx-rm");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        with_nginx(&sys);
        let e = env(&f, &sys, &reg);
        apply(&e, VHOST).unwrap();
        execute(&e, &Action::NginxRemove { name: "shop".into() }).unwrap();
        assert!(!sys.path_exists(TARGET));
        let missing = execute(&e, &Action::NginxRemove { name: "shop".into() });
        assert!(matches!(missing, Err(ActionError::Denied(_))));
    }
}

#[cfg(test)]
mod privileged_ops_tests {
    use super::tests_support::*;
    use super::*;

    fn policy(toml: &str) -> Policy {
        Policy::from_toml_str(toml).unwrap()
    }

    const CERTS: &str = "[certs]\nemail = 'ops@example.com'\nagree_tos = true\ndomains = ['shop.example.com', '*.apps.example.com']\nmax_per_day = 2";

    #[test]
    fn pkg_install_runs_apt_for_listed_packages_only() {
        let mut f = fixture("pkg");
        f.policy = policy("[packages]\nallow = ['python3-venv', 'tmux']");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        let install = |names: &[&str]| {
            execute(&e, &Action::PkgInstall { names: names.iter().map(|s| s.to_string()).collect() })
        };
        install(&["python3-venv", "tmux"]).unwrap();
        assert_eq!(
            sys.calls.borrow()[0],
            "apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold -- python3-venv tmux"
        );
        sys.calls.borrow_mut().clear();
        // One unlisted name refuses the whole call: nothing is installed "partially".
        for bad in [&["python3-venv", "docker.io"][..], &["-o", "tmux"], &["tmux=3.4"], &[]] {
            assert!(matches!(install(bad), Err(ActionError::Denied(_))), "{bad:?}");
        }
        assert!(sys.calls.borrow().is_empty());
        execute(&e, &Action::PkgUpdate).unwrap();
        assert_eq!(sys.calls.borrow()[0], "apt-get update");
    }

    #[test]
    fn pkg_update_needs_a_non_empty_allow_list() {
        let f = fixture("pkg-off");
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        assert!(matches!(execute(&env(&f, &sys, &reg), &Action::PkgUpdate), Err(ActionError::Denied(_))));
    }

    #[test]
    fn cert_issue_calls_certbot_with_fixed_arguments() {
        let mut f = fixture("cert");
        f.policy = policy(CERTS);
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        sys.write_file("/usr/bin/certbot", b"").unwrap();
        let e = env(&f, &sys, &reg);
        let v = execute(&e, &Action::CertIssue { domain: "a.apps.example.com".into() }).unwrap();
        assert_eq!(
            sys.calls.borrow()[0],
            "certbot certonly --nginx --non-interactive --agree-tos --keep-until-expiring -m ops@example.com -d a.apps.example.com"
        );
        assert_eq!(v["cert_dir"], "/etc/letsencrypt/live/a.apps.example.com");
    }

    #[test]
    fn cert_issue_refuses_unlisted_domains_and_a_missing_certbot() {
        let mut f = fixture("cert-deny");
        f.policy = policy(CERTS);
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        let e = env(&f, &sys, &reg);
        let issue = |d: &str| execute(&e, &Action::CertIssue { domain: d.into() });
        assert!(matches!(issue("shop.example.com"), Err(ActionError::Denied(_)))); // certbot missing
        sys.write_file("/usr/bin/certbot", b"").unwrap();
        assert!(matches!(issue("evil.example.net"), Err(ActionError::Denied(_))));
        assert!(matches!(issue("shop.example.com --pre-hook id"), Err(ActionError::Denied(_))));
        assert!(sys.calls.borrow().is_empty());
    }

    #[test]
    fn cert_issue_counts_attempts_per_day_including_failures() {
        let mut f = fixture("cert-cap");
        f.policy = policy(CERTS);
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        sys.write_file("/usr/bin/certbot", b"").unwrap();
        sys.canned.borrow_mut().push(("certbot".into(), 1, "challenge failed".into()));
        let e = env(&f, &sys, &reg);
        let issue = || execute(&e, &Action::CertIssue { domain: "shop.example.com".into() });
        assert_eq!(issue().unwrap()["exit_code"], 1);
        assert_eq!(issue().unwrap()["exit_code"], 1);
        assert!(matches!(issue(), Err(ActionError::Denied(_)))); // max_per_day = 2
        assert_eq!(sys.calls.borrow().len(), 2);
        sys.clock.set(86_400);
        assert!(issue().is_ok());
    }

    #[test]
    fn cert_issue_reuses_an_existing_certificate_without_calling_certbot() {
        let mut f = fixture("cert-have");
        f.policy = policy(CERTS);
        let sys = Fake::default();
        let reg = f.dir.join("users.json");
        sys.write_file("/usr/bin/certbot", b"").unwrap();
        sys.write_file("/etc/letsencrypt/live/shop.example.com/fullchain.pem", b"x").unwrap();
        let v = execute(&env(&f, &sys, &reg), &Action::CertIssue { domain: "shop.example.com".into() }).unwrap();
        assert_eq!(v["already_present"], true);
        assert!(sys.calls.borrow().is_empty());
    }

    fn db_env(tag: &str) -> (Fixture, Fake, std::path::PathBuf) {
        let mut f = fixture(tag);
        f.policy = policy("[databases]\npostgres = true");
        let sys = Fake::default();
        sys.write_file("/usr/bin/createuser", b"").unwrap();
        let reg = f.dir.join("users.json");
        (f, sys, reg)
    }

    fn db(e: &Env, user: &str, name: &str, password: bool) -> Result<serde_json::Value, ActionError> {
        execute(e, &Action::DbCreate { user: user.into(), name: name.into(), password })
    }

    #[test]
    fn db_create_with_peer_auth_has_no_password_anywhere() {
        let (f, sys, reg) = db_env("db-peer");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        sys.calls.borrow_mut().clear();
        let v = db(&e, "shop", "shop_prod", false).unwrap();
        assert_eq!(
            *sys.calls.borrow(),
            [
                "runuser -u postgres -- psql -At -v n=shop",
                "runuser -u postgres -- createuser --no-superuser --no-createdb --no-createrole -- shop",
                "runuser -u postgres -- psql -At -v n=shop_prod",
                "runuser -u postgres -- createdb --owner shop -- shop_prod",
            ]
        );
        assert_eq!(v["auth"], "peer");
        assert_eq!(v["url"], "postgresql:///shop_prod?host=/var/run/postgresql");
        // Only the two catalog lookups went to stdin, and they quote the name through psql.
        assert_eq!(sys.inputs.borrow().len(), 2);
        assert!(sys.inputs.borrow().iter().all(|sql| sql.contains(":'n'") && !sql.contains("shop")));
        assert!(!v.to_string().contains("5ec2e7"));
    }

    #[test]
    fn db_create_with_password_never_returns_or_exposes_it_in_arguments() {
        let (f, sys, reg) = db_env("db-pass");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        sys.calls.borrow_mut().clear();
        let v = db(&e, "shop", "shop_prod", true).unwrap();
        let secret = "5ec2e7".repeat(8);
        assert_eq!(v["auth"], "password");
        assert_eq!(v["env_file"], "/srv/apps/shop/.vps-agent/db-shop_prod.env");
        assert!(!v.to_string().contains(&secret));
        // Arguments are visible in `ps` to every user; the secret travels on stdin only.
        assert!(!sys.calls.borrow().iter().any(|c| c.contains(&secret)));
        let inputs = sys.inputs.borrow();
        assert!(inputs[2].contains("ALTER ROLE \"shop\" PASSWORD") && inputs[2].contains(&secret));
        assert_eq!(inputs[3], format!("DATABASE_URL=postgresql://shop:{secret}@127.0.0.1:5432/shop_prod\n"));
        // The file is written as the app user, so a symlink planted in its home cannot aim root at /etc.
        assert!(sys.calls.borrow().iter().any(|c| c.starts_with("runuser -u shop -- sh -c ")));
    }

    #[test]
    fn db_create_tolerates_an_existing_role_but_not_an_existing_database() {
        let (f, sys, reg) = db_env("db-exists");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        // Existence is asked from the catalog, not read off error text: the server words
        // its errors in its own locale ("роль уже существует").
        sys.canned.borrow_mut().push(("psql -At -v n=shop".into(), 0, "1\n".into()));
        sys.canned.borrow_mut().push(("createuser".into(), 1, "ОШИБКА: роль \"shop\" уже существует".into()));
        sys.calls.borrow_mut().clear();
        assert!(db(&e, "shop", "second", false).is_ok());
        assert!(!sys.calls.borrow().iter().any(|c| c.contains("createuser")));

        sys.canned.borrow_mut().push(("psql -At -v n=second".into(), 0, "1\n".into()));
        sys.calls.borrow_mut().clear();
        assert!(matches!(db(&e, "shop", "second", false), Err(ActionError::Denied(_))));
        assert!(!sys.calls.borrow().iter().any(|c| c.contains("createdb")));
    }

    #[test]
    fn db_create_is_refused_when_off_unmanaged_misnamed_or_without_postgres() {
        let (f, sys, reg) = db_env("db-deny");
        let e = env(&f, &sys, &reg);
        create(&e, "shop").unwrap();
        sys.calls.borrow_mut().clear();
        for (user, name) in [("root", "x"), ("postgres", "x"), ("shop", "postgres"), ("shop", "a;b"), ("shop", "A")] {
            assert!(matches!(db(&e, user, name, false), Err(ActionError::Denied(_))), "{user} {name}");
        }
        sys.remove_file("/usr/bin/createuser").unwrap();
        assert!(matches!(db(&e, "shop", "ok", false), Err(ActionError::Denied(_))));

        let off = fixture("db-off");
        sys.write_file("/usr/bin/createuser", b"").unwrap();
        let reg_off = off.dir.join("users.json");
        std::fs::copy(&reg, &reg_off).unwrap();
        assert!(matches!(db(&env(&off, &sys, &reg_off), "shop", "ok", false), Err(ActionError::Denied(_))));
        assert!(sys.calls.borrow().is_empty());
    }
}
