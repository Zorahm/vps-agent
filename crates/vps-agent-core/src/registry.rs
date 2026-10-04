use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub uid: u32,
    pub adopted: bool,
    pub created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub users: BTreeMap<String, UserEntry>,
}

impl Registry {
    pub fn load(path: &Path) -> Result<Registry, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| format!("{}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn next_free_uid(&self, range: (u32, u32), taken: &dyn Fn(u32) -> bool) -> Option<u32> {
        (range.0..=range.1)
            .find(|uid| !self.users.values().any(|u| u.uid == *uid) && !taken(*uid))
    }
}

pub struct RegistryLock {
    path: PathBuf,
}

impl Drop for RegistryLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn lock(dir: &Path) -> Result<RegistryLock, String> {
    let path = dir.join(".lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(RegistryLock { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(60));
                if stale {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err("registry is locked by another vps-agent-priv call".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vps-agent-reg-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_file_is_empty_registry() {
        let r = Registry::load(&dir("missing").join("users.json")).unwrap();
        assert!(r.users.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let p = dir("rt").join("users.json");
        let mut r = Registry::default();
        r.users.insert("shop".into(), UserEntry { uid: 20000, adopted: false, created_at: 1 });
        r.save(&p).unwrap();
        let back = Registry::load(&p).unwrap();
        assert_eq!(back.users["shop"].uid, 20000);
        assert!(!p.with_extension("json.tmp").exists());
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_registry() {
        let p = dir("bad").join("users.json");
        std::fs::write(&p, "{not json").unwrap();
        assert!(Registry::load(&p).is_err());
    }

    #[test]
    fn next_uid_skips_registry_and_system_users() {
        let mut r = Registry::default();
        r.users.insert("a".into(), UserEntry { uid: 20000, adopted: false, created_at: 0 });
        let taken = |uid: u32| uid == 20001;
        assert_eq!(r.next_free_uid((20000, 20005), &taken), Some(20002));
    }

    #[test]
    fn next_uid_is_none_when_range_is_full() {
        let r = Registry::default();
        assert_eq!(r.next_free_uid((20000, 20001), &|_| true), None);
    }

    #[test]
    fn second_lock_waits_until_first_is_dropped() {
        let d = dir("lock");
        let first = lock(&d).unwrap();
        let d2 = d.clone();
        let t = std::thread::spawn(move || lock(&d2).map(|_| ()));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!t.is_finished());
        drop(first);
        assert!(t.join().unwrap().is_ok());
    }
}
