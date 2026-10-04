use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    Invalid,
    Reserved,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Invalid => write!(f, "name must match ^[a-z][a-z0-9-]{{1,30}}$"),
            NameError::Reserved => write!(f, "name is reserved"),
        }
    }
}

pub const RESERVED_USERS: &[&str] = &[
    "root", "agent", "admin", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "nobody", "sshd", "ubuntu",
    "debian", "messagebus", "syslog", "postfix", "mysql", "postgres", "redis", "nginx",
];

fn shape_ok(name: &str) -> bool {
    let b = name.as_bytes();
    (2..=31).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub fn validate_group_name(name: &str) -> Result<(), NameError> {
    if shape_ok(name) {
        Ok(())
    } else {
        Err(NameError::Invalid)
    }
}

pub fn validate_user_name(name: &str) -> Result<(), NameError> {
    validate_group_name(name)?;
    if RESERVED_USERS.contains(&name) || name.starts_with("systemd-") {
        return Err(NameError::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_names() {
        for n in ["ab", "shop", "my-app-2", "a123456789012345678901234567890"] {
            assert_eq!(validate_user_name(n), Ok(()), "{n}");
        }
    }

    #[test]
    fn rejects_bad_shapes() {
        for n in ["", "a", "1abc", "-rf", "Abc", "a_b", "a;b", "a b", "a/b", "a\n",
                  "a1234567890123456789012345678901"] {
            assert_eq!(validate_user_name(n), Err(NameError::Invalid), "{n:?}");
        }
    }

    #[test]
    fn rejects_reserved() {
        for n in ["root", "agent", "www-data", "nobody", "sshd", "ubuntu", "systemd-network"] {
            assert_eq!(validate_user_name(n), Err(NameError::Reserved), "{n}");
        }
    }
}
