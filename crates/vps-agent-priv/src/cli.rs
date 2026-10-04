#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shell {
    Bash,
    Nologin,
}

#[derive(Debug)]
pub enum Action {
    UserCreate { name: String, shell: Shell },
    UserDelete { name: String, archive: bool },
    UserList,
    UserCheck { name: String },
    GroupAdd { user: String, group: String },
}

pub const USAGE: &str = "usage: vps-agent-priv user create <name> [--shell bash|nologin] | \
user delete <name> [--archive] | user list | user check <name> | group add <user> <group>";

pub fn parse(args: &[String]) -> Result<Action, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["user", "create", name] | ["user", "create", name, "--shell", "bash"] => {
            Ok(Action::UserCreate { name: name.to_string(), shell: Shell::Bash })
        }
        ["user", "create", name, "--shell", "nologin"] => {
            Ok(Action::UserCreate { name: name.to_string(), shell: Shell::Nologin })
        }
        ["user", "delete", name] => Ok(Action::UserDelete { name: name.to_string(), archive: false }),
        ["user", "delete", name, "--archive"] => {
            Ok(Action::UserDelete { name: name.to_string(), archive: true })
        }
        ["user", "list"] => Ok(Action::UserList),
        ["user", "check", name] => Ok(Action::UserCheck { name: name.to_string() }),
        ["group", "add", user, group] => {
            Ok(Action::GroupAdd { user: user.to_string(), group: group.to_string() })
        }
        _ => Err(USAGE.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Action, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn parses_every_action() {
        assert!(matches!(p("user create shop"), Ok(Action::UserCreate { shell: Shell::Bash, .. })));
        assert!(matches!(
            p("user create shop --shell nologin"),
            Ok(Action::UserCreate { shell: Shell::Nologin, .. })
        ));
        assert!(matches!(p("user delete shop --archive"), Ok(Action::UserDelete { archive: true, .. })));
        assert!(matches!(p("user delete shop"), Ok(Action::UserDelete { archive: false, .. })));
        assert!(matches!(p("user list"), Ok(Action::UserList)));
        assert!(matches!(p("user check shop"), Ok(Action::UserCheck { .. })));
        assert!(matches!(p("group add shop www-data"), Ok(Action::GroupAdd { .. })));
    }

    #[test]
    fn rejects_unknown_and_extra_arguments() {
        for bad in ["", "user", "user create", "user create a b", "user create shop --shell zsh",
                    "user delete shop --purge", "user list extra", "group add shop", "exec ls",
                    "nginx apply x", "linger enable shop"] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }
}
