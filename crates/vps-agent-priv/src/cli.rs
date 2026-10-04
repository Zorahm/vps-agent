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
    Linger { user: String, enable: bool },
    /// `content` arrives on stdin; `parse` leaves it empty and `main` fills it in.
    NginxApply { name: String, content: Vec<u8> },
    NginxRemove { name: String },
    /// A system service from the policy's allow list.
    Service { verb: String, unit: String },
    ServiceLogs { unit: String, lines: u32 },
    PkgUpdate,
    PkgInstall { names: Vec<String> },
    CertIssue { domain: String },
    /// A PostgreSQL role named after the managed user plus a database it owns.
    DbCreate { user: String, name: String, password: bool },
}

pub const USAGE: &str = "usage: vps-agent-priv user create <name> [--shell bash|nologin] | \
user delete <name> [--archive] | user list | user check <name> | group add <user> <group> | linger enable|disable <user> | \nnginx apply <name> (vhost on stdin) | nginx remove <name> | \
service start|stop|restart|reload|status <unit> | service logs <unit> [lines] | \
pkg update | pkg install <name>... | cert issue <domain> | db create <user> <database> [--password]";

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
        ["linger", "enable", user] => Ok(Action::Linger { user: user.to_string(), enable: true }),
        ["linger", "disable", user] => Ok(Action::Linger { user: user.to_string(), enable: false }),
        ["nginx", "apply", name] => {
            Ok(Action::NginxApply { name: name.to_string(), content: Vec::new() })
        }
        ["nginx", "remove", name] => Ok(Action::NginxRemove { name: name.to_string() }),
        ["service", verb @ ("start" | "stop" | "restart" | "reload" | "status"), unit] => {
            Ok(Action::Service { verb: verb.to_string(), unit: unit.to_string() })
        }
        ["pkg", "update"] => Ok(Action::PkgUpdate),
        ["pkg", "install", names @ ..] if (1..=20).contains(&names.len()) => {
            Ok(Action::PkgInstall { names: names.iter().map(|n| n.to_string()).collect() })
        }
        ["cert", "issue", domain] => Ok(Action::CertIssue { domain: domain.to_string() }),
        ["db", "create", user, name] => {
            Ok(Action::DbCreate { user: user.to_string(), name: name.to_string(), password: false })
        }
        ["db", "create", user, name, "--password"] => {
            Ok(Action::DbCreate { user: user.to_string(), name: name.to_string(), password: true })
        }
        ["service", "logs", unit] => Ok(Action::ServiceLogs { unit: unit.to_string(), lines: 100 }),
        ["service", "logs", unit, lines] => match lines.parse::<u32>() {
            Ok(n) if (1..=1000).contains(&n) => {
                Ok(Action::ServiceLogs { unit: unit.to_string(), lines: n })
            }
            _ => Err(USAGE.to_string()),
        },
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
        assert!(matches!(p("linger enable shop"), Ok(Action::Linger { enable: true, .. })));
        assert!(matches!(p("linger disable shop"), Ok(Action::Linger { enable: false, .. })));
        assert!(matches!(p("nginx apply shop"), Ok(Action::NginxApply { .. })));
        assert!(matches!(p("nginx remove shop"), Ok(Action::NginxRemove { .. })));
        assert!(matches!(p("pkg update"), Ok(Action::PkgUpdate)));
        assert!(matches!(p("pkg install tmux git"), Ok(Action::PkgInstall { names }) if names == ["tmux", "git"]));
        assert!(matches!(p("cert issue a.example.com"), Ok(Action::CertIssue { .. })));
        assert!(matches!(p("db create shop shop_prod"), Ok(Action::DbCreate { password: false, .. })));
        assert!(matches!(p("db create shop shop_prod --password"), Ok(Action::DbCreate { password: true, .. })));
        for bad in ["pkg install", "pkg remove tmux", "pkg update now", "cert issue", "cert issue a b",
                    "cert renew a.example.com", "db create shop", "db drop shop x",
                    "db create shop x --superuser"] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(p("service restart bot.service"), Ok(Action::Service { .. })));
        assert!(matches!(p("service status bot.service"), Ok(Action::Service { .. })));
        assert!(matches!(p("service logs bot.service"), Ok(Action::ServiceLogs { lines: 100, .. })));
        assert!(matches!(p("service logs bot.service 50"), Ok(Action::ServiceLogs { lines: 50, .. })));
        for bad in ["service enable bot.service", "service mask bot.service", "service restart",
                    "service logs bot.service 0", "service logs bot.service 5000",
                    "service logs bot.service -f", "service edit bot.service"] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_unknown_and_extra_arguments() {
        for bad in ["", "user", "user create", "user create a b", "user create shop --shell zsh",
                    "user delete shop --purge", "user list extra", "group add shop", "exec ls",
                    "nginx apply", "nginx apply a b", "nginx reload", "linger enable",
                    "linger toggle shop"] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }
}
