//! A guard for vhost files the agent hands to the root helper.
//!
//! The nginx master process runs as root and opens log, cache, module and key files
//! itself, so a few directives would let a vhost write or read arbitrary paths as root.
//! This check refuses those. It is a deny list over directive names, not a parser of
//! nginx semantics: `nginx -t` still decides whether the file is valid.

pub const MAX_VHOST_BYTES: usize = 256 * 1024;
pub const SITES_DIR: &str = "/etc/nginx/sites-agent";
pub const INCLUDE_FILE: &str = "/etc/nginx/conf.d/vps-agent.conf";
pub const INCLUDE_LINE: &str = "include /etc/nginx/sites-agent/*.conf;\n";

const LOG_PREFIX: &str = "/var/log/nginx/";
const TLS_PREFIXES: &[&str] = &["/etc/letsencrypt/", "/etc/ssl/"];
const DENIED: &[&str] = &[
    "include", "load_module", "user", "pid", "daemon", "master_process", "lock_file",
    "working_directory", "env", "ssl_engine", "worker_processes", "worker_rlimit_core",
];

fn strip_comments(conf: &str) -> String {
    conf.lines().map(|l| l.split('#').next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

fn unquote(token: &str) -> &str {
    token.trim_matches(|c| c == '"' || c == '\'')
}

fn check_statement(directive: &str, args: &[&str]) -> Result<(), String> {
    let deny = |why: &str| Err(format!("nginx directive `{directive}` is not allowed: {why}"));
    let first = args.first().copied().unwrap_or("");
    if DENIED.contains(&directive) {
        return deny("it changes how the nginx master process runs");
    }
    if directive.contains("lua") || directive.starts_with("perl") || directive.starts_with("js_") {
        return deny("embedded scripting is disabled");
    }
    if directive.ends_with("_temp_path") || directive.ends_with("_cache_path") {
        return deny("it makes nginx create directories as root");
    }
    if directive == "access_log" || directive == "error_log" {
        let ok = (directive == "access_log" && first == "off")
            || (first.starts_with(LOG_PREFIX) && !first.contains(".."));
        if !ok {
            return deny("logs must be under /var/log/nginx/");
        }
    }
    if directive.starts_with("ssl_") || directive.contains("_ssl_") {
        for arg in args.iter().filter(|a| a.starts_with('/')) {
            if !TLS_PREFIXES.iter().any(|p| arg.starts_with(p)) || arg.contains("..") {
                return deny("TLS files must be under /etc/letsencrypt/ or /etc/ssl/");
            }
        }
    }
    Ok(())
}

pub fn check_vhost(conf: &str) -> Result<(), String> {
    if conf.len() > MAX_VHOST_BYTES {
        return Err(format!("vhost is larger than {MAX_VHOST_BYTES} bytes"));
    }
    let clean = strip_comments(conf);
    if clean.trim().is_empty() {
        return Err("vhost is empty".into());
    }
    for statement in clean.split([';', '{', '}']) {
        let tokens: Vec<&str> = statement.split_whitespace().map(unquote).collect();
        let Some((directive, args)) = tokens.split_first() else { continue };
        check_statement(&directive.to_ascii_lowercase(), args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
# reverse proxy for the shop app
server {
    listen 80;
    server_name shop.example.com;
    access_log /var/log/nginx/shop.access.log;
    error_log /var/log/nginx/shop.error.log warn;
    ssl_certificate /etc/letsencrypt/live/shop/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
    location /static/ { root /srv/apps/shop/public; access_log off; }
}
"#;

    #[test]
    fn accepts_an_ordinary_vhost() {
        assert_eq!(check_vhost(GOOD), Ok(()));
    }

    #[test]
    fn rejects_directives_that_let_root_touch_arbitrary_files() {
        for bad in [
            "server { access_log /etc/cron.d/pwn; }",
            "server { error_log /root/.ssh/authorized_keys; }",
            "server { access_log /var/log/nginx/../../etc/cron.d/pwn; }",
            "server { access_log syslog:server=1.2.3.4; }",
            "include /etc/shadow;",
            "server { include /srv/apps/shop/extra.conf; }",
            "load_module /srv/apps/shop/evil.so;",
            "server { client_body_temp_path /etc/cron.d; }",
            "proxy_cache_path /etc/cron.d keys_zone=a:1m;",
            "server { ssl_certificate /etc/shadow; }",
            "server { proxy_ssl_certificate_key /root/key.pem; }",
            "server { content_by_lua_block { os.execute('id') } }",
            "server { perl_set $x 'sub { 1 }'; }",
            "user root;",
            "server { \"access_log\" /etc/cron.d/pwn; }",
            "server { ACCESS_LOG /etc/cron.d/pwn; }",
            "server {\n  listen 80; access_log\n    /etc/cron.d/pwn;\n}",
        ] {
            assert!(check_vhost(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn comments_do_not_hide_or_trigger_rules() {
        assert!(check_vhost("server { listen 80; } # include /etc/shadow;").is_ok());
        assert!(check_vhost("# harmless\nserver { access_log /etc/passwd; }").is_err());
    }

    #[test]
    fn rejects_empty_and_oversized_input() {
        assert!(check_vhost("   \n").is_err());
        assert!(check_vhost(&"server { listen 80; }\n".repeat(20_000)).is_err());
    }
}
