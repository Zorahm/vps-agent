//! Remote MCP over HTTP for claude.ai and other hosted clients.
//!
//! `vps-agent serve-http` listens on a loopback port as the agent user. TLS terminates in
//! front of it (nginx or Caddy); `public_url` is the address clients see. Access is granted
//! through the OAuth flow in `oauth`, approved with the pairing secret.

pub mod oauth;

use crate::ctx::Ctx;
use crate::server::Server;
use axum::extract::{Form, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oauth::{AuthorizeParams, OAuthError, Persisted, Store};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde::Deserialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use vps_agent_core::paths::STATE_DIR;

pub const HTTP_CONFIG: &str = "/etc/vps-agent/http.toml";
const UNIT_FILE: &str = "/etc/systemd/system/vps-agent-http.service";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    /// Loopback address to listen on, for example 127.0.0.1:8722.
    pub bind: String,
    /// Public https origin clients use, without a trailing slash.
    pub public_url: String,
    /// SHA-256 of the pairing secret, hex.
    pub pairing_secret_sha256: String,
}

pub fn parse_http_config(text: &str) -> Result<(HttpConfig, [u8; 32]), String> {
    let mut cfg: HttpConfig = toml::from_str(text).map_err(|e| format!("http.toml: {e}"))?;
    cfg.public_url = cfg.public_url.trim_end_matches('/').to_string();
    let host = public_host(&cfg.public_url).ok_or("http.toml: public_url must be an https:// origin without a path")?;
    if host.is_empty() {
        return Err("http.toml: public_url has no host".into());
    }
    let bind: std::net::SocketAddr = cfg.bind.parse().map_err(|e| format!("http.toml: bind: {e}"))?;
    if !bind.ip().is_loopback() {
        return Err("http.toml: bind must be a loopback address; put a TLS reverse proxy in front".into());
    }
    let secret = oauth::parse_hex32(&cfg.pairing_secret_sha256)
        .ok_or("http.toml: pairing_secret_sha256 must be 64 hex characters")?;
    Ok((cfg, secret))
}

/// The host[:port] of an https origin; None when it is not a bare https origin.
pub fn public_host(public_url: &str) -> Option<&str> {
    let host = public_url.strip_prefix("https://")?;
    (!host.contains(['/', '?', '#', '@']) && host.bytes().all(|b| b.is_ascii_graphic())).then_some(host)
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

struct App {
    public_url: String,
    store: Mutex<Store>,
    state_file: PathBuf,
}

impl App {
    fn save(&self, store: &Store) {
        let tmp = self.state_file.with_extension("json.tmp");
        let result = serde_json::to_vec(store.persisted())
            .map_err(|e| e.to_string())
            .and_then(|body| std::fs::write(&tmp, body).map_err(|e| e.to_string()))
            .and_then(|_| std::fs::rename(&tmp, &self.state_file).map_err(|e| e.to_string()));
        if let Err(e) = result {
            eprintln!("vps-agent: cannot save {}: {e}", self.state_file.display());
        }
    }
}

fn now() -> u64 {
    crate::tools::now()
}

fn oauth_error(status: StatusCode, e: &OAuthError) -> Response {
    (status, Json(json!({"error": e.code(), "error_description": e.description()}))).into_response()
}

async fn protected_resource(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": format!("{}/mcp", app.public_url),
        "authorization_servers": [app.public_url],
        "bearer_methods_supported": ["header"],
    }))
}

async fn authorization_server(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    let base = &app.public_url;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}

#[derive(Deserialize)]
struct RegisterBody {
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

async fn register(State(app): State<Arc<App>>, Json(body): Json<RegisterBody>) -> Response {
    let mut store = app.store.lock().unwrap();
    match store.register(body.client_name, body.redirect_uris) {
        Ok(client) => {
            app.save(&store);
            (
                StatusCode::CREATED,
                Json(json!({
                    "client_id": client.client_id,
                    "client_name": client.client_name,
                    "redirect_uris": client.redirect_uris,
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                })),
            )
                .into_response()
        }
        Err(e) => oauth_error(StatusCode::BAD_REQUEST, &e),
    }
}

fn page(status: StatusCode, body: String) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>vps-agent</title>\
         <style>body{{font:16px system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}}\
         input,button{{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin:.5rem 0}}\
         .err{{color:#b00020}}code{{word-break:break-all}}</style></head><body>{body}</body></html>"
    );
    let mut response = (status, Html(html)).into_response();
    let headers = response.headers_mut();
    // The consent page must never be framed: a framed page invites clickjacking.
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn consent_page(app: &App, p: &AuthorizeParams, client_name: &str, error: Option<&str>) -> Response {
    let hidden = [
        ("response_type", p.response_type.as_str()),
        ("client_id", p.client_id.as_str()),
        ("redirect_uri", p.redirect_uri.as_str()),
        ("code_challenge", p.code_challenge.as_str()),
        ("code_challenge_method", p.code_challenge_method.as_deref().unwrap_or("")),
        ("state", p.state.as_deref().unwrap_or("")),
    ]
    .iter()
    .map(|(k, v)| format!("<input type=\"hidden\" name=\"{k}\" value=\"{}\">", escape_html(v)))
    .collect::<String>();
    let error = error.map(|e| format!("<p class=\"err\">{}</p>", escape_html(e))).unwrap_or_default();
    page(
        if error.is_empty() { StatusCode::OK } else { StatusCode::FORBIDDEN },
        format!(
            "<h1>Allow access to this server?</h1>\
             <p><b>{}</b> is asking for shell access to <code>{}</code> through vps-agent.</p>\
             <p>After approval it will be sent to <code>{}</code>.</p>{error}\
             <form method=\"post\" action=\"/authorize\">{hidden}\
             <label>Pairing secret<input type=\"password\" name=\"secret\" autocomplete=\"off\" autofocus required></label>\
             <button type=\"submit\">Allow</button></form>\
             <p>Close this page to refuse.</p>",
            escape_html(client_name),
            escape_html(&app.public_url),
            escape_html(&p.redirect_uri),
        ),
    )
}

async fn authorize_page(State(app): State<Arc<App>>, Query(p): Query<AuthorizeParams>) -> Response {
    let store = app.store.lock().unwrap();
    match store.validate_authorize(&p) {
        Ok(client) => consent_page(&app, &p, &client.client_name, None),
        // Not redirected: until the request validates, the redirect target is not trusted.
        Err(e) => page(StatusCode::BAD_REQUEST, format!("<h1>Request refused</h1><p>{}</p>", escape_html(&e.description()))),
    }
}

#[derive(Deserialize)]
struct ApproveForm {
    #[serde(flatten)]
    params: AuthorizeParams,
    secret: String,
}

async fn authorize_submit(State(app): State<Arc<App>>, Form(form): Form<ApproveForm>) -> Response {
    let mut store = app.store.lock().unwrap();
    match store.approve(&form.params, &form.secret, now()) {
        Ok(code) => {
            let p = &form.params;
            let sep = if p.redirect_uri.contains('?') { '&' } else { '?' };
            let mut target = format!("{}{sep}code={code}", p.redirect_uri);
            if let Some(state) = p.state.as_deref().filter(|s| !s.is_empty()) {
                target.push_str(&format!("&state={}", urlencode(state)));
            }
            Redirect::to(&target).into_response()
        }
        Err(e @ (OAuthError::AccessDenied | OAuthError::LockedOut(_))) => {
            let name = store.validate_authorize(&form.params).map(|c| c.client_name.clone()).unwrap_or_default();
            consent_page(&app, &form.params, &name, Some(&e.description()))
        }
        Err(e) => page(StatusCode::BAD_REQUEST, format!("<h1>Request refused</h1><p>{}</p>", escape_html(&e.description()))),
    }
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    client_id: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
    refresh_token: Option<String>,
}

async fn token(State(app): State<Arc<App>>, Form(f): Form<TokenForm>) -> Response {
    let mut store = app.store.lock().unwrap();
    let client_id = f.client_id.unwrap_or_default();
    let result = match f.grant_type.as_str() {
        "authorization_code" => store.exchange_code(
            &f.code.unwrap_or_default(),
            &f.code_verifier.unwrap_or_default(),
            &client_id,
            &f.redirect_uri.unwrap_or_default(),
            now(),
        ),
        "refresh_token" => store.refresh(&f.refresh_token.unwrap_or_default(), &client_id, now()),
        other => Err(OAuthError::InvalidRequest(format!("unsupported grant_type {other:?}"))),
    };
    match result {
        Ok(tokens) => {
            app.save(&store);
            let mut response = Json(tokens).into_response();
            response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(e) => oauth_error(StatusCode::BAD_REQUEST, &e),
    }
}

async fn require_bearer(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let allowed = token.is_some_and(|t| app.store.lock().unwrap().check_access(t, now()));
    if allowed {
        return next.run(request).await;
    }
    let challenge = format!("Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"", app.public_url);
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

pub async fn serve_http(ctx: Ctx) -> Result<(), String> {
    let text = std::fs::read_to_string(HTTP_CONFIG).map_err(|e| format!("{HTTP_CONFIG}: {e}"))?;
    let (cfg, secret) = parse_http_config(&text)?;
    let state_dir = Path::new(STATE_DIR).join("http");
    std::fs::create_dir_all(&state_dir).map_err(|e| format!("{}: {e}", state_dir.display()))?;
    let state_file = state_dir.join("state.json");
    let persisted: Persisted = match std::fs::read(&state_file) {
        Ok(body) => serde_json::from_slice(&body).map_err(|e| format!("{}: {e}", state_file.display()))?,
        Err(_) => Persisted::default(),
    };
    let app = Arc::new(App {
        public_url: cfg.public_url.clone(),
        store: Mutex::new(Store::new(secret, persisted)),
        state_file,
    });

    let ctx = Arc::new(ctx);
    let host = public_host(&cfg.public_url).unwrap_or_default().to_string();
    let mcp = StreamableHttpService::new(
        move || Ok(Server::new(ctx.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_allowed_hosts([host]),
    );
    let router = Router::new()
        .nest_service("/mcp", mcp)
        .layer(axum::middleware::from_fn_with_state(app.clone(), require_bearer))
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(protected_resource))
        .route("/.well-known/oauth-authorization-server", get(authorization_server))
        .route("/register", post(register))
        .route("/authorize", get(authorize_page).post(authorize_submit))
        .route("/token", post(token))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await.map_err(|e| format!("{}: {e}", cfg.bind))?;
    eprintln!("vps-agent: serving MCP on http://{} as {}/mcp", cfg.bind, cfg.public_url);
    axum::serve(listener, router).await.map_err(|e| e.to_string())
}

/// `vps-agent http-setup`: writes http.toml and the systemd unit, prints the pairing secret once.
pub fn setup(public_url: &str, bind: &str) -> Result<(), String> {
    let public_url = public_url.trim_end_matches('/');
    let secret = oauth::random_token();
    let config = format!(
        "bind = \"{bind}\"\npublic_url = \"{public_url}\"\npairing_secret_sha256 = \"{}\"\n",
        oauth::hex(&oauth::sha256(secret.as_bytes()))
    );
    // Validate before touching the disk, so a typo in the flags leaves nothing behind.
    parse_http_config(&config)?;
    let host = public_host(public_url).unwrap_or_default();
    crate::admin::write_root_file(HTTP_CONFIG, &config, "0640", "agent")?;
    crate::admin::write_root_file(UNIT_FILE, UNIT, "0644", "root")?;
    crate::admin::run("systemctl", &["daemon-reload"])?;
    println!(
        "Wrote {HTTP_CONFIG} and {UNIT_FILE}.\n\n\
         Pairing secret (shown once, type it on the consent page):\n\n  {secret}\n\n\
         Next steps:\n\
         1. Put a TLS reverse proxy in front, for example this nginx vhost for {host}:\n\n\
         server {{\n    listen 443 ssl;\n    server_name {host};\n\
         \x20   ssl_certificate /etc/letsencrypt/live/{host}/fullchain.pem;\n\
         \x20   ssl_certificate_key /etc/letsencrypt/live/{host}/privkey.pem;\n\
         \x20   location / {{\n        proxy_pass http://{bind};\n        proxy_set_header Host $host;\n\
         \x20       proxy_buffering off;\n        proxy_read_timeout 1h;\n    }}\n}}\n\n\
         2. systemctl enable --now vps-agent-http\n\
         3. Add {public_url}/mcp as a custom connector in claude.ai."
    );
    Ok(())
}

const UNIT: &str = "[Unit]\n\
Description=vps-agent remote MCP endpoint\n\
After=network.target\n\n\
[Service]\n\
User=agent\n\
ExecStart=/usr/local/bin/vps-agent serve-http\n\
Restart=on-failure\n\
RestartSec=5\n\n\
[Install]\n\
WantedBy=multi-user.target\n";

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    fn cfg(bind: &str, url: &str, hash: &str) -> String {
        format!("bind = \"{bind}\"\npublic_url = \"{url}\"\npairing_secret_sha256 = \"{hash}\"\n")
    }

    #[test]
    fn parses_a_valid_config_and_trims_the_trailing_slash() {
        let (c, _) = parse_http_config(&cfg("127.0.0.1:8722", "https://mcp.example.com/", HASH)).unwrap();
        assert_eq!(c.public_url, "https://mcp.example.com");
        assert_eq!(public_host(&c.public_url), Some("mcp.example.com"));
    }

    #[test]
    fn refuses_public_binds_plain_http_and_bad_hashes() {
        for bad in [
            cfg("0.0.0.0:8722", "https://mcp.example.com", HASH),
            cfg("127.0.0.1:8722", "http://mcp.example.com", HASH),
            cfg("127.0.0.1:8722", "https://mcp.example.com/path", HASH),
            cfg("127.0.0.1:8722", "https://user@mcp.example.com", HASH),
            cfg("127.0.0.1:8722", "https://", HASH),
            cfg("127.0.0.1:8722", "https://mcp.example.com", "abc"),
            cfg("not-an-address", "https://mcp.example.com", HASH),
        ] {
            assert!(parse_http_config(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn html_and_url_escaping() {
        assert_eq!(escape_html("<b a=\"1\">&'"), "&lt;b a=&quot;1&quot;&gt;&amp;&#39;");
        assert_eq!(urlencode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}
