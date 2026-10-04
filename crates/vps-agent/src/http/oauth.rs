//! A minimal OAuth 2.1 authorization server for the remote MCP endpoint: dynamic client
//! registration, authorization code with PKCE (S256 only), refresh token rotation.
//!
//! There are no user accounts. The person approving a client proves they own the server
//! by typing the pairing secret that `vps-agent http-setup` printed once.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const CODE_TTL: u64 = 60;
pub const ACCESS_TTL: u64 = 3600;
pub const REFRESH_TTL: u64 = 30 * 24 * 3600;
const MAX_CLIENTS: usize = 100;
const MAX_FAILURES: u32 = 5;
const LOCKOUT_SECS: u64 = 300;

#[derive(Debug, PartialEq)]
pub enum OAuthError {
    /// Shown to the person in the browser; never redirected, because the client is not trusted yet.
    InvalidRequest(String),
    InvalidGrant(String),
    InvalidClient,
    AccessDenied,
    LockedOut(u64),
}

impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            OAuthError::InvalidRequest(_) => "invalid_request",
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::InvalidClient => "invalid_client",
            OAuthError::AccessDenied | OAuthError::LockedOut(_) => "access_denied",
        }
    }

    pub fn description(&self) -> String {
        match self {
            OAuthError::InvalidRequest(m) | OAuthError::InvalidGrant(m) => m.clone(),
            OAuthError::InvalidClient => "unknown client_id".into(),
            OAuthError::AccessDenied => "wrong pairing secret".into(),
            OAuthError::LockedOut(s) => format!("too many wrong attempts; try again in {s} s"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
}

struct Code {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    expires: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Refresh {
    client_id: String,
    expires: u64,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Tokens {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
}

/// What survives a restart: registered clients and refresh tokens (stored as hashes).
#[derive(Default, Serialize, Deserialize)]
pub struct Persisted {
    clients: HashMap<String, Client>,
    refresh: HashMap<String, Refresh>,
}

pub struct Store {
    secret_sha256: [u8; 32],
    persisted: Persisted,
    codes: HashMap<String, Code>,
    access: HashMap<String, u64>,
    failures: u32,
    locked_until: u64,
    random: fn() -> String,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// 32 random bytes, base64url. Used for client ids, codes and tokens.
pub fn random_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("the OS random source is unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
    constant_time_eq(&sha256(computed.as_bytes()), &sha256(challenge.as_bytes()))
}

/// https anywhere, or plain http only for a loopback callback (native clients).
pub fn redirect_uri_ok(uri: &str) -> bool {
    let loopback = ["http://localhost", "http://127.0.0.1"]
        .iter()
        .any(|p| uri.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/'])));
    (uri.starts_with("https://") || loopback)
        && uri.len() <= 2048
        && !uri.contains('#')
        && uri.bytes().all(|b| b.is_ascii_graphic())
}

fn key(token: &str) -> String {
    hex(&sha256(token.as_bytes()))
}

impl Store {
    pub fn new(secret_sha256: [u8; 32], persisted: Persisted) -> Self {
        Store {
            secret_sha256,
            persisted,
            codes: HashMap::new(),
            access: HashMap::new(),
            failures: 0,
            locked_until: 0,
            random: random_token,
        }
    }

    pub fn persisted(&self) -> &Persisted {
        &self.persisted
    }

    pub fn register(&mut self, client_name: Option<String>, redirect_uris: Vec<String>) -> Result<Client, OAuthError> {
        if redirect_uris.is_empty() || redirect_uris.len() > 10 {
            return Err(OAuthError::InvalidRequest("redirect_uris must list 1 to 10 URIs".into()));
        }
        if let Some(bad) = redirect_uris.iter().find(|u| !redirect_uri_ok(u)) {
            return Err(OAuthError::InvalidRequest(format!("redirect_uri not allowed: {bad}")));
        }
        if self.persisted.clients.len() >= MAX_CLIENTS {
            return Err(OAuthError::InvalidRequest("too many registered clients".into()));
        }
        let name: String = client_name.unwrap_or_else(|| "unnamed client".into()).chars().take(80).collect();
        let client = Client { client_id: (self.random)(), client_name: name, redirect_uris };
        self.persisted.clients.insert(client.client_id.clone(), client.clone());
        Ok(client)
    }

    /// Checks an authorization request before the consent page is shown.
    pub fn validate_authorize(&self, p: &AuthorizeParams) -> Result<&Client, OAuthError> {
        let client = self.persisted.clients.get(&p.client_id).ok_or(OAuthError::InvalidClient)?;
        if !client.redirect_uris.contains(&p.redirect_uri) {
            return Err(OAuthError::InvalidRequest("redirect_uri is not registered for this client".into()));
        }
        if p.response_type != "code" {
            return Err(OAuthError::InvalidRequest("response_type must be code".into()));
        }
        if p.code_challenge_method.as_deref() != Some("S256") {
            return Err(OAuthError::InvalidRequest("code_challenge_method must be S256".into()));
        }
        if !(43..=128).contains(&p.code_challenge.len()) {
            return Err(OAuthError::InvalidRequest("code_challenge has the wrong length".into()));
        }
        Ok(client)
    }

    /// The person typed the pairing secret on the consent page.
    pub fn approve(&mut self, p: &AuthorizeParams, secret: &str, now: u64) -> Result<String, OAuthError> {
        self.validate_authorize(p)?;
        if now < self.locked_until {
            return Err(OAuthError::LockedOut(self.locked_until - now));
        }
        if !constant_time_eq(&sha256(secret.as_bytes()), &self.secret_sha256) {
            self.failures += 1;
            if self.failures >= MAX_FAILURES {
                self.failures = 0;
                self.locked_until = now + LOCKOUT_SECS;
            }
            return Err(OAuthError::AccessDenied);
        }
        self.failures = 0;
        self.codes.retain(|_, c| c.expires > now);
        let code = (self.random)();
        self.codes.insert(
            key(&code),
            Code {
                client_id: p.client_id.clone(),
                redirect_uri: p.redirect_uri.clone(),
                challenge: p.code_challenge.clone(),
                expires: now + CODE_TTL,
            },
        );
        Ok(code)
    }

    fn issue(&mut self, client_id: &str, now: u64) -> Tokens {
        self.access.retain(|_, exp| *exp > now);
        self.persisted.refresh.retain(|_, r| r.expires > now);
        let access_token = (self.random)();
        let refresh_token = (self.random)();
        self.access.insert(key(&access_token), now + ACCESS_TTL);
        self.persisted
            .refresh
            .insert(key(&refresh_token), Refresh { client_id: client_id.to_string(), expires: now + REFRESH_TTL });
        Tokens { access_token, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token }
    }

    pub fn exchange_code(
        &mut self,
        code: &str,
        verifier: &str,
        client_id: &str,
        redirect_uri: &str,
        now: u64,
    ) -> Result<Tokens, OAuthError> {
        // Removed before any check: a code is single-use even when the exchange fails.
        let entry = self.codes.remove(&key(code)).ok_or_else(|| OAuthError::InvalidGrant("unknown or used code".into()))?;
        if entry.expires <= now {
            return Err(OAuthError::InvalidGrant("code expired".into()));
        }
        if entry.client_id != client_id || entry.redirect_uri != redirect_uri {
            return Err(OAuthError::InvalidGrant("code was issued to another client or redirect_uri".into()));
        }
        if !pkce_matches(verifier, &entry.challenge) {
            return Err(OAuthError::InvalidGrant("code_verifier does not match".into()));
        }
        Ok(self.issue(client_id, now))
    }

    pub fn refresh(&mut self, refresh_token: &str, client_id: &str, now: u64) -> Result<Tokens, OAuthError> {
        let entry = self
            .persisted
            .refresh
            .remove(&key(refresh_token))
            .ok_or_else(|| OAuthError::InvalidGrant("unknown or used refresh token".into()))?;
        if entry.expires <= now || entry.client_id != client_id {
            return Err(OAuthError::InvalidGrant("refresh token expired or issued to another client".into()));
        }
        Ok(self.issue(client_id, now))
    }

    pub fn check_access(&self, token: &str, now: u64) -> bool {
        self.access.get(&key(token)).is_some_and(|exp| *exp > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "correct horse battery staple";
    const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
    // RFC 7636 appendix B.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn store() -> (Store, AuthorizeParams) {
        let mut s = Store::new(sha256(SECRET.as_bytes()), Persisted::default());
        let c = s.register(Some("Claude".into()), vec![REDIRECT.into()]).unwrap();
        let p = AuthorizeParams {
            response_type: "code".into(),
            client_id: c.client_id,
            redirect_uri: REDIRECT.into(),
            code_challenge: CHALLENGE.into(),
            code_challenge_method: Some("S256".into()),
            state: Some("xyz".into()),
        };
        (s, p)
    }

    #[test]
    fn full_flow_issues_working_tokens() {
        let (mut s, p) = store();
        let code = s.approve(&p, SECRET, 1000).unwrap();
        let t = s.exchange_code(&code, VERIFIER, &p.client_id, REDIRECT, 1010).unwrap();
        assert!(s.check_access(&t.access_token, 1020));
        assert!(!s.check_access(&t.access_token, 1010 + ACCESS_TTL));
        assert!(!s.check_access("made-up", 1020));
        assert!(!s.check_access("", 1020));
    }

    #[test]
    fn registration_checks_redirect_uris() {
        let mut s = Store::new([0; 32], Persisted::default());
        for ok in ["https://claude.ai/cb", "http://localhost:8080/cb", "http://127.0.0.1/cb"] {
            assert!(s.register(None, vec![ok.into()]).is_ok(), "{ok}");
        }
        for bad in ["http://evil.example/cb", "javascript:alert(1)", "http://localhost.evil.example/cb",
                    "https://a/cb#frag", "https://a/c b", ""] {
            assert!(s.register(None, vec![bad.into()]).is_err(), "{bad:?}");
        }
        assert!(s.register(None, vec![]).is_err());
    }

    #[test]
    fn authorize_request_is_validated() {
        let (s, p) = store();
        assert!(s.validate_authorize(&p).is_ok());
        let mut q = p.clone();
        q.redirect_uri = "https://evil.example/cb".into();
        assert!(matches!(s.validate_authorize(&q), Err(OAuthError::InvalidRequest(_))));
        let mut q = p.clone();
        q.client_id = "nope".into();
        assert_eq!(s.validate_authorize(&q).err(), Some(OAuthError::InvalidClient));
        let mut q = p.clone();
        q.code_challenge_method = Some("plain".into());
        assert!(s.validate_authorize(&q).is_err());
        let mut q = p.clone();
        q.code_challenge_method = None;
        assert!(s.validate_authorize(&q).is_err());
        let mut q = p;
        q.response_type = "token".into();
        assert!(s.validate_authorize(&q).is_err());
    }

    #[test]
    fn wrong_secret_is_refused_and_five_failures_lock_out() {
        let (mut s, p) = store();
        for _ in 0..4 {
            assert_eq!(s.approve(&p, "guess", 1000), Err(OAuthError::AccessDenied));
        }
        assert_eq!(s.approve(&p, "guess", 1000), Err(OAuthError::AccessDenied));
        // Locked: even the right secret is refused until the lockout ends.
        assert_eq!(s.approve(&p, SECRET, 1001), Err(OAuthError::LockedOut(LOCKOUT_SECS - 1)));
        assert!(s.approve(&p, SECRET, 1000 + LOCKOUT_SECS).is_ok());
    }

    #[test]
    fn code_is_single_use_bound_and_short_lived() {
        let (mut s, p) = store();
        let code = s.approve(&p, SECRET, 1000).unwrap();
        assert!(s.exchange_code(&code, "wrong-verifier-wrong-verifier-wrong-verifier-x", &p.client_id, REDIRECT, 1001).is_err());
        // The failed attempt burned the code.
        assert!(s.exchange_code(&code, VERIFIER, &p.client_id, REDIRECT, 1002).is_err());

        let code = s.approve(&p, SECRET, 2000).unwrap();
        assert!(s.exchange_code(&code, VERIFIER, &p.client_id, REDIRECT, 2000 + CODE_TTL).is_err());

        let code = s.approve(&p, SECRET, 3000).unwrap();
        assert!(s.exchange_code(&code, VERIFIER, "other-client", REDIRECT, 3001).is_err());

        let code = s.approve(&p, SECRET, 4000).unwrap();
        assert!(s.exchange_code(&code, VERIFIER, &p.client_id, "https://evil.example/cb", 4001).is_err());
    }

    #[test]
    fn refresh_rotates_and_old_token_stops_working() {
        let (mut s, p) = store();
        let code = s.approve(&p, SECRET, 1000).unwrap();
        let t1 = s.exchange_code(&code, VERIFIER, &p.client_id, REDIRECT, 1001).unwrap();
        let t2 = s.refresh(&t1.refresh_token, &p.client_id, 2000).unwrap();
        assert_ne!(t1.refresh_token, t2.refresh_token);
        assert!(s.check_access(&t2.access_token, 2001));
        assert!(s.refresh(&t1.refresh_token, &p.client_id, 2002).is_err());
        assert!(s.refresh(&t2.refresh_token, "other-client", 2003).is_err());
    }

    #[test]
    fn refresh_tokens_survive_a_restart_but_only_as_hashes() {
        let (mut s, p) = store();
        let code = s.approve(&p, SECRET, 1000).unwrap();
        let t = s.exchange_code(&code, VERIFIER, &p.client_id, REDIRECT, 1001).unwrap();
        let saved = serde_json::to_string(s.persisted()).unwrap();
        assert!(!saved.contains(&t.refresh_token));
        assert!(!saved.contains(&t.access_token));
        let mut restarted = Store::new(sha256(SECRET.as_bytes()), serde_json::from_str(&saved).unwrap());
        assert!(!restarted.check_access(&t.access_token, 1002));
        assert!(restarted.refresh(&t.refresh_token, &p.client_id, 1002).is_ok());
    }

    #[test]
    fn hex_round_trips() {
        let h = sha256(b"x");
        assert_eq!(parse_hex32(&hex(&h)), Some(h));
        assert_eq!(parse_hex32("zz"), None);
        assert_eq!(parse_hex32(&"g".repeat(64)), None);
    }
}
