//! Shared OAuth2 authorization-code flow with PKCE + token management.
//!
//! Used by the Dropbox, Google Drive, OneDrive and Box backends.
//!
//! Flow (run by `connect_oauth`):
//! 1. Generate a random PKCE `code_verifier` + a `state` nonce.
//! 2. Open the provider's consent page in the default browser, pointing the
//!    redirect at a random 127.0.0.1 loopback port.
//! 3. Listen on that port for the redirect; the browser hands back `code` + `state`.
//! 4. Exchange the code (with the verifier) for an access/refresh token.
//! 5. Store the token (as JSON) as the connection's secret.
//!
//! At runtime a backend re-reads that JSON secret and sends
//! `Authorization: Bearer <access_token>`, transparently refreshing the token
//! when it expires.

use crate::config::{self, ConnType};
use crate::error::{Error, Result};
use rand::Rng;
use reqwest::{Body, Client, Method};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const USER_AGENT: &str = "cloudup/1.0";

/// Static endpoint + scope metadata for an OAuth provider.
pub struct ProviderMeta {
    pub name: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    /// Space-separated scope request for the consent screen.
    pub scopes: &'static str,
    /// Extra authorize-URL parameters that make the provider issue a refresh
    /// token (without them Dropbox and Google tokens expire within hours).
    pub offline_params: &'static str,
}

impl ProviderMeta {
    /// Metadata for a connection type, or `None` for non-OAuth providers.
    pub fn for_ctype(t: ConnType) -> Option<&'static ProviderMeta> {
        Some(match t {
            ConnType::Dropbox => &DROPBOX,
            ConnType::GoogleDrive => &GDRIVE,
            ConnType::Onedrive => &ONEDRIVE,
            ConnType::Box => &BOX,
            _ => return None,
        })
    }
}

pub const DROPBOX: ProviderMeta = ProviderMeta {
    name: "Dropbox",
    authorize_url: "https://www.dropbox.com/oauth2/authorize",
    token_url: "https://api.dropboxapi.com/oauth2/token",
    scopes: "files.content.read files.content.write",
    offline_params: "&token_access_type=offline",
};

pub const GDRIVE: ProviderMeta = ProviderMeta {
    name: "Google Drive",
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    scopes: "https://www.googleapis.com/auth/drive",
    offline_params: "&access_type=offline&prompt=consent",
};

pub const ONEDRIVE: ProviderMeta = ProviderMeta {
    name: "OneDrive",
    authorize_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
    scopes: "Files.ReadWrite offline_access",
    offline_params: "",
};

pub const BOX: ProviderMeta = ProviderMeta {
    name: "Box",
    authorize_url: "https://account.box.com/api/oauth2/authorize",
    token_url: "https://api.box.com/oauth2/token",
    scopes: "file_downloads item_upload",
    offline_params: "",
};

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A token as returned by the provider's token endpoint. Serialized to JSON
/// and stored as the connection's secret.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
    /// Unix seconds at which this token was obtained/last refreshed.
    #[serde(default)]
    pub obtained_at: u64,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Base64url (RFC 4648 §5) with the `=` padding stripped.
fn b64url(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64URL[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64URL[(n & 63) as usize] as char } else { '=' });
    }
    while out.ends_with('=') {
        out.pop();
    }
    out
}

/// A 43-char random PKCE code verifier (RFC 7636 §4.1).
pub fn new_verifier() -> String {
    let mut rng = rand::thread_rng();
    (0..43).map(|_| B64URL[rng.gen_range(0..64usize)] as char).collect()
}

/// `BASE64URL(SHA256(ASCII(verifier)))` — the S256 code challenge.
pub fn code_challenge(verifier: &str) -> String {
    b64url(Sha256::digest(verifier.as_bytes()).as_slice())
}

/// Percent-encode a value for use in a URL query (RFC 3986 unreserved set).
pub fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Reverse of [`urlenc`]; also treats `+` as a space.
pub fn urldec(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
                let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0) as u8;
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Parse a stored secret into a [`Token`] (a JSON token object, or a bare
/// access-token string with no expiry/refresh metadata).
pub fn load_token(secret: &str) -> Token {
    if let Ok(t) = serde_json::from_str::<Token>(secret) {
        if !t.access_token.trim().is_empty() {
            return t;
        }
    }
    Token { access_token: secret.trim().to_string(), ..Default::default() }
}

/// Whether the token is (or is about to be) expired.
fn is_expired(t: &Token) -> bool {
    match t.expires_in {
        Some(e) => now_secs().saturating_sub(t.obtained_at) >= e.saturating_sub(60),
        None => false, // no expiry metadata (e.g. a manually pasted token)
    }
}

/// Persist a token (as JSON) into the connection's secret slot.
pub fn persist_token(conn_id: &str, tok: &Token) -> Result<()> {
    let json = serde_json::to_string(tok).map_err(|e| Error::Other(e.to_string()))?;
    config::store_secret(conn_id, &json).map_err(|e| Error::Other(format!("saving token: {e}")))
}

/// Run the full PKCE browser flow. Waits (on a worker thread) for the browser
/// to redirect back, then exchanges the code for a token.
pub async fn run_flow(meta: &ProviderMeta, client_id: &str, client_secret: &str) -> Result<Token> {
    if client_id.trim().is_empty() {
        return Err(Error::Other(format!("{}: an OAuth Client ID is required — fill in the Client ID field", meta.name)));
    }
    let verifier = new_verifier();
    let state = new_verifier();

    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| Error::Other(format!("could not bind a loopback port for the OAuth callback: {e}")))?;
    let port = listener.local_addr().map_err(|e| Error::Other(e.to_string()))?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256{}",
        meta.authorize_url,
        urlenc(client_id),
        urlenc(&redirect),
        urlenc(meta.scopes),
        urlenc(&state),
        urlenc(&code_challenge(&verifier)),
        meta.offline_params,
    );
    open::that(&url).map_err(|e| Error::Other(format!("could not open the browser to the consent page ({url}): {e}")))?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = listener.set_nonblocking(false);
        if let Ok((mut stream, _addr)) = listener.accept() {
            let (code, got_state) = read_callback(&mut stream);
            let _ = tx.send((code, got_state));
        }
    });

    let (code, got_state) = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(240)))
        .await
        .map_err(|e| Error::Other(format!("waiting for the OAuth callback: {e}")))?
        .map_err(|_| Error::Other("timed out waiting for the provider to redirect back — try again".to_string()))?;

    if got_state != state {
        return Err(Error::Other("OAuth state mismatch (possible CSRF) — try again".to_string()));
    }
    if code.trim().is_empty() {
        return Err(Error::Other("the provider redirected back without an authorization code — did you cancel?".to_string()));
    }

    exchange_token(meta, client_id, client_secret, &code, &redirect, &verifier).await
}

/// Read one HTTP request off the callback socket, answer 200, and pull out
/// the `code` + `state` query params.
fn read_callback(stream: &mut std::net::TcpStream) -> (String, String) {
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return (String::new(), String::new()),
    };
    let text = String::from_utf8_lossy(&buf[..n]);
    let request_line = text.lines().next().unwrap_or("");
    let target = request_line.split_whitespace().nth(1).unwrap_or("");
    let query = target.splitn(2, '?').nth(1).unwrap_or("");
    let mut code = String::new();
    let mut got_state = String::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let v = urldec(v);
            match k {
                "code" => code = v,
                "state" => got_state = v,
                "error" => return (String::new(), got_state), // user denied
                _ => {}
            }
        }
    }
    let html = "<!doctype html><html><body style=\"font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0\"><div style=\"text-align:center\"><h2>CloudUp</h2><p>Authorization complete — you can close this window and return to CloudUp.</p></div></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(resp.as_bytes());
    (code, got_state)
}

/// Exchange an authorization code for a token (token endpoint).
pub async fn exchange_token(
    meta: &ProviderMeta,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect: &str,
    verifier: &str,
) -> Result<Token> {
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.into()),
        ("redirect_uri".into(), redirect.into()),
        ("client_id".into(), client_id.into()),
        ("code_verifier".into(), verifier.into()),
    ];
    if !client_secret.trim().is_empty() {
        form.push(("client_secret".into(), client_secret.into()));
    }
    token_request(meta, client_id, client_secret, form).await
}

/// Perform a token/refresh grant POST and parse the token response.
async fn token_request(meta: &ProviderMeta, _client_id: &str, _client_secret: &str, form: Vec<(String, String)>) -> Result<Token> {
    let http = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap_or_default();
    let req = http.post(meta.token_url).header("User-Agent", USER_AGENT).form(&form);
    let resp = req
        .send()
        .await
        .map_err(|e| Error::Http(format!("{} token request: {e}", meta.name)))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.is_success() {
        let mut tok: Token = serde_json::from_str(&body)
            .map_err(|e| Error::Api { provider: meta.name.into(), status: status.as_u16(), body: format!("bad token JSON: {e} {body}") })?;
        tok.obtained_at = now_secs();
        Ok(tok)
    } else {
        Err(Error::Api { provider: meta.name.into(), status: status.as_u16(), body: body.chars().take(400).collect() })
    }
}

/// An HTTP client that authenticates calls with a stored OAuth token and
/// transparently refreshes it when it expires. Shared by the four OAuth
/// backends.
#[derive(Clone)]
pub struct OAuthHttp {
    pub meta: &'static ProviderMeta,
    pub conn_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub token: Arc<Mutex<Token>>,
    /// Held while refreshing, so parallel requests share one refresh (Box and
    /// OneDrive refresh tokens are single-use).
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
    http: Client,
}

impl OAuthHttp {
    pub fn new(meta: &'static ProviderMeta, conn_id: &str, client_id: &str, client_secret: &str, secret: &str) -> Self {
        let token = load_token(secret);
        Self {
            meta,
            conn_id: conn_id.to_string(),
            client_id: client_id.trim().to_string(),
            client_secret: client_secret.trim().to_string(),
            token: Arc::new(Mutex::new(token)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            http: Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .unwrap_or_default(),
        }
    }

    /// A valid access token, refreshing (and persisting) if it has expired.
    pub async fn access_token(&self) -> Result<String> {
        let tok = self.token.lock().unwrap().clone();
        if !tok.access_token.trim().is_empty() && !is_expired(&tok) {
            return Ok(tok.access_token.clone());
        }
        let _guard = self.refresh_lock.lock().await;
        // Another request may have refreshed while we waited.
        let tok = self.token.lock().unwrap().clone();
        if !tok.access_token.trim().is_empty() && !is_expired(&tok) {
            return Ok(tok.access_token.clone());
        }
        let new = self.refresh_current(&tok).await?;
        Ok(new.access_token.clone())
    }

    /// Refresh the currently-stored token. Errors if there is no refresh token.
    pub async fn force_refresh(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        let tok = self.token.lock().unwrap().clone();
        self.refresh_current(&tok).await?;
        Ok(())
    }

    async fn refresh_current(&self, tok: &Token) -> Result<Token> {
        let rt = tok
            .refresh_token
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                Error::Other(format!(
                    "{}: the stored token has expired and no refresh token is available — click Connect to authorize again",
                    self.meta.name
                ))
            })?;
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), rt.to_string()),
            ("client_id".into(), self.client_id.clone()),
        ];
        if !self.client_secret.is_empty() {
            form.push(("client_secret".into(), self.client_secret.clone()));
        }
        let mut new = token_request(self.meta, &self.client_id, &self.client_secret, form).await?;
        // Google and Dropbox don't send a new refresh token on refresh: keep
        // the one we have, or the next expiry would need a new sign-in.
        if new.refresh_token.as_deref().map_or(true, |s| s.trim().is_empty()) {
            new.refresh_token = Some(rt.to_string());
        }
        self.persist(&new);
        Ok(new)
    }

    fn persist(&self, tok: &Token) {
        if let Err(e) = persist_token(&self.conn_id, tok) {
            eprintln!("[cloudup] {}: could not save the refreshed token: {e}", self.meta.name);
        }
        *self.token.lock().unwrap() = tok.clone();
    }

    /// Issue an HTTP request with a Bearer token. On a 401/403, refresh the
    /// token once and retry. `method` is "GET"/"POST"/"PUT"/"DELETE".
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        extra: &[(String, String)],
    ) -> Result<reqwest::Response> {
        let m = Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Other(format!("bad HTTP method {method}: {e}")))?;
        for attempt in 0..2u8 {
            let token = self.access_token().await?;
            let mut req = self.http.request(m.clone(), url);
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
            req = req.header(reqwest::header::USER_AGENT, USER_AGENT);
            if let Some(ct) = content_type {
                req = req.header(reqwest::header::CONTENT_TYPE, ct);
            }
            for (k, v) in extra {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(b) = body.clone() {
                req = req.body(Body::from(b));
            }
            let resp = req.send().await.map_err(Error::http)?;
            let status = resp.status().as_u16();
            if (status == 401 || status == 403) && attempt == 0 {
                self.force_refresh().await?;
                continue;
            }
            return Ok(resp);
        }
        Err(Error::Other("unreachable: request loop".into()))
    }
}

/// Consume a response as JSON, mapping non-2xx to `Error::Api`.
pub async fn resp_json(provider: &str, resp: reqwest::Response) -> Result<serde_json::Value> {
    let status = resp.status();
    let body = resp.text().await.map_err(Error::http)?;
    if status.is_success() {
        serde_json::from_str(&body).map_err(|e| Error::Parse(format!("{provider}: {e}")))
    } else {
        Err(Error::Api { provider: provider.into(), status: status.as_u16(), body: body.chars().take(400).collect() })
    }
}

/// Consume a response as raw bytes, mapping non-2xx to `Error::Api`.
pub async fn resp_bytes(provider: &str, resp: reqwest::Response) -> Result<Vec<u8>> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.bytes().await.map_err(Error::http)?.to_vec());
    }
    let body = resp.text().await.unwrap_or_default();
    Err(Error::Api { provider: provider.into(), status: status.as_u16(), body: body.chars().take(400).collect() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_challenge() {
        // The canonical PKCE test vector from RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(code_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn verifier_shape() {
        let v = new_verifier();
        assert_eq!(v.len(), 43);
        assert!(v.bytes().all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_')));
    }

    #[test]
    fn urlenc_dec_roundtrip() {
        let s = "a b/c?d=1&e+2~x";
        let enc = urlenc(s);
        assert!(!enc.contains(' '));
        assert!(!enc.contains('/'));
        // urlenc percent-encodes a literal `+` to %2B, so this roundtrips losslessly.
        assert_eq!(urldec(&enc), s);
        assert_eq!(urlenc("plain-1._~"), "plain-1._~");
        // A bare `+` decodes to a space (form-style); %2B decodes to a literal `+`.
        assert_eq!(urldec("a+b"), "a b");
        assert_eq!(urldec("a%2Bb"), "a+b");
    }

    #[test]
    fn load_token_bare_string() {
        let t = load_token("  just-a-token  ");
        assert_eq!(t.access_token, "just-a-token");
        assert!(t.refresh_token.is_none());
        assert!(!is_expired(&t));
    }

    #[test]
    fn load_token_json() {
        let t = load_token(r#"{"access_token":"abc","refresh_token":"r","expires_in":3600,"obtained_at":0}"#);
        assert_eq!(t.access_token, "abc");
        assert_eq!(t.refresh_token.as_deref(), Some("r"));
        assert!(is_expired(&t)); // obtained 0 (epoch), long ago
    }

    #[test]
    fn b64url_no_padding() {
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }
}
