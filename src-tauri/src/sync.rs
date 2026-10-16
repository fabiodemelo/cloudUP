//! Optional CloudUp accounts with end-to-end encrypted sync of connections
//! across Macs. The server contract is docs/sync-api.md.
//!
//! Keys. The password never leaves the Mac: Argon2id turns it into a master
//! key, HKDF splits that into `auth_key` (sent; the server stores only a hash
//! of it) and `enc_key` (kept). A random `vault_key` encrypts the vault; the
//! server holds it only wrapped, by `enc_key` and by the recovery key. Once
//! signed in, the session token and the unwrapped vault key are kept in the
//! keychain (item "account"), so the password is needed only to sign in.
//! Signing out deletes that item; connections on this Mac stay.
//!
//! Between register and verify nothing is written to disk or the keychain.
//! `account_register` makes the vault key and the recovery key, uploads them
//! wrapped, and returns the recovery key for the UI to show after
//! verification. The vault key stays in this process's memory only (wiped on
//! drop), because until the account is verified `prelogin` answers with a
//! fake salt and the password can't unwrap it. `account_verify` uses that
//! in-memory key; if CloudUp quit in between, the account is verified by
//! then, so `prelogin` gives the real salt and the password unwraps the key
//! the server returns. Only after verify succeeds is the account saved to
//! the keychain.
//!
//! Sync runs at startup, about 2 s after a connection is saved or deleted,
//! when the window gains focus (at most once a minute) and every 5 minutes,
//! and only while signed in. Passwords, keys, tokens and vault contents are
//! never logged.

mod crypto;
mod vault;

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub use crypto::{crockford_decode, crockford_encode, Kdf};
pub use vault::{add_tombstone, merge, LocalState, Vault, VaultEntry};

use crate::config;
use crypto::Key32;

pub const DEFAULT_BASE_URL: &str = "https://www.demelos.com/tools/cloudup/api/v1/";
/// Keychain item holding the signed-in account (never a connection id).
pub const ACCOUNT_ITEM: &str = "account";
const MIN_PASSWORD: usize = 10;
const MAX_BLOB: usize = 2 * 1024 * 1024;
const PUT_ATTEMPTS: usize = 3;
const PERIOD: Duration = Duration::from_secs(5 * 60);
const DEBOUNCE: Duration = Duration::from_secs(2);
const FOCUS_GAP: Duration = Duration::from_secs(60);

// ------------------------------------------------------------------ errors

/// An error for the UI: a stable `code` and a short message to show.
#[derive(Debug, Clone, Serialize)]
pub struct AccountError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

impl AccountError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        AccountError { code: code.into(), message: message.into(), retry_after: None }
    }
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

type Res<T> = Result<T, AccountError>;

fn offline() -> AccountError {
    AccountError::new("offline", "Can't reach demelos.com; your connections are still saved on this Mac.")
}

fn local_err(e: impl std::fmt::Display) -> AccountError {
    AccountError::new("local", format!("CloudUp couldn't update this Mac: {e}"))
}

fn not_signed_in() -> AccountError {
    AccountError::new("not_signed_in", "Sign in to sync your connections.")
}

fn signed_out() -> AccountError {
    AccountError::new(
        "signed_out",
        "This Mac was signed out of your CloudUp account. Sign in again to keep syncing; your connections are still saved here.",
    )
}

fn rate_limited(secs: u64) -> AccountError {
    let wait = if secs < 60 {
        format!("{} second{}", secs.max(1), if secs == 1 { "" } else { "s" })
    } else {
        let m = secs.div_ceil(60);
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    };
    AccountError { retry_after: Some(secs), ..AccountError::new("rate_limited", format!("Too many attempts. Try again in {wait}.")) }
}

// ------------------------------------------------------------------ HTTP

fn base_url() -> String {
    // Tests point this at a local mock; only https, or http on this Mac.
    let mut url = std::env::var("CLOUDUP_SYNC_URL")
        .ok()
        .filter(|u| u.starts_with("https://") || u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost"))
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    if !url.ends_with('/') {
        url.push('/');
    }
    url
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("CloudUp/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client")
    })
}

struct Reply {
    status: u16,
    body: Value,
}

impl Reply {
    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    fn code(&self) -> &str {
        self.body.get("error").and_then(Value::as_str).unwrap_or("")
    }
    fn str(&self, key: &str) -> Res<String> {
        self.body.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(bad_reply)
    }
    fn bytes(&self, key: &str) -> Res<Vec<u8>> {
        B64.decode(self.str(key)?).map_err(|_| bad_reply())
    }
    fn u64(&self, key: &str) -> Res<u64> {
        self.body.get(key).and_then(Value::as_u64).ok_or_else(bad_reply)
    }
    /// Any other failure: the server's message if it sent one.
    fn error(&self) -> AccountError {
        let msg = self.body.get("message").and_then(Value::as_str).map(str::trim).filter(|m| !m.is_empty());
        match msg {
            Some(m) => AccountError::new("server", m.chars().take(300).collect::<String>()),
            None => AccountError::new(
                "server",
                format!("The CloudUp server had a problem (error {}). Try again later.", self.status),
            ),
        }
    }
}

fn bad_reply() -> AccountError {
    AccountError::new("server", "The CloudUp server sent an answer this version doesn't understand.")
}

async fn request(method: reqwest::Method, path: &str, token: Option<&str>, body: Option<Value>) -> Res<Reply> {
    let mut req = client().request(method, format!("{}{path}", base_url()));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.map_err(|_| offline())?;
    let status = resp.status().as_u16();
    let header_retry = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
    let bytes = resp.bytes().await.map_err(|_| offline())?;
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status == 429 {
        let secs = body.get("retry_after").and_then(Value::as_u64).or(header_retry).unwrap_or(60);
        return Err(rate_limited(secs));
    }
    Ok(Reply { status, body })
}

async fn post(path: &str, body: Value) -> Res<Reply> {
    request(reqwest::Method::POST, path, None, Some(body)).await
}

/// A call with the session token. 401 means this Mac was signed out
/// (revoked, password changed elsewhere, token expired): forget the account.
async fn authed(method: reqwest::Method, path: &str, acct: &Account, body: Option<Value>) -> Res<Reply> {
    let r = request(method, path, Some(&acct.token), body).await?;
    if r.status == 401 {
        clear_account_if(&acct.token);
        return Err(signed_out());
    }
    Ok(r)
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

// ------------------------------------------------------------------ account state

/// The signed-in account, kept as JSON in the keychain item "account".
/// No Debug: it holds the token and the vault key.
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    pub email: String,
    pub token: String,
    /// base64 of the 32-byte vault key.
    pub vault_key: String,
    pub vault_version: u64,
    #[serde(default)]
    pub last_sync: Option<String>,
}

impl Account {
    fn key(&self) -> Res<Key32> {
        let raw = Zeroizing::new(B64.decode(&self.vault_key).map_err(|_| corrupt_account())?);
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| corrupt_account())?;
        Ok(Zeroizing::new(arr))
    }
}

fn corrupt_account() -> AccountError {
    AccountError::new("local", "The saved sign-in on this Mac is damaged. Sign out and sign in again.")
}

/// Guards read-modify-write of the account item.
static ACCOUNT_LOCK: Mutex<()> = Mutex::new(());
/// Serialises syncs and account changes (sign in, sign out, reset...).
static OP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn account_lock() -> std::sync::MutexGuard<'static, ()> {
    ACCOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn load_account() -> Option<Account> {
    let raw = Zeroizing::new(config::read_secret(ACCOUNT_ITEM).ok().flatten()?);
    serde_json::from_str(&raw).ok()
}

fn save_account(a: &Account) -> Res<()> {
    let _g = account_lock();
    let raw = Zeroizing::new(serde_json::to_string(a).map_err(local_err)?);
    config::store_secret(ACCOUNT_ITEM, &raw).map_err(local_err)
}

/// Forget the account, unless it was replaced meanwhile (a new sign-in).
fn clear_account_if(token: &str) {
    let _g = account_lock();
    if load_account().is_some_and(|a| a.token == token) {
        config::delete_secret(ACCOUNT_ITEM);
    }
}

fn update_account_if(token: &str, f: impl FnOnce(&mut Account)) {
    let _g = account_lock();
    if let Some(mut a) = load_account().filter(|a| a.token == token) {
        f(&mut a);
        if let Ok(raw) = serde_json::to_string(&a) {
            let _ = config::store_secret(ACCOUNT_ITEM, &Zeroizing::new(raw));
        }
    }
}

fn need_account() -> Res<Account> {
    load_account().ok_or_else(not_signed_in)
}

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(e: Option<String>) {
    *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = e;
}

#[derive(Serialize)]
pub struct Status {
    pub signed_in: bool,
    pub email: Option<String>,
    pub last_sync: Option<String>,
    /// The last background sync's error, if it failed.
    pub last_error: Option<String>,
    pub device_name: String,
}

pub fn status() -> Status {
    let a = load_account();
    Status {
        signed_in: a.is_some(),
        email: a.as_ref().map(|a| a.email.clone()),
        last_sync: a.and_then(|a| a.last_sync),
        last_error: LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        device_name: device_name(),
    }
}

/// This Mac's name in the account's device list. `CLOUDUP_DEVICE_NAME`
/// overrides it (tests).
pub fn device_name() -> String {
    if let Some(n) = std::env::var("CLOUDUP_DEVICE_NAME").ok().filter(|n| !n.trim().is_empty()) {
        return n;
    }
    #[cfg(target_os = "macos")]
    if let Some(n) = crate::macos::computer_name() {
        return n;
    }
    "Mac".into()
}

// ------------------------------------------------------------------ input checks

fn normalize_email(email: &str) -> Res<String> {
    let e = email.trim().to_lowercase();
    let ok = e.len() <= 254
        && !e.chars().any(char::is_whitespace)
        && e.split_once('@').is_some_and(|(user, host)| !user.is_empty() && host.contains('.') && !host.starts_with('.'));
    if ok {
        Ok(e)
    } else {
        Err(AccountError::new("invalid", "Enter a valid email address."))
    }
}

fn check_new_password(pw: &str) -> Res<()> {
    if pw.chars().count() < MIN_PASSWORD {
        return Err(AccountError::new("invalid", format!("Use a password with at least {MIN_PASSWORD} characters.")));
    }
    Ok(())
}

/// Argon2id is slow on purpose: run it on a blocking thread.
async fn password_keys(password: &str, salt: &[u8], kdf: &Kdf) -> Res<crypto::PasswordKeys> {
    let (pw, salt, kdf) = (Zeroizing::new(password.to_string()), salt.to_vec(), kdf.clone());
    tokio::task::spawn_blocking(move || crypto::password_keys(&pw, &salt, &kdf))
        .await
        .map_err(local_err)?
        .map_err(local_err)
}

async fn prelogin(email: &str) -> Res<(Vec<u8>, Kdf)> {
    let r = post("prelogin", json!({ "email": email })).await?;
    if !r.ok() {
        return Err(r.error());
    }
    let kdf: Kdf = serde_json::from_value(r.body.get("kdf").cloned().unwrap_or(Value::Null)).map_err(|_| bad_reply())?;
    let salt = r.bytes("salt")?;
    if !kdf.acceptable() || !(8..=64).contains(&salt.len()) {
        return Err(AccountError::new(
            "server",
            "The CloudUp server asked for key settings this version doesn't accept. Update CloudUp and try again.",
        ));
    }
    Ok((salt, kdf))
}

/// A sign-up waiting for its emailed code: the vault key it made, in memory
/// only (prelogin gives unverified accounts a fake salt, so the password
/// alone can't unwrap it again until the account is verified).
struct Pending {
    email: String,
    vault_key: Key32,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

fn pending_key(email: &str) -> Option<Key32> {
    let p = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    p.as_ref().filter(|p| p.email == email).map(|p| p.vault_key.clone())
}

/// Forget a sign-up in progress, as quitting CloudUp does (tests).
#[doc(hidden)]
pub fn forget_pending_signup() {
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Fresh password keys for a new password: salt, KDF and the derived keys.
async fn new_password_keys(password: &str) -> Res<(Vec<u8>, Kdf, crypto::PasswordKeys)> {
    let salt = crypto::random_bytes(16);
    let kdf = Kdf::default();
    let keys = password_keys(password, &salt, &kdf).await?;
    Ok((salt, kdf, keys))
}

/// Parse `{token, wrapped_vault_key?, vault_version}` from a sign-in reply.
fn session(r: &Reply) -> Res<(String, u64)> {
    let token = r.str("token")?;
    let version = r.body.get("vault_version").and_then(Value::as_u64).unwrap_or(0);
    Ok((token, version))
}

async fn start_session(email: &str, token: String, vault_key: &Key32, vault_version: u64) -> Res<Status> {
    save_account(&Account {
        email: email.to_string(),
        token,
        vault_key: b64(&**vault_key),
        vault_version,
        last_sync: None,
    })?;
    set_last_error(None);
    Ok(status())
}

/// Best effort: revoke a token we can't use.
async fn drop_token(token: &str) {
    let _ = request(reqwest::Method::POST, "logout", Some(token), None).await;
}

// ------------------------------------------------------------------ account flows

/// Create an account. Returns the recovery key, to show once the email is
/// verified. Nothing is stored on this Mac yet.
pub async fn register(email: &str, password: &str) -> Res<String> {
    let email = normalize_email(email)?;
    check_new_password(password)?;
    let (salt, kdf, keys) = new_password_keys(password).await?;
    let vault_key = crypto::random_key();
    let recovery = crypto::random_key();
    let body = json!({
        "email": email,
        "salt": b64(&salt),
        "kdf": kdf,
        "auth_key": b64(&*keys.auth_key),
        "wrapped_vault_key": b64(&crypto::seal(&keys.enc_key, &*vault_key)),
        "recovery_wrapped_vault_key": b64(&crypto::seal(&recovery, &*vault_key)),
        "recovery_auth": b64(&*crypto::hkdf32(&*recovery, crypto::INFO_RECOVERY_AUTH)),
    });
    let r = post("register", body).await?;
    if !r.ok() {
        return Err(r.error());
    }
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending { email, vault_key });
    Ok(crypto::crockford_encode(&*recovery))
}

fn bad_code() -> AccountError {
    AccountError::new("bad_code", "That code is wrong or has expired. Check the email or send a new code.")
}

fn clean_code(code: &str) -> Res<String> {
    let c: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if c.len() == 6 {
        Ok(c)
    } else {
        Err(AccountError::new("invalid", "Enter the 6-digit code from the email."))
    }
}

/// Confirm the emailed code and sign this Mac in.
pub async fn verify(email: &str, code: &str, password: &str) -> Res<Status> {
    let _op = OP_LOCK.lock().await;
    let email = normalize_email(email)?;
    let code = clean_code(code)?;
    let r = post("verify", json!({ "email": email, "code": code, "device_name": device_name() })).await?;
    if !r.ok() {
        return Err(if r.status == 401 { bad_code() } else { r.error() });
    }
    let (token, version) = session(&r)?;
    let wrapped = r.bytes("wrapped_vault_key")?;
    let vault_key = match pending_key(&email) {
        Some(k) => k,
        // CloudUp quit after register: the account is verified now, so
        // prelogin gives the real salt and the password unwraps the key.
        None => {
            let unlocked = match prelogin(&email).await {
                Ok((salt, kdf)) => {
                    let keys = password_keys(password, &salt, &kdf).await?;
                    crypto::open_key(&keys.enc_key, &wrapped).ok()
                }
                Err(_) => None,
            };
            let Some(k) = unlocked else {
                drop_token(&token).await;
                return Err(AccountError::new(
                    "bad_credentials",
                    "Your account is ready, but that password doesn't match it. Sign in with your email and password.",
                ));
            };
            k
        }
    };
    forget_pending_signup();
    start_session(&email, token, &vault_key, version).await
}

/// Email a new verification code.
pub async fn resend(email: &str) -> Res<()> {
    let email = normalize_email(email)?;
    let r = post("resend", json!({ "email": email })).await?;
    if r.ok() {
        Ok(())
    } else {
        Err(r.error())
    }
}

pub async fn login(email: &str, password: &str) -> Res<Status> {
    let _op = OP_LOCK.lock().await;
    let email = normalize_email(email)?;
    if password.is_empty() {
        return Err(AccountError::new("invalid", "Enter your password."));
    }
    let (salt, kdf) = prelogin(&email).await?;
    let keys = password_keys(password, &salt, &kdf).await?;
    let r = post("login", json!({ "email": email, "auth_key": b64(&*keys.auth_key), "device_name": device_name() })).await?;
    match r.status {
        200..=299 => {}
        // Also an unverified account: the server doesn't say which.
        401 => return Err(AccountError::new("bad_credentials", "Wrong email or password.")),
        _ => return Err(r.error()),
    }
    let (token, version) = session(&r)?;
    let Ok(vault_key) = crypto::open_key(&keys.enc_key, &r.bytes("wrapped_vault_key")?) else {
        drop_token(&token).await;
        return Err(AccountError::new("crypto", "Your synced data can't be unlocked with this password."));
    };
    start_session(&email, token, &vault_key, version).await
}

/// Sign this Mac out. Connections saved here stay.
pub async fn logout() -> Res<()> {
    let _op = OP_LOCK.lock().await;
    if let Some(a) = load_account() {
        clear_account_if(&a.token);
        drop_token(&a.token).await;
    }
    set_last_error(None);
    Ok(())
}

#[derive(Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub created_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub current: bool,
}

pub async fn devices() -> Res<Vec<Device>> {
    let a = need_account()?;
    let r = authed(reqwest::Method::GET, "devices", &a, None).await?;
    if !r.ok() {
        return Err(r.error());
    }
    let list = r.body.as_array().or_else(|| r.body.get("devices").and_then(Value::as_array)).ok_or_else(bad_reply)?;
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(list
        .iter()
        .filter_map(|d| {
            let id = match d.get("id")? {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return None,
            };
            Some(Device {
                id,
                name: text(d, "name").unwrap_or_else(|| "Mac".into()),
                created_at: text(d, "created_at"),
                last_seen_at: text(d, "last_seen_at"),
                current: d.get("current").and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect())
}

/// Sign another device out.
pub async fn revoke_device(id: &str) -> Res<()> {
    if id.is_empty() || id.len() > 100 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(AccountError::new("invalid", "Unknown device."));
    }
    let a = need_account()?;
    let r = authed(reqwest::Method::DELETE, &format!("devices/{id}"), &a, None).await?;
    if r.ok() || r.status == 404 {
        Ok(())
    } else {
        Err(r.error())
    }
}

/// A 401 on a call that also checks the password: wrong password, unless the
/// server says the session itself is gone.
fn password_or_session(r: &Reply, acct: &Account) -> AccountError {
    let c = r.code();
    if c.contains("token") || c == "unauthorized" || c == "unauthenticated" {
        clear_account_if(&acct.token);
        signed_out()
    } else {
        AccountError::new("bad_credentials", "That password is wrong.")
    }
}

/// Change the password. The vault key stays; other Macs are signed out.
pub async fn change_password(current: &str, new: &str) -> Res<()> {
    let _op = OP_LOCK.lock().await;
    check_new_password(new)?;
    let a = need_account()?;
    let vault_key = a.key()?;
    let (salt, kdf) = prelogin(&a.email).await?;
    let cur = password_keys(current, &salt, &kdf).await?;
    let (new_salt, new_kdf, nk) = new_password_keys(new).await?;
    let body = json!({
        "auth_key": b64(&*cur.auth_key),
        "new_salt": b64(&new_salt),
        "new_kdf": new_kdf,
        "new_auth_key": b64(&*nk.auth_key),
        "new_wrapped_vault_key": b64(&crypto::seal(&nk.enc_key, &*vault_key)),
    });
    let r = request(reqwest::Method::POST, "password", Some(&a.token), Some(body)).await?;
    match r.status {
        200..=299 => Ok(()),
        401 => Err(password_or_session(&r, &a)),
        _ => Err(r.error()),
    }
}

/// Forgot the password, have the recovery key: set a new password and keep
/// the synced data. Signs this Mac in.
pub async fn recover(email: &str, recovery_key: &str, new_password: &str) -> Res<Status> {
    let _op = OP_LOCK.lock().await;
    let email = normalize_email(email)?;
    check_new_password(new_password)?;
    let rk = crypto::parse_recovery_key(recovery_key).map_err(|_| {
        AccountError::new("invalid", "That isn't a recovery key. It has 52 letters and digits in groups of 4.")
    })?;
    let mismatch = || AccountError::new("bad_credentials", "That email and recovery key don't match.");
    let r = post(
        "recover/start",
        json!({ "email": email, "recovery_auth": b64(&*crypto::hkdf32(&*rk, crypto::INFO_RECOVERY_AUTH)) }),
    )
    .await?;
    if !r.ok() {
        return Err(if r.status == 401 { mismatch() } else { r.error() });
    }
    let reset_token = r.str("reset_token")?;
    let vault_key = crypto::open_key(&rk, &r.bytes("recovery_wrapped_vault_key")?).map_err(|_| mismatch())?;
    let (salt, kdf, keys) = new_password_keys(new_password).await?;
    let r = post(
        "recover/finish",
        json!({
            "reset_token": reset_token,
            "salt": b64(&salt),
            "kdf": kdf,
            "auth_key": b64(&*keys.auth_key),
            "wrapped_vault_key": b64(&crypto::seal(&keys.enc_key, &*vault_key)),
            "device_name": device_name(),
        }),
    )
    .await?;
    if !r.ok() {
        return Err(if r.status == 401 {
            AccountError::new("expired", "The reset took too long. Start again.")
        } else {
            r.error()
        });
    }
    let (token, version) = session(&r)?;
    start_session(&email, token, &vault_key, version).await
}

/// Forgot the password and the recovery key: email a reset code.
pub async fn reset_start(email: &str) -> Res<()> {
    let email = normalize_email(email)?;
    let r = post("reset/start", json!({ "email": email })).await?;
    if r.ok() {
        Ok(())
    } else {
        Err(r.error())
    }
}

/// Finish a reset by email code: the synced data on the server is erased
/// and replaced by a new, empty vault (this Mac's connections are uploaded
/// by the next sync). Returns the new recovery key.
pub async fn reset_finish(email: &str, code: &str, new_password: &str) -> Res<String> {
    let _op = OP_LOCK.lock().await;
    let email = normalize_email(email)?;
    let code = clean_code(code)?;
    check_new_password(new_password)?;
    let (salt, kdf, keys) = new_password_keys(new_password).await?;
    let vault_key = crypto::random_key();
    let recovery = crypto::random_key();
    let r = post(
        "reset/finish",
        json!({
            "email": email,
            "code": code,
            "salt": b64(&salt),
            "kdf": kdf,
            "auth_key": b64(&*keys.auth_key),
            "wrapped_vault_key": b64(&crypto::seal(&keys.enc_key, &*vault_key)),
            "recovery_wrapped_vault_key": b64(&crypto::seal(&recovery, &*vault_key)),
            "recovery_auth": b64(&*crypto::hkdf32(&*recovery, crypto::INFO_RECOVERY_AUTH)),
            "device_name": device_name(),
        }),
    )
    .await?;
    if !r.ok() {
        return Err(if r.status == 401 { bad_code() } else { r.error() });
    }
    let (token, _) = session(&r)?;
    start_session(&email, token, &vault_key, 0).await?;
    Ok(crypto::crockford_encode(&*recovery))
}

/// Delete the account and the synced data (App Review 5.1.1(v)). Signs this
/// Mac out; its connections stay.
pub async fn delete_account(password: &str) -> Res<()> {
    let _op = OP_LOCK.lock().await;
    let a = need_account()?;
    let (salt, kdf) = prelogin(&a.email).await?;
    let keys = password_keys(password, &salt, &kdf).await?;
    let r =
        request(reqwest::Method::DELETE, "account", Some(&a.token), Some(json!({ "auth_key": b64(&*keys.auth_key) })))
            .await?;
    match r.status {
        200..=299 => {
            clear_account_if(&a.token);
            set_last_error(None);
            Ok(())
        }
        401 => Err(password_or_session(&r, &a)),
        _ => Err(r.error()),
    }
}

// ------------------------------------------------------------------ sync

#[derive(Default, Serialize)]
pub struct SyncOutcome {
    /// Local connections changed (added, edited or removed by another Mac).
    pub changed: bool,
    /// Connections removed from this Mac.
    pub removed: Vec<String>,
}

fn decode_vault(key: &Key32, blob: &str) -> Res<Vault> {
    let damaged = || AccountError::new("crypto", "Your synced data can't be read. Sign out and sign in again.");
    let sealed = B64.decode(blob).map_err(|_| damaged())?;
    let plain = Zeroizing::new(crypto::open(key, &sealed).map_err(|_| damaged())?);
    let v: Vault = serde_json::from_slice(&plain).map_err(|_| damaged())?;
    if v.schema > vault::SCHEMA {
        return Err(AccountError::new(
            "outdated",
            "Your connections were synced by a newer version of CloudUp. Update CloudUp to keep syncing.",
        ));
    }
    Ok(v)
}

fn encode_vault(key: &Key32, v: &Vault) -> Res<String> {
    let plain = Zeroizing::new(serde_json::to_vec(v).map_err(local_err)?);
    let blob = b64(&crypto::seal(key, &plain));
    if blob.len() > MAX_BLOB {
        return Err(AccountError::new("too_large", "Your connections are too large to sync (over 2 MB)."));
    }
    Ok(blob)
}

/// One merge against `remote`, writing this Mac's side. Returns the vault to
/// upload, if it changed.
async fn merge_and_write(remote: Option<Vault>, outcome: &mut SyncOutcome) -> Res<Option<Vault>> {
    let (vault, changed, removed) = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let _g = config::edit_lock();
        let local = vault::read_local()?;
        let m = vault::merge(&local, remote.as_ref(), chrono::Utc::now());
        if m.local_changed {
            vault::write_local(&local, &m.local)?;
        }
        let upload = (m.remote_changed).then_some(m.vault);
        Ok((upload, m.local_changed, m.removed))
    })
    .await
    .map_err(local_err)?
    .map_err(local_err)?;
    outcome.changed |= changed;
    outcome.removed.extend(removed);
    Ok(vault)
}

/// Sync now: download the vault, merge, write this Mac's side, upload.
pub async fn sync_now() -> Res<SyncOutcome> {
    let _op = OP_LOCK.lock().await;
    let result = sync_locked().await;
    set_last_error(result.as_ref().err().map(|e| e.message.clone()));
    result
}

async fn sync_locked() -> Res<SyncOutcome> {
    let acct = need_account()?;
    let key = acct.key()?;
    let r = authed(reqwest::Method::GET, "vault", &acct, None).await?;
    let (mut remote, mut version) = match r.status {
        204 => (None, 0),
        200 => (Some(decode_vault(&key, &r.str("blob")?)?), r.u64("version")?),
        _ => return Err(r.error()),
    };
    let mut outcome = SyncOutcome::default();
    let mut attempt = 0;
    loop {
        let Some(new_vault) = merge_and_write(remote.take(), &mut outcome).await? else { break };
        attempt += 1;
        if attempt > PUT_ATTEMPTS {
            return Err(AccountError::new(
                "conflict",
                "Your connections changed on another Mac at the same time. CloudUp will try again shortly.",
            ));
        }
        let blob = encode_vault(&key, &new_vault)?;
        let r = authed(reqwest::Method::PUT, "vault", &acct, Some(json!({ "base_version": version, "blob": blob })))
            .await?;
        match r.status {
            200..=299 => {
                version = r.u64("version")?;
                break;
            }
            409 => {
                // Someone else uploaded first (or the vault was erased by a
                // reset: blob null): merge with theirs and try again.
                remote = match r.body.get("blob").and_then(Value::as_str) {
                    Some(blob) => Some(decode_vault(&key, blob)?),
                    None => None,
                };
                version = r.body.get("version").and_then(Value::as_u64).unwrap_or(0);
            }
            413 => return Err(AccountError::new("too_large", "Your connections are too large to sync (over 2 MB).")),
            _ => return Err(r.error()),
        }
    }
    let now = config::now_rfc3339();
    update_account_if(&acct.token, |a| {
        a.vault_version = version;
        a.last_sync = Some(now);
    });
    Ok(outcome)
}

// ------------------------------------------------------------------ scheduling

/// Why a sync was asked for.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Trigger {
    /// Right away (startup, sign-in, "Sync now").
    Now,
    /// A connection was saved or deleted: wait for edits to settle.
    Change,
    /// The window gained focus: at most once a minute.
    Focus,
}

static TX: OnceLock<tokio::sync::mpsc::UnboundedSender<Trigger>> = OnceLock::new();

/// Ask the background loop for a sync. Ignored while signed out.
pub fn kick(t: Trigger) {
    if let Some(tx) = TX.get() {
        let _ = tx.send(t);
    }
}

/// Start the background sync loop (once, at app start).
pub fn start(app: tauri::AppHandle) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    if TX.set(tx).is_err() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let mut last_run: Option<Instant> = None;
        let mut next_periodic = tokio::time::Instant::now() + PERIOD;
        let mut queued = Some(Trigger::Now);
        loop {
            let trigger = match queued.take() {
                Some(t) => t,
                None => tokio::select! {
                    m = rx.recv() => match m { Some(t) => t, None => return },
                    _ = tokio::time::sleep_until(next_periodic) => Trigger::Now,
                },
            };
            match trigger {
                Trigger::Change => loop {
                    // Restart the wait on every further change.
                    tokio::select! {
                        m = rx.recv() => match m {
                            Some(Trigger::Now) => break,
                            Some(_) => continue,
                            None => return,
                        },
                        _ = tokio::time::sleep(DEBOUNCE) => break,
                    }
                },
                Trigger::Focus if last_run.is_some_and(|t| t.elapsed() < FOCUS_GAP) => continue,
                _ => {}
            }
            next_periodic = tokio::time::Instant::now() + PERIOD;
            if load_account().is_none() {
                continue;
            }
            last_run = Some(Instant::now());
            let _ = run_and_notify(&app).await;
        }
    });
}

/// Sync, then tell the window: "sync-changed" when connections changed,
/// "account-changed" after every attempt (last sync time, sign-out).
async fn run_and_notify(app: &tauri::AppHandle) -> Res<SyncOutcome> {
    use tauri::Emitter;
    let result = sync_now().await;
    if let Ok(o) = &result {
        // A drive whose connection was deleted on another Mac goes away
        // too. Drives whose settings changed keep running, as after an edit.
        let mounted = crate::mount::list_mounted();
        for id in o.removed.iter().filter(|id| mounted.iter().any(|m| &m.id == *id)).cloned() {
            let _ = tokio::task::spawn_blocking(move || crate::mount::unmount(&id)).await;
        }
        if o.changed {
            let _ = app.emit("sync-changed", ());
        }
    }
    let _ = app.emit("account-changed", ());
    result
}

// ------------------------------------------------------------------ commands

#[tauri::command]
pub fn account_status() -> Status {
    status()
}

#[derive(Serialize)]
pub struct RecoveryKey {
    pub recovery_key: String,
}

#[tauri::command]
pub async fn account_register(email: String, password: String) -> Res<RecoveryKey> {
    let password = Zeroizing::new(password);
    Ok(RecoveryKey { recovery_key: register(&email, &password).await? })
}

#[tauri::command]
pub async fn account_verify(email: String, code: String, password: String) -> Res<Status> {
    let password = Zeroizing::new(password);
    let s = verify(&email, &code, &password).await?;
    kick(Trigger::Now);
    Ok(s)
}

#[tauri::command]
pub async fn account_resend(email: String) -> Res<()> {
    resend(&email).await
}

#[tauri::command]
pub async fn account_login(email: String, password: String) -> Res<Status> {
    let password = Zeroizing::new(password);
    let s = login(&email, &password).await?;
    kick(Trigger::Now);
    Ok(s)
}

#[tauri::command]
pub async fn account_logout() -> Res<()> {
    logout().await
}

#[tauri::command]
pub async fn account_sync(app: tauri::AppHandle) -> Res<Status> {
    run_and_notify(&app).await?;
    Ok(status())
}

#[tauri::command]
pub async fn account_devices() -> Res<Vec<Device>> {
    devices().await
}

#[tauri::command]
pub async fn account_revoke_device(id: String) -> Res<()> {
    revoke_device(&id).await
}

#[tauri::command]
pub async fn account_change_password(current: String, new: String) -> Res<()> {
    let (current, new) = (Zeroizing::new(current), Zeroizing::new(new));
    change_password(&current, &new).await
}

#[tauri::command]
pub async fn account_recover(email: String, recovery_key: String, new_password: String) -> Res<Status> {
    let (recovery_key, new_password) = (Zeroizing::new(recovery_key), Zeroizing::new(new_password));
    let s = recover(&email, &recovery_key, &new_password).await?;
    kick(Trigger::Now);
    Ok(s)
}

#[tauri::command]
pub async fn account_reset(email: String) -> Res<()> {
    reset_start(&email).await
}

#[tauri::command]
pub async fn account_reset_finish(email: String, code: String, new_password: String) -> Res<RecoveryKey> {
    let new_password = Zeroizing::new(new_password);
    let recovery_key = reset_finish(&email, &code, &new_password).await?;
    kick(Trigger::Now);
    Ok(RecoveryKey { recovery_key })
}

#[tauri::command]
pub async fn account_delete(password: String) -> Res<()> {
    let password = Zeroizing::new(password);
    delete_account(&password).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_checked_and_lowercased() {
        assert_eq!(normalize_email("  Me@Example.COM ").unwrap(), "me@example.com");
        assert!(normalize_email("me@localhost").is_err());
        assert!(normalize_email("me example.com").is_err());
        assert!(normalize_email("@example.com").is_err());
    }

    #[test]
    fn passwords_need_ten_characters() {
        assert!(check_new_password("123456789").is_err());
        assert!(check_new_password("1234567890").is_ok());
        assert!(check_new_password("ééééééééééé").is_ok(), "characters, not bytes");
    }

    #[test]
    fn codes_keep_digits_only() {
        assert_eq!(clean_code(" 123-456 ").unwrap(), "123456");
        assert!(clean_code("12345").is_err());
    }

    #[test]
    fn rate_limit_messages() {
        assert_eq!(rate_limited(30).message, "Too many attempts. Try again in 30 seconds.");
        assert_eq!(rate_limited(61).message, "Too many attempts. Try again in 2 minutes.");
        assert_eq!(rate_limited(60).message, "Too many attempts. Try again in 1 minute.");
    }

    #[test]
    fn vault_blob_round_trip() {
        let key = crypto::random_key();
        let mut v = Vault { schema: 1, known_hosts: "h k\n".into(), ..Default::default() };
        // '-' never occurs in standard base64, so the marker can't appear in
        // the blob by chance (a short marker like "pw" sometimes does).
        v.secrets.insert("a".into(), "plain-text-secret".into());
        let blob = encode_vault(&key, &v).unwrap();
        assert!(!blob.contains("plain-text-secret"));
        assert!(decode_vault(&key, &blob).unwrap() == v);
        assert_eq!(decode_vault(&crypto::random_key(), &blob).err().unwrap().code, "crypto");
        v.schema = 2;
        assert_eq!(decode_vault(&key, &encode_vault(&key, &v).unwrap()).err().unwrap().code, "outdated");
    }
}
