//! Free CloudUp license, required before use in the direct-download build.
//! The Mac App Store build has none of this (see `lib.rs` and APP_REVIEW.md).
//!
//! Getting a key: `license/start` emails a code and `license/finish` returns
//! the email's key (CloudUp API, docs/license-api.md); the website does the
//! same before the download. Checking it: the demelos license server answers
//! `license/v1/validate` with a payload signed by its Ed25519 key, which is
//! embedded here. A Mac counts as one activation (fingerprint below).
//!
//! `license.json` in the data dir keeps the key and the last signed "valid"
//! answer, so CloudUp starts offline until `next_check_before` plus the grace
//! period the server grants. A background check runs every few hours.

use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};

use crate::config;

const PRODUCT: &str = "cloudup";
const VALIDATE_URL: &str = "https://www.demelos.com/admin/api/license/v1/validate";
/// The license server's signing key (GET /admin/api/license/v1/pubkey), raw
/// 32 bytes of its SPKI, and its id.
const PUBLIC_KEY_B64: &str = "sYSd4nI9d+Xn8dEc0fuX3uxWa6n2W2KiV7mwG6asra8=";
const KEY_ID: &str = "dm-4ee864c1de46";
const LICENSE_FILE: &str = "license.json";
const RECHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Short, so a dead network can't hold up start-up for long.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// An answer issued this far in the "future" means the clock went back.
const CLOCK_SLACK: i64 = 86_400;
/// Used when the server leaves them out (it always sends both today).
const DEFAULT_GRACE: i64 = 5 * 86_400;
const DEFAULT_RECHECK: i64 = 15 * 86_400;

pub const CHANGED_EVENT: &str = "license-changed";

// ------------------------------------------------------------------ types

/// What the UI needs to know. `state`: `licensed`, `unlicensed` (no key),
/// `invalid` (the server refused the key: `message` says why) or `offline`
/// (the saved check ran out and the server can't be reached).
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct LicenseStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_key: Option<String>,
}

impl LicenseStatus {
    fn licensed(s: &Stored) -> Self {
        Self { state: "licensed", message: None, email: s.email.clone(), license_key: Some(mask(&s.license_key)) }
    }
    fn unlicensed() -> Self {
        Self { state: "unlicensed", message: None, email: None, license_key: None }
    }
    fn invalid(msg: String) -> Self {
        Self { state: "invalid", message: Some(msg), email: None, license_key: None }
    }
    fn offline() -> Self {
        Self {
            state: "offline",
            message: Some("CloudUp couldn't reach demelos.com to check your license. Connect to the internet and try again.".into()),
            email: None,
            license_key: None,
        }
    }
    pub fn is_licensed(&self) -> bool {
        self.state == "licensed"
    }
}

/// `license.json`: the key, who it's for, and the last signed answer.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Stored {
    license_key: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    payload: String,
    #[serde(default)]
    signature: String,
    /// Latest clock time seen while licensed: a clock set back further than
    /// a day before it can't stretch an old answer.
    #[serde(default)]
    seen_max: i64,
}

/// The signed payload from `license/v1/validate`.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Payload {
    pub v: u32,
    pub status: String,
    #[serde(default)]
    pub license_key: String,
    pub product: String,
    pub fingerprint: String,
    pub nonce: String,
    pub issued_at: i64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub next_check_before: Option<i64>,
    #[serde(default)]
    pub grace_seconds: Option<i64>,
    #[serde(default)]
    pub max_activations: Option<u64>,
}

/// How a saved "valid" answer stands at a given time.
#[derive(Debug, PartialEq)]
pub enum Freshness {
    /// Before `next_check_before`: no need to ask the server.
    Fresh,
    /// Past it but within the grace period: ask, and keep working if offline.
    Stale,
    /// Past the grace period, expired, or for another key or Mac.
    Dead,
}

// ------------------------------------------------------------------ pure checks

fn server_key() -> (VerifyingKey, String) {
    // Debug builds (tests, local runs) may point at a test key. Release
    // builds always trust only the embedded key.
    if cfg!(debug_assertions) {
        if let (Ok(k), Ok(id)) = (std::env::var("CLOUDUP_LICENSE_PUBKEY"), std::env::var("CLOUDUP_LICENSE_KEY_ID")) {
            if let Some(vk) = decode_key(&k) {
                return (vk, id);
            }
        }
    }
    (decode_key(PUBLIC_KEY_B64).expect("embedded license key"), KEY_ID.to_string())
}

fn decode_key(b64: &str) -> Option<VerifyingKey> {
    let raw: [u8; 32] = B64.decode(b64.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

/// Check the signature over the exact payload bytes, then parse it.
pub fn verify_signed(payload: &str, signature: &str, key_id: &str, key: &VerifyingKey, want_id: &str) -> Result<Payload, String> {
    if key_id != want_id {
        return Err("signed with an unknown key".into());
    }
    let raw: [u8; 64] = B64
        .decode(signature.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("malformed signature")?;
    key.verify_strict(payload.as_bytes(), &Signature::from_bytes(&raw))
        .map_err(|_| "bad signature".to_string())?;
    let p: Payload = serde_json::from_str(payload).map_err(|_| "unreadable payload".to_string())?;
    if p.v != 1 {
        return Err("unsupported payload version".into());
    }
    Ok(p)
}

/// Is this signed answer a live "valid" for `key` on this Mac at `now`?
pub fn freshness(p: &Payload, key: &str, fingerprint: &str, now: i64) -> Freshness {
    if p.status != "valid" || p.product != PRODUCT || p.license_key != key || !p.fingerprint.eq_ignore_ascii_case(fingerprint) {
        return Freshness::Dead;
    }
    if p.issued_at > now + CLOCK_SLACK || p.expires_at.is_some_and(|e| e <= now) {
        return Freshness::Dead;
    }
    let recheck = p.next_check_before.unwrap_or(p.issued_at + DEFAULT_RECHECK);
    let grace = p.grace_seconds.unwrap_or(DEFAULT_GRACE).max(0);
    if now < recheck {
        Freshness::Fresh
    } else if now < recheck + grace {
        Freshness::Stale
    } else {
        Freshness::Dead
    }
}

/// The message for a refused key.
pub fn refusal(p: &Payload) -> String {
    match p.status.as_str() {
        "not_found" => "That license key wasn't found. Check it, or get yours with your email address.".into(),
        "product_mismatch" => "That key is for a different demelos product, not CloudUp.".into(),
        "revoked" | "suspended" => "This license is turned off. Contact support@demelos.com.".into(),
        "expired" => "This license has expired. Get a new one with your email address.".into(),
        "deactivated" => "This Mac was removed from the license. Contact support@demelos.com.".into(),
        "activation_limit" => format!(
            "This license is already used on {} Macs. Contact support@demelos.com to move it to this one.",
            p.max_activations.unwrap_or(5)
        ),
        other => format!("The license server refused the key ({other})."),
    }
}

/// `DM-XXXX-…` in upper case without spaces, or None.
pub fn normalize_key(input: &str) -> Option<String> {
    let k: String = input.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    let groups: Vec<&str> = k.split('-').collect();
    let ok = groups.len() == 7
        && groups[0] == "DM"
        && groups[1..].iter().all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_alphanumeric()));
    ok.then_some(k)
}

/// `DM-ABCD-…-WXYZ` → `DM-ABCD-••••-…-WXYZ`, for display.
fn mask(key: &str) -> String {
    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() < 3 {
        return key.to_string();
    }
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| if i <= 1 || i == last { p.to_string() } else { "••••".into() })
        .collect::<Vec<_>>()
        .join("-")
}

// ------------------------------------------------------------------ this Mac

/// A stable id for this Mac that doesn't reveal the hardware UUID:
/// SHA-256 of a CloudUp label and the host UUID.
pub fn fingerprint() -> String {
    let mut h = Sha256::new();
    h.update(b"cloudup-license-v1|");
    h.update(host_id());
    hex::encode(h.finalize())
}

#[cfg(target_os = "macos")]
fn host_id() -> Vec<u8> {
    let mut id = [0u8; 16];
    let wait = libc::timespec { tv_sec: 5, tv_nsec: 0 };
    // SAFETY: gethostuuid writes exactly 16 bytes into `id`.
    if unsafe { libc::gethostuuid(id.as_mut_ptr(), &wait) } == 0 && id != [0u8; 16] {
        return id.to_vec();
    }
    fallback_id()
}

#[cfg(not(target_os = "macos"))]
fn host_id() -> Vec<u8> {
    fallback_id()
}

/// A random id kept in the data dir, when the host UUID isn't available.
fn fallback_id() -> Vec<u8> {
    let path = config::data_dir().join("license-device-id");
    if let Ok(s) = std::fs::read_to_string(&path) {
        if s.trim().len() == 32 {
            return s.trim().as_bytes().to_vec();
        }
    }
    let id = hex::encode(rand::random::<[u8; 16]>());
    let _ = write_private(&path, id.as_bytes());
    id.into_bytes()
}

// ------------------------------------------------------------------ storage

fn license_path() -> std::path::PathBuf {
    config::data_dir().join(LICENSE_FILE)
}

/// Serializes reads and writes of license.json (UI and background check).
static FILE_LOCK: Mutex<()> = Mutex::new(());

fn load() -> Option<Stored> {
    let _g = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let raw = std::fs::read_to_string(license_path()).ok()?;
    serde_json::from_str::<Stored>(&raw).ok().filter(|s| normalize_key(&s.license_key).is_some())
}

fn save(s: &Stored) -> Result<(), String> {
    let _g = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let raw = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    write_private(&license_path(), &raw)
}

fn forget() {
    let _g = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::remove_file(license_path());
}

/// Write a 0600 file through a temp name and a rename.
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// The saved answer, verified, and how it stands now.
fn saved_freshness(s: &Stored) -> Freshness {
    if s.payload.is_empty() || now() < s.seen_max - CLOCK_SLACK {
        return Freshness::Dead;
    }
    let (key, id) = server_key();
    match verify_signed(&s.payload, &s.signature, &id, &key, &id) {
        Ok(p) => freshness(&p, &s.license_key, &fingerprint(), now()),
        Err(_) => Freshness::Dead,
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ------------------------------------------------------------------ network

fn validate_url() -> String {
    if cfg!(debug_assertions) {
        if let Ok(u) = std::env::var("CLOUDUP_LICENSE_URL") {
            if u.starts_with("https://") || u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost") {
                return u;
            }
        }
    }
    VALIDATE_URL.to_string()
}

enum Checked {
    /// A verified answer (any status) and its raw payload and signature.
    Answer(Payload, String, String),
    /// No usable answer: offline, server error, or an answer that fails checks.
    Unreachable,
}

/// Ask the license server about `key` for this Mac.
async fn check_online(key: &str) -> Checked {
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let fp = fingerprint();
    let body = json!({
        "license_key": key,
        "product": PRODUCT,
        "fingerprint": fp,
        "label": concat!("CloudUp ", env!("CARGO_PKG_VERSION")),
        "nonce": nonce,
        "sdk": concat!("cloudup-rs/", env!("CARGO_PKG_VERSION")),
    });
    let Ok(resp) = crate::sync::client().post(validate_url()).timeout(CHECK_TIMEOUT).json(&body).send().await else {
        return Checked::Unreachable;
    };
    if !resp.status().is_success() {
        return Checked::Unreachable;
    }
    let Ok(v) = resp.json::<Value>().await else { return Checked::Unreachable };
    let d = v.get("data").unwrap_or(&v);
    let get = |k: &str| d.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let (payload, signature, key_id) = (get("payload"), get("signature"), get("key_id"));
    let (vk, want_id) = server_key();
    match verify_signed(&payload, &signature, &key_id, &vk, &want_id) {
        // The answer must be for this request: our nonce, key, Mac and product.
        Ok(p) if p.nonce == nonce && p.license_key == key && p.fingerprint.eq_ignore_ascii_case(&fp) && p.product == PRODUCT => {
            Checked::Answer(p, payload, signature)
        }
        Ok(_) | Err(_) => {
            eprintln!("[cloudup] license answer failed verification");
            Checked::Unreachable
        }
    }
}

/// Check `key` online and save it when valid. Err is the message to show.
pub async fn activate(key: String, email: Option<String>) -> Result<LicenseStatus, String> {
    match check_online(&key).await {
        Checked::Answer(p, payload, signature) if p.status == "valid" => {
            let s = Stored { license_key: key, email, payload, signature, seen_max: now() };
            save(&s)?;
            Ok(LicenseStatus::licensed(&s))
        }
        Checked::Answer(p, ..) => Err(refusal(&p)),
        Checked::Unreachable => Err(LicenseStatus::offline().message.unwrap_or_default()),
    }
}

/// The current state, asking the server only when the saved answer is stale
/// or gone. Offline while still within grace counts as licensed.
pub async fn status() -> LicenseStatus {
    let Some(s) = load() else { return LicenseStatus::unlicensed() };
    let fresh = saved_freshness(&s);
    if fresh == Freshness::Fresh {
        if now() > s.seen_max {
            let _ = save(&Stored { seen_max: now(), ..s.clone() });
        }
        return LicenseStatus::licensed(&s);
    }
    match check_online(&s.license_key).await {
        Checked::Answer(p, payload, signature) if p.status == "valid" => {
            let s = Stored { payload, signature, seen_max: now().max(s.seen_max), ..s };
            if let Err(e) = save(&s) {
                eprintln!("[cloudup] could not save the license check: {e}");
            }
            LicenseStatus::licensed(&s)
        }
        Checked::Answer(p, ..) => {
            forget();
            LicenseStatus::invalid(refusal(&p))
        }
        Checked::Unreachable if fresh == Freshness::Stale => LicenseStatus::licensed(&s),
        Checked::Unreachable => LicenseStatus::offline(),
    }
}

/// Licensed right now, from the saved answer alone (no network).
pub fn licensed_offline() -> bool {
    load().is_some_and(|s| saved_freshness(&s) != Freshness::Dead)
}

/// Licensed, checking online if the saved answer needs it (start-up mounts).
pub async fn allowed() -> bool {
    status().await.is_licensed()
}

/// For commands that need a license (mounting): a message when there's none.
pub fn require() -> Result<(), String> {
    if licensed_offline() {
        Ok(())
    } else {
        Err("CloudUp needs your free license first.".into())
    }
}

// ------------------------------------------------------------------ CloudUp API (email code)

async fn api_post(path: &str, body: Value) -> Result<Value, String> {
    let resp = crate::sync::client()
        .post(format!("{}{path}", crate::sync::base_url()))
        .json(&body)
        .send()
        .await
        .map_err(|_| "No connection to demelos.com. Check your internet connection.".to_string())?;
    let status = resp.status().as_u16();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return Ok(v);
    }
    if status == 429 {
        let mins = v.get("retry_after").and_then(Value::as_u64).unwrap_or(60).div_ceil(60).max(1);
        return Err(format!("Too many tries. Wait about {mins} minute{} and try again.", if mins == 1 { "" } else { "s" }));
    }
    if v.get("error").and_then(Value::as_str) == Some("invalid_request") {
        return Err("Check the email address and the code, then try again.".into());
    }
    Err(v
        .get("message")
        .and_then(Value::as_str)
        .map(|m| m.chars().take(300).collect())
        .unwrap_or_else(|| format!("demelos.com had a problem (error {status}). Try again later.")))
}

// ------------------------------------------------------------------ commands

#[tauri::command]
pub async fn license_status() -> LicenseStatus {
    status().await
}

/// Use a key the person pasted.
#[tauri::command]
pub async fn license_activate(app: tauri::AppHandle, key: String) -> Result<LicenseStatus, String> {
    let key = normalize_key(&key).ok_or("A license key looks like DM-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX.")?;
    let st = activate(key, None).await?;
    unlocked(&app);
    Ok(st)
}

/// Email a 6-digit code to `email`.
#[tauri::command]
pub async fn license_request_code(email: String) -> Result<(), String> {
    let email = email.trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') {
        return Err("Enter a valid email address.".into());
    }
    api_post("license/start", json!({ "email": email })).await.map(|_| ())
}

/// Trade the emailed code for the email's key, then activate it here.
#[tauri::command]
pub async fn license_verify_code(app: tauri::AppHandle, email: String, code: String) -> Result<LicenseStatus, String> {
    let st = verify_code(email, code).await?;
    unlocked(&app);
    Ok(st)
}

/// `license/finish`, then [`activate`] the key it returns.
pub async fn verify_code(email: String, code: String) -> Result<LicenseStatus, String> {
    let email = email.trim().to_lowercase();
    let code: String = code.chars().filter(char::is_ascii_digit).collect();
    if code.len() != 6 {
        return Err("Enter the 6-digit code from the email.".into());
    }
    let v = api_post("license/finish", json!({ "email": email, "code": code })).await?;
    let key = v
        .get("license_key")
        .and_then(Value::as_str)
        .and_then(normalize_key)
        .ok_or("demelos.com sent an answer this version doesn't understand.")?;
    match activate(key.clone(), Some(email.clone())).await {
        Ok(st) => Ok(st),
        Err(msg) => {
            // The code is used up now: keep the key, so the next start (or
            // "I have a license key") can try again without a new code.
            let _ = save(&Stored { license_key: key, email: Some(email), ..Default::default() });
            Err(format!("{msg} Your license key is saved on this Mac and was emailed to you, so you don't need a new code."))
        }
    }
}

/// The saved key, for the "I have a license key" screen.
#[tauri::command]
pub fn license_saved_key() -> Option<String> {
    load().map(|s| s.license_key)
}

/// Licensed now: mount the drives that were waiting for it.
fn unlocked(app: &tauri::AppHandle) {
    let _ = app.emit(CHANGED_EVENT, ());
    tauri::async_runtime::spawn(crate::commands::mount_auto());
}

/// Show the window (it starts hidden for login-item and Finder starts) so
/// the license screen can't go unseen.
fn show_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// At start, bring up the window if there's no valid license (drives don't
/// mount until there is). Then re-check every few hours; if the license stops
/// being valid, unmount everything and tell the window.
pub fn start(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        if !status().await.is_licensed() {
            show_window(&app);
            let _ = app.emit(CHANGED_EVENT, ());
        }
        loop {
            tokio::time::sleep(RECHECK_EVERY).await;
            if load().is_none() {
                continue;
            }
            if !status().await.is_licensed() {
                crate::mount::unmount_all();
                show_window(&app);
                let _ = app.emit(CHANGED_EVENT, ());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const FP: &str = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
    const KEY: &str = "DM-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23";

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed(v: Value) -> (String, String) {
        let payload = v.to_string();
        (payload.clone(), B64.encode(signer().sign(payload.as_bytes()).to_bytes()))
    }

    fn valid(now: i64) -> Value {
        json!({"v":1,"status":"valid","license_key":KEY,"product":"cloudup","fingerprint":FP,
               "nonce":"00112233445566778899aabbccddeeff","issued_at":now,"expires_at":null,
               "next_check_before":now + 15 * 86400,"grace_seconds":5 * 86400})
    }

    #[test]
    fn real_server_answer_verifies_with_embedded_key() {
        // Captured from https://www.demelos.com/admin/api/license/v1/validate (2026-11-21).
        let payload = r#"{"v":1,"status":"not_found","license_key":"DM-0000-0000-0000-0000-0000-0000","product":"cloudup","fingerprint":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881","nonce":"00112233445566778899aabbccddeeff","issued_at":1795303110}"#;
        let sig = "xENWj5tjmN2uYc+kM5E7kHHrqPmCGi41Ko0KpnWns2QiDUpqv3bniazXqdK3aWEU4e0yuTfz1Cplxtb2p7sMBg==";
        let key = decode_key(PUBLIC_KEY_B64).unwrap();
        let p = verify_signed(payload, sig, KEY_ID, &key, KEY_ID).unwrap();
        assert_eq!(p.status, "not_found");
        assert!(verify_signed(&payload.replace("not_found", "valid"), sig, KEY_ID, &key, KEY_ID).is_err());
        assert!(verify_signed(payload, sig, "dm-other", &key, KEY_ID).is_err());
    }

    #[test]
    fn tampered_or_foreign_signatures_fail() {
        let (payload, sig) = signed(valid(1_000));
        let ours = signer().verifying_key();
        assert!(verify_signed(&payload, &sig, "t", &ours, "t").is_ok());
        assert!(verify_signed(&payload, &sig, "t", &decode_key(PUBLIC_KEY_B64).unwrap(), "t").is_err());
        assert!(verify_signed(&payload.replace(KEY, "DM-ZZZZ-EFGH-JKMN-PQRS-TVWX-YZ23"), &sig, "t", &ours, "t").is_err());
        assert!(verify_signed(&payload, "bm90IGEgc2ln", "t", &ours, "t").is_err());
    }

    #[test]
    fn freshness_windows() {
        let t = 1_800_000_000;
        let p: Payload = serde_json::from_value(valid(t)).unwrap();
        assert_eq!(freshness(&p, KEY, FP, t + 10), Freshness::Fresh);
        assert_eq!(freshness(&p, KEY, FP, t + 16 * 86400), Freshness::Stale);
        assert_eq!(freshness(&p, KEY, FP, t + 21 * 86400), Freshness::Dead);
        assert_eq!(freshness(&p, KEY, &FP.to_uppercase(), t), Freshness::Fresh);
        assert_eq!(freshness(&p, KEY, "ab", t), Freshness::Dead, "another Mac");
        assert_eq!(freshness(&p, "DM-OTHER", FP, t), Freshness::Dead, "another key");
        assert_eq!(freshness(&p, KEY, FP, t - 2 * 86400), Freshness::Dead, "clock set back");
        let mut v = valid(t);
        v["status"] = json!("revoked");
        assert_eq!(freshness(&serde_json::from_value(v).unwrap(), KEY, FP, t), Freshness::Dead);
        let mut v = valid(t);
        v["expires_at"] = json!(t + 60);
        assert_eq!(freshness(&serde_json::from_value(v).unwrap(), KEY, FP, t + 61), Freshness::Dead);
        let mut v = valid(t);
        v["product"] = json!("bidas");
        assert_eq!(freshness(&serde_json::from_value(v).unwrap(), KEY, FP, t), Freshness::Dead);
    }

    #[test]
    fn keys_are_normalized() {
        assert_eq!(normalize_key(" dm-abcd-efgh-jkmn-pqrs-tvwx-yz23 ").as_deref(), Some(KEY));
        assert_eq!(normalize_key("DM-ABCD-EFGH-JKMN-PQRS-TVWX").as_deref(), None);
        assert_eq!(normalize_key("XX-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23").as_deref(), None);
        assert_eq!(normalize_key("DM-AB D-EFGH-JKMN-PQRS-TVWX-YZ23").as_deref(), None);
        assert_eq!(mask(KEY), "DM-ABCD-••••-••••-••••-••••-YZ23");
    }

    #[test]
    fn refusals_read_well() {
        let mut v = valid(0);
        v["status"] = json!("activation_limit");
        v["max_activations"] = json!(5);
        assert!(refusal(&serde_json::from_value(v).unwrap()).contains("5 Macs"));
    }

    #[test]
    fn fingerprint_is_stable_hex() {
        let a = fingerprint();
        assert_eq!(a, fingerprint());
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
