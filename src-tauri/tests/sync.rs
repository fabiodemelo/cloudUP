//! Accounts and sync end to end, against an in-process mock of the API in
//! docs/sync-api.md (never the real server). Two "Macs" are two data
//! directories (`CLOUDUP_DATA_DIR`); secrets go to the fallback file in each
//! (`CLOUDUP_NO_KEYCHAIN`), so the user's keychain is never touched.
//!
//! Run with `cargo test --release --test sync` (Argon2id is slow unoptimised).

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cloudup_lib::config::{self, ConnType, Connection};
use cloudup_lib::sync;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

// ------------------------------------------------------------------ mock server

#[derive(Default)]
struct User {
    salt: String,
    kdf: Value,
    auth_key: String,
    wrapped: String,
    recovery_wrapped: String,
    recovery_auth: String,
    verified: bool,
    /// (version, blob, updated_at)
    vault: Option<(u64, String, String)>,
}

#[derive(Default)]
struct Mock {
    users: HashMap<String, User>,
    codes: HashMap<String, String>,
    guesses: HashMap<String, u32>,
    /// token -> device id
    tokens: HashMap<String, u64>,
    /// device id -> (email, name)
    devices: HashMap<u64, (String, String)>,
    next_id: u64,
    reset_tokens: HashMap<String, String>,
    /// Applied just before the next PUT vault: another Mac uploading first.
    inject: Option<(u64, String)>,
    puts: u32,
    conflicts: u32,
    rate_limit_next: Option<u64>,
    /// Every request body, to check no password is ever sent.
    bodies: Vec<String>,
}

impl Mock {
    fn code_for(&mut self, email: &str) -> String {
        let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
        self.codes.insert(email.to_string(), code.clone());
        self.guesses.insert(email.to_string(), 0);
        code
    }

    /// One guess at the live code: 5 in total, then the code is dead.
    fn check_code(&mut self, email: &str, code: &str) -> bool {
        let Some(live) = self.codes.get(email).cloned() else { return false };
        let n = self.guesses.entry(email.to_string()).or_insert(0);
        *n += 1;
        if *n > 5 {
            self.codes.remove(email);
            return false;
        }
        if live == code {
            self.codes.remove(email);
            return true;
        }
        false
    }

    fn session(&mut self, email: &str, name: &str) -> String {
        self.next_id += 1;
        let id = self.next_id;
        self.devices.insert(id, (email.to_string(), name.to_string()));
        let token = format!("tok-{id}-{}", rand::random::<u64>());
        self.tokens.insert(token.clone(), id);
        token
    }

    fn sign_out_all(&mut self, email: &str, except: Option<u64>) {
        let gone: Vec<u64> =
            self.devices.iter().filter(|(id, (e, _))| e == email && Some(**id) != except).map(|(id, _)| *id).collect();
        for id in gone {
            self.devices.remove(&id);
            self.tokens.retain(|_, d| *d != id);
        }
    }

    fn vault(&self, email: &str) -> Option<(u64, String, String)> {
        self.users.get(email).and_then(|u| u.vault.clone())
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn route(m: &mut Mock, method: &str, path: &str, token: Option<&str>, b: &Value) -> (u16, Value) {
    if let Some(secs) = m.rate_limit_next.take() {
        return (429, json!({"error": "rate_limited", "message": "slow down", "retry_after": secs}));
    }
    let err = |status: u16, code: &str| (status, json!({"error": code, "message": format!("mock: {code}")}));
    let session = |m: &mut Mock, email: &str, name: &str| {
        let token = m.session(email, name);
        let u = &m.users[email];
        (200, json!({"token": token, "wrapped_vault_key": u.wrapped, "vault_version": u.vault.as_ref().map_or(0, |v| v.0)}))
    };
    // Authenticated endpoints.
    let me = token.and_then(|t| m.tokens.get(t).copied()).and_then(|id| m.devices.get(&id).map(|d| (id, d.0.clone())));
    let needs_auth = matches!(
        (method, path),
        ("POST", "logout") | ("GET", "account") | ("GET", "vault") | ("PUT", "vault") | ("GET", "devices")
            | ("POST", "password") | ("DELETE", "account")
    ) || path.starts_with("devices/");
    if needs_auth && me.is_none() {
        return err(401, "unauthorized");
    }
    // Key sizes from the spec: anything else is 400 invalid_request.
    let size = |k: &str| B64.decode(s(b, k)).map(|v| v.len()).unwrap_or(0);
    for (k, want) in [
        ("salt", 16),
        ("new_salt", 16),
        ("auth_key", 32),
        ("new_auth_key", 32),
        ("recovery_auth", 32),
        ("wrapped_vault_key", 72),
        ("new_wrapped_vault_key", 72),
        ("recovery_wrapped_vault_key", 72),
    ] {
        if b.get(k).is_some() && size(k) != want {
            return err(400, "invalid_request");
        }
    }
    let email_b = s(b, "email");
    match (method, path) {
        // Unverified accounts get the fake salt too.
        ("POST", "prelogin") => match m.users.get(&email_b).filter(|u| u.verified) {
            Some(u) => (200, json!({"kdf": u.kdf, "salt": u.salt})),
            None => (200, json!({"kdf": {"alg":"argon2id","m":65536,"t":3,"p":1}, "salt": B64.encode([email_b.len() as u8; 16])})),
        },
        ("POST", "register") => {
            if m.users.get(&email_b).is_some_and(|u| u.verified) {
                return (202, json!({"status": "verify"}));
            }
            m.users.insert(
                email_b.clone(),
                User {
                    salt: s(b, "salt"),
                    kdf: b["kdf"].clone(),
                    auth_key: s(b, "auth_key"),
                    wrapped: s(b, "wrapped_vault_key"),
                    recovery_wrapped: s(b, "recovery_wrapped_vault_key"),
                    recovery_auth: s(b, "recovery_auth"),
                    ..Default::default()
                },
            );
            m.code_for(&email_b);
            (202, json!({"status": "verify"}))
        }
        ("POST", "verify") => {
            if !m.users.get(&email_b).is_some_and(|u| !u.verified) || !m.check_code(&email_b, &s(b, "code")) {
                return err(401, "bad_code");
            }
            m.users.get_mut(&email_b).unwrap().verified = true;
            session(m, &email_b, &s(b, "device_name"))
        }
        ("POST", "resend") => {
            if m.users.get(&email_b).is_some_and(|u| !u.verified) {
                m.code_for(&email_b);
            }
            (202, json!({"status": "sent"}))
        }
        ("POST", "login") => {
            // Unknown, wrong key and unverified all look the same.
            match m.users.get(&email_b) {
                Some(u) if u.verified && u.auth_key == s(b, "auth_key") => session(m, &email_b, &s(b, "device_name")),
                _ => err(401, "bad_credentials"),
            }
        }
        ("POST", "logout") => {
            m.tokens.remove(token.unwrap());
            (204, Value::Null)
        }
        ("GET", "vault") => match m.vault(&me.unwrap().1) {
            None => (204, Value::Null),
            Some((v, blob, at)) => (200, json!({"version": v, "blob": blob, "updated_at": at})),
        },
        ("PUT", "vault") => {
            let email = me.unwrap().1;
            if let Some((v, blob)) = m.inject.take() {
                m.users.get_mut(&email).unwrap().vault = Some((v, blob, "injected".into()));
            }
            let current = m.vault(&email).map_or(0, |v| v.0);
            if b["base_version"].as_u64() != Some(current) {
                m.conflicts += 1;
                return match m.vault(&email) {
                    Some((v, blob, at)) => (409, json!({"error": "conflict", "version": v, "blob": blob, "updated_at": at})),
                    None => (409, json!({"error": "conflict", "version": 0, "blob": null, "updated_at": null})),
                };
            }
            m.puts += 1;
            let v = current + 1;
            m.users.get_mut(&email).unwrap().vault = Some((v, s(b, "blob"), format!("t{v}")));
            (200, json!({"version": v}))
        }
        ("GET", "devices") => {
            let (my_id, email) = me.unwrap();
            let list: Vec<Value> = m
                .devices
                .iter()
                .filter(|(_, (e, _))| *e == email)
                .map(|(id, (_, name))| {
                    json!({"id": id, "name": name, "created_at": "2026-10-16T00:00:00Z", "last_seen_at": null, "current": *id == my_id})
                })
                .collect();
            (200, Value::Array(list))
        }
        ("DELETE", p) if p.starts_with("devices/") => {
            let id: u64 = p["devices/".len()..].parse().unwrap_or(0);
            if m.devices.get(&id).map(|d| &d.0) != Some(&me.unwrap().1) {
                return err(404, "not_found");
            }
            m.devices.remove(&id);
            m.tokens.retain(|_, d| *d != id);
            (204, Value::Null)
        }
        ("POST", "password") => {
            let (my_id, email) = me.unwrap();
            let u = m.users.get_mut(&email).unwrap();
            if u.auth_key != s(b, "auth_key") {
                return err(401, "bad_credentials");
            }
            u.salt = s(b, "new_salt");
            u.kdf = b["new_kdf"].clone();
            u.auth_key = s(b, "new_auth_key");
            u.wrapped = s(b, "new_wrapped_vault_key");
            m.sign_out_all(&email, Some(my_id));
            (204, Value::Null)
        }
        ("POST", "recover/start") => match m.users.get(&email_b) {
            Some(u) if u.recovery_auth == s(b, "recovery_auth") => {
                let rt = format!("reset-{}", rand::random::<u64>());
                m.reset_tokens.insert(rt.clone(), email_b.clone());
                (200, json!({"recovery_wrapped_vault_key": u.recovery_wrapped, "reset_token": rt}))
            }
            _ => err(401, "bad_credentials"),
        },
        ("POST", "recover/finish") => {
            let Some(email) = m.reset_tokens.remove(&s(b, "reset_token")) else { return err(401, "bad_token") };
            let u = m.users.get_mut(&email).unwrap();
            u.salt = s(b, "salt");
            u.kdf = b["kdf"].clone();
            u.auth_key = s(b, "auth_key");
            u.wrapped = s(b, "wrapped_vault_key");
            m.sign_out_all(&email, None);
            let (status, mut out) = session(m, &email, &s(b, "device_name"));
            out.as_object_mut().unwrap().remove("wrapped_vault_key");
            (status, out)
        }
        ("POST", "reset/start") => {
            if m.users.get(&email_b).is_some_and(|u| u.verified) {
                m.code_for(&email_b);
            }
            (202, json!({"status": "sent"}))
        }
        ("POST", "reset/finish") => {
            if !m.users.get(&email_b).is_some_and(|u| u.verified) || !m.check_code(&email_b, &s(b, "code")) {
                return err(401, "bad_code");
            }
            let u = m.users.get_mut(&email_b).unwrap();
            u.salt = s(b, "salt");
            u.kdf = b["kdf"].clone();
            u.auth_key = s(b, "auth_key");
            u.wrapped = s(b, "wrapped_vault_key");
            u.recovery_wrapped = s(b, "recovery_wrapped_vault_key");
            u.recovery_auth = s(b, "recovery_auth");
            u.vault = None;
            m.sign_out_all(&email_b, None);
            let token = m.session(&email_b, &s(b, "device_name"));
            (200, json!({"token": token, "vault_version": 0}))
        }
        ("DELETE", "account") => {
            let email = me.unwrap().1;
            if m.users[&email].auth_key != s(b, "auth_key") {
                return err(401, "bad_credentials");
            }
            m.users.remove(&email);
            m.sign_out_all(&email, None);
            (204, Value::Null)
        }
        _ => err(404, "not_found"),
    }
}

async fn handle(state: Arc<Mutex<Mock>>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().trim_start_matches("/api/v1/").to_string();
    let ua = req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    let raw = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    assert!(ua.starts_with("CloudUp/"), "User-Agent: {ua}");
    let (status, out) = {
        let mut m = state.lock().unwrap();
        m.bodies.push(String::from_utf8_lossy(&raw).to_string());
        route(&mut m, &method, &path, token.as_deref(), &body)
    };
    let bytes = if status == 204 { Bytes::new() } else { Bytes::from(out.to_string()) };
    let resp = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(bytes))
        .unwrap();
    Ok(resp)
}

async fn serve(listener: tokio::net::TcpListener, state: Arc<Mutex<Mock>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let st = state.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(st.clone(), req));
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}

// ------------------------------------------------------------------ helpers

fn use_mac(dir: &Path, name: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::env::set_var("CLOUDUP_DATA_DIR", dir);
    std::env::set_var("CLOUDUP_DEVICE_NAME", name);
}

fn add_conn(name: &str, ctype: ConnType, secret: &str) -> String {
    let mut c = Connection::new(ctype);
    c.name = name.into();
    c.endpoint = "https://files.example.com/dav".into();
    c.access_key = "me".into();
    if ctype == ConnType::Dropbox {
        c.fields.insert("client_id".into(), "cid".into());
        c.fields.insert("client_secret".into(), "client-secret-1".into());
    }
    let id = c.id.clone();
    config::store_secret(&id, secret).unwrap();
    config::upsert(c).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    id
}

fn rename(id: &str, name: &str) {
    let mut c = config::load_connections().unwrap().into_iter().find(|c| c.id == id).unwrap();
    c.name = name.into();
    config::upsert(c).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
}

/// What `delete_connection` does, minus Finder.
fn delete(id: &str) {
    config::remove(id).unwrap();
    config::delete_secret(id);
    config::delete_field_secrets(id);
    sync::add_tombstone(id).unwrap();
}

/// Connections as (id, name, updated_at, secret), sorted, for comparing Macs.
fn snapshot() -> Vec<(String, String, String, Option<String>)> {
    let mut v: Vec<_> = config::load_connections()
        .unwrap()
        .into_iter()
        .map(|c| {
            let secret = config::read_secret(&c.id).unwrap();
            (c.id, c.name, c.updated_at, secret)
        })
        .collect();
    v.sort();
    v
}

fn names() -> Vec<String> {
    let mut n: Vec<String> = config::load_connections().unwrap().into_iter().map(|c| c.name).collect();
    n.sort();
    n
}

fn known_hosts() -> String {
    std::fs::read_to_string(config::known_hosts_path()).unwrap_or_default()
}

fn code(mock: &Arc<Mutex<Mock>>, email: &str) -> String {
    mock.lock().unwrap().codes[email].clone()
}

// ------------------------------------------------------------------ the test

#[test]
fn two_macs_register_sync_conflict_and_converge() {
    let root: PathBuf = std::env::temp_dir().join(format!("cloudup-sync-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (mac_a, mac_b) = (root.join("a"), root.join("b"));
    std::env::set_var("CLOUDUP_NO_KEYCHAIN", "1");

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let mock = Arc::new(Mutex::new(Mock::default()));
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    rt.spawn(serve(listener, mock.clone()));
    std::env::set_var("CLOUDUP_SYNC_URL", format!("http://127.0.0.1:{port}/api/v1/"));

    let email = "me@example.com";
    let pw1 = "correct horse battery";

    rt.block_on(async {
        // ---- Mac A: two connections, then create the account.
        use_mac(&mac_a, "Mac A");
        let work = add_conn("Work DAV", ConnType::Webdav, "pw-work");
        let ftp = add_conn("Old FTP", ConnType::Ftp, "pw-ftp");
        let dbx = add_conn("Dropbox", ConnType::Dropbox, "{\"access_token\":\"t\"}");
        std::fs::write(config::known_hosts_path(), "hostA ssh-ed25519 AAAAA\n").unwrap();

        assert!(!sync::status().signed_in);
        assert_eq!(sync::sync_now().await.err().unwrap().code, "not_signed_in");
        assert_eq!(sync::register(email, "short").await.err().unwrap().code, "invalid");

        let recovery = sync::register("  Me@Example.com ", pw1).await.unwrap();
        assert_eq!(recovery.len(), 64);
        assert!(sync::crockford_decode(&recovery).unwrap().len() == 32);
        assert!(!sync::status().signed_in, "nothing is stored before verification");
        assert_eq!(sync::login(email, pw1).await.err().unwrap().code, "bad_credentials", "unverified looks unknown");
        let wrong = if code(&mock, email) == "000000" { "111111" } else { "000000" };
        assert_eq!(sync::verify(email, wrong, pw1).await.err().unwrap().code, "bad_code");
        // An interrupted sign-up (CloudUp quit): resend, then verify with
        // the password alone.
        sync::forget_pending_signup();
        sync::resend(email).await.unwrap();
        let st = sync::verify(email, &code(&mock, email), pw1).await.unwrap();
        assert!(st.signed_in && st.email.as_deref() == Some(email));
        assert!(st.last_sync.is_none());

        let o = sync::sync_now().await.unwrap();
        assert!(!o.changed);
        assert_eq!(mock.lock().unwrap().vault(email).unwrap().0, 1);
        assert!(sync::status().last_sync.is_some());

        // ---- Mac B: one connection of its own, then sign in.
        use_mac(&mac_b, "Mac B");
        let sftp = add_conn("B SFTP", ConnType::Sftp, "pw-sftp");
        std::fs::write(config::known_hosts_path(), "hostB ssh-ed25519 BBBBB\n").unwrap();
        assert!(!sync::status().signed_in);
        assert_eq!(sync::login(email, "wrong password!").await.err().unwrap().code, "bad_credentials");
        sync::login(email, pw1).await.unwrap();
        let o = sync::sync_now().await.unwrap();
        assert!(o.changed);
        assert_eq!(names(), ["B SFTP", "Dropbox", "Old FTP", "Work DAV"]);
        assert_eq!(config::read_secret(&work).unwrap().as_deref(), Some("pw-work"));
        assert_eq!(config::read_field_secret(&dbx, "client_secret").as_deref(), Some("client-secret-1"));
        let kh = known_hosts();
        assert!(kh.contains("hostA") && kh.contains("hostB"));

        // ---- Mac A picks up B's connection.
        use_mac(&mac_a, "Mac A");
        assert!(sync::sync_now().await.unwrap().changed);
        assert_eq!(names(), ["B SFTP", "Dropbox", "Old FTP", "Work DAV"]);
        assert!(known_hosts().contains("hostB"));

        // ---- Edits on B, uploaded; then A edits and deletes without having
        // seen them, and its upload races B's (the mock replays B's upload
        // between A's download and A's upload).
        let before = mock.lock().unwrap().vault(email).unwrap();
        use_mac(&mac_b, "Mac B");
        rename(&work, "Work DAV (edited on B)");
        config::store_secret(&work, "pw-work-2").unwrap();
        rename(&sftp, "B SFTP (edited on B)");
        sync::sync_now().await.unwrap();
        {
            let mut m = mock.lock().unwrap();
            let after = m.vault(email).unwrap();
            assert_eq!(after.0, before.0 + 1);
            m.users.get_mut(email).unwrap().vault = Some(before.clone());
            m.inject = Some((after.0, after.1));
        }

        use_mac(&mac_a, "Mac A");
        rename(&sftp, "B SFTP (edited on A, later)");
        delete(&ftp);
        let o = sync::sync_now().await.unwrap();
        assert!(o.changed, "B's edit of Work DAV arrived");
        assert_eq!(mock.lock().unwrap().conflicts, 1);
        assert_eq!(names(), ["B SFTP (edited on A, later)", "Dropbox", "Work DAV (edited on B)"]);
        assert_eq!(config::read_secret(&work).unwrap().as_deref(), Some("pw-work-2"));
        let a_state = snapshot();

        use_mac(&mac_b, "Mac B");
        let o = sync::sync_now().await.unwrap();
        assert!(o.changed);
        assert_eq!(o.removed, vec![ftp.clone()]);
        assert_eq!(config::read_secret(&ftp).unwrap(), None, "a deleted connection's password goes too");
        assert!(snapshot() == a_state, "both Macs converge");

        // Nothing left to do on either Mac.
        let puts = mock.lock().unwrap().puts;
        assert!(!sync::sync_now().await.unwrap().changed);
        use_mac(&mac_a, "Mac A");
        assert!(!sync::sync_now().await.unwrap().changed);
        assert_eq!(mock.lock().unwrap().puts, puts, "no upload without a change");

        // The server never sees a password, a secret or a connection name.
        {
            let m = mock.lock().unwrap();
            for b in &m.bodies {
                for secret in [pw1, "pw-work", "client-secret-1", "Work DAV", "hostA"] {
                    assert!(!b.contains(secret), "{secret} was sent in the clear");
                }
            }
        }

        // ---- Devices: A signs B out.
        let devs = sync::devices().await.unwrap();
        assert_eq!(devs.len(), 2);
        let me = devs.iter().find(|d| d.current).unwrap();
        assert_eq!(me.name, "Mac A");
        let b_dev = devs.iter().find(|d| !d.current).unwrap();
        assert_eq!(b_dev.name, "Mac B");
        sync::revoke_device(&b_dev.id).await.unwrap();
        use_mac(&mac_b, "Mac B");
        assert_eq!(sync::sync_now().await.err().unwrap().code, "signed_out");
        assert!(!sync::status().signed_in);
        assert_eq!(names().len(), 3, "connections stay after sign-out");

        // ---- Password change on A: B needs the new one; the data stays.
        use_mac(&mac_a, "Mac A");
        let pw2 = "a brand new password";
        assert_eq!(sync::change_password("not my password", pw2).await.err().unwrap().code, "bad_credentials");
        sync::change_password(pw1, pw2).await.unwrap();
        assert!(sync::sync_now().await.is_ok(), "this Mac stays signed in");
        use_mac(&mac_b, "Mac B");
        assert_eq!(sync::login(email, pw1).await.err().unwrap().code, "bad_credentials");
        sync::login(email, pw2).await.unwrap();
        assert!(!sync::sync_now().await.unwrap().changed);

        // ---- Forgot the password: the recovery key keeps the synced data.
        let pw3 = "third time lucky pw";
        assert_eq!(sync::recover(email, "not a key", pw3).await.err().unwrap().code, "invalid");
        let wrong_key = sync::crockford_encode(&[7u8; 32]);
        assert_eq!(sync::recover(email, &wrong_key, pw3).await.err().unwrap().code, "bad_credentials");
        sync::recover(email, &recovery.to_lowercase().replace('-', " "), pw3).await.unwrap();
        assert!(!sync::sync_now().await.unwrap().changed, "same vault, same key");
        use_mac(&mac_a, "Mac A");
        assert_eq!(sync::sync_now().await.err().unwrap().code, "signed_out", "recovery signs other Macs out");

        // ---- Rate limiting and an unreachable server.
        mock.lock().unwrap().rate_limit_next = Some(120);
        let e = sync::login(email, pw3).await.err().unwrap();
        assert_eq!((e.code.as_str(), e.retry_after), ("rate_limited", Some(120)));
        assert_eq!(e.message, "Too many attempts. Try again in 2 minutes.");
        let url = std::env::var("CLOUDUP_SYNC_URL").unwrap();
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        std::env::set_var("CLOUDUP_SYNC_URL", format!("http://127.0.0.1:{dead}/api/v1/"));
        let e = sync::login(email, pw3).await.err().unwrap();
        assert_eq!(e.code, "offline");
        assert_eq!(e.message, "Can't reach demelos.com; your connections are still saved on this Mac.");
        std::env::set_var("CLOUDUP_SYNC_URL", url);
        sync::login(email, pw3).await.unwrap();

        // ---- Forgot both: reset by email code erases the synced vault; this
        // Mac's connections are uploaded again.
        sync::reset_start(email).await.unwrap();
        let pw4 = "fourth and final pw";
        assert_eq!(sync::reset_finish(email, "999999", pw4).await.err().unwrap().code, "bad_code");
        let recovery2 = sync::reset_finish(email, &code(&mock, email), pw4).await.unwrap();
        assert_ne!(recovery2, recovery);
        assert!(mock.lock().unwrap().vault(email).is_none());
        sync::sync_now().await.unwrap();
        assert_eq!(mock.lock().unwrap().vault(email).unwrap().0, 1);
        use_mac(&mac_b, "Mac B");
        assert_eq!(sync::sync_now().await.err().unwrap().code, "signed_out");
        sync::login(email, pw4).await.unwrap();
        assert!(!sync::sync_now().await.unwrap().changed, "B already had the same connections");
        assert!(snapshot() == a_state);

        // ---- Delete the account (App Review 5.1.1(v)).
        assert_eq!(sync::delete_account("wrong password!!").await.err().unwrap().code, "bad_credentials");
        sync::delete_account(pw4).await.unwrap();
        assert!(!sync::status().signed_in);
        assert!(mock.lock().unwrap().users.is_empty());
        assert_eq!(names().len(), 3, "connections stay on the Mac");

        // ---- A sign-up finished in one go uses the keys kept in memory.
        let two = "two@example.com";
        sync::register(two, pw1).await.unwrap();
        sync::verify(two, &code(&mock, two), "the password isn't needed").await.unwrap();
        sync::sync_now().await.unwrap();
        assert_eq!(mock.lock().unwrap().vault(two).unwrap().0, 1);
        sync::logout().await.unwrap();
        assert!(!sync::status().signed_in);
        assert_eq!(sync::sync_now().await.err().unwrap().code, "not_signed_in");
    });

    let _ = std::fs::remove_dir_all(&root);
}
