//! Accounts and sync end to end against the REAL server. Ignored by default;
//! run it by hand:
//!
//! ```sh
//! CLOUDUP_TEST_SECRET="$(ssh -o RemoteCommand=none -o BatchMode=yes demelos \
//!   'sudo -n sed -n s/^TEST_SECRET=//p /home/demelos.com/cloudup-api.env')" \
//!   cargo test --release --test sync_live -- --ignored --nocapture
//! ```
//!
//! `CLOUDUP_LIVE_URL` picks the server (default production). The app never
//! sends the test header: this test runs a small proxy on 127.0.0.1 that the
//! app talks to (`CLOUDUP_SYNC_URL`), which adds `X-CloudUp-Test`, reads the
//! `test_code` the server returns for `cloudup-test+*@demelos.com` addresses,
//! clears rate limits with `test/reset-limits` on a 429, and can replay a
//! stale vault download to force a real 409. The account is deleted at the
//! end, pass or fail.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};

use cloudup_lib::config::{self, ConnType, Connection};
use cloudup_lib::sync;
use futures_util::FutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

const PROD: &str = "https://www.demelos.com/tools/cloudup/api/v1/";

#[derive(Default)]
struct Proxy {
    upstream: String,
    secret: String,
    /// email -> last code from register / resend / reset/start
    codes: HashMap<String, String>,
    /// The last `GET vault` reply, and one to serve instead of the next.
    last_vault: Option<(u16, Bytes)>,
    stale_next: Option<(u16, Bytes)>,
    conflicts: u32,
    rate_limit_resets: u32,
}

async fn forward(
    p: &Arc<Mutex<Proxy>>,
    http: &reqwest::Client,
    method: &reqwest::Method,
    path: &str,
    auth: Option<&str>,
    body: &Bytes,
) -> (u16, Option<String>, Bytes) {
    let (upstream, secret) = {
        let g = p.lock().unwrap();
        (g.upstream.clone(), g.secret.clone())
    };
    let mut req = http
        .request(method.clone(), format!("{upstream}{path}"))
        .header("X-CloudUp-Test", secret)
        .header("User-Agent", concat!("CloudUp/", env!("CARGO_PKG_VERSION"), " (live test)"));
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    if !body.is_empty() {
        req = req.header("Content-Type", "application/json").body(body.clone());
    }
    match req.send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let retry = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_string);
            (status, retry, r.bytes().await.unwrap_or_default())
        }
        Err(_) => (502, None, Bytes::new()),
    }
}

async fn handle(
    p: Arc<Mutex<Proxy>>,
    http: reqwest::Client,
    email: String,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes()).unwrap();
    let path = req.uri().path().trim_start_matches('/').to_string();
    let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();

    let stale = if method == reqwest::Method::GET && path == "vault" { p.lock().unwrap().stale_next.take() } else { None };
    let (status, retry, out) = match stale {
        Some((s, b)) => (s, None, b),
        None => {
            let mut r = forward(&p, &http, &method, &path, auth.as_deref(), &body).await;
            if r.0 == 429 {
                // Clear the test address's and this IP's limits, then retry once.
                let reset = Bytes::from(json!({ "emails": [email] }).to_string());
                let rr = forward(&p, &http, &reqwest::Method::POST, "test/reset-limits", None, &reset).await;
                eprintln!("live test: rate limited on {path}; test/reset-limits answered {}", rr.0);
                p.lock().unwrap().rate_limit_resets += 1;
                r = forward(&p, &http, &method, &path, auth.as_deref(), &body).await;
            }
            r
        }
    };

    {
        let mut g = p.lock().unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap_or(Value::Null);
        if let Some(code) = v.get("test_code").and_then(Value::as_str) {
            let req_email = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|b| b.get("email").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            g.codes.insert(req_email, code.to_string());
        }
        if method == reqwest::Method::GET && path == "vault" {
            g.last_vault = Some((status, out.clone()));
        }
        if status == 409 {
            g.conflicts += 1;
        }
    }
    // The app never sees test_code (it doesn't know about it anyway).
    let mut resp = Response::builder().status(status).header("content-type", "application/json");
    if let Some(r) = retry {
        resp = resp.header("retry-after", r);
    }
    Ok(resp.body(Full::new(out)).unwrap())
}

async fn serve(listener: tokio::net::TcpListener, p: Arc<Mutex<Proxy>>, email: String) {
    let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap();
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let (p, http, email) = (p.clone(), http.clone(), email.clone());
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(p.clone(), http.clone(), email.clone(), req));
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

fn delete(id: &str) {
    config::remove(id).unwrap();
    config::delete_secret(id);
    sync::add_tombstone(id).unwrap();
}

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

// ------------------------------------------------------------------ the test

#[test]
#[ignore = "talks to the real server; needs CLOUDUP_TEST_SECRET"]
fn live_two_macs_against_the_real_server() {
    let secret = std::env::var("CLOUDUP_TEST_SECRET").unwrap_or_default();
    assert!(secret.trim().len() >= 32, "set CLOUDUP_TEST_SECRET (see the top of this file)");
    let mut upstream = std::env::var("CLOUDUP_LIVE_URL").unwrap_or_else(|_| PROD.into());
    if !upstream.ends_with('/') {
        upstream.push('/');
    }
    let email = format!("cloudup-test+{:016x}@demelos.com", rand::random::<u64>());
    eprintln!("live test: {upstream} as {email}");

    let root = std::env::temp_dir().join(format!("cloudup-sync-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (mac_a, mac_b) = (root.join("a"), root.join("b"));
    std::env::set_var("CLOUDUP_NO_KEYCHAIN", "1");

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let proxy = Arc::new(Mutex::new(Proxy { upstream, secret: secret.trim().to_string(), ..Default::default() }));
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    rt.spawn(serve(listener, proxy.clone(), email.clone()));
    std::env::set_var("CLOUDUP_SYNC_URL", format!("http://127.0.0.1:{port}/"));

    // The current password, for the clean-up.
    let password = Arc::new(Mutex::new(String::new()));
    let code = |p: &Arc<Mutex<Proxy>>| p.lock().unwrap().codes.get(&email).cloned().expect("a test_code");

    let result = rt.block_on(
        std::panic::AssertUnwindSafe(async {
            let pw1 = "live test password one";
            *password.lock().unwrap() = pw1.into();

            // ---- Mac A: two connections, create the account, sync.
            use_mac(&mac_a, "Live test Mac A");
            let work = add_conn("Work DAV", ConnType::Webdav, "pw-work");
            let ftp = add_conn("Old FTP", ConnType::Ftp, "pw-ftp");
            std::fs::write(config::known_hosts_path(), "hostA ssh-ed25519 AAAAA\n").unwrap();
            sync::register(&email, pw1).await.expect("register");
            sync::verify(&email, &code(&proxy), pw1).await.expect("verify");
            sync::sync_now().await.expect("first sync on A");

            // ---- Mac B: its own connection, sign in, sync.
            use_mac(&mac_b, "Live test Mac B");
            let sftp = add_conn("B SFTP", ConnType::Sftp, "pw-sftp");
            sync::login(&email, pw1).await.expect("login on B");
            assert!(sync::sync_now().await.expect("sync on B").changed);
            assert_eq!(names(), ["B SFTP", "Old FTP", "Work DAV"]);
            assert_eq!(config::read_secret(&work).unwrap().as_deref(), Some("pw-work"));
            assert!(std::fs::read_to_string(config::known_hosts_path()).unwrap().contains("hostA"));

            use_mac(&mac_a, "Live test Mac A");
            assert!(sync::sync_now().await.expect("sync on A").changed);
            assert_eq!(names(), ["B SFTP", "Old FTP", "Work DAV"]);

            // ---- Edit on B and upload; A edits and deletes, and its download
            // is replayed from before B's upload, so the server answers 409.
            let stale = proxy.lock().unwrap().last_vault.clone().expect("a vault download");
            use_mac(&mac_b, "Live test Mac B");
            rename(&work, "Work DAV (edited on B)");
            config::store_secret(&work, "pw-work-2").unwrap();
            rename(&sftp, "B SFTP (edited on B)");
            sync::sync_now().await.expect("sync B edits");
            proxy.lock().unwrap().stale_next = Some(stale);

            use_mac(&mac_a, "Live test Mac A");
            rename(&sftp, "B SFTP (edited on A, later)");
            delete(&ftp);
            assert!(sync::sync_now().await.expect("sync A through a conflict").changed);
            assert_eq!(proxy.lock().unwrap().conflicts, 1, "the server answered 409 once");
            assert_eq!(names(), ["B SFTP (edited on A, later)", "Work DAV (edited on B)"]);
            assert_eq!(config::read_secret(&work).unwrap().as_deref(), Some("pw-work-2"));
            let a_state = snapshot();

            use_mac(&mac_b, "Live test Mac B");
            let o = sync::sync_now().await.expect("sync B after the conflict");
            assert_eq!(o.removed, vec![ftp.clone()]);
            assert!(snapshot() == a_state, "both Macs converge");
            assert!(!sync::sync_now().await.unwrap().changed);

            let devices = sync::devices().await.expect("devices");
            assert_eq!(devices.len(), 2);

            // ---- Change the password on A; B signs in again with it.
            use_mac(&mac_a, "Live test Mac A");
            let pw2 = "live test password two";
            assert_eq!(sync::change_password("not the password", pw2).await.err().unwrap().code, "bad_credentials");
            sync::change_password(pw1, pw2).await.expect("change password");
            *password.lock().unwrap() = pw2.into();
            use_mac(&mac_b, "Live test Mac B");
            assert_eq!(sync::sync_now().await.err().unwrap().code, "signed_out");
            sync::login(&email, pw2).await.expect("login with the new password");
            assert!(!sync::sync_now().await.unwrap().changed);
            sync::logout().await.unwrap();

            // ---- Delete the account.
            use_mac(&mac_a, "Live test Mac A");
            sync::delete_account(pw2).await.expect("delete account");
            assert!(!sync::status().signed_in);
            assert_eq!(sync::login(&email, pw2).await.err().unwrap().code, "bad_credentials", "the account is gone");
        })
        .catch_unwind(),
    );

    // Clean up, pass or fail: make sure the account is gone.
    rt.block_on(async {
        let pw = password.lock().unwrap().clone();
        for mac in [&mac_a, &mac_b] {
            use_mac(mac, "Live test cleanup");
            if sync::status().signed_in && sync::delete_account(&pw).await.is_ok() {
                eprintln!("live test: account deleted in clean-up");
                return;
            }
        }
        if !pw.is_empty() && sync::login(&email, &pw).await.is_ok() {
            match sync::delete_account(&pw).await {
                Ok(()) => eprintln!("live test: account deleted in clean-up"),
                Err(e) => eprintln!("live test: COULD NOT DELETE {email}: {}", e.message),
            }
        }
    });
    let resets = proxy.lock().unwrap().rate_limit_resets;
    eprintln!("live test: rate-limit resets: {resets}");
    let _ = std::fs::remove_dir_all(&root);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
