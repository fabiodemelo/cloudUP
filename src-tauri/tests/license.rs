//! The free license check end to end, against an in-process mock of the
//! license server and of `license/start` / `license/finish` (never the real
//! servers). Needs a debug build: release builds ignore the test overrides
//! (`CLOUDUP_LICENSE_URL`, `CLOUDUP_LICENSE_PUBKEY`, `CLOUDUP_LICENSE_KEY_ID`).
//!
//!     cargo test --test license
//!
//! Skipped in `cargo test --release`, where the overrides are ignored.
#![cfg(all(feature = "license", not(feature = "mas"), debug_assertions))]

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cloudup_lib::license;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

const KEY: &str = "DM-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23";
const CODE: &str = "123456";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Valid,
    Stale,
    Dead,
    Revoked,
    ActivationLimit,
    BadSignature,
    WrongNonce,
    Down,
}

struct Mock {
    mode: Mode,
    validations: usize,
    codes_sent: Vec<String>,
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn validate(m: &mut Mock, body: &Value) -> (u16, Value) {
    m.validations += 1;
    let s = |k: &str| body[k].as_str().unwrap_or("").to_string();
    let t = now();
    let (status, recheck, grace) = match m.mode {
        Mode::Down => return (500, json!({"error": "boom"})),
        Mode::Revoked => ("revoked", t + 86400, 0),
        Mode::ActivationLimit => ("activation_limit", t + 86400, 0),
        Mode::Stale => ("valid", t - 10, 5 * 86400),
        Mode::Dead => ("valid", t - 10, 0),
        _ => ("valid", t + 15 * 86400, 5 * 86400),
    };
    let nonce = if m.mode == Mode::WrongNonce { "ffffffffffffffffffffffffffffffff".to_string() } else { s("nonce") };
    let mut p = json!({"v": 1, "status": status, "license_key": s("license_key"), "product": s("product"),
        "fingerprint": s("fingerprint").to_lowercase(), "nonce": nonce, "issued_at": t});
    if status == "valid" {
        p["expires_at"] = Value::Null;
        p["next_check_before"] = json!(recheck);
        p["grace_seconds"] = json!(grace);
    }
    if status == "activation_limit" {
        p["max_activations"] = json!(5);
    }
    let payload = p.to_string();
    let mut sig = signer().sign(payload.as_bytes()).to_bytes();
    if m.mode == Mode::BadSignature {
        sig[0] ^= 1;
    }
    (200, json!({"data": {"payload": payload, "signature": B64.encode(sig), "key_id": "test-key"}}))
}

fn route(m: &mut Mock, path: &str, body: &Value) -> (u16, Value) {
    match path {
        "/validate" => validate(m, body),
        "/api/v1/license/start" => {
            m.codes_sent.push(body["email"].as_str().unwrap_or("").to_string());
            (202, json!({"status": "sent"}))
        }
        "/api/v1/license/finish" if body["code"] == CODE => {
            (200, json!({"license_key": KEY, "email": body["email"], "max_activations": 5}))
        }
        "/api/v1/license/finish" => (401, json!({"error": "bad_code", "message": "The code is wrong or has expired. Ask for a new one."})),
        _ => (404, json!({"error": "not_found"})),
    }
}

async fn handle(state: Arc<Mutex<Mock>>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let raw = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let (status, out) = route(&mut state.lock().unwrap(), &path, &body);
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(out.to_string())))
        .unwrap())
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

#[test]
fn free_license_activation_checks_and_revocation() {
    let dir = std::env::temp_dir().join(format!("cloudup-license-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("CLOUDUP_DATA_DIR", &dir);
    std::env::set_var("CLOUDUP_NO_KEYCHAIN", "1");

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let mock = Arc::new(Mutex::new(Mock { mode: Mode::Valid, validations: 0, codes_sent: vec![] }));
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    rt.spawn(serve(listener, mock.clone()));
    std::env::set_var("CLOUDUP_SYNC_URL", format!("http://127.0.0.1:{port}/api/v1/"));
    std::env::set_var("CLOUDUP_LICENSE_URL", format!("http://127.0.0.1:{port}/validate"));
    std::env::set_var("CLOUDUP_LICENSE_PUBKEY", B64.encode(signer().verifying_key().to_bytes()));
    std::env::set_var("CLOUDUP_LICENSE_KEY_ID", "test-key");
    let set = |mode| mock.lock().unwrap().mode = mode;
    let calls = || mock.lock().unwrap().validations;
    let file = dir.join("license.json");

    rt.block_on(async {
        // No license yet: nothing may mount.
        assert_eq!(license::status().await.state, "unlicensed");
        assert!(license::require().is_err());
        assert!(!license::allowed().await);

        // Email, code, key.
        license::license_request_code(" Me@Example.com ".into()).await.unwrap();
        assert_eq!(mock.lock().unwrap().codes_sent, vec!["me@example.com"]);
        let e = license::verify_code("me@example.com".into(), "000000".into()).await.unwrap_err();
        assert!(e.contains("wrong"), "{e}");
        assert!(license::verify_code("me@example.com".into(), "12345".into()).await.is_err(), "short code");
        let st = license::verify_code("me@example.com".into(), CODE.into()).await.unwrap();
        assert!(st.is_licensed());
        assert_eq!(st.email.as_deref(), Some("me@example.com"));
        assert_eq!(st.license_key.as_deref(), Some("DM-ABCD-••••-••••-••••-••••-YZ23"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(license::require().is_ok());

        // A fresh answer needs no network.
        let before = calls();
        set(Mode::Down);
        assert!(license::status().await.is_licensed());
        assert_eq!(calls(), before, "fresh answer: no request");

        // Stale but within grace: asks, and stays licensed while offline.
        set(Mode::Stale);
        assert!(license::activate(KEY.into(), None).await.unwrap().is_licensed());
        set(Mode::Down);
        assert!(license::status().await.is_licensed());
        assert_eq!(calls(), before + 2, "stale answer: re-checked");

        // Past grace and offline: blocked until it can check.
        set(Mode::Dead);
        assert!(license::activate(KEY.into(), None).await.unwrap().is_licensed());
        set(Mode::Down);
        let st = license::status().await;
        assert_eq!(st.state, "offline");
        assert!(license::require().is_err());
        set(Mode::Valid);
        assert!(license::status().await.is_licensed(), "back online");

        // Revoked: forgotten, with a reason.
        set(Mode::Stale);
        license::activate(KEY.into(), None).await.unwrap();
        set(Mode::Revoked);
        let st = license::status().await;
        assert_eq!(st.state, "invalid");
        assert!(st.message.unwrap().contains("turned off"));
        assert!(!file.exists());
        assert!(license::require().is_err());

        // Refusals and forged or replayed answers never activate.
        set(Mode::ActivationLimit);
        assert!(license::activate(KEY.into(), None).await.unwrap_err().contains("5 Macs"));
        set(Mode::BadSignature);
        assert!(license::activate(KEY.into(), None).await.unwrap_err().contains("couldn't reach"));
        set(Mode::WrongNonce);
        assert!(license::activate(KEY.into(), None).await.is_err());
        assert!(!file.exists());

        // The code is used up but the key doesn't activate: the key stays here.
        set(Mode::Down);
        let e = license::verify_code("me@example.com".into(), CODE.into()).await.unwrap_err();
        assert!(e.contains("saved on this Mac"), "{e}");
        assert_eq!(license::license_saved_key().as_deref(), Some(KEY));
        assert!(license::require().is_err(), "a saved key alone doesn't license");
        set(Mode::Valid);
        assert!(license::status().await.is_licensed(), "next start activates the saved key");
        std::fs::remove_file(&file).unwrap();

        // A key typed in directly works too.
        set(Mode::Valid);
        assert!(license::activate(KEY.into(), None).await.unwrap().is_licensed());
        assert!(license::licensed_offline());
    });
    let _ = std::fs::remove_dir_all(&dir);
}
