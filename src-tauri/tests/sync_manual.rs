//! Sign-up with a REAL mailbox against the real server, the way a user does
//! it: the verification code arrives by email. Ignored by default; run it by
//! hand while someone reads the inbox:
//!
//! ```sh
//! CLOUDUP_MANUAL_EMAIL=you@example.com CLOUDUP_MANUAL_PASSWORD=... \
//! CLOUDUP_MANUAL_DIR=/some/private/dir \
//!   cargo test --release --test sync_manual -- --ignored --nocapture
//! ```
//!
//! The test registers the account, writes the recovery key to
//! `$CLOUDUP_MANUAL_DIR/recovery_key` (0600) and then waits up to 30 minutes
//! for the emailed code in `$CLOUDUP_MANUAL_DIR/code`. It needs one process
//! from register to verify, because the new account's vault key lives only in
//! memory until the code is confirmed.
//!
//! After verifying it syncs a throwaway connection from "Mac A", signs in on
//! "Mac B" and checks the connection and its password arrived, then deletes
//! that connection everywhere and signs Mac B out. The account stays, so the
//! owner can sign in to it from the app. It never touches the real keychain
//! or the app's own settings (`CLOUDUP_NO_KEYCHAIN`, `CLOUDUP_DATA_DIR`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cloudup_lib::config::{self, ConnType, Connection};
use cloudup_lib::sync;

const CODE_WAIT: Duration = Duration::from_secs(30 * 60);
const TEST_SECRET: &str = "manual-sync-test-secret";

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

fn use_mac(dir: &Path, name: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::env::set_var("CLOUDUP_DATA_DIR", dir);
    std::env::set_var("CLOUDUP_DEVICE_NAME", name);
}

fn write_private(path: &Path, text: &str) {
    config::write_private(path, text.as_bytes()).unwrap();
}

/// Wait for the code file the person reading the inbox fills in.
fn wait_for_code(path: &Path) -> String {
    let start = Instant::now();
    while start.elapsed() < CODE_WAIT {
        if let Ok(code) = std::fs::read_to_string(path) {
            let code = code.trim().to_string();
            if code.len() >= 6 {
                return code;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!("no code in {} after 30 minutes", path.display());
}

fn test_connection() -> String {
    let mut c = Connection::new(ConnType::Webdav);
    c.name = "CloudUp sync test".into();
    c.endpoint = "https://files.example.com/dav".into();
    c.access_key = "sync-test".into();
    let id = c.id.clone();
    config::store_secret(&id, TEST_SECRET).unwrap();
    config::upsert(c).unwrap();
    id
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real mailbox and server; run by hand"]
async fn manual_signup_and_two_mac_sync() {
    std::env::set_var("CLOUDUP_NO_KEYCHAIN", "1");
    let email = env("CLOUDUP_MANUAL_EMAIL");
    let password = env("CLOUDUP_MANUAL_PASSWORD");
    let dir = PathBuf::from(env("CLOUDUP_MANUAL_DIR"));
    let (mac_a, mac_b) = (dir.join("mac-a"), dir.join("mac-b"));

    use_mac(&mac_a, "Test Mac A");
    let recovery = sync::register(&email, &password).await.expect("register");
    write_private(&dir.join("recovery_key"), &recovery);
    println!("registered; waiting for the code in {}", dir.join("code").display());

    let code = wait_for_code(&dir.join("code"));
    sync::verify(&email, &code, &password).await.expect("verify");
    println!("verified and signed in on Mac A");

    let id = test_connection();
    sync::sync_now().await.expect("sync on Mac A");

    use_mac(&mac_b, "Test Mac B");
    sync::login(&email, &password).await.expect("login on Mac B");
    sync::sync_now().await.expect("sync on Mac B");
    let on_b = config::load_connections().unwrap();
    assert!(on_b.iter().any(|c| c.id == id && c.name == "CloudUp sync test"), "connection reached Mac B");
    assert_eq!(config::read_secret(&id).unwrap().as_deref(), Some(TEST_SECRET), "password reached Mac B");
    assert_eq!(sync::devices().await.expect("devices").len(), 2, "both Macs listed");
    println!("Mac B received the connection and its password");

    // Remove the throwaway connection everywhere, then sign Mac B out.
    config::remove(&id).unwrap();
    config::delete_secret(&id);
    sync::add_tombstone(&id).unwrap();
    sync::sync_now().await.expect("sync the delete from Mac B");
    use_mac(&mac_a, "Test Mac A");
    sync::sync_now().await.expect("sync the delete to Mac A");
    assert!(!config::load_connections().unwrap().iter().any(|c| c.id == id), "delete reached Mac A");
    use_mac(&mac_b, "Test Mac B");
    sync::logout().await.expect("sign Mac B out");
    use_mac(&mac_a, "Test Mac A");
    sync::logout().await.expect("sign Mac A out");
    println!("done: account kept, test connection deleted, both test Macs signed out");
}
