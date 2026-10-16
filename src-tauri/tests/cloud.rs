//! Integration tests: exercise every backend against a live endpoint.
//!
//! Connection details come from environment variables (never hardcode
//! credentials in source):
//!   CM_TEST_S3_ENDPOINT / CM_TEST_S3_REGION / CM_TEST_S3_KEY / CM_TEST_S3_SECRET / CM_TEST_S3_BUCKET
//!   CM_TEST_SFTP_HOST / CM_TEST_SFTP_PORT / CM_TEST_SFTP_USER / CM_TEST_SFTP_SECRET / CM_TEST_SFTP_ROOT
//!   CM_TEST_MEGA_EMAIL / CM_TEST_MEGA_PASSWORD
//!   CM_TEST_WEBDAV_URL / CM_TEST_WEBDAV_USER / CM_TEST_WEBDAV_PASSWORD
//!   CM_TEST_FTP_HOST / CM_TEST_FTP_PORT / CM_TEST_FTP_USER / CM_TEST_FTP_PASSWORD / CM_TEST_FTP_ROOT
//!   CM_TEST_SWIFT_AUTH_URL / CM_TEST_SWIFT_USER / CM_TEST_SWIFT_PASSWORD / CM_TEST_SWIFT_PROJECT /
//!     CM_TEST_SWIFT_CONTAINER / CM_TEST_SWIFT_USER_DOMAIN / CM_TEST_SWIFT_PROJECT_DOMAIN / CM_TEST_SWIFT_REGION
//!   CM_TEST_PCLOUD_EMAIL / CM_TEST_PCLOUD_PASSWORD / CM_TEST_PCLOUD_ENDPOINT
//!   OAuth providers (P = DROPBOX, GDRIVE, ONEDRIVE, BOX):
//!     CM_TEST_<P>_TOKEN (an access token), plus optionally CM_TEST_<P>_REFRESH_TOKEN,
//!     CM_TEST_<P>_CLIENT_ID and CM_TEST_<P>_CLIENT_SECRET so an expired token can be
//!     refreshed. (A refreshed token is saved to the keychain under a throwaway
//!     connection id, as the app would.)
//!   CM_TEST_LARGE=1 adds a 64 MiB upload/download to every round trip (Box takes at
//!     most 50 MB per upload without its chunked API, so expect it to fail there).
//!
//! Variables shown after a slash in a group are optional where the test
//! gives them a default; each test only runs when its required variables are
//! set (it skips with a reason otherwise), so plain `cargo test` stays green:
//!   cargo test --test cloud -- --nocapture
//!
//! These are write tests: they create a throwaway `cloudup-test-*` folder
//! in the provider's root, fill it, and delete it afterwards.

use cloudup_lib::backend::Backend;
use cloudup_lib::config::{Connection, ConnType};
use std::io::{Read, Write};
use std::path::Path;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|s| !s.trim().is_empty())
}

fn need(vars: &[&str]) -> Option<Vec<String>> {
    if vars.iter().any(|v| env(v).is_none()) {
        return None;
    }
    Some(vars.iter().map(|v| env(v).unwrap()).collect())
}

/// Run a backend test, skipping (pass) when its env vars are missing.
macro_rules! maybe {
    ($test:ident, $vars:expr, $body:expr) => {
        #[test]
        fn $test() {
            if need($vars).is_none() {
                eprintln!("{}: skipped (set {})", stringify!($test), $vars.join(", "));
                return;
            }
            $body
        }
    };
}

/// Deterministic test data of `len` bytes, written to `path` in pieces.
fn make_file(path: &Path, len: usize, seed: u8) {
    let mut f = std::fs::File::create(path).unwrap();
    let block: Vec<u8> = (0..1 << 20).map(|i: usize| (i % 251) as u8 ^ seed).collect();
    let mut left = len;
    let mut n = 0usize;
    while left > 0 {
        let take = left.min(block.len());
        // Vary each block so a misplaced chunk is caught.
        let mut b = block[..take].to_vec();
        b[0] = n as u8;
        f.write_all(&b).unwrap();
        left -= take;
        n += 1;
    }
}

/// Compare two files without loading them whole.
fn same_file(a: &Path, b: &Path) -> bool {
    let (mut fa, mut fb) = (std::fs::File::open(a).unwrap(), std::fs::File::open(b).unwrap());
    if fa.metadata().unwrap().len() != fb.metadata().unwrap().len() {
        return false;
    }
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = fa.read(&mut ba).unwrap();
        if n == 0 {
            return true;
        }
        fb.read_exact(&mut bb[..n]).unwrap();
        if ba[..n] != bb[..n] {
            return false;
        }
    }
}

/// Upload `len` bytes from a local file to `remote`, download them into
/// another file and compare (the streaming paths used for drag and drop and
/// the Finder drive).
async fn file_roundtrip(backend: &Backend, remote: &str, len: usize, local: &Path) {
    let up = local.join(format!("up-{len}"));
    let down = local.join(format!("down-{len}"));
    make_file(&up, len, 0x5a);
    backend.write_from_file(remote, &up).await.expect("write_from_file");
    let n = backend.read_to_file(remote, &down).await.expect("read_to_file");
    assert_eq!(n, len as u64, "downloaded size");
    assert!(same_file(&up, &down), "downloaded content differs ({len} bytes)");
    // Overwrite with a different size: the old content must not linger.
    make_file(&up, len / 2 + 1, 0xa5);
    backend.write_from_file(remote, &up).await.expect("overwrite");
    backend.read_to_file(remote, &down).await.expect("read back overwrite");
    assert!(same_file(&up, &down), "overwritten content differs");
    backend.remove(remote, false).await.expect("remove streamed file");
}

/// Create a throwaway test folder, write a file in it, verify, then clean up.
fn roundtrip(conn: &Connection, secret: &str) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let backend = Backend::from_connection(conn, secret).expect("backend construction");
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let dir = format!("/cloudup-test-{}", stamp);
        let file = format!("{dir}/hello.txt");
        let data = b"hello from cloudup integration test\n";
        let local = std::env::temp_dir().join(format!("cloudup-it-{stamp}-{}", std::process::id()));
        std::fs::create_dir_all(&local).unwrap();

        backend.mkdir(&dir).await.expect("mkdir");
        backend.write(&file, data).await.expect("write");
        let got = backend.read(&file).await.expect("read");
        assert_eq!(got, data, "read-back content mismatch");
        let entries = backend.list(&dir).await.expect("list");
        assert!(entries.iter().any(|e| e.name == "hello.txt"), "file missing from listing");

        file_roundtrip(&backend, &format!("{dir}/stream.bin"), 300_000, &local).await;
        if env("CM_TEST_LARGE").as_deref() == Some("1") {
            file_roundtrip(&backend, &format!("{dir}/large.bin"), 64 << 20, &local).await;
            println!("{:?}: 64 MiB roundtrip OK", conn.ctype);
        }

        backend.remove(&file, false).await.expect("remove file");
        backend.remove(&dir, true).await.expect("remove dir");
        std::fs::remove_dir_all(&local).ok();
        println!("{:?}: roundtrip OK", conn.ctype);
    });
}

/// A stored OAuth secret built from `CM_TEST_<P>_*`, and the connection with
/// its client id/secret.
fn oauth_conn(ctype: ConnType, prefix: &str) -> (Connection, String) {
    let mut conn = Connection::new(ctype);
    conn.name = format!("test-{}", prefix.to_lowercase());
    conn.bucket = "/".into();
    if let Some(id) = env(&format!("CM_TEST_{prefix}_CLIENT_ID")) {
        conn.fields.insert("client_id".into(), id);
    }
    if let Some(s) = env(&format!("CM_TEST_{prefix}_CLIENT_SECRET")) {
        conn.fields.insert("client_secret".into(), s);
    }
    let mut token = serde_json::json!({ "access_token": env(&format!("CM_TEST_{prefix}_TOKEN")).unwrap() });
    if let Some(r) = env(&format!("CM_TEST_{prefix}_REFRESH_TOKEN")) {
        token["refresh_token"] = serde_json::json!(r);
    }
    (conn, token.to_string())
}

maybe!(sftp_roundtrip,
    &["CM_TEST_SFTP_HOST", "CM_TEST_SFTP_USER", "CM_TEST_SFTP_SECRET"],
    {
        let port = env("CM_TEST_SFTP_PORT").unwrap_or_else(|| "22".into());
        let root = env("CM_TEST_SFTP_ROOT").unwrap_or_else(|| "/".into());
        let mut conn = Connection::new(ConnType::Sftp);
        conn.name = "test-sftp".into();
        conn.endpoint = env("CM_TEST_SFTP_HOST").unwrap();
        conn.access_key = env("CM_TEST_SFTP_USER").unwrap();
        conn.bucket = root;
        conn.fields.insert("port".into(), port);
        let secret = env("CM_TEST_SFTP_SECRET").unwrap();
        roundtrip(&conn, &secret);
    }
);

maybe!(mega_roundtrip,
    &["CM_TEST_MEGA_EMAIL", "CM_TEST_MEGA_PASSWORD"],
    {
        let mut conn = Connection::new(ConnType::MEGA);
        conn.name = "test-mega".into();
        conn.endpoint = "https://mega.nz".into();
        conn.access_key = env("CM_TEST_MEGA_EMAIL").unwrap();
        conn.bucket = "/".into();
        let secret = env("CM_TEST_MEGA_PASSWORD").unwrap();
        roundtrip(&conn, &secret);
    }
);

maybe!(s3_roundtrip,
    &["CM_TEST_S3_ENDPOINT", "CM_TEST_S3_KEY", "CM_TEST_S3_SECRET", "CM_TEST_S3_BUCKET"],
    {
        let mut conn = Connection::new(ConnType::S3);
        conn.name = "test-s3".into();
        conn.endpoint = env("CM_TEST_S3_ENDPOINT").unwrap();
        conn.region = env("CM_TEST_S3_REGION").unwrap_or_else(|| "us-east-1".into());
        conn.access_key = env("CM_TEST_S3_KEY").unwrap();
        conn.bucket = env("CM_TEST_S3_BUCKET").unwrap();
        let secret = env("CM_TEST_S3_SECRET").unwrap();
        roundtrip(&conn, &secret);
    }
);

maybe!(webdav_roundtrip,
    &["CM_TEST_WEBDAV_URL"],
    {
        let mut conn = Connection::new(ConnType::Webdav);
        conn.name = "test-webdav".into();
        conn.endpoint = env("CM_TEST_WEBDAV_URL").unwrap();
        conn.access_key = env("CM_TEST_WEBDAV_USER").unwrap_or_default();
        let secret = env("CM_TEST_WEBDAV_PASSWORD").unwrap_or_default();
        roundtrip(&conn, &secret);
    }
);

maybe!(ftp_roundtrip,
    &["CM_TEST_FTP_HOST", "CM_TEST_FTP_USER", "CM_TEST_FTP_PASSWORD"],
    {
        let mut conn = Connection::new(ConnType::Ftp);
        conn.name = "test-ftp".into();
        conn.endpoint = env("CM_TEST_FTP_HOST").unwrap();
        conn.access_key = env("CM_TEST_FTP_USER").unwrap();
        conn.bucket = env("CM_TEST_FTP_ROOT").unwrap_or_else(|| "/".into());
        conn.fields.insert("port".into(), env("CM_TEST_FTP_PORT").unwrap_or_else(|| "21".into()));
        let secret = env("CM_TEST_FTP_PASSWORD").unwrap();
        roundtrip(&conn, &secret);
    }
);

maybe!(swift_roundtrip,
    &["CM_TEST_SWIFT_AUTH_URL", "CM_TEST_SWIFT_USER", "CM_TEST_SWIFT_PASSWORD", "CM_TEST_SWIFT_PROJECT", "CM_TEST_SWIFT_CONTAINER"],
    {
        let mut conn = Connection::new(ConnType::OpenStack);
        conn.name = "test-swift".into();
        conn.endpoint = env("CM_TEST_SWIFT_AUTH_URL").unwrap();
        conn.access_key = env("CM_TEST_SWIFT_USER").unwrap();
        conn.bucket = env("CM_TEST_SWIFT_CONTAINER").unwrap();
        conn.region = env("CM_TEST_SWIFT_REGION").unwrap_or_default();
        conn.fields.insert("project".into(), env("CM_TEST_SWIFT_PROJECT").unwrap());
        conn.fields.insert("user_domain".into(), env("CM_TEST_SWIFT_USER_DOMAIN").unwrap_or_else(|| "Default".into()));
        conn.fields.insert("project_domain".into(), env("CM_TEST_SWIFT_PROJECT_DOMAIN").unwrap_or_else(|| "Default".into()));
        let secret = env("CM_TEST_SWIFT_PASSWORD").unwrap();
        roundtrip(&conn, &secret);
    }
);

maybe!(pcloud_roundtrip,
    &["CM_TEST_PCLOUD_EMAIL", "CM_TEST_PCLOUD_PASSWORD"],
    {
        let mut conn = Connection::new(ConnType::Pcloud);
        conn.name = "test-pcloud".into();
        if let Some(e) = env("CM_TEST_PCLOUD_ENDPOINT") {
            conn.endpoint = e;
        }
        conn.access_key = env("CM_TEST_PCLOUD_EMAIL").unwrap();
        conn.bucket = "/".into();
        let secret = env("CM_TEST_PCLOUD_PASSWORD").unwrap();
        roundtrip(&conn, &secret);
    }
);

maybe!(dropbox_roundtrip, &["CM_TEST_DROPBOX_TOKEN"], {
    let (conn, secret) = oauth_conn(ConnType::Dropbox, "DROPBOX");
    roundtrip(&conn, &secret);
});

maybe!(gdrive_roundtrip, &["CM_TEST_GDRIVE_TOKEN"], {
    let (conn, secret) = oauth_conn(ConnType::GoogleDrive, "GDRIVE");
    roundtrip(&conn, &secret);
});

maybe!(onedrive_roundtrip, &["CM_TEST_ONEDRIVE_TOKEN"], {
    let (conn, secret) = oauth_conn(ConnType::Onedrive, "ONEDRIVE");
    roundtrip(&conn, &secret);
});

maybe!(box_roundtrip, &["CM_TEST_BOX_TOKEN"], {
    let (conn, secret) = oauth_conn(ConnType::Box, "BOX");
    roundtrip(&conn, &secret);
});
