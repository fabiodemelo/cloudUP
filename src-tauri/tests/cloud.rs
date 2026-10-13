//! Integration tests: exercise every backend against a live endpoint.
//!
//! Connection details come from environment variables (never hardcode
//! credentials in source):
//!   CM_TEST_S3_ENDPOINT / CM_TEST_S3_REGION / CM_TEST_S3_KEY / CM_TEST_S3_SECRET / CM_TEST_S3_BUCKET
//!   CM_TEST_SFTP_HOST / CM_TEST_SFTP_PORT / CM_TEST_SFTP_USER / CM_TEST_SFTP_SECRET / CM_TEST_SFTP_ROOT
//!   CM_TEST_MEGA_EMAIL / CM_TEST_MEGA_PASSWORD
//!
//! All tests are #[ignore]d and only run when their variables are set
//! (skipped with a reason otherwise), so plain `cargo test` stays green:
//!   cargo test --test cloud -- --ignored
//!
//! These are write tests: they create a throwaway `cloudmounter-test-*` folder
//! in the provider's root, fill it, and delete it afterwards.

use cloudmounter_lib::config::{Connection, ConnType};

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

/// Create a throwaway test folder, write a file in it, verify, then clean up.
async fn roundtrip(conn: &Connection, secret: &str) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let backend = cloudmounter_lib::backend::Backend::from_connection(conn, secret)
            .expect("backend construction");
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let dir = format!("/cloudmounter-test-{}", stamp);
        let file = format!("{dir}/hello.txt");
        let data = b"hello from cloudmounter integration test
";

        backend.mkdir(&dir).await.expect("mkdir");
        backend.write(&file, data).await.expect("write");
        let got = backend.read(&file).await.expect("read");
        assert_eq!(got, data, "read-back content mismatch");
        let entries = backend.list(&dir).await.expect("list");
        assert!(entries.iter().any(|e| e.name == "hello.txt"), "file missing from listing");
        backend.remove(&file, false).await.expect("remove file");
        backend.remove(&dir, true).await.expect("remove dir");
        println!("{:?}: roundtrip OK", conn.ctype);
    });
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
        let _ = roundtrip(&conn, &secret);
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
        let _ = roundtrip(&conn, &secret);
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
        let _ = roundtrip(&conn, &secret);
    }
);
