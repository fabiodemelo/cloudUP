//! Upload/download of whole trees (used by drag and drop), against a live
//! WebDAV server. Skips unless CM_TEST_WEBDAV_URL is set, e.g. a local
//! Apache with mod_dav:  CM_TEST_WEBDAV_URL=http://127.0.0.1:18080/ cargo test --test transfer

use cloudup_lib::backend::Backend;
use cloudup_lib::config::{ConnType, Connection};

#[test]
fn upload_then_download_tree() {
    let Ok(url) = std::env::var("CM_TEST_WEBDAV_URL") else {
        eprintln!("upload_then_download_tree: skipped (set CM_TEST_WEBDAV_URL)");
        return;
    };
    let mut conn = Connection::new(ConnType::Webdav);
    conn.endpoint = url;
    conn.bucket = "/".into();
    let backend = Backend::from_connection(&conn, "").expect("backend");

    let tmp = std::env::temp_dir().join(format!("cloudup-transfer-{}", std::process::id()));
    let src = tmp.join("src");
    std::fs::create_dir_all(src.join("folder/sub")).unwrap();
    std::fs::write(src.join("top.txt"), b"top").unwrap();
    std::fs::write(src.join("folder/a.txt"), b"a").unwrap();
    std::fs::write(src.join("folder/sub/b.txt"), b"b").unwrap();
    std::fs::write(src.join("folder/.DS_Store"), b"junk").unwrap();

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        backend.mkdir("/dnd-test").await.ok();
        let paths = vec![src.join("top.txt").display().to_string(), src.join("folder").display().to_string()];
        let n = backend.upload_tree("/dnd-test", &paths).await.expect("upload");
        assert_eq!(n, 3, "three files, .DS_Store skipped");

        let out = tmp.join("out");
        backend.download_tree("/dnd-test/folder", true, &out).await.expect("download folder");
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(out.join("sub/b.txt")).unwrap(), b"b");
        assert!(!out.join(".DS_Store").exists());
        backend.download_tree("/dnd-test/top.txt", false, &tmp.join("top-copy.txt")).await.expect("download file");
        assert_eq!(std::fs::read(tmp.join("top-copy.txt")).unwrap(), b"top");

        for f in ["/dnd-test/folder/sub/b.txt", "/dnd-test/folder/a.txt", "/dnd-test/top.txt"] {
            backend.remove(f, false).await.unwrap();
        }
        for d in ["/dnd-test/folder/sub", "/dnd-test/folder", "/dnd-test"] {
            backend.remove(d, true).await.unwrap();
        }
    });
    std::fs::remove_dir_all(&tmp).ok();
}
