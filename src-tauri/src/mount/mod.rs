//! Mount management: expose a connection as a drive in Finder.
//!
//! Each mounted connection gets a small WebDAV server bound to 127.0.0.1 on a
//! random port, under an unguessable path, serving that connection's files
//! (see `davfs`). macOS's built-in WebDAV client (`mount_webdav`) then mounts
//! it at `~/CloudUp/<name>`, so it appears in Finder like any network drive —
//! no macFUSE or other driver to install. The server lives inside the app, so
//! drives stay mounted while CloudUp runs (closing the window keeps it running)
//! and are unmounted when it quits.

mod davfs;

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use dav_server::{fakels::FakeLs, DavHandler};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::backend::Backend;
use crate::config::Connection;
use crate::error::{Error, Result};

/// Describes an active mount.
#[derive(Clone, serde::Serialize)]
pub struct MountInfo {
    pub id: String,   // connection id
    pub name: String, // display name
    pub mount_point: String,
}

struct Active {
    info: MountInfo,
    server: tokio::task::JoinHandle<()>,
}

static MOUNTS: LazyLock<Mutex<HashMap<String, Active>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether mounting as a drive is possible on this system.
pub fn is_available() -> bool {
    cfg!(target_os = "macos") && std::path::Path::new("/sbin/mount_webdav").exists()
}

/// Human-readable note about mounting on this system.
pub fn availability_note() -> String {
    if is_available() {
        "Drives are mounted with macOS's built-in WebDAV support; no extra software is needed.".into()
    } else {
        "Mounting as a drive is only supported on macOS in this version.".into()
    }
}

/// Request log for diagnosing Finder behaviour; only when CLOUDUP_DAV_LOG is
/// set to a file path.
fn dav_log(line: &str) {
    static PATH: LazyLock<Option<String>> = LazyLock::new(|| std::env::var("CLOUDUP_DAV_LOG").ok());
    if let Some(p) = PATH.as_ref() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{} {line}", chrono::Local::now().format("%H:%M:%S%.3f"));
        }
    }
}

/// Folder that holds the mount points (`~/CloudUp`).
fn mounts_root() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp")).join("CloudUp")
}

/// Make a connection name safe as a folder / volume name.
fn safe_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c == '/' || c == ':' || c.is_control() { '-' } else { c })
        .collect();
    let s = s.trim().trim_start_matches('.').to_string();
    if s.is_empty() { "Cloud Drive".into() } else { s }
}

/// A DNS label made from a connection name ("DM bucket" -> "DM-bucket").
fn host_label(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out: String = out.trim_matches('-').chars().take(60).collect();
    if out.is_empty() { "cloudup".into() } else { out }
}

/// Mount points currently in the system mount table under `dir`.
fn mounts_under(dir: &std::path::Path) -> Vec<String> {
    let Ok(out) = std::process::Command::new("/sbin/mount").output() else { return vec![] };
    let prefix = format!(" on {}/", dir.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let i = l.find(&prefix)?;
            let rest = &l[i + 4..];
            Some(rest[..rest.rfind(" (")?].to_string())
        })
        .collect()
}

/// Force-unmount every mount stacked on `path` (left by a crashed or
/// force-quit run: their server is gone, and Finder would hang on them).
fn clear_stale(path: &std::path::Path) {
    let p = path.display().to_string();
    for _ in 0..10 {
        if !mounts_under(path.parent().unwrap_or(path)).contains(&p) {
            break;
        }
        let _ = std::process::Command::new("/sbin/umount").arg("-f").arg(path).status();
    }
}

/// At start-up nothing is mounted by this process yet, so anything under
/// `~/CloudUp` is left over from a previous run.
pub fn cleanup_stale() {
    let root = mounts_root();
    let mut seen = std::collections::HashSet::new();
    for p in mounts_under(&root) {
        if seen.insert(p.clone()) {
            clear_stale(std::path::Path::new(&p));
            let _ = std::fs::remove_dir(&p);
        }
    }
}

/// Mount a connection as a drive. Returns the mount info on success.
pub async fn mount(conn: &Connection, secret: &str) -> Result<MountInfo> {
    if !is_available() {
        return Err(Error::Other(availability_note()));
    }
    if let Some(a) = MOUNTS.lock().unwrap().get(&conn.id) {
        return Ok(a.info.clone());
    }
    let backend = Backend::from_connection(conn, secret)?;
    // Fail fast with the real error (bad password etc.) instead of a mount
    // that Finder can't open.
    backend.test().await?;

    let token = uuid::Uuid::new_v4().simple().to_string();
    let prefix = format!("/{token}");
    let handler = DavHandler::builder()
        .filesystem(Box::new(davfs::CloudFs::new(backend)))
        .locksystem(FakeLs::new())
        .strip_prefix(prefix.clone())
        .build_handler();

    // Loopback only. `<name>.localhost` resolves to ::1 first, then 127.0.0.1,
    // so listen on both (same port).
    let v4 = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| Error::Other(e.to_string()))?;
    let port = v4.local_addr().map_err(|e| Error::Other(e.to_string()))?.port();
    let v6 = TcpListener::bind(("::1", port)).await.ok();
    let server = tokio::spawn(async move {
        let serve = |listener: TcpListener, handler: DavHandler| async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { continue };
                dav_log(&format!("accept {peer}"));
                let handler = handler.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let handler = handler.clone();
                        async move {
                            let (m, u, t) = (req.method().clone(), req.uri().path().to_string(), std::time::Instant::now());
                            let resp = handler.handle(req).await;
                            dav_log(&format!("{m} {u} -> {} in {:?}", resp.status(), t.elapsed()));
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let r = http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
                    dav_log(&format!("close {peer} {r:?}"));
                });
            }
        };
        match v6 {
            Some(v6) => {
                tokio::join!(serve(v4, handler.clone()), serve(v6, handler));
            }
            None => serve(v4, handler).await,
        }
    });

    let name = safe_name(&conn.name);
    let mount_point = mounts_root().join(&name);
    clear_stale(&mount_point);
    std::fs::create_dir_all(&mount_point).map_err(|e| Error::Other(format!("cannot create {}: {e}", mount_point.display())))?;

    // Finder's sidebar lists network drives by host name, so give each drive
    // its own: "DM bucket" -> http://DM-bucket.localhost:<port>/...
    let url = format!("http://{}.localhost:{port}{prefix}/", host_label(&conn.name));
    let mp = mount_point.clone();
    let vol = name.clone();
    // mount_webdav leaves a helper (webdavfs_agent) running for the life of
    // the mount. Give it no pipes to inherit: errors go to a temp file.
    let err_path = std::env::temp_dir().join(format!("cloudup-mount-{token}.err"));
    let err_file = std::fs::File::create(&err_path).map_err(|e| Error::Other(e.to_string()))?;
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/sbin/mount_webdav")
            .args(["-v", &vol, &url])
            .arg(&mp)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(err_file)
            .status()
    })
    .await
    .map_err(|e| Error::Other(e.to_string()))?
    .map_err(|e| Error::Other(format!("mount_webdav: {e}")))?;
    let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
    let _ = std::fs::remove_file(&err_path);
    if !status.success() {
        server.abort();
        let _ = std::fs::remove_dir(&mount_point);
        let msg = stderr.trim().to_string();
        return Err(Error::Other(format!(
            "macOS could not mount the drive{}",
            if msg.is_empty() { String::new() } else { format!(": {msg}") }
        )));
    }

    let info = MountInfo { id: conn.id.clone(), name, mount_point: mount_point.display().to_string() };
    MOUNTS.lock().unwrap().insert(conn.id.clone(), Active { info: info.clone(), server });
    Ok(info)
}

fn unmount_path(path: &str) {
    let ok = std::process::Command::new("/sbin/umount").arg(path).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        let _ = std::process::Command::new("/usr/sbin/diskutil").args(["unmount", "force", path]).status();
    }
    let _ = std::fs::remove_dir(path); // only removes it if empty (i.e. unmounted)
}

/// Unmount a previously mounted connection by id.
pub fn unmount(id: &str) -> Result<()> {
    let active = MOUNTS.lock().unwrap().remove(id);
    match active {
        Some(a) => {
            unmount_path(&a.info.mount_point);
            a.server.abort();
            Ok(())
        }
        None => Err(Error::Other("not mounted".into())),
    }
}

/// Unmount every active mount. Called on app exit.
pub fn unmount_all() {
    let all: Vec<Active> = MOUNTS.lock().unwrap().drain().map(|(_, a)| a).collect();
    for a in all {
        unmount_path(&a.info.mount_point);
        a.server.abort();
    }
}

/// All active mounts.
pub fn list_mounted() -> Vec<MountInfo> {
    MOUNTS.lock().unwrap().values().map(|a| a.info.clone()).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn safe_names() {
        assert_eq!(super::safe_name("DM bucket"), "DM bucket");
        assert_eq!(super::safe_name("a/b:c"), "a-b-c");
        assert_eq!(super::safe_name(" .hidden "), "hidden");
        assert_eq!(super::safe_name(""), "Cloud Drive");
        assert_eq!(super::host_label("DM bucket"), "DM-bucket");
        assert_eq!(super::host_label("  Alta FTP (prod) "), "Alta-FTP-prod");
        assert_eq!(super::host_label("☁️"), "cloudup");
    }
}
