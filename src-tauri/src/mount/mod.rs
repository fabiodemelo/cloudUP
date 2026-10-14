//! Mount management: show a connection in Finder.
//!
//! Each mounted connection gets a small WebDAV server bound to 127.0.0.1 on a
//! random port, under an unguessable path, serving that connection's files
//! (see `davfs`). It is registered as a File Provider domain (see `finder`),
//! so Finder's sidebar lists it under Locations as "CloudUp - <name>"; the
//! bundled Finder extension reads and writes files through that server.
//! Locations persist across restarts; when one is opened while CloudUp isn't
//! running, the extension starts CloudUp in the background.

mod davfs;
mod finder;

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
    refresh: tokio::task::JoinHandle<()>,
}

static MOUNTS: LazyLock<Mutex<HashMap<String, Active>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether mounting as a drive is possible on this system.
pub fn is_available() -> bool {
    cfg!(target_os = "macos")
}

/// Human-readable note about mounting on this system.
pub fn availability_note() -> String {
    if is_available() {
        "Mounted connections appear in Finder's sidebar under Locations.".into()
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

    // Show it in Finder: publish the server for the extension, then add the
    // connection as a Location ("CloudUp - <name>").
    let url = format!("http://127.0.0.1:{port}{prefix}/");
    let name = conn.name.trim().to_string();
    let (id, n) = (conn.id.clone(), name.clone());
    let added = tokio::task::spawn_blocking(move || {
        finder::publish(&id, &n, &url)?;
        finder::add(&id, &n)
    })
    .await
    .map_err(|e| Error::Other(e.to_string()))?;
    if let Err(e) = added {
        server.abort();
        finder::unpublish(&conn.id);
        return Err(Error::Other(format!("macOS could not add the Finder location: {e}")));
    }

    // Finder only re-lists folders when told to; nudge it regularly so
    // changes made elsewhere (web console, other machines) show up.
    let id = conn.id.clone();
    let refresh = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(45)).await;
            let id = id.clone();
            let _ = tokio::task::spawn_blocking(move || finder::signal(&id)).await;
        }
    });

    let info = MountInfo { id: conn.id.clone(), name: name.clone(), mount_point: finder::location_path(&name) };
    MOUNTS.lock().unwrap().insert(conn.id.clone(), Active { info: info.clone(), server, refresh });
    Ok(info)
}

/// Something changed through CloudUp itself: refresh the Finder Location now.
pub fn changed(id: &str) {
    if MOUNTS.lock().unwrap().contains_key(id) {
        let id = id.to_string();
        std::thread::spawn(move || finder::signal(&id));
    }
}

/// Connections that have a Finder Location registered (they persist across
/// app restarts; their servers need starting again).
pub fn registered_locations() -> Vec<String> {
    finder::registered()
}

/// Unmount: remove the Finder Location and stop serving it.
pub fn unmount(id: &str) -> Result<()> {
    let active = MOUNTS.lock().unwrap().remove(id);
    let _ = finder::remove(id);
    finder::unpublish(id);
    match active {
        Some(a) => {
            a.server.abort();
            a.refresh.abort();
            Ok(())
        }
        None => Ok(()), // a Location left from an earlier run: removing it is enough
    }
}

/// App is quitting: stop the servers. Finder Locations stay (macOS keeps
/// them); opening one starts CloudUp again in the background.
pub fn unmount_all() {
    let all: Vec<(String, Active)> = MOUNTS.lock().unwrap().drain().collect();
    for (id, a) in all {
        finder::unpublish(&id);
        a.server.abort();
        a.refresh.abort();
    }
}

/// All active mounts (with the Location's folder, once macOS has made it).
pub fn list_mounted() -> Vec<MountInfo> {
    MOUNTS
        .lock()
        .unwrap()
        .values()
        .map(|a| MountInfo { mount_point: finder::location_path(&a.info.name), ..a.info.clone() })
        .collect()
}
