//! Tauri IPC commands exposed to the frontend.

use crate::backend::{Backend, Entry};
use crate::config::{self, Connection, ConnType};
use crate::mount;
use crate::oauth;
#[cfg(all(feature = "updater", not(feature = "mas")))]
use tauri_plugin_updater::UpdaterExt;

/// Build a backend for a saved connection (reads its secrets from the keychain).
fn backend_for(id: &str) -> Result<(Connection, Backend), String> {
    let conn = saved_connection(id)?;
    let secret = config::read_secret(&conn.id)?.unwrap_or_default();
    let backend = build_backend(&conn, &secret)?;
    Ok((conn, backend))
}

/// A saved connection, with its field secrets (OAuth client secret) filled in.
fn saved_connection(id: &str) -> Result<Connection, String> {
    let conns = config::load_connections()?;
    let conn = conns.into_iter().find(|c| c.id == id).ok_or_else(|| "connection not found".to_string())?;
    Ok(config::with_field_secrets(conn))
}

/// `Backend::from_connection`, refusing the types this build leaves out (the
/// Mac App Store build can't run Mega's external command-line client).
fn build_backend(conn: &Connection, secret: &str) -> Result<Backend, String> {
    check_allowed(conn)?;
    Backend::from_connection(conn, secret).map_err(|e| e.to_string())
}

fn check_allowed(conn: &Connection) -> Result<(), String> {
    if cfg!(feature = "mas") && conn.ctype == ConnType::MEGA {
        return Err(format!("{} connections aren't available in this version of CloudUp", conn.ctype.label()));
    }
    Ok(())
}

// ------------------------------------------------------------------ connections

#[tauri::command]
pub fn list_connections() -> Result<Vec<Connection>, String> {
    config::load_connections()
}

/// Save a connection. Field secrets in `conn.fields` (the OAuth client
/// secret) go to the keychain; an empty one keeps the stored value.
#[tauri::command]
pub fn save_connection(conn: Connection, secret: Option<String>) -> Result<(), String> {
    // `secret: None` means "leave the stored credential untouched" — used by
    // OAuth connections, whose token lives in the keychain and is set by
    // `connect_oauth`, not re-typed in the form.
    if let Some(s) = secret {
        config::store_secret(&conn.id, &s)?;
    }
    config::upsert(conn)
}

/// Delete a connection, its Finder Location and its keychain items. If the
/// Location can't be removed, the connection is kept and the error returned:
/// deleting anyway would throw away its settings and credentials while Finder
/// may still show the Location, and trying again costs the user nothing.
#[tauri::command]
pub async fn delete_connection(id: String) -> Result<(), String> {
    let unmount_id = id.clone();
    tokio::task::spawn_blocking(move || mount::unmount(&unmount_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("could not remove the connection from Finder, so it was kept: {e}"))?;
    config::remove(&id)?;
    config::delete_secret(&id);
    config::delete_field_secrets(&id);
    Ok(())
}

#[tauri::command]
pub fn get_secret(id: String) -> Option<String> {
    config::read_secret(&id).ok().flatten()
}

/// A connection field kept in the keychain instead of config.json (`key` is
/// "client_secret"), to fill the edit form.
#[tauri::command]
pub fn get_field_secret(id: String, key: String) -> Option<String> {
    config::read_field_secret(&id, &key)
}

/// Validate credentials by listing the root. Returns number of top-level entries.
#[tauri::command]
pub async fn test_connection(conn: Connection, secret: String) -> Result<u32, String> {
    let backend = build_backend(&config::with_field_secrets(conn), &secret)?;
    backend.test().await.map_err(|e| e.to_string())
}

/// Run the OAuth2 PKCE browser flow for an OAuth provider connection, store the
/// resulting token, then verify with a test listing. Returns a human message.
#[tauri::command]
pub async fn connect_oauth(conn: Connection) -> Result<String, String> {
    // An empty Client Secret box means "use the saved one".
    let conn = config::with_field_secrets(conn);
    let client_id = conn.field("client_id");
    if client_id.trim().is_empty() {
        return Err("a Client ID is required before authorizing".into());
    }
    let meta = oauth::ProviderMeta::for_ctype(conn.ctype)
        .ok_or_else(|| "that provider does not use OAuth".to_string())?;
    let token = oauth::run_flow(meta, &client_id, &conn.field("client_secret"))
        .await
        .map_err(|e| e.to_string())?;
    oauth::persist_token(&conn.id, &token).map_err(|e| e.to_string())?;
    // Persist the connection so its (now populated) fields are saved.
    config::upsert(conn.clone()).map_err(|e| e.to_string())?;

    let secret = config::read_secret(&conn.id)?.unwrap_or_default();
    let backend = build_backend(&conn, &secret)?;
    match backend.test().await {
        Ok(n) => Ok(format!("{} is connected ({n} top-level items)", meta.name)),
        Err(e) => Ok(format!("{} token saved, but the first listing failed: {e}", meta.name)),
    }
}

/// List buckets (S3) for the "choose bucket" helper.
#[tauri::command]
pub async fn list_buckets(conn: Connection, secret: String) -> Result<Vec<String>, String> {
    let backend = build_backend(&conn, &secret)?;
    backend.list_buckets().await.map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ file browser

/// List the children of `path` within a saved connection (in-app browser).
#[tauri::command]
pub async fn browse(id: String, path: String) -> Result<Vec<Entry>, String> {
    let (_, backend) = backend_for(&id)?;
    backend.list(&path).await.map_err(|e| e.to_string())
}

/// Enforce a byte cap after a read. The frontend uses the listing's reported
/// size as the primary guard; this is a backstop against a file that has since
/// grown (or whose size was unknown). Returns `None` if within the cap.
fn over_cap(bytes: &[u8], max_bytes: Option<u64>) -> Option<String> {
    match max_bytes {
        Some(limit) if bytes.len() as u64 > limit => Some(format!(
            "file is {} bytes, above the {} byte cap — open the full file another way",
            bytes.len(),
            limit
        )),
        _ => None,
    }
}

/// Read a file's contents, returned as base64. `max_bytes` is an optional cap.
#[tauri::command]
pub async fn read_file(id: String, path: String, max_bytes: Option<u64>) -> Result<String, String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = backend.read(&path).await.map_err(|e| e.to_string())?;
    if let Some(err) = over_cap(&bytes, max_bytes) {
        return Err(err);
    }
    Ok(encode_base64(&bytes))
}

/// Read a file as text (for the editor). Returns UTF-8 (lossy) content.
#[tauri::command]
pub async fn read_text(id: String, path: String, max_bytes: Option<u64>) -> Result<String, String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = backend.read(&path).await.map_err(|e| e.to_string())?;
    if let Some(err) = over_cap(&bytes, max_bytes) {
        return Err(err);
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Write text content to a file.
#[tauri::command]
pub async fn write_text(id: String, path: String, content: String) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    backend.write(&path, content.as_bytes()).await.map_err(|e| e.to_string())?;
    mount::changed(&id);
    Ok(())
}

/// Create a folder.
#[tauri::command]
pub async fn mkdir_entry(id: String, path: String) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    backend.mkdir(&path).await.map_err(|e| e.to_string())?;
    mount::changed(&id);
    Ok(())
}

/// Delete a file or folder.
#[tauri::command]
pub async fn remove_entry(id: String, path: String, is_dir: bool) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    backend.remove(&path, is_dir).await.map_err(|e| e.to_string())?;
    mount::changed(&id);
    Ok(())
}

/// Download a cloud file into the user's Downloads folder. Returns the saved path.
#[tauri::command]
pub async fn download(id: String, cloud_path: String) -> Result<String, String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = backend.read(&cloud_path).await.map_err(|e| e.to_string())?;
    let name = cloud_path
        .trim_start_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download");
    let name = if crate::backend::is_plain_name(name) { name } else { "download" };
    let dir = dirs::download_dir().ok_or_else(|| "no downloads folder".to_string())?;
    let path = unique_path(&dir, name);
    crate::backend::write_downloaded(&path, &bytes)?;
    Ok(path.to_string_lossy().to_string())
}

/// `dir/name`, or `dir/name 2.ext`, `dir/name 3.ext`... if it already exists
/// (Finder's naming), so a download never overwrites an existing file.
fn unique_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (2..)
        .map(|n| dir.join(format!("{stem} {n}{ext}")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// Upload a local file to a cloud path.
#[tauri::command]
pub async fn upload(id: String, cloud_path: String, local_path: String) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = std::fs::read(&local_path).map_err(|e| e.to_string())?;
    backend.write(&cloud_path, &bytes).await.map_err(|e| e.to_string())?;
    mount::changed(&id);
    Ok(())
}

/// Upload local files and folders (dropped from Finder) into `dest_dir`.
/// Folders are uploaded recursively. Returns the number of files uploaded.
#[tauri::command]
pub async fn upload_paths(id: String, dest_dir: String, paths: Vec<String>) -> Result<u32, String> {
    let (_, backend) = backend_for(&id)?;
    let n = backend.upload_tree(&dest_dir, &paths).await?;
    mount::changed(&id);
    Ok(n)
}

/// Start dragging cloud files/folders out of the window (into Finder).
#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn drag_out(window: tauri::WebviewWindow, id: String, items: Vec<crate::dragout::DragItem>) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    let ns_window = window.ns_window().map_err(|e| e.to_string())? as usize;
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .run_on_main_thread(move || {
            let _ = tx.send(crate::dragout::start(ns_window as *mut std::ffi::c_void, backend, items));
        })
        .map_err(|e| e.to_string())?;
    rx.await.map_err(|e| e.to_string())?
}

/// Open a web page (http/https) in the browser, a mounted drive's Finder
/// Location in Finder, or a file in the Downloads folder (where `download`
/// saves) with its default app. Anything else is refused: the window has no
/// reason to open other paths, so a compromised page can't use this to run
/// arbitrary files.
#[cfg(target_os = "macos")]
#[tauri::command]
pub fn open_path(path: String) -> Result<(), String> {
    use std::path::Path;
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return crate::macos::open_url(&path);
    }
    let real = Path::new(&path).canonicalize().map_err(|e| format!("{path}: {e}"))?;
    let canon = |p: &Path| p.canonicalize().ok();
    let in_location = mount::list_mounted()
        .iter()
        .filter_map(|m| canon(Path::new(&m.mount_point)))
        .any(|loc| real.starts_with(&loc));
    if in_location {
        return crate::macos::open_file(&real);
    }
    let in_downloads = dirs::download_dir()
        .and_then(|d| canon(&d))
        .is_some_and(|d| real != d && real.starts_with(&d));
    if in_downloads {
        // No app for this kind of file: show it in Finder instead.
        if crate::macos::open_file(&real).is_err() {
            crate::macos::reveal(&real);
        }
        return Ok(());
    }
    Err(format!("CloudUp only opens web links, its Finder locations and downloaded files, not {path}"))
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub fn open_path(path: String) -> Result<(), String> {
    Err(format!("opening {path} is only supported on macOS"))
}

// ------------------------------------------------------------------ mounting

#[tauri::command]
pub fn mount_available() -> bool {
    mount::is_available()
}

#[tauri::command]
pub fn mount_availability_note() -> String {
    mount::availability_note()
}

#[tauri::command]
pub fn list_mounted() -> Vec<mount::MountInfo> {
    mount::list_mounted()
}

#[tauri::command]
pub async fn mount_connection(id: String) -> Result<mount::MountInfo, String> {
    let conn = saved_connection(&id)?;
    check_allowed(&conn)?;
    let secret = config::read_secret(&conn.id)?.unwrap_or_default();
    mount::mount(&conn, &secret).await.map_err(|e| e.to_string())
}

/// Errors from the start-up auto-mount, waiting for the window to show them.
static MOUNT_ERRORS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Hand the pending auto-mount errors to the UI (once).
#[tauri::command]
pub fn take_mount_errors() -> Vec<String> {
    std::mem::take(&mut *MOUNT_ERRORS.lock().unwrap())
}

/// Mount every connection marked "mount automatically"; called once at app
/// start. Failures (by connection name) are queued for `take_mount_errors`.
pub async fn mount_auto() {
    let Ok(conns) = config::load_connections() else { return };
    // Finder Locations persist across restarts: serve those again, plus the
    // connections marked "mount automatically".
    let registered = tokio::task::spawn_blocking(mount::registered_locations).await.unwrap_or_default();
    // A Location whose connection is gone (deleted while CloudUp was closed):
    // remove it from Finder.
    for id in registered.iter().filter(|id| !conns.iter().any(|c| &c.id == *id)) {
        let id = id.clone();
        let _ = tokio::task::spawn_blocking(move || mount::unmount(&id)).await;
    }
    let mut errors = vec![];
    for conn in conns.into_iter().filter(|c| c.field("auto_mount") == "1" || registered.contains(&c.id)) {
        if let Err(e) = check_allowed(&conn) {
            errors.push(format!("{}: {e}", conn.name));
            continue;
        }
        let conn = config::with_field_secrets(conn);
        let secret = config::read_secret(&conn.id).ok().flatten().unwrap_or_default();
        if let Err(e) = mount::mount(&conn, &secret).await {
            errors.push(format!("{}: {e}", conn.name));
        }
    }
    MOUNT_ERRORS.lock().unwrap().extend(errors);
}

/// Whether CloudUp opens automatically when the user logs in (an
/// SMAppService login item, listed in System Settings → Login Items).
#[cfg(target_os = "macos")]
#[tauri::command]
pub fn get_launch_at_login() -> bool {
    crate::macos::login_item_enabled()
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub fn set_launch_at_login(enabled: bool) -> Result<(), String> {
    crate::macos::set_login_item(enabled)
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub fn get_launch_at_login() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub fn set_launch_at_login(_enabled: bool) -> Result<(), String> {
    Err("opening at login is only supported on macOS".into())
}

#[tauri::command]
pub async fn unmount_connection(id: String) -> Result<(), String> {
    // `umount` can take a moment; keep it off the UI thread.
    tokio::task::spawn_blocking(move || mount::unmount(&id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ helpers

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Names of the connection types that are fully functional in this build.
#[tauri::command]
pub fn functional_types() -> Vec<String> {
    ConnType::ALL
        .iter()
        .filter(|t| t.functional())
        .map(|t| format!("{:?}", t).to_lowercase())
        .collect()
}


/// Check for a new CloudUp version. Returns the new version string, or None if up to date.
/// Not in the Mac App Store build: there the command is missing, the call
/// fails and the frontend shows no update banner.
#[cfg(all(feature = "updater", not(feature = "mas")))]
#[tauri::command]
pub async fn check_for_updates(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let checker = app.updater().map_err(|e| e.to_string())?;
    match checker.check().await {
        Ok(Some(update)) => Ok(Some(update.version.clone())),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Download the latest version and install it (replaces the app and relaunches).
#[cfg(all(feature = "updater", not(feature = "mas")))]
#[tauri::command]
pub async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    let checker = app.updater().map_err(|e| e.to_string())?;
    let update = checker
        .check()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no update available".to_string())?;
    let size = update
        .download(|_len, _total| {}, || ())
        .await
        .map_err(|e| e.to_string())?;
    update.install(size).map_err(|e| e.to_string())?;
    // Reopen the freshly installed version.
    app.restart();
}
