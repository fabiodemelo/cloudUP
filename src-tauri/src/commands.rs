//! Tauri IPC commands exposed to the frontend.

use crate::backend::{Backend, Entry};
use crate::config::{self, Connection, ConnType};
use crate::mount;

/// Build a backend for a saved connection (reads its secret from the keychain).
fn backend_for(id: &str) -> Result<(Connection, Backend), String> {
    let conns = config::load_connections()?;
    let conn = conns.into_iter().find(|c| c.id == id).ok_or_else(|| "connection not found".to_string())?;
    let secret = config::read_secret(&conn.id)?.unwrap_or_default();
    let backend = Backend::from_connection(&conn, &secret)?;
    Ok((conn, backend))
}

// ------------------------------------------------------------------ connections

#[tauri::command]
pub fn list_connections() -> Result<Vec<Connection>, String> {
    config::load_connections()
}

#[tauri::command]
pub fn save_connection(conn: Connection, secret: String) -> Result<(), String> {
    config::store_secret(&conn.id, &secret)?;
    config::upsert(conn)
}

#[tauri::command]
pub fn delete_connection(id: String) -> Result<(), String> {
    // Unmount first if it's mounted.
    let _ = mount::unmount(&id);
    config::delete_secret(&id);
    config::remove(&id)
}

#[tauri::command]
pub fn get_secret(id: String) -> Option<String> {
    config::read_secret(&id).ok().flatten()
}

/// Validate credentials by listing the root. Returns number of top-level entries.
#[tauri::command]
pub async fn test_connection(conn: Connection, secret: String) -> Result<u32, String> {
    let backend = Backend::from_connection(&conn, &secret).map_err(|e| e.to_string())?;
    backend.test().await.map_err(|e| e.to_string())
}

/// List buckets (S3) for the "choose bucket" helper.
#[tauri::command]
pub async fn list_buckets(conn: Connection, secret: String) -> Result<Vec<String>, String> {
    let backend = Backend::from_connection(&conn, &secret).map_err(|e| e.to_string())?;
    backend.list_buckets().await.map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ file browser

/// List the children of `path` within a saved connection (in-app browser).
#[tauri::command]
pub async fn browse(id: String, path: String) -> Result<Vec<Entry>, String> {
    let (_, backend) = backend_for(&id)?;
    backend.list(&path).await.map_err(|e| e.to_string())
}

/// Read a file's contents, returned as base64.
#[tauri::command]
pub async fn read_file(id: String, path: String) -> Result<String, String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = backend.read(&path).await.map_err(|e| e.to_string())?;
    Ok(encode_base64(&bytes))
}

/// Read a file as text (for the editor). Returns UTF-8 (lossy) content.
#[tauri::command]
pub async fn read_text(id: String, path: String) -> Result<String, String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = backend.read(&path).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Write text content to a file.
#[tauri::command]
pub async fn write_text(id: String, path: String, content: String) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    backend.write(&path, content.as_bytes()).await.map_err(|e| e.to_string())
}

/// Create a folder.
#[tauri::command]
pub async fn mkdir_entry(id: String, path: String) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    backend.mkdir(&path).await.map_err(|e| e.to_string())
}

/// Delete a file or folder.
#[tauri::command]
pub async fn remove_entry(id: String, path: String, is_dir: bool) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    backend.remove(&path, is_dir).await.map_err(|e| e.to_string())
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
    let dir = dirs::download_dir().ok_or_else(|| "no downloads folder".to_string())?;
    let path = dir.join(name);
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

/// Upload a local file to a cloud path.
#[tauri::command]
pub async fn upload(id: String, cloud_path: String, local_path: String) -> Result<(), String> {
    let (_, backend) = backend_for(&id)?;
    let bytes = std::fs::read(&local_path).map_err(|e| e.to_string())?;
    backend.write(&cloud_path, &bytes).await.map_err(|e| e.to_string())
}

/// Open a local path with the default application.
#[tauri::command]
pub fn open_path(path: String) -> Result<(), String> {
    open::that(&path).map_err(|e| e.to_string())
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
pub fn mount_connection(id: String) -> Result<mount::MountInfo, String> {
    let conns = config::load_connections()?;
    let conn = conns.into_iter().find(|c| c.id == id).ok_or_else(|| "connection not found".to_string())?;
    let secret = config::read_secret(&conn.id)?.unwrap_or_default();
    mount::mount(&conn, &secret).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn unmount_connection(id: String) -> Result<(), String> {
    mount::unmount(&id).map_err(|e| e.to_string())
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
    // TODO(step 6): derive from ConnType::functional() once all backends land.
    [ConnType::S3, ConnType::Webdav, ConnType::OpenStack, ConnType::Ftp, ConnType::Pcloud]
        .iter()
        .map(|t| format!("{:?}", t).to_lowercase())
        .collect()
}
