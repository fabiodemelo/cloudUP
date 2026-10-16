//! Unified cloud backend.
//!
//! Both the in-app file browser (IPC commands) and the FUSE/WinFsp mount speak
//! this single interface. Paths are always relative to the connection's mount
//! root (the S3 bucket, or the WebDAV base URL) and use a leading "/".

use crate::boxprovider::BoxProvider;
use crate::config::{Connection, ConnType};
use crate::dropbox::Dropbox;
use crate::error::{Error, Result};
use crate::ftp::Ftp;
use crate::gdrive::GDrive;
use crate::onedrive::Onedrive;
use crate::mega::Mega;
use crate::pcloud::Pcloud;
use crate::s3::S3;
use crate::sftp::Sftp;
use crate::swift::Swift;
use crate::webdav::Webdav;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use bytes::Bytes;

/// A single directory entry (file or folder) as seen by the UI / filesystem.
#[derive(Clone, serde::Serialize)]
pub struct Entry {
    pub name: String,
    /// Full path relative to the mount root, e.g. "/folder/file.txt".
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// Unix permissions, e.g. "drwxr-xr-x" (SFTP/FTP only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perms: Option<String>,
}

#[derive(Clone)]
pub enum Backend {
    S3 { client: S3, bucket: String },
    Webdav(Webdav),
    Swift(Swift),
    Ftp(Ftp),
    Sftp(Sftp),
    Mega(Mega),
    Pcloud(Pcloud),
    Dropbox(Dropbox),
    GDrive(GDrive),
    Onedrive(Onedrive),
    Box(BoxProvider),
}

impl Backend {
    /// Build a backend from a saved connection + its secret.
    pub fn from_connection(conn: &Connection, secret: &str) -> Result<Self> {
        match conn.ctype {
            ConnType::S3 => Ok(Backend::S3 {
                client: S3::new(&conn.endpoint, &conn.region, &conn.access_key, secret),
                bucket: conn.bucket.trim_matches('/').to_string(),
            }),
            // Backblaze B2 speaks the S3 API; reuse the S3 client with B2
            // defaults (endpoint/region) when the user leaves them blank.
            ConnType::Backblaze => {
                let endpoint = if conn.endpoint.trim().is_empty() {
                    conn.ctype.default_endpoint() // https://s3.us-west-0.backblazeb2.com
                } else {
                    conn.endpoint.as_str()
                };
                let region = if conn.region.trim().is_empty() { "us-west-0" } else { conn.region.as_str() };
                Ok(Backend::S3 {
                    client: S3::new(endpoint, region, &conn.access_key, secret),
                    bucket: conn.bucket.trim_matches('/').to_string(),
                })
            }
            ConnType::Webdav => Ok(Backend::Webdav(Webdav::new(&conn.endpoint, &conn.access_key, secret))),
            ConnType::OpenStack => Ok(Backend::Swift(Swift::new(
                &conn.endpoint, // Keystone auth URL
                &conn.access_key, // username
                secret, // password
                &conn.field("project"),
                &conn.field("user_domain"),
                &conn.field("project_domain"),
                &conn.region,
                &conn.bucket,
            ))),
            ConnType::Ftp => {
                let (host, port) = ftp_endpoint(&conn.endpoint, &conn.field("port"));
                Ok(Backend::Ftp(Ftp::new(
                    &host,
                    port,
                    &conn.access_key,
                    secret,
                    &conn.bucket,
                )))
            }
            ConnType::Sftp => {
                let (host, port) = ftp_endpoint(&conn.endpoint, &conn.field("port"));
                let port = if port == 21 { 22 } else { port };
                Ok(Backend::Sftp(Sftp::new(
                    &host,
                    port,
                    &conn.access_key,
                    secret,
                    &conn.field("key"),
                    &conn.bucket,
                )))
            }
            ConnType::MEGA => Ok(Backend::Mega(Mega::new(
                &conn.endpoint,
                &conn.access_key,
                secret,
                &conn.bucket,
            ))),
            ConnType::Pcloud => Ok(Backend::Pcloud(Pcloud::new(
                &conn.endpoint, // default https://api.pcloud.com
                &conn.access_key, // account email
                secret, // account password
                &conn.bucket, // folder to mount
            ))),
            ConnType::Dropbox => Ok(Backend::Dropbox(Dropbox::new(
                &conn.id,
                &conn.field("client_id"),
                &conn.field("client_secret"),
                secret,
                &conn.bucket,
            ))),
            ConnType::GoogleDrive => Ok(Backend::GDrive(GDrive::new(
                &conn.id,
                &conn.field("client_id"),
                &conn.field("client_secret"),
                secret,
                &conn.bucket,
            ))),
            ConnType::Onedrive => Ok(Backend::Onedrive(Onedrive::new(
                &conn.id,
                &conn.field("client_id"),
                &conn.field("client_secret"),
                secret,
                &conn.bucket,
            ))),
            ConnType::Box => Ok(Backend::Box(BoxProvider::new(
                &conn.id,
                &conn.field("client_id"),
                &conn.field("client_secret"),
                secret,
                &conn.bucket,
            ))),
        }
    }

    /// Lightweight credential check: list the root. Returns an error message on failure.
    pub async fn test(&self) -> Result<u32> {
        let entries = self.list("/").await?;
        Ok(entries.len() as u32)
    }

    /// Convert a directory path to an S3 prefix. "/" -> "", "/a/b" -> "a/b/".
    fn s3_prefix(dir: &str) -> String {
        let p = dir.trim_start_matches('/');
        if p.is_empty() {
            String::new()
        } else {
            format!("{}/", p.trim_end_matches('/'))
        }
    }

    /// List the immediate children of `dir`.
    pub async fn list(&self, dir: &str) -> Result<Vec<Entry>> {
        match self {
            Backend::S3 { client, bucket } => {
                let prefix = Self::s3_prefix(dir);
                let (objects, prefixes) = client.list_objects(bucket, &prefix).await?;
                let mut out = vec![];
                for o in objects {
                    if !o.key.starts_with(&prefix) || o.key == prefix {
                        continue;
                    }
                    let name = o.key[prefix.len()..].to_string();
                    if name.is_empty() {
                        continue;
                    }
                    out.push(Entry {
                        name,
                        path: format!("/{}", o.key),
                        is_dir: false,
                        size: o.size,
                        modified: o.last_modified,
                        perms: None,
                    });
                }
                for p in prefixes {
                    if !p.starts_with(&prefix) || p == prefix {
                        continue;
                    }
                    let name = p[prefix.len()..].trim_end_matches('/').to_string();
                    if name.is_empty() {
                        continue;
                    }
                    out.push(Entry {
                        name,
                        path: format!("/{}", p.trim_end_matches('/')),
                        is_dir: true,
                        size: 0,
                        modified: None,
                        perms: None,
                    });
                }
                out.sort_by(|a, b| {
                    b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
                Ok(out)
            }
            Backend::Webdav(w) => {
                let entries = w.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::Swift(s) => {
                let entries = s.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::Ftp(f) => {
                let entries = f.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: e.perms,
                    })
                    .collect())
            }
            Backend::Sftp(f) => {
                let entries = f.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: e.perms,
                    })
                    .collect())
            }
            Backend::Mega(m) => {
                let entries = m.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::Pcloud(p) => {
                let entries = p.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::Dropbox(d) => {
                let entries = d.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::GDrive(g) => {
                let entries = g.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::Onedrive(o) => {
                let entries = o.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
            Backend::Box(b) => {
                let entries = b.list(dir).await?;
                Ok(entries
                    .into_iter()
                    .map(|e| Entry {
                        name: e.name,
                        path: e.path,
                        is_dir: e.is_dir,
                        size: e.size,
                        modified: e.modified,
                        perms: None,
                    })
                    .collect())
            }
        }
    }

    #[allow(dead_code)]
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Backend::S3 { client, bucket } => client.get_object(bucket, path.trim_start_matches('/')).await,
            Backend::Webdav(w) => w.read(path).await,
            Backend::Swift(s) => s.read(path).await,
            Backend::Ftp(f) => f.read(path).await,
            Backend::Sftp(f) => f.read(path).await,
            Backend::Mega(m) => m.read(path).await,
            Backend::Pcloud(p) => p.read(path).await,
            Backend::Dropbox(d) => d.read(path).await,
            Backend::GDrive(g) => g.read(path).await,
            Backend::Onedrive(o) => o.read(path).await,
            Backend::Box(b) => b.read(path).await,
        }
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        match self {
            Backend::S3 { client, bucket } => client.put_object(bucket, path.trim_start_matches('/'), data).await,
            Backend::Webdav(w) => w.write(path, data).await,
            Backend::Swift(s) => s.write(path, data).await,
            Backend::Ftp(f) => f.write(path, data).await,
            Backend::Sftp(f) => f.write(path, data).await,
            Backend::Mega(m) => m.write(path, data).await,
            Backend::Pcloud(p) => p.write(path, data).await,
            Backend::Dropbox(d) => d.write(path, data).await,
            Backend::GDrive(g) => g.write(path, data).await,
            Backend::Onedrive(o) => o.write(path, data).await,
            Backend::Box(b) => b.write(path, data).await,
        }
    }

    /// Stream a remote file into `dest` (created or replaced) without holding
    /// it in memory. Returns the number of bytes written. On failure the
    /// partial `dest` is removed.
    pub async fn read_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        let r = match self {
            Backend::S3 { client, bucket } => client.get_object_to_file(bucket, path.trim_start_matches('/'), dest).await,
            Backend::Webdav(w) => w.read_to_file(path, dest).await,
            Backend::Swift(s) => s.read_to_file(path, dest).await,
            Backend::Ftp(f) => f.read_to_file(path, dest).await,
            Backend::Sftp(f) => f.read_to_file(path, dest).await,
            Backend::Mega(m) => m.read_to_file(path, dest).await,
            Backend::Pcloud(p) => p.read_to_file(path, dest).await,
            Backend::Dropbox(d) => d.read_to_file(path, dest).await,
            Backend::GDrive(g) => g.read_to_file(path, dest).await,
            Backend::Onedrive(o) => o.read_to_file(path, dest).await,
            Backend::Box(b) => b.read_to_file(path, dest).await,
        };
        if r.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        r
    }

    /// Upload the local file `src` to `path`, streaming it from disk.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        match self {
            Backend::S3 { client, bucket } => client.put_object_from_file(bucket, path.trim_start_matches('/'), src).await,
            Backend::Webdav(w) => w.write_from_file(path, src).await,
            Backend::Swift(s) => s.write_from_file(path, src).await,
            Backend::Ftp(f) => f.write_from_file(path, src).await,
            Backend::Sftp(f) => f.write_from_file(path, src).await,
            Backend::Mega(m) => m.write_from_file(path, src).await,
            Backend::Pcloud(p) => p.write_from_file(path, src).await,
            Backend::Dropbox(d) => d.write_from_file(path, src).await,
            Backend::GDrive(g) => g.write_from_file(path, src).await,
            Backend::Onedrive(o) => o.write_from_file(path, src).await,
            Backend::Box(b) => b.write_from_file(path, src).await,
        }
    }

    /// Copy a remote file to another remote path through a local temp file
    /// (no backend has a server-side copy yet).
    pub async fn copy_file(&self, from: &str, to: &str) -> Result<()> {
        let tmp = TempPath::new("copy")?;
        self.read_to_file(from, tmp.path()).await?;
        self.write_from_file(to, tmp.path()).await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        match self {
            Backend::S3 { client, bucket } => {
                let key = format!("{}/", path.trim_matches('/'));
                client.put_object(bucket, &key, b"").await
            }
            Backend::Webdav(w) => w.mkdir(path).await,
            Backend::Swift(s) => s.mkdir(path).await,
            Backend::Ftp(f) => f.mkdir(path).await,
            Backend::Sftp(f) => f.mkdir(path).await,
            Backend::Mega(m) => m.mkdir(path).await,
            Backend::Pcloud(p) => p.mkdir(path).await,
            Backend::Dropbox(d) => d.mkdir(path).await,
            Backend::GDrive(g) => g.mkdir(path).await,
            Backend::Onedrive(o) => o.mkdir(path).await,
            Backend::Box(b) => b.mkdir(path).await,
        }
    }

    /// Remove a file or folder. `is_dir` tells us which (S3 folders are prefixes).
    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        match self {
            Backend::S3 { client, bucket } => {
                let key = path.trim_start_matches('/');
                if is_dir || key.ends_with('/') {
                    client.delete_prefix(bucket, &format!("{}/", key.trim_end_matches('/'))).await?;
                } else {
                    client.delete_object(bucket, key).await?;
                }
                Ok(())
            }
            Backend::Webdav(w) => w.remove(path).await,
            Backend::Swift(s) => s.remove(path, is_dir).await,
            Backend::Ftp(f) => f.remove(path, is_dir).await,
            Backend::Sftp(f) => f.remove(path, is_dir).await,
            Backend::Mega(m) => m.remove(path, is_dir).await,
            Backend::Pcloud(p) => p.remove(path, is_dir).await,
            Backend::Dropbox(d) => d.remove(path, is_dir).await,
            Backend::GDrive(g) => g.remove(path, is_dir).await,
            Backend::Onedrive(o) => o.remove(path, is_dir).await,
            Backend::Box(b) => b.remove(path, is_dir).await,
        }
    }

    /// List buckets / containers — used by the "choose bucket" helper in the form.
    /// Upload local files and folders into `dest_dir` (folders recursively,
    /// skipping `.DS_Store`). Returns the number of files uploaded.
    pub async fn upload_tree(&self, dest_dir: &str, paths: &[String]) -> std::result::Result<u32, String> {
        let join = |dir: &str, name: &str| if dir == "/" || dir.is_empty() { format!("/{name}") } else { format!("{dir}/{name}") };
        let mut count = 0;
        let mut stack: Vec<(std::path::PathBuf, String)> = paths
            .iter()
            .filter_map(|p| {
                let pb = std::path::PathBuf::from(p);
                let name = pb.file_name()?.to_string_lossy().to_string();
                Some((pb, join(dest_dir, &name)))
            })
            .collect();
        while let Some((local, remote)) = stack.pop() {
            if local.is_dir() {
                self.mkdir(&remote).await.map_err(|e| format!("{remote}: {e}"))?;
                for entry in std::fs::read_dir(&local).map_err(|e| e.to_string())? {
                    let entry = entry.map_err(|e| e.to_string())?;
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name != ".DS_Store" {
                        stack.push((entry.path(), join(&remote, &name)));
                    }
                }
            } else {
                self.write_from_file(&remote, &local).await.map_err(|e| format!("{remote}: {e}"))?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Download a remote file, or a folder recursively, to the local `dest`.
    pub async fn download_tree(&self, remote: &str, is_dir: bool, dest: &std::path::Path) -> std::result::Result<(), String> {
        if !is_dir {
            return self.download_file(remote, dest).await;
        }
        std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
        let mut stack = vec![(remote.to_string(), dest.to_path_buf())];
        while let Some((dir, local)) = stack.pop() {
            for e in self.list(&dir).await.map_err(|e| e.to_string())? {
                // Names come from the server: never let one step outside `dest`.
                if !is_plain_name(&e.name) {
                    continue;
                }
                let to = local.join(&e.name);
                if e.is_dir {
                    std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
                    stack.push((e.path, to));
                } else {
                    self.download_file(&e.path, &to).await?;
                }
            }
        }
        Ok(())
    }

    /// Stream one remote file to `dest` and mark it as downloaded.
    pub async fn download_file(&self, remote: &str, dest: &std::path::Path) -> std::result::Result<(), String> {
        self.read_to_file(remote, dest).await.map_err(|e| e.to_string())?;
        mark_downloaded(dest);
        Ok(())
    }

    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        match self {
            Backend::S3 { client, .. } => Ok(client.list_buckets().await?.into_iter().map(|b| b.name).collect()),
            Backend::Webdav(_) => Err(Error::NotImplemented),
            Backend::Swift(s) => Ok(s.list_containers_names().await?),
            Backend::Ftp(_) => Err(Error::NotImplemented),
            Backend::Sftp(_) => Err(Error::NotImplemented),
            Backend::Mega(_) => Err(Error::NotImplemented),
            Backend::Pcloud(p) => Ok(p.list_folders_names().await?),
            Backend::Dropbox(_) => Err(Error::NotImplemented),
            Backend::GDrive(_) => Err(Error::NotImplemented),
            Backend::Onedrive(_) => Err(Error::NotImplemented),
            Backend::Box(_) => Err(Error::NotImplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b2_defaults_endpoint_and_region_when_blank() {
        let mut conn = Connection::new(ConnType::Backblaze);
        conn.endpoint.clear();
        conn.region.clear();
        conn.access_key = "key".into();
        match Backend::from_connection(&conn, "secret").expect("b2 backend") {
            Backend::S3 { client, bucket } => {
                assert_eq!(client.endpoint, "https://s3.us-west-0.backblazeb2.com");
                assert_eq!(client.region, "us-west-0");
                assert_eq!(bucket, "");
            }
            other => panic!("expected S3 backend for Backblaze, got {:?}", other_name(&other)),
        }
    }

    #[test]
    fn b2_honors_custom_endpoint_and_region() {
        let mut conn = Connection::new(ConnType::Backblaze);
        conn.endpoint = "https://s3.us-west-10.backblazeb2.com".into();
        conn.region = "us-west-10".into();
        conn.access_key = "key".into();
        conn.bucket = "my-bucket".into();
        match Backend::from_connection(&conn, "secret").expect("b2 backend") {
            Backend::S3 { client, bucket } => {
                assert_eq!(client.endpoint, "https://s3.us-west-10.backblazeb2.com");
                assert_eq!(client.region, "us-west-10");
                assert_eq!(bucket, "my-bucket");
            }
            other => panic!("expected S3 backend for Backblaze, got {:?}", other_name(&other)),
        }
    }

    fn other_name(b: &Backend) -> &'static str {
        match b {
            Backend::S3 { .. } => "S3",
            Backend::Webdav(_) => "Webdav",
            Backend::Swift(_) => "Swift",
            Backend::Ftp(_) => "Ftp",
            Backend::Sftp(_) => "Sftp",
            Backend::Mega(_) => "Mega",
            Backend::Pcloud(_) => "Pcloud",
            Backend::Dropbox(_) => "Dropbox",
            Backend::GDrive(_) => "GDrive",
            Backend::Onedrive(_) => "Onedrive",
            Backend::Box(_) => "Box",
        }
    }
}

/// Parse an FTP endpoint ("ftp://host:2121", "host", "host:2121") into
/// (host, port). `port_override` (from `fields.port`) wins over an embedded
/// port; default 21.
fn ftp_endpoint(endpoint: &str, port_override: &str) -> (String, u16) {
    let trimmed = endpoint.trim();
    let stripped = trimmed
        .strip_prefix("ftp://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let stripped = stripped.trim_matches('/');
    let port_from_url = stripped.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
    let host = match stripped.split_once(':') {
        Some((h, _)) => h.to_string(),
        None => stripped.to_string(),
    };
    let port = port_override
        .parse::<u16>()
        .ok()
        .or(port_from_url)
        .unwrap_or(21);
    (host, port)
}

/// A single path component: not empty, `.`, `..`, and without separators.
pub fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && !name.contains('\0')
}

/// Mark a file that came from the network as downloaded
/// (`com.apple.quarantine`), like a browser does, so Gatekeeper checks it
/// before it can run. Call it once the file is complete.
pub fn mark_downloaded(path: &std::path::Path) {
    quarantine(path);
}

/// Write small downloaded contents to `path` and mark them as downloaded.
/// Files are better streamed with `Backend::download_file`.
pub fn write_downloaded(path: &std::path::Path, data: &[u8]) -> std::result::Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()))?;
    mark_downloaded(path);
    Ok(())
}

#[cfg(target_os = "macos")]
fn quarantine(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let value = format!("0081;{now:x};CloudUp;");
    // SAFETY: both pointers are valid NUL-terminated / sized buffers for the call.
    unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            c"com.apple.quarantine".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            0,
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn quarantine(_path: &std::path::Path) {}

// ------------------------------------------------------------------ transfers
//
// Shared plumbing for moving file contents between disk and network in
// chunks, so a file of any size never has to fit in memory.

/// Read/write buffer size for file transfers.
pub(crate) const CHUNK: usize = 256 * 1024;

/// A download that delivers no data for this long has stalled.
pub(crate) const IDLE: Duration = Duration::from_secs(120);

/// HTTP client for file bodies. Unlike the backends' own clients it has no
/// overall deadline (a large file can take hours); stalls are caught per
/// request instead (`upload_timeout`, `send_download`, `save_response`).
pub(crate) fn transfer_client() -> reqwest::Client {
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default()
    });
    CLIENT.clone()
}

/// Deadline for sending `len` bytes and getting the reply: generous (a
/// 50 KB/s floor), but a hung upload still ends.
pub(crate) fn upload_timeout(len: u64) -> Duration {
    Duration::from_secs(300 + len / (50 * 1024))
}

/// Send a request that starts a download: only the wait for the response
/// headers is bounded here; `save_response` watches the body.
pub(crate) async fn send_download(req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    tokio::time::timeout(IDLE, req.send())
        .await
        .map_err(|_| Error::Http("the server did not answer in time".into()))?
        .map_err(Error::http)
}

/// Stream a response body into `dest` (created or truncated), chunk by
/// chunk. Returns the number of bytes written.
pub(crate) async fn save_response(resp: reqwest::Response, dest: &Path) -> Result<u64> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(dest).await.map_err(|e| local_err(dest, e))?;
    let mut stream = resp.bytes_stream();
    let mut n = 0u64;
    loop {
        let next = tokio::time::timeout(IDLE, stream.next())
            .await
            .map_err(|_| Error::Http("the download stalled".into()))?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(Error::http)?;
        file.write_all(&chunk).await.map_err(|e| local_err(dest, e))?;
        n += chunk.len() as u64;
    }
    file.flush().await.map_err(|e| local_err(dest, e))?;
    Ok(n)
}

/// A local I/O error, naming the file.
pub(crate) fn local_err(path: &Path, e: std::io::Error) -> Error {
    Error::Other(format!("{}: {e}", path.display()))
}

/// Blocking copy in `CHUNK`-sized pieces (FTP sockets, SFTP files): large
/// reads and writes let libssh2 pipeline its requests. Returns bytes copied.
pub(crate) fn copy_blocking(from: &mut impl std::io::Read, to: &mut impl std::io::Write) -> std::io::Result<u64> {
    let mut buf = vec![0u8; CHUNK];
    let mut n = 0u64;
    loop {
        let got = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(got) => got,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..got])?;
        n += got as u64;
    }
    to.flush()?;
    Ok(n)
}

/// Size of a local file.
pub(crate) async fn file_len(path: &Path) -> Result<u64> {
    Ok(tokio::fs::metadata(path).await.map_err(|e| local_err(path, e))?.len())
}

/// A request body streamed from a local file: `prefix`, then `len` bytes of
/// the file starting at `offset`, then `suffix`. The framing carries
/// multipart headers; the range lets chunked uploads send part of a file.
#[derive(Clone)]
pub(crate) struct FileBody {
    pub path: PathBuf,
    pub offset: u64,
    pub len: u64,
    pub prefix: Bytes,
    pub suffix: Bytes,
}

impl FileBody {
    /// The whole file, unframed.
    pub async fn whole(path: &Path) -> Result<Self> {
        let len = file_len(path).await?;
        Ok(Self::range(path, 0, len))
    }

    /// `len` bytes of the file from `offset`, unframed.
    pub fn range(path: &Path, offset: u64, len: u64) -> Self {
        Self { path: path.to_path_buf(), offset, len, prefix: Bytes::new(), suffix: Bytes::new() }
    }

    /// Wrap the file data in `prefix` and `suffix`.
    pub fn framed(self, prefix: impl Into<Bytes>, suffix: impl Into<Bytes>) -> Self {
        Self { prefix: prefix.into(), suffix: suffix.into(), ..self }
    }

    /// Total body size, for `Content-Length` (services such as S3 refuse
    /// chunked transfer encoding).
    pub fn content_len(&self) -> u64 {
        self.prefix.len() as u64 + self.len + self.suffix.len() as u64
    }

    /// Open the file and build the body. A body can be sent once: call this
    /// again for a retry.
    pub async fn body(&self) -> Result<reqwest::Body> {
        Ok(reqwest::Body::wrap_stream(self.stream().await?))
    }

    async fn stream(&self) -> Result<impl futures_util::Stream<Item = std::io::Result<Bytes>> + Send + 'static> {
        use futures_util::StreamExt;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file = tokio::fs::File::open(&self.path).await.map_err(|e| local_err(&self.path, e))?;
        file.seek(std::io::SeekFrom::Start(self.offset)).await.map_err(|e| local_err(&self.path, e))?;
        // A file that shrank meanwhile ends early, and the HTTP layer then
        // fails the request for a short body instead of sending garbage.
        let data = futures_util::stream::unfold(Some(file.take(self.len)), |reader| async move {
            let mut reader = reader?;
            let mut buf = vec![0u8; CHUNK];
            match reader.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some((Ok(Bytes::from(buf)), Some(reader)))
                }
                Err(e) => Some((Err(e), None)),
            }
        });
        let frame = |b: &Bytes| futures_util::stream::iter((!b.is_empty()).then(|| Ok(b.clone())));
        Ok(frame(&self.prefix).chain(data).chain(frame(&self.suffix)))
    }
}

/// CloudUp's folder for temporary files (`$TMPDIR/cloudup-tmp`; plain
/// `cloudup` is WebKit's), readable only by the user: spooled file
/// contents can be private.
pub fn temp_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("cloudup-tmp");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700);
        builder.create(&dir).map_err(|e| local_err(&dir, e))?;
        // `mode` only applies when the folder is created.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    builder.create(&dir).map_err(|e| local_err(&dir, e))?;
    // Once per run, drop what a crashed run left behind (anything a day old;
    // a transfer still running in another process is younger).
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(|| {
        let day = Duration::from_secs(24 * 3600);
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let old = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > day);
            if old {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    });
    Ok(dir)
}

/// A unique path in `temp_dir()`; whatever is there is deleted on drop.
pub struct TempPath(PathBuf);

impl TempPath {
    pub fn new(tag: &str) -> Result<Self> {
        Ok(Self(temp_dir()?.join(format!("{tag}-{}", uuid::Uuid::new_v4().simple()))))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Fail a non-2xx response with its status and (the start of) its body.
pub(crate) async fn ok_or_api(provider: &str, resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(Error::Api { provider: provider.into(), status: status.as_u16(), body: body.chars().take(400).collect() })
}

/// An OAuth-authenticated request on the transfer client, for file bodies.
/// Like `OAuthHttp::request` it refreshes the token and retries once on a
/// 401/403; an upload body is reopened from disk for the retry. The status
/// is not checked.
pub(crate) async fn oauth_send(
    oh: &crate::oauth::OAuthHttp,
    method: reqwest::Method,
    url: &str,
    headers: &[(&str, String)],
    upload: Option<&FileBody>,
) -> Result<reqwest::Response> {
    for attempt in 0..2u8 {
        let token = oh.access_token().await?;
        let mut req = transfer_client()
            .request(method.clone(), url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::USER_AGENT, concat!("CloudUp/", env!("CARGO_PKG_VERSION")));
        for (k, v) in headers {
            req = req.header(*k, v.as_str());
        }
        let resp = match upload {
            Some(b) => req
                .header(reqwest::header::CONTENT_LENGTH, b.content_len())
                .timeout(upload_timeout(b.content_len()))
                .body(b.body().await?)
                .send()
                .await
                .map_err(Error::http)?,
            None => send_download(req).await?,
        };
        let status = resp.status().as_u16();
        if (status == 401 || status == 403) && attempt == 0 {
            oh.force_refresh().await?;
            continue;
        }
        return Ok(resp);
    }
    Err(Error::Other("unreachable: request loop".into()))
}

/// Part size for a multipart upload of `len` bytes: at least `min`, and
/// large enough (rounded up to a whole MiB) to stay within `max_parts`.
pub(crate) fn part_size(len: u64, min: u64, max_parts: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    let needed = len.div_ceil(max_parts.max(1)).div_ceil(MIB) * MIB;
    min.max(needed)
}

/// `Content-Range` for `n` bytes at `offset` of a `total`-byte file.
pub(crate) fn content_range(offset: u64, n: u64, total: u64) -> String {
    format!("bytes {}-{}/{}", offset, (offset + n).saturating_sub(1), total)
}

/// Escape text for an XML element or attribute.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Split `len` bytes into consecutive `(offset, length)` pieces of at most
/// `size` bytes, for chunked uploads. An empty file is one empty piece.
pub(crate) fn chunks(len: u64, size: u64) -> Vec<(u64, u64)> {
    let size = size.max(1);
    let mut out = vec![];
    let mut offset = 0;
    while offset < len {
        let n = size.min(len - offset);
        out.push((offset, n));
        offset += n;
    }
    if out.is_empty() {
        out.push((0, 0));
    }
    out
}

/// The opening and closing parts of a one-file multipart body, to go around
/// the file's bytes: `parts` are (headers, content) pairs sent before the
/// file, `file_headers` the file part's own headers.
pub(crate) fn multipart_frame(boundary: &str, parts: &[(&str, &str)], file_headers: &str) -> (String, String) {
    let mut head = String::new();
    for (headers, content) in parts {
        head.push_str(&format!("--{boundary}\r\n{headers}\r\n\r\n{content}\r\n"));
    }
    head.push_str(&format!("--{boundary}\r\n{file_headers}\r\n\r\n"));
    (head, format!("\r\n--{boundary}--\r\n"))
}

#[cfg(test)]
mod transfer_tests {
    use super::*;

    async fn collect(b: &FileBody) -> Vec<u8> {
        use futures_util::StreamExt;
        let mut out = vec![];
        let mut s = Box::pin(b.stream().await.unwrap());
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn file_body_frames_and_ranges() {
        let tmp = TempPath::new("test-body").unwrap();
        // Larger than one chunk, so the reader loops.
        let data: Vec<u8> = (0..(CHUNK * 2 + 17)).map(|i| (i % 251) as u8).collect();
        std::fs::write(tmp.path(), &data).unwrap();

        let whole = FileBody::whole(tmp.path()).await.unwrap();
        assert_eq!(whole.content_len(), data.len() as u64);
        assert_eq!(collect(&whole).await, data);

        let framed = whole.clone().framed("<<", ">>");
        assert_eq!(framed.content_len(), data.len() as u64 + 4);
        let got = collect(&framed).await;
        assert_eq!(&got[..2], b"<<");
        assert_eq!(&got[got.len() - 2..], b">>");
        assert_eq!(&got[2..got.len() - 2], &data[..]);

        let part = FileBody::range(tmp.path(), 10, 1000);
        assert_eq!(collect(&part).await, &data[10..1010]);
        // A range past the end of the file stops at the end.
        let tail = FileBody::range(tmp.path(), data.len() as u64 - 5, 100);
        assert_eq!(collect(&tail).await, &data[data.len() - 5..]);
    }

    #[test]
    fn temp_path_is_private_and_removed() {
        let t = TempPath::new("test-tmp").unwrap();
        std::fs::write(t.path(), b"x").unwrap();
        let p = t.path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p.parent().unwrap()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        drop(t);
        assert!(!p.exists());
    }

    #[test]
    fn multipart_frame_layout() {
        let (head, tail) = multipart_frame("B", &[("Content-Type: application/json", "{}")], "Content-Type: application/octet-stream");
        assert_eq!(
            head,
            "--B\r\nContent-Type: application/json\r\n\r\n{}\r\n--B\r\nContent-Type: application/octet-stream\r\n\r\n"
        );
        assert_eq!(tail, "\r\n--B--\r\n");
    }

    #[test]
    fn chunks_cover_the_file() {
        assert_eq!(chunks(0, 10), vec![(0, 0)]);
        assert_eq!(chunks(10, 10), vec![(0, 10)]);
        assert_eq!(chunks(25, 10), vec![(0, 10), (10, 10), (20, 5)]);
    }

    #[test]
    fn part_sizes() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(part_size(10, 64 * MIB, 10_000), 64 * MIB);
        // 1 TiB in at most 10,000 parts needs ~105 MiB parts.
        let p = part_size(1 << 40, 64 * MIB, 10_000);
        assert_eq!(p % MIB, 0);
        assert!(p * 10_000 >= 1 << 40 && (p - MIB) * 10_000 < 1 << 40);
        assert_eq!(content_range(0, 10, 25), "bytes 0-9/25");
        assert_eq!(content_range(20, 5, 25), "bytes 20-24/25");
        assert_eq!(xml_escape(r#""a"<&>'"#), "&quot;a&quot;&lt;&amp;&gt;&apos;");
    }

    #[test]
    fn upload_timeout_grows_with_size() {
        assert_eq!(upload_timeout(0), Duration::from_secs(300));
        assert!(upload_timeout(10 << 30) > Duration::from_secs(3600));
    }
}
