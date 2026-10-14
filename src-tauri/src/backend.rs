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
                &conn.endpoint, // default https://my.pcloud.com
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
            _ => Err(Error::NotImplemented),
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
