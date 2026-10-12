//! Unified cloud backend.
//!
//! Both the in-app file browser (IPC commands) and the FUSE/WinFsp mount speak
//! this single interface. Paths are always relative to the connection's mount
//! root (the S3 bucket, or the WebDAV base URL) and use a leading "/".

use crate::config::{Connection, ConnType};
use crate::error::{Error, Result};
use crate::s3::S3;
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
}

#[derive(Clone)]
pub enum Backend {
    S3 { client: S3, bucket: String },
    Webdav(Webdav),
    Swift(Swift),
}

impl Backend {
    /// Build a backend from a saved connection + its secret.
    pub fn from_connection(conn: &Connection, secret: &str) -> Result<Self> {
        match conn.ctype {
            ConnType::S3 => Ok(Backend::S3 {
                client: S3::new(&conn.endpoint, &conn.region, &conn.access_key, secret),
                bucket: conn.bucket.trim_matches('/').to_string(),
            }),
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
                    })
                    .collect())
            }
        }
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Backend::S3 { client, bucket } => client.get_object(bucket, path.trim_start_matches('/')).await,
            Backend::Webdav(w) => w.read(path).await,
            Backend::Swift(s) => s.read(path).await,
        }
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        match self {
            Backend::S3 { client, bucket } => client.put_object(bucket, path.trim_start_matches('/'), data).await,
            Backend::Webdav(w) => w.write(path, data).await,
            Backend::Swift(s) => s.write(path, data).await,
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
        }
    }

    /// List buckets / containers — used by the "choose bucket" helper in the form.
    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        match self {
            Backend::S3 { client, .. } => Ok(client.list_buckets().await?.into_iter().map(|b| b.name).collect()),
            Backend::Webdav(_) => Err(Error::NotImplemented),
            Backend::Swift(s) => Ok(s.list_containers_names().await?),
        }
    }
}
