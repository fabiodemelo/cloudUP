//! Dropbox backend (OAuth2 PKCE — see oauth.rs).
//!
//! Connection mapping:
//! - `fields.client_id` / `fields.client_secret` = OAuth app credentials
//! - `bucket` = path to mount (e.g. `/Mount`; `/` = the whole app folder)
//! - the OAuth token is stored in the connection secret (see oauth.rs)

use crate::error::Result;
use crate::oauth::{self, urlenc, OAuthHttp, DROPBOX};

const API: &str = "https://api.dropboxapi.com/2";
const CONTENT: &str = "https://api-content.dropboxapi.com/2";

#[derive(Clone)]
pub struct Dropbox {
    pub bucket: String,
    pub oh: OAuthHttp,
}

pub struct DropboxEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

/// Join a mount-relative dir with a child name, keeping a leading "/".
fn join_rel(dir: &str, name: &str) -> String {
    let d = dir.trim_matches('/');
    if d.is_empty() {
        format!("/{name}")
    } else {
        format!("/{d}/{name}")
    }
}

impl Dropbox {
    pub fn new(conn_id: &str, client_id: &str, client_secret: &str, secret: &str, bucket: &str) -> Self {
        let oh = OAuthHttp::new(&DROPBOX, conn_id, client_id, client_secret, secret);
        let bucket = if bucket.trim().is_empty() || bucket == "/" {
            "/".to_string()
        } else {
            format!("/{}", bucket.trim_matches('/'))
        };
        Self { bucket, oh }
    }

    /// Absolute Dropbox path for a mount-relative path.
    fn abs(&self, path: &str) -> String {
        let rel = path.trim_matches('/');
        let b = self.bucket.trim_matches('/');
        if b.is_empty() {
            if rel.is_empty() { "/".into() } else { format!("/{rel}") }
        } else {
            if rel.is_empty() { format!("/{b}") } else { format!("/{b}/{rel}") }
        }
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<DropboxEntry>> {
        let path = self.abs(dir);
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut body = serde_json::json!({ "path": path, "limit": 1000 });
            if let Some(c) = &cursor {
                body["start_cursor"] = serde_json::json!(c);
            }
            let resp = self
                .oh
                .request("POST", &format!("{API}/files/list_folder"), Some(body.to_string().into_bytes()), Some("application/json"), &[])
                .await?;
            let v = oauth::resp_json("Dropbox", resp).await?;
            if let Some(entries) = v.get("entries").and_then(|e| e.as_array()) {
                for e in entries {
                    let is_dir = e.get(".tag").and_then(|t| t.as_str()) == Some("folder");
                    let name = e.get("name").and_then(|t| t.as_str()).unwrap_or("").to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let size = if is_dir { 0 } else { e.get("size").and_then(|s| s.as_u64()).unwrap_or(0) };
                    let modified = e.get("client_modified").and_then(|s| s.as_str()).map(|s| s.to_string());
                    let path = join_rel(dir, &name);
                    out.push(DropboxEntry { name, path, is_dir, size, modified });
                }
            }
            if v.get("has_more").and_then(|h| h.as_bool()).unwrap_or(false) {
                cursor = v.get("cursor").and_then(|c| c.as_str()).map(|s| s.to_string());
            } else {
                break;
            }
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{CONTENT}/files/download?path={}", urlenc(&self.abs(path)));
        let resp = self.oh.request("GET", &url, None, None, &[]).await?;
        oauth::resp_bytes("Dropbox", resp).await
    }

    /// Upload/replace a file. The path goes in the `Dropbox-Api-Arg` header
    /// and the raw bytes are the body.
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let url = format!("{API}/files/upload");
        let arg = serde_json::json!({ "path": self.abs(path) }).to_string();
        let resp = self
            .oh
            .request("POST", &url, Some(data.to_vec()), Some("application/octet-stream"), &[("Dropbox-Api-Arg".into(), arg)])
            .await?;
        let _ = oauth::resp_bytes("Dropbox", resp).await?;
        Ok(())
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let body = serde_json::json!({ "path": self.abs(path) }).to_string();
        let resp = self
            .oh
            .request("POST", &format!("{API}/files/create_folder_v2"), Some(body.into_bytes()), Some("application/json"), &[])
            .await?;
        let _ = oauth::resp_bytes("Dropbox", resp).await?;
        Ok(())
    }

    /// `delete_v2` removes a file, or a folder and (recursively) everything in it.
    pub async fn remove(&self, path: &str, _is_dir: bool) -> Result<()> {
        let body = serde_json::json!({ "path": self.abs(path) }).to_string();
        let resp = self
            .oh
            .request("POST", &format!("{API}/files/delete_v2"), Some(body.into_bytes()), Some("application/json"), &[])
            .await?;
        let _ = oauth::resp_bytes("Dropbox", resp).await?;
        Ok(())
    }
}
