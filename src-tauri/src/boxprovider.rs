//! Box backend (OAuth2 PKCE — see oauth.rs).
//!
//! The file is `boxprovider.rs` (and the struct `BoxProvider`) because the
//! name `Box` would clash with `std::boxed::Box`.
//!
//! Connection mapping:
//! - `fields.client_id` / `fields.client_secret` = OAuth app credentials
//! - `bucket` = the folder **id** to mount (`0` = the whole account; leave
//!   empty/"`/`" to use the root). Paths are resolved to ids by walking.
//! - the OAuth token is stored in the connection secret (see oauth.rs)

use crate::error::{Error, Result};
use crate::oauth::{self, urlenc, OAuthHttp, BOX};

const API: &str = "https://api.box.com/2.0";

#[derive(Clone)]
pub struct BoxProvider {
    pub bucket: String,
    pub oh: OAuthHttp,
}

pub struct BoxEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

fn join_rel(dir: &str, name: &str) -> String {
    let d = dir.trim_matches('/');
    if d.is_empty() {
        format!("/{name}")
    } else {
        format!("/{d}/{name}")
    }
}

impl BoxProvider {
    pub fn new(conn_id: &str, client_id: &str, client_secret: &str, secret: &str, bucket: &str) -> Self {
        let oh = OAuthHttp::new(&BOX, conn_id, client_id, client_secret, secret);
        let bucket = if bucket.trim().is_empty() || bucket == "/" {
            "0".to_string()
        } else {
            bucket.trim().to_string()
        };
        Self { bucket, oh }
    }

    /// Find a child of `parent` by `name` (file or folder).
    async fn child_id(&self, parent: &str, name: &str) -> Result<String> {
        let mut marker: Option<String> = None;
        loop {
            let mut url = format!("{API}/folders/{}/items?limit=1000", urlenc(parent));
            if let Some(m) = &marker {
                url = format!("{url}&marker={}", urlenc(m));
            }
            let resp = self.oh.request("GET", &url, None, None, &[]).await?;
            let v = oauth::resp_json("Box", resp).await?;
            if let Some(entries) = v.get("entries").and_then(|e| e.as_array()) {
                for e in entries {
                    if e.get("name").and_then(|x| x.as_str()) == Some(name) {
                        if let Some(id) = e.get("id").and_then(|x| x.as_str()) {
                            return Ok(id.to_string());
                        }
                    }
                }
            }
            match v.get("next_marker").and_then(|x| x.as_str()) {
                Some(m) => marker = Some(m.to_string()),
                None => break,
            }
        }
        Err(Error::Api {
            provider: "Box".into(),
            status: 404,
            body: format!("could not find '{name}' under '{parent}'"),
        })
    }

    /// Walk a mount-relative path segment-by-segment, resolving to a Box id.
    async fn resolve_id(&self, path: &str) -> Result<String> {
        let rel = path.trim_matches('/');
        if rel.is_empty() {
            return Ok(self.bucket.clone());
        }
        let segs: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        let mut id = self.bucket.clone();
        for seg in &segs {
            let parent = id.clone();
            id = self.child_id(&parent, seg).await?;
        }
        Ok(id)
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<BoxEntry>> {
        let folder_id = self.resolve_id(dir).await?;
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut url = format!("{API}/folders/{}/items?limit=1000", urlenc(&folder_id));
            if let Some(m) = &marker {
                url = format!("{url}&marker={}", urlenc(m));
            }
            let resp = self.oh.request("GET", &url, None, None, &[]).await?;
            let v = oauth::resp_json("Box", resp).await?;
            if let Some(entries) = v.get("entries").and_then(|e| e.as_array()) {
                for e in entries {
                    let name = e.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let is_dir = e.get("type").and_then(|x| x.as_str()) == Some("folder");
                    let size = if is_dir {
                        0
                    } else {
                        e.get("size").and_then(|x| x.as_u64()).unwrap_or(0)
                    };
                    let modified = e.get("content_modified_at").and_then(|x| x.as_str()).map(|s| s.to_string());
                    let path = join_rel(dir, &name);
                    out.push(BoxEntry { name, path, is_dir, size, modified });
                }
            }
            match v.get("next_marker").and_then(|x| x.as_str()) {
                Some(m) => marker = Some(m.to_string()),
                None => break,
            }
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let file_id = self.resolve_id(path).await?;
        let url = format!("{API}/files/{}/content", urlenc(&file_id));
        let resp = self.oh.request("GET", &url, None, None, &[]).await?;
        oauth::resp_bytes("Box", resp).await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let file_id = self.resolve_id(path).await?;
        let url = format!("{API}/files/content?file_id={}", urlenc(&file_id));
        let resp = self
            .oh
            .request("PUT", &url, Some(data.to_vec()), Some("application/octet-stream"), &[])
            .await?;
        let _ = oauth::resp_bytes("Box", resp).await?;
        Ok(())
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let rel = path.trim_matches('/');
        let (parent_path, name) = match rel.rfind('/') {
            Some(s) if s > 0 => (rel[..s].to_string(), &rel[s + 1..]),
            _ => ("/".to_string(), rel),
        };
        let parent_id = self.resolve_id(&parent_path).await?;
        let body = serde_json::json!({ "name": name, "parent": { "id": parent_id } }).to_string();
        let resp = self
            .oh
            .request("POST", &format!("{API}/folders"), Some(body.into_bytes()), Some("application/json"), &[])
            .await?;
        let _ = oauth::resp_json("Box", resp).await?;
        Ok(())
    }

    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let id = self.resolve_id(path).await?;
        let kind = if is_dir { "folders" } else { "files" };
        let url = format!("{API}/{kind}/{}", urlenc(&id));
        let resp = self.oh.request("DELETE", &url, None, None, &[]).await?;
        let _ = oauth::resp_bytes("Box", resp).await?;
        Ok(())
    }
}
