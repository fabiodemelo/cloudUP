//! OneDrive backend (OAuth2 PKCE, Microsoft Graph — see oauth.rs).
//!
//! Connection mapping:
//! - `fields.client_id` / `fields.client_secret` = OAuth app credentials
//! - `bucket` = path to mount (e.g. `/Mount`; `/` = the whole drive)
//! - the OAuth token is stored in the connection secret (see oauth.rs)

use crate::error::Result;
use crate::oauth::{self, urlenc, OAuthHttp, ONEDRIVE};

const API: &str = "https://graph.microsoft.com/v1.0";

#[derive(Clone)]
pub struct Onedrive {
    pub bucket: String,
    pub oh: OAuthHttp,
}

pub struct OnedriveEntry {
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

/// Percent-encode each segment of a path, keeping the "/" separators.
fn enc_path(p: &str) -> String {
    let p = p.trim_end_matches('/');
    p.split('/').map(urlenc).collect::<Vec<_>>().join("/")
}

impl Onedrive {
    pub fn new(conn_id: &str, client_id: &str, client_secret: &str, secret: &str, bucket: &str) -> Self {
        let oh = OAuthHttp::new(&ONEDRIVE, conn_id, client_id, client_secret, secret);
        let bucket = if bucket.trim().is_empty() || bucket == "/" {
            "/".to_string()
        } else {
            format!("/{}", bucket.trim_matches('/'))
        };
        Self { bucket, oh }
    }

    /// Absolute OneDrive path for a mount-relative path.
    fn abs(&self, path: &str) -> String {
        let rel = path.trim_matches('/');
        let b = self.bucket.trim_matches('/');
        if b.is_empty() {
            if rel.is_empty() { "/".into() } else { format!("/{rel}") }
        } else {
            if rel.is_empty() { format!("/{b}") } else { format!("/{b}/{rel}") }
        }
    }

    /// The Graph item addressable syntax for a path (e.g. `me/drive/root:/Mount`).
    fn item(&self, path: &str) -> String {
        let abs = self.abs(path);
        if abs == "/" {
            format!("{API}/me/drive/root")
        } else {
            format!("{API}/me/drive/root:{}", enc_path(&abs))
        }
    }

    /// A sub-resource of the item at `path`. Path-addressed items need the
    /// closing colon (`root:/Mount:/children`), or `children` would be read
    /// as part of the path.
    fn item_op(&self, path: &str, op: &str) -> String {
        if self.abs(path) == "/" {
            format!("{}/{op}", self.item(path))
        } else {
            format!("{}:/{op}", self.item(path))
        }
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<OnedriveEntry>> {
        let url = format!("{}?$top=200", self.item_op(dir, "children"));
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let u = match &next {
                Some(n) => n.clone(),
                None => url.clone(),
            };
            let resp = self.oh.request("GET", &u, None, None, &[]).await?;
            let v = oauth::resp_json("OneDrive", resp).await?;
            if let Some(values) = v.get("value").and_then(|x| x.as_array()) {
                for e in values {
                    let name = e.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let is_dir = e.pointer("/folder").is_some();
                    let size = if is_dir {
                        0
                    } else {
                        e.pointer("/size").and_then(|x| x.as_u64()).unwrap_or(0)
                    };
                    let modified = e.pointer("/lastModifiedDateTime").and_then(|x| x.as_str()).map(|s| s.to_string());
                    let path = join_rel(dir, &name);
                    out.push(OnedriveEntry { name, path, is_dir, size, modified });
                }
            }
            match v.get("@odata.nextLink").and_then(|x| x.as_str()) {
                Some(n) => next = Some(n.to_string()),
                None => break,
            }
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let url = self.item_op(path, "content");
        let resp = self.oh.request("GET", &url, None, None, &[]).await?;
        oauth::resp_bytes("OneDrive", resp).await
    }

    /// Create-or-replace the file content at `path`.
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let url = self.item_op(path, "content");
        let resp = self
            .oh
            .request("PUT", &url, Some(data.to_vec()), Some("application/octet-stream"), &[])
            .await?;
        let _ = oauth::resp_bytes("OneDrive", resp).await?;
        Ok(())
    }

    /// Create a folder: POST a folder item to the parent's children.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let rel = path.trim_matches('/');
        let (parent, name) = match rel.rfind('/') {
            Some(i) => (format!("/{}", &rel[..i]), &rel[i + 1..]),
            None => ("/".to_string(), rel),
        };
        let url = self.item_op(&parent, "children");
        let body = serde_json::json!({ "name": name, "folder": {}, "@microsoft.graph.conflictBehavior": "fail" }).to_string();
        let resp = self
            .oh
            .request("POST", &url, Some(body.into_bytes()), Some("application/json"), &[])
            .await?;
        let _ = oauth::resp_bytes("OneDrive", resp).await?;
        Ok(())
    }

    /// DELETE a file or a folder (folders are deleted recursively).
    pub async fn remove(&self, path: &str, _is_dir: bool) -> Result<()> {
        let url = self.item(path);
        let resp = self.oh.request("DELETE", &url, None, None, &[]).await?;
        let _ = oauth::resp_bytes("OneDrive", resp).await?;
        Ok(())
    }
}
