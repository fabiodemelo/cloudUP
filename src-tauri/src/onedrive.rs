//! OneDrive backend (OAuth2 PKCE, Microsoft Graph — see oauth.rs).
//!
//! Connection mapping:
//! - `fields.client_id` / `fields.client_secret` = OAuth app credentials
//! - `bucket` = path to mount (e.g. `/Mount`; `/` = the whole drive)
//! - the OAuth token is stored in the connection secret (see oauth.rs)

use crate::backend::{chunks, file_len, oauth_send, ok_or_api, save_response, transfer_client, upload_timeout, FileBody};
use crate::error::{Error, Result};
use crate::oauth::{self, urlenc, OAuthHttp, ONEDRIVE};
use reqwest::Method;
use std::path::Path;

const API: &str = "https://graph.microsoft.com/v1.0";
/// Larger files go through an upload session.
const SIMPLE_MAX: u64 = 4 * 1024 * 1024;
/// Upload-session fragment size: Graph wants a multiple of 320 KiB.
const FRAGMENT: u64 = 32 * 320 * 1024;

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

/// PUT the file to an upload session, fragment by fragment. The session
/// URL is pre-authorized: Graph rejects an Authorization header on it.
async fn upload_fragments(url: &str, src: &Path, len: u64) -> Result<()> {
    for (offset, n) in chunks(len, FRAGMENT) {
        let body = FileBody::range(src, offset, n);
        let resp = transfer_client()
            .put(url)
            .header(reqwest::header::CONTENT_LENGTH, n)
            .header(reqwest::header::CONTENT_RANGE, content_range(offset, n, len))
            .timeout(upload_timeout(n))
            .body(body.body().await?)
            .send()
            .await
            .map_err(Error::http)?;
        ok_or_api("OneDrive", resp).await?;
    }
    Ok(())
}

/// `Content-Range` for `n` bytes at `offset` of a `total`-byte file.
fn content_range(offset: u64, n: u64, total: u64) -> String {
    format!("bytes {}-{}/{}", offset, (offset + n).saturating_sub(1), total)
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

    /// Stream a file into `dest`.
    pub async fn read_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        let resp = oauth_send(&self.oh, Method::GET, &self.item_op(path, "content"), &[], None).await?;
        save_response(ok_or_api("OneDrive", resp).await?, dest).await
    }

    /// Create-or-replace a file, streamed from disk: a single PUT up to
    /// 4 MiB, an upload session beyond.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let len = file_len(src).await?;
        if len <= SIMPLE_MAX {
            let body = FileBody::range(src, 0, len);
            let headers = [("Content-Type", "application/octet-stream".to_string())];
            let resp = oauth_send(&self.oh, Method::PUT, &self.item_op(path, "content"), &headers, Some(&body)).await?;
            let _ = oauth::resp_bytes("OneDrive", resp).await?;
            return Ok(());
        }
        let req = serde_json::json!({ "item": { "@microsoft.graph.conflictBehavior": "replace" } }).to_string();
        let resp = self
            .oh
            .request("POST", &self.item_op(path, "createUploadSession"), Some(req.into_bytes()), Some("application/json"), &[])
            .await?;
        let v = oauth::resp_json("OneDrive", resp).await?;
        let url = v
            .get("uploadUrl")
            .and_then(|u| u.as_str())
            .ok_or_else(|| Error::Parse("OneDrive: no upload URL".into()))?
            .to_string();
        let result = upload_fragments(&url, src, len).await;
        if result.is_err() {
            // Cancel the session so the partial upload is discarded now.
            let _ = transfer_client().delete(&url).send().await;
        }
        result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_and_ranges() {
        assert_eq!(FRAGMENT % (320 * 1024), 0);
        assert_eq!(content_range(0, 10, 25), "bytes 0-9/25");
        assert_eq!(content_range(20, 5, 25), "bytes 20-24/25");
    }
}
