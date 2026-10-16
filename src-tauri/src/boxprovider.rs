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

use crate::backend::{multipart_frame, oauth_send, ok_or_api, save_response, FileBody};
use crate::error::{Error, Result};
use crate::oauth::{self, urlenc, OAuthHttp, BOX};
use reqwest::Method;
use std::path::Path;

const API: &str = "https://api.box.com/2.0";
const UPLOAD: &str = "https://upload.box.com/api/2.0";

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

/// `("/a/b", "c")` for `/a/b/c`; the parent of a top-level item is `/`.
fn split_parent(path: &str) -> (String, &str) {
    let rel = path.trim_matches('/');
    match rel.rfind('/') {
        Some(s) if s > 0 => (rel[..s].to_string(), &rel[s + 1..]),
        _ => ("/".to_string(), rel),
    }
}

/// Multipart framing for an upload: the `attributes` part, then the
/// opening of the file part (`.0`), and the closing boundary (`.1`).
fn upload_frame(boundary: &str, attributes: &str) -> (String, String) {
    multipart_frame(
        boundary,
        &[("Content-Disposition: form-data; name=\"attributes\"", attributes)],
        "Content-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\nContent-Type: application/octet-stream",
    )
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

    /// Where to upload `path`: a new version of the existing file, or a new
    /// file in its parent folder. Returns (URL, attributes JSON).
    async fn upload_target(&self, path: &str) -> Result<(String, String)> {
        let (parent_path, name) = split_parent(path);
        Ok(match self.resolve_id(path).await {
            Ok(file_id) => (
                format!("{UPLOAD}/files/{}/content", urlenc(&file_id)),
                serde_json::json!({ "name": name }).to_string(),
            ),
            Err(Error::Api { status: 404, .. }) => {
                let parent_id = self.resolve_id(&parent_path).await?;
                (
                    format!("{UPLOAD}/files/content"),
                    serde_json::json!({ "name": name, "parent": { "id": parent_id } }).to_string(),
                )
            }
            Err(e) => return Err(e),
        })
    }

    /// Upload a new version of an existing file, or create the file in its
    /// parent folder if there is none yet (Box's multipart upload API).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let (url, attributes) = self.upload_target(path).await?;
        let boundary = format!("cloudup-{}", uuid::Uuid::new_v4().simple());
        let (head, tail) = upload_frame(&boundary, &attributes);
        let mut body = head.into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(tail.as_bytes());
        let ct = format!("multipart/form-data; boundary={boundary}");
        let resp = self.oh.request("POST", &url, Some(body), Some(&ct), &[]).await?;
        let _ = oauth::resp_bytes("Box", resp).await?;
        Ok(())
    }

    /// Like `write`, with the content streamed from disk. (Box takes files
    /// up to 50 MB this way; larger ones would need its chunked upload API.)
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let file = FileBody::whole(src).await?;
        let (url, attributes) = self.upload_target(path).await?;
        let boundary = format!("cloudup-{}", uuid::Uuid::new_v4().simple());
        let (head, tail) = upload_frame(&boundary, &attributes);
        let body = file.framed(head, tail);
        let ct = format!("multipart/form-data; boundary={boundary}");
        let resp = oauth_send(&self.oh, Method::POST, &url, &[("Content-Type", ct)], Some(&body)).await?;
        let _ = oauth::resp_bytes("Box", resp).await?;
        Ok(())
    }

    /// Stream a file into `dest`.
    pub async fn read_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        let file_id = self.resolve_id(path).await?;
        let url = format!("{API}/files/{}/content", urlenc(&file_id));
        let resp = oauth_send(&self.oh, Method::GET, &url, &[], None).await?;
        save_response(ok_or_api("Box", resp).await?, dest).await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let (parent_path, name) = split_parent(path);
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
        // A folder delete must ask for its contents too, or Box refuses it.
        let url = if is_dir {
            format!("{API}/folders/{}?recursive=true", urlenc(&id))
        } else {
            format!("{API}/files/{}", urlenc(&id))
        };
        let resp = self.oh.request("DELETE", &url, None, None, &[]).await?;
        let _ = oauth::resp_bytes("Box", resp).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_frame_layout() {
        let (head, tail) = upload_frame("B", r#"{"name":"a"}"#);
        assert_eq!(
            head,
            "--B\r\nContent-Disposition: form-data; name=\"attributes\"\r\n\r\n{\"name\":\"a\"}\r\n\
             --B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        );
        assert_eq!(tail, "\r\n--B--\r\n");
    }
}
