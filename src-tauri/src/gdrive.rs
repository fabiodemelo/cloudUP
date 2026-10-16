//! Google Drive backend (OAuth2 PKCE — see oauth.rs).
//!
//! Connection mapping:
//! - `fields.client_id` / `fields.client_secret` = OAuth app credentials
//! - `bucket` = the folder **id** to mount (`root` = the whole My Drive; leave
//!   empty/"`/`" to use the root). Paths are resolved to ids by walking.
//! - the OAuth token is stored in the connection secret (see oauth.rs)

use crate::backend::{multipart_frame, oauth_send, ok_or_api, save_response, FileBody};
use crate::error::{Error, Result};
use crate::oauth::{self, urlenc, OAuthHttp, GDRIVE};
use reqwest::Method;
use std::path::Path;

const API: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
/// Drive wants files over 5 MB sent through a resumable upload session.
const SIMPLE_MAX: u64 = 5 * 1024 * 1024;

/// Where an upload goes: a new revision of a file, or a new file.
enum Target {
    Update(String),
    Create { parent_id: String, name: String },
}

#[derive(Clone)]
pub struct GDrive {
    pub bucket: String,
    pub oh: OAuthHttp,
}

pub struct GDriveEntry {
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

/// Multipart framing for creating a file: its metadata part, then the
/// opening of the content part (`.0`), and the closing boundary (`.1`).
fn create_frame(boundary: &str, name: &str, parent_id: &str) -> (String, String) {
    let meta = serde_json::json!({ "name": name, "parents": [parent_id] }).to_string();
    multipart_frame(
        boundary,
        &[("Content-Type: application/json; charset=UTF-8", &meta)],
        "Content-Type: application/octet-stream",
    )
}

/// Escape a value for a single-quoted string in a Drive `q` query.
fn query_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

impl GDrive {
    pub fn new(conn_id: &str, client_id: &str, client_secret: &str, secret: &str, bucket: &str) -> Self {
        let oh = OAuthHttp::new(&GDRIVE, conn_id, client_id, client_secret, secret);
        let bucket = if bucket.trim().is_empty() || bucket == "/" {
            "root".to_string()
        } else {
            bucket.trim().to_string()
        };
        Self { bucket, oh }
    }

    /// Resolve a single child of `parent` by `name` (file or folder).
    async fn child_id(&self, parent: &str, name: &str) -> Result<String> {
        let url = format!(
            "{API}/files?q=%27{p}%27+in+parents+and+name=%27{n}%27+and+trashed=false&fields=files(id)&pageSize=1",
            p = urlenc(parent),
            n = urlenc(&query_escape(name)),
        );
        let resp = self.oh.request("GET", &url, None, None, &[]).await?;
        let v = oauth::resp_json("Google Drive", resp).await?;
        v.pointer("/files/0/id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Api {
                provider: "Google Drive".into(),
                status: 404,
                body: format!("could not find '{name}' under '{parent}'"),
            })
    }

    /// Walk a mount-relative path segment-by-segment, resolving to a Drive id.
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

    pub async fn list(&self, dir: &str) -> Result<Vec<GDriveEntry>> {
        let folder_id = self.resolve_id(dir).await?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!(
                "{API}/files?q=%27{p}%27+in+parents+and+trashed=false&fields=nextPageToken,files(id,name,mimeType,size,modifiedTime)&pageSize=1000",
                p = urlenc(&folder_id)
            );
            if let Some(pt) = &page_token {
                url = format!("{url}&pageToken={}", urlenc(pt));
            }
            let resp = self.oh.request("GET", &url, None, None, &[]).await?;
            let v = oauth::resp_json("Google Drive", resp).await?;
            if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
                for f in files {
                    let name = f.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let mime = f.get("mimeType").and_then(|x| x.as_str()).unwrap_or("");
                    let is_dir = mime == FOLDER_MIME;
                    let size = if is_dir {
                        0
                    } else {
                        f.get("size").and_then(|x| x.as_str()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
                    };
                    let modified = f.get("modifiedTime").and_then(|x| x.as_str()).map(|s| s.to_string());
                    let path = join_rel(dir, &name);
                    out.push(GDriveEntry { name, path, is_dir, size, modified });
                }
            }
            match v.get("nextPageToken").and_then(|x| x.as_str()) {
                Some(pt) => page_token = Some(pt.to_string()),
                None => break,
            }
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let file_id = self.resolve_id(path).await?;
        let url = format!("{API}/files/{}?alt=media", urlenc(&file_id));
        let resp = self.oh.request("GET", &url, None, None, &[]).await?;
        oauth::resp_bytes("Google Drive", resp).await
    }

    /// Replace an existing file's content, or create the file in its parent
    /// folder if there is none yet.
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        match self.resolve_id(path).await {
            Ok(file_id) => {
                let url = format!("{UPLOAD}/files/{}?uploadType=media", urlenc(&file_id));
                let resp = self
                    .oh
                    .request("PATCH", &url, Some(data.to_vec()), Some("application/octet-stream"), &[])
                    .await?;
                let _ = oauth::resp_json("Google Drive", resp).await?;
                Ok(())
            }
            Err(Error::Api { status: 404, .. }) => self.create_file(path, data).await,
            Err(e) => Err(e),
        }
    }

    /// Multipart upload: the file's metadata (name, parent) and its content.
    async fn create_file(&self, path: &str, data: &[u8]) -> Result<()> {
        let (parent_path, name) = split_parent(path);
        let parent_id = self.resolve_id(&parent_path).await?;
        let boundary = format!("cloudup-{}", uuid::Uuid::new_v4().simple());
        let (head, tail) = create_frame(&boundary, name, &parent_id);
        let mut body = head.into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(tail.as_bytes());
        let ct = format!("multipart/related; boundary={boundary}");
        let resp = self
            .oh
            .request("POST", &format!("{UPLOAD}/files?uploadType=multipart"), Some(body), Some(&ct), &[])
            .await?;
        let _ = oauth::resp_json("Google Drive", resp).await?;
        Ok(())
    }

    /// Stream a file into `dest`.
    pub async fn read_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        let file_id = self.resolve_id(path).await?;
        let url = format!("{API}/files/{}?alt=media", urlenc(&file_id));
        let resp = oauth_send(&self.oh, Method::GET, &url, &[], None).await?;
        save_response(ok_or_api("Google Drive", resp).await?, dest).await
    }

    /// Like `write`, with the content streamed from disk. Files over 5 MB
    /// go through a resumable upload session.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let file = FileBody::whole(src).await?;
        let target = match self.resolve_id(path).await {
            Ok(file_id) => Target::Update(file_id),
            Err(Error::Api { status: 404, .. }) => {
                let (parent_path, name) = split_parent(path);
                Target::Create { parent_id: self.resolve_id(&parent_path).await?, name: name.to_string() }
            }
            Err(e) => return Err(e),
        };
        let octets = "application/octet-stream".to_string();
        let (method, url, ct, body) = if file.len > SIMPLE_MAX {
            (Method::PUT, self.resumable_session(&target, file.len).await?, octets, file)
        } else {
            match target {
                Target::Update(file_id) => {
                    (Method::PATCH, format!("{UPLOAD}/files/{}?uploadType=media", urlenc(&file_id)), octets, file)
                }
                Target::Create { parent_id, name } => {
                    let boundary = format!("cloudup-{}", uuid::Uuid::new_v4().simple());
                    let (head, tail) = create_frame(&boundary, &name, &parent_id);
                    (
                        Method::POST,
                        format!("{UPLOAD}/files?uploadType=multipart"),
                        format!("multipart/related; boundary={boundary}"),
                        file.framed(head, tail),
                    )
                }
            }
        };
        let resp = oauth_send(&self.oh, method, &url, &[("Content-Type", ct)], Some(&body)).await?;
        let _ = oauth::resp_json("Google Drive", resp).await?;
        Ok(())
    }

    /// Start a resumable upload of `len` bytes; returns the session URL to
    /// PUT the content to.
    async fn resumable_session(&self, target: &Target, len: u64) -> Result<String> {
        let (method, url, meta) = match target {
            Target::Update(file_id) => {
                ("PATCH", format!("{UPLOAD}/files/{}?uploadType=resumable", urlenc(file_id)), serde_json::json!({}))
            }
            Target::Create { parent_id, name } => (
                "POST",
                format!("{UPLOAD}/files?uploadType=resumable"),
                serde_json::json!({ "name": name, "parents": [parent_id] }),
            ),
        };
        let extra = [
            ("X-Upload-Content-Type".to_string(), "application/octet-stream".to_string()),
            ("X-Upload-Content-Length".to_string(), len.to_string()),
        ];
        let resp = self
            .oh
            .request(method, &url, Some(meta.to_string().into_bytes()), Some("application/json; charset=UTF-8"), &extra)
            .await?;
        let resp = ok_or_api("Google Drive", resp).await?;
        resp.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| Error::Parse("Google Drive: no upload session URL".into()))
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let (parent_path, name) = split_parent(path);
        let parent_id = self.resolve_id(&parent_path).await?;
        let body = serde_json::json!({ "name": name, "mimeType": FOLDER_MIME, "parents": [parent_id] }).to_string();
        let resp = self
            .oh
            .request("POST", &format!("{API}/files"), Some(body.into_bytes()), Some("application/json"), &[])
            .await?;
        let _ = oauth::resp_json("Google Drive", resp).await?;
        Ok(())
    }

    /// Move to the trash. For a folder this also removes its contents.
    pub async fn remove(&self, path: &str, _is_dir: bool) -> Result<()> {
        let file_id = self.resolve_id(path).await?;
        let url = format!("{API}/files/{}", urlenc(&file_id));
        // DELETE would skip the trash; trashing keeps the item recoverable.
        let body = br#"{"trashed":true}"#.to_vec();
        let resp = self.oh.request("PATCH", &url, Some(body), Some("application/json"), &[]).await?;
        let _ = oauth::resp_bytes("Google Drive", resp).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_frame_layout() {
        let (head, tail) = create_frame("B", "a.txt", "PID");
        assert_eq!(
            head,
            "--B\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"name\":\"a.txt\",\"parents\":[\"PID\"]}\r\n\
             --B\r\nContent-Type: application/octet-stream\r\n\r\n"
        );
        assert_eq!(tail, "\r\n--B--\r\n");
    }
}
