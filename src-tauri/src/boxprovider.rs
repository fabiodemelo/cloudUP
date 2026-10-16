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

use crate::backend::{chunks, content_range, local_err, multipart_frame, oauth_send, ok_or_api, save_response, FileBody, CHUNK};
use crate::error::{Error, Result};
use crate::oauth::{self, urlenc, OAuthHttp, BOX};
use reqwest::Method;
use sha1::{Digest, Sha1};
use std::path::Path;

const API: &str = "https://api.box.com/2.0";
const UPLOAD: &str = "https://upload.box.com/api/2.0";
/// Box's direct upload takes at most 50 MB; larger files go through a
/// chunked upload session.
const SIMPLE_MAX: u64 = 50 * 1024 * 1024;

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

    /// Like `write`, with the content streamed from disk; files over 50 MB
    /// go through a chunked upload session.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let file = FileBody::whole(src).await?;
        if file.len > SIMPLE_MAX {
            return self.chunked_upload(path, src, file.len).await;
        }
        let (url, attributes) = self.upload_target(path).await?;
        let boundary = format!("cloudup-{}", uuid::Uuid::new_v4().simple());
        let (head, tail) = upload_frame(&boundary, &attributes);
        let body = file.framed(head, tail);
        let ct = format!("multipart/form-data; boundary={boundary}");
        let resp = oauth_send(&self.oh, Method::POST, &url, &[("Content-Type", ct)], Some(&body)).await?;
        let _ = oauth::resp_bytes("Box", resp).await?;
        Ok(())
    }

    /// Chunked upload: open a session (for a new version, or a new file in
    /// the parent folder), send the parts, commit. Aborted on failure.
    async fn chunked_upload(&self, path: &str, src: &Path, len: u64) -> Result<()> {
        let (parent_path, name) = split_parent(path);
        let (url, req) = match self.resolve_id(path).await {
            Ok(file_id) => (
                format!("{UPLOAD}/files/{}/upload_sessions", urlenc(&file_id)),
                serde_json::json!({ "file_size": len, "file_name": name }),
            ),
            Err(Error::Api { status: 404, .. }) => {
                let parent_id = self.resolve_id(&parent_path).await?;
                (
                    format!("{UPLOAD}/files/upload_sessions"),
                    serde_json::json!({ "folder_id": parent_id, "file_size": len, "file_name": name }),
                )
            }
            Err(e) => return Err(e),
        };
        let resp = self.oh.request("POST", &url, Some(req.to_string().into_bytes()), Some("application/json"), &[]).await?;
        let session = oauth::resp_json("Box", resp).await?;
        let endpoint = |k: &str| {
            session
                .pointer(&format!("/session_endpoints/{k}"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| Error::Parse(format!("Box: no {k} endpoint for the upload session")))
        };
        let (upload, commit, abort) = (endpoint("upload_part")?, endpoint("commit")?, endpoint("abort")?);
        let part = session
            .get("part_size")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .ok_or_else(|| Error::Parse("Box: no part size for the upload session".into()))?;
        let result = self.upload_parts(&upload, &commit, src, len, part).await;
        if result.is_err() {
            let _ = self.oh.request("DELETE", &abort, None, None, &[]).await;
        }
        result
    }

    /// PUT each part with its SHA-1, then commit with the whole file's.
    async fn upload_parts(&self, upload: &str, commit: &str, src: &Path, len: u64, part_size: u64) -> Result<()> {
        let mut whole = Sha1::new();
        let mut parts = vec![];
        for (offset, n) in chunks(len, part_size) {
            let digest = sha1_range(src, offset, n, &mut whole).await?;
            let headers = [
                ("Content-Type", "application/octet-stream".to_string()),
                ("Content-Range", content_range(offset, n, len)),
                ("Digest", format!("sha={}", base64(&digest))),
            ];
            let resp = oauth_send(&self.oh, Method::PUT, upload, &headers, Some(&FileBody::range(src, offset, n))).await?;
            let v = oauth::resp_json("Box", resp).await?;
            parts.push(v.get("part").cloned().ok_or_else(|| Error::Parse("Box: no part in the upload reply".into()))?);
        }
        let body = serde_json::json!({ "parts": parts }).to_string();
        let digest = format!("sha={}", base64(&whole.finalize()));
        // Box may still be assembling the parts: it answers 202 and when to ask again.
        for _ in 0..60 {
            let resp = self
                .oh
                .request("POST", commit, Some(body.clone().into_bytes()), Some("application/json"), &[("Digest".into(), digest.clone())])
                .await?;
            if resp.status().as_u16() == 202 {
                let wait = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(2)
                    .clamp(1, 30);
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                continue;
            }
            let _ = oauth::resp_bytes("Box", resp).await?;
            return Ok(());
        }
        Err(Error::Other("Box: the upload was not committed in time".into()))
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

/// SHA-1 of `len` bytes of `path` from `offset`, also fed to `whole`.
async fn sha1_range(path: &Path, offset: u64, len: u64, whole: &mut Sha1) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path).await.map_err(|e| local_err(path, e))?;
    file.seek(std::io::SeekFrom::Start(offset)).await.map_err(|e| local_err(path, e))?;
    let mut part = Sha1::new();
    let mut buf = vec![0u8; CHUNK];
    let mut left = len;
    while left > 0 {
        let want = (left as usize).min(buf.len());
        let n = file.read(&mut buf[..want]).await.map_err(|e| local_err(path, e))?;
        if n == 0 {
            return Err(Error::Other(format!("{}: file shrank during upload", path.display())));
        }
        part.update(&buf[..n]);
        whole.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(part.finalize().to_vec())
}

/// Standard base64 (for `Digest: sha=` headers).
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_digest() {
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        // SHA-1("abc"), as Box wants it in `Digest: sha=`.
        assert_eq!(base64(&Sha1::digest(b"abc")), "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
    }

    #[tokio::test]
    async fn part_digests_and_whole_digest() {
        let tmp = crate::backend::TempPath::new("box-sha").unwrap();
        let data: Vec<u8> = (0..(CHUNK * 3 + 5)).map(|i| (i % 249) as u8).collect();
        std::fs::write(tmp.path(), &data).unwrap();
        let mut whole = Sha1::new();
        let size = CHUNK as u64 + 7;
        for (offset, n) in chunks(data.len() as u64, size) {
            let d = sha1_range(tmp.path(), offset, n, &mut whole).await.unwrap();
            assert_eq!(d, Sha1::digest(&data[offset as usize..(offset + n) as usize]).to_vec());
        }
        assert_eq!(whole.finalize().to_vec(), Sha1::digest(&data).to_vec());
        // A range past the end is an error, not a short digest.
        assert!(sha1_range(tmp.path(), data.len() as u64 - 1, 10, &mut Sha1::new()).await.is_err());
    }

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
