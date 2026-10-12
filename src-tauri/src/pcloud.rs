//! pCloud client (plain user/password authentication).
//!
//! pCloud identifies the caller on every request with `user` (email) and
//! `password` (base64-encoded) parameters, and — importantly — requires the
//! `User-Agent` header to contain `api_2.0` or it rejects the request.
//!
//! Connection mapping:
//! - `endpoint`   = API host (default `https://my.pcloud.com`; use
//!   `https://api.pcloud.com` / `https://my-pcloud-cdn.com` for enterprise)
//! - `access_key` = account email, `secret` = account password
//! - `bucket`     = folder to mount (e.g. `/photos`; `/` = the whole account)

use crate::error::{Error, Result};
use reqwest::Client;
use std::io::Write;

const PROVIDER: &str = "pCloud";
/// Must contain "api_2.0" — pCloud refuses requests from other user agents.
const USER_AGENT: &str = "cloudmounter/1.0 api_2.0";

#[derive(Clone)]
pub struct Pcloud {
    pub base: String,
    pub user: String,
    pub password: String,
    /// Folder to mount (absolute pCloud path, e.g. "/photos").
    pub bucket: String,
    http: Client,
}

pub struct PcloudEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

impl Pcloud {
    pub fn new(base: &str, user: &str, password: &str, bucket: &str) -> Self {
        let base = if base.trim().is_empty() {
            "https://my.pcloud.com".to_string()
        } else {
            let b = if base.contains("://") {
                base.to_string()
            } else {
                format!("https://{}", base)
            };
            b.trim_end_matches('/').to_string()
        };
        Self {
            base,
            user: user.trim().to_string(),
            password: password.to_string(),
            bucket: normalize_path(bucket),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }

    /// The pCloud account-absolute path for a mount-relative path.
    /// `bucket` is already absolute, so this is a plain prefix join.
    fn abs(&self, path: &str) -> String {
        let rel = path.trim_matches('/');
        if rel.is_empty() {
            return self.bucket.clone(); // "/" or "/photos"
        }
        let b = self.bucket.trim_matches('/');
        if b.is_empty() {
            format!("/{rel}")
        } else {
            format!("/{b}/{rel}")
        }
    }

    fn auth(&self) -> (String, String) {
        (pct(&self.user), pct(&b64(&self.password)))
    }

    /// Call a JSON operation (GET or POST form) and return the parsed body.
    async fn call(&self, method: &str, op: &str, params: &[(&str, &str)]) -> Result<serde_json::Value> {
        let url = format!("{}/{}", self.base, op);
        let mut form = vec![
            ("user".to_string(), self.user.clone()),
            ("password".to_string(), b64(&self.password)),
        ];
        for (k, v) in params {
            form.push((k.to_string(), v.to_string()));
        }

        let req = match method {
            "GET" => {
                let qs = form
                    .iter()
                    .map(|(k, v)| format!("{}={}", pct(&**k), pct(&**v)))
                    .collect::<Vec<_>>()
                    .join("&");
                self.http.get(format!("{url}?{qs}"))
            }
            _ => self.http.post(&url).form(&form),
        };

        let resp = req
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Api { provider: PROVIDER.into(), status: status.as_u16(), body });
        }
        let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| Error::Parse(e.to_string()))?;
        let result = json.get("result").and_then(|v| v.as_i64()).unwrap_or(0);
        if result != 0 {
            let msg = json
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown pCloud error")
                .to_string();
            return Err(Error::Api { provider: PROVIDER.into(), status: result as u16, body: msg });
        }
        Ok(json)
    }

    // ------------------------------------------------------------- operations

    /// List the children of a mount-relative directory.
    pub async fn list(&self, dir: &str) -> Result<Vec<PcloudEntry>> {
        let abs_dir = self.abs(dir);
        let json = self
            .call("GET", "listfolder", &[("path", &pct(&abs_dir)), ("foldertype", "0"), ("getthumbnail", "0")])
            .await?;

        let contents = json.pointer("/metadata/contents").cloned().unwrap_or(serde_json::Value::Null);
        let mount_prefix = self.bucket.clone();

        let mut out = vec![];
        if let Some(items) = contents.as_array() {
            for it in items {
                let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() || name == "." || name == ".." {
                    continue;
                }
                let is_dir = it.get("isfolder").and_then(|v| v.as_bool()).unwrap_or(false);
                let full = it.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let size = it.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                let modified = it.get("modified").and_then(|v| v.as_str()).map(|s| s.to_string());
                let rel = strip_mount_prefix(&full, &mount_prefix);
                out.push(PcloudEntry { name, path: format!("/{rel}"), is_dir, size, modified });
            }
        }
        out.sort_by(|a, b| {
            b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    /// Download a file.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let abs_path = self.abs(path);
        let (u, p) = self.auth();
        let url = format!("{}/getfile?user={u}&password={p}&path={}", self.base, pct(&abs_path));
        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Api { provider: PROVIDER.into(), status: status.as_u16(), body });
        }
        Ok(resp.bytes().await.map_err(|e| Error::Http(e.to_string()))?.to_vec())
    }

    /// Upload/replace a file at `path` (multipart `uploadfile`).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let abs_path = self.abs(path);
        let slash = abs_path.rfind('/').unwrap_or(0);
        let parent = if slash == 0 { "/".to_string() } else { abs_path[..slash].to_string() };
        let name = abs_path[slash + 1..].to_string();

        let boundary = format!("cloudmounter{}", uuid::Uuid::new_v4().simple());
        let mut body = Vec::new();
        let part_field = |b: &mut Vec<u8>, name: &str, value: &str| {
            b.write_fmt(format_args!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ))
            .ok();
        };
        part_field(&mut body, "user", &self.user);
        part_field(&mut body, "password", &b64(&self.password));
        part_field(&mut body, "path", &parent);
        part_field(&mut body, "rename", "1");
        body.write_fmt(format_args!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ))
        .ok();
        body.extend_from_slice(data);
        body.write_all(format!("\r\n--{boundary}--\r\n").as_bytes()).ok();

        let url = format!("{}/uploadfile", self.base);
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::Api { provider: PROVIDER.into(), status: status.as_u16(), body: text });
        }
        let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| Error::Parse(e.to_string()))?;
        let result = json.get("result").and_then(|v| v.as_i64()).unwrap_or(0);
        if result != 0 {
            let msg = json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error").to_string();
            return Err(Error::Api { provider: PROVIDER.into(), status: result as u16, body: msg });
        }
        Ok(())
    }

    /// Create a folder.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let abs_path = self.abs(path);
        self.call("POST", "createfolder", &[("path", &pct(&abs_path))]).await?;
        Ok(())
    }

    /// Delete a file or (recursively) a folder. pCloud deletes by id, so we
    /// resolve the id from the parent listing first.
    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let abs_path = self.abs(path);
        let slash = abs_path.rfind('/').unwrap_or(0);
        let parent = if slash == 0 { "/".to_string() } else { abs_path[..slash].to_string() };
        let name = abs_path[slash + 1..].to_string();

        let json = self.call("GET", "listfolder", &[("path", &pct(&parent))]).await?;
        let id = json
            .pointer("/metadata/contents")
            .and_then(|v| v.as_array())
            .and_then(|items| {
                items
                    .iter()
                    .find(|it| it.get("name").and_then(|v| v.as_str()) == Some(name.as_str()))
            })
            .and_then(|it| if is_dir { it.get("folderid") } else { it.get("fileid") })
            .and_then(|v| v.as_i64())
            .ok_or_else(|| Error::Api {
                provider: PROVIDER.into(),
                status: 0,
                body: format!("could not resolve id for \"{name}\""),
            })?;

        let op = if is_dir { "deletefolder" } else { "deletefile" };
        let key = if is_dir { "folderid" } else { "fileid" };
        self.call("GET", op, &[(key, &id.to_string())]).await?;
        Ok(())
    }

    /// List top-level folder names (for the "choose bucket" helper).
    pub async fn list_folders_names(&self) -> Result<Vec<String>> {
        let json = self.call("GET", "listfolders", &[("path", "/")]).await?;
        // listfolders returns a top-level array (no metadata wrapper).
        let items = match &json {
            v if v.is_array() => v.clone(),
            _ => json.pointer("/metadata/contents").cloned().unwrap_or(serde_json::Value::Null),
        };
        let mut out = vec![];
        if let Some(arr) = items.as_array() {
            for it in arr {
                if let Some(name) = it.get("name").and_then(|v| v.as_str()) {
                    if !name.is_empty() {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

// --------------------------------------------------------------------- helpers

/// Normalize a mount path: leading "/" always present, no trailing "/" (except
/// the root itself).
fn normalize_path(p: &str) -> String {
    let t = p.trim().trim_matches('/');
    if t.is_empty() {
        "/".to_string()
    } else {
        format!("/{t}")
    }
}

/// Strip the mount prefix from an absolute pCloud path, keeping the remainder.
fn strip_mount_prefix(full: &str, prefix: &str) -> String {
    if prefix == "/" || prefix.is_empty() {
        return full.trim_start_matches('/').to_string();
    }
    if let Some(rest) = full.strip_prefix(prefix) {
        rest.trim_start_matches('/').to_string()
    } else {
        full.trim_start_matches('/').to_string()
    }
}

/// Percent-encode a string, encoding even '/' (for query values).
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

fn b64(input: &str) -> String {
    const B: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B[((n >> 18) & 63) as usize] as char);
        out.push(B[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_path_joining() {
        let p = Pcloud::new("", "u@x.com", "pw", "/photos");
        assert_eq!(p.base, "https://my.pcloud.com");
        assert_eq!(p.abs("/a.txt"), "/photos/a.txt");
        assert_eq!(p.abs("a/b.txt"), "/photos/a/b.txt");
        assert_eq!(p.abs("/"), "/photos");
        let root = Pcloud::new("https://my.pcloud.com", "u", "p", "/");
        assert_eq!(root.abs("/a.txt"), "/a.txt");
        assert_eq!(root.abs("/"), "/");
        let trailing = Pcloud::new("", "u", "p", "/photos/");
        assert_eq!(trailing.abs("/a.txt"), "/photos/a.txt");
    }

    #[test]
    fn strip_prefix_handling() {
        assert_eq!(strip_mount_prefix("/photos/a/b.txt", "/photos"), "a/b.txt");
        assert_eq!(strip_mount_prefix("/a/b.txt", "/"), "a/b.txt");
        assert_eq!(strip_mount_prefix("/other/x", "/photos"), "other/x");
    }

    #[test]
    fn b64_matches_stdlib() {
        assert_eq!(b64("hello world"), "aGVsbG8gd29ybGQ=");
        assert_eq!(b64("a"), "YQ==");
        assert_eq!(b64("ab"), "YWI=");
        assert_eq!(b64("abcdef"), "YWJjZGVm");
    }

    #[test]
    fn pct_encodes() {
        assert_eq!(pct("a b/c"), "a%20b%2Fc");
        assert_eq!(pct("abc-_.~"), "abc-_.~");
    }
}
