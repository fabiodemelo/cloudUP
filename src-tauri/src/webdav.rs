//! A compact WebDAV client (PROPFIND / GET / PUT / MKCOL / DELETE).
//!
//! Works against any WebDAV server (Nextcloud, ownCloud, nginx, IIS, ...).
//! Uses HTTP Basic authentication.

use crate::error::{Error, Result};
use reqwest::Client;
use roxmltree::Document;

#[derive(Clone)]
pub struct Webdav {
    pub base: String, // e.g. "https://example.com/remote"
    pub username: String,
    pub password: String,
    http: Client,
}

impl Webdav {
    pub fn new(base: &str, username: &str, password: &str) -> Self {
        let base = if base.trim().is_empty() {
            String::new()
        } else {
            let b = if base.contains("://") { base.to_string() } else { format!("https://{}", base) };
            b.trim_end_matches('/').to_string()
        };
        Self {
            base,
            username: username.to_string(),
            password: password.to_string(),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }

    fn url(&self, path: &str) -> String {
        let p = if path.starts_with('/') { path } else { &format!("/{}", path) };
        format!("{}{}", self.base, p)
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<reqwest::Response> {
        let url = self.url(path);
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Other(e.to_string()))?;
        let mut req = self.http.request(m, &url);
        if !self.username.is_empty() {
            req = req.header(reqwest::header::AUTHORIZATION, basic_auth(&self.username, &self.password));
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.body(b.to_vec());
        }
        let resp = req.send().await.map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Webdav { status: status.as_u16(), body: text });
        }
        Ok(resp)
    }

    /// List the children of a directory path. Returns entries (dirs + files).
    pub async fn list(&self, dir: &str) -> Result<Vec<WebdavEntry>> {
        let path = if dir.is_empty() || dir == "/" { "/".to_string() } else { dir.trim_end_matches('/').to_string() };
        let body = br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/><D:getlastmodified/><D:resourcetype/></D:prop></D:propfind>"#;
        let resp = self.request("PROPFIND", &path, &[("Depth", "1"), ("Content-Type", "application/xml")], Some(body)).await?;
        let xml = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        parse_multistatus(&xml, &path)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self.request("GET", path, &[], None).await?;
        Ok(resp.bytes().await.map_err(|e| Error::Http(e.to_string()))?.to_vec())
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.request("PUT", path, &[], Some(data)).await?;
        Ok(())
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.request("MKCOL", path, &[], None).await?;
        Ok(())
    }

    pub async fn remove(&self, path: &str) -> Result<()> {
        self.request("DELETE", path, &[], None).await?;
        Ok(())
    }
}

pub struct WebdavEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

fn basic_auth(user: &str, pass: &str) -> String {
    format!("Basic {}", base64(&format!("{}:{}", user, pass)))
}

// Minimal base64 (standard) to avoid an extra dependency for one use.
fn base64(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn parse_multistatus(xml: &str, dir: &str) -> Result<Vec<WebdavEntry>> {
    let doc = Document::parse(xml).map_err(|e| Error::Parse(e.to_string()))?;
    let root = doc.root_element();

    // The directory prefix to strip from child hrefs.
    let dir_prefix = if dir.is_empty() || dir == "/" { String::new() } else { dir.trim_end_matches('/').to_string() };

    let mut out = vec![];
    for response in root.descendants().filter(|n| n.has_tag_name("response")) {
        let href = response
            .children()
            .find(|n| n.has_tag_name("href"))
            .and_then(|n| n.text())
            .unwrap_or("")
            .to_string();

        // Skip the directory itself (first response).
        let clean = href.split('?').next().unwrap_or(&href);
        if clean == dir || (dir_prefix.is_empty() && (clean == "/" || clean.is_empty())) {
            continue;
        }

        // Determine the child's path relative to root.
        let rel = clean.strip_prefix(&dir_prefix).unwrap_or(clean);
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            continue;
        }

        // Last path segment is the display name.
        let name = rel.rsplit('/').next().unwrap_or(rel).to_string();

        // Properties.
        let prop = response.children().find(|n| n.has_tag_name("prop"));
        let is_dir = prop
            .and_then(|p| p.descendants().find(|n| n.has_tag_name("collection")))
            .is_some();
        let size = prop
            .and_then(|p| p.children().find(|n| n.has_tag_name("getcontentlength")))
            .and_then(|n| n.text())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let modified = prop
            .and_then(|p| p.children().find(|n| n.has_tag_name("getlastmodified")))
            .and_then(|n| n.text())
            .map(|s| s.to_string());

        let path = if dir_prefix.is_empty() {
            format!("/{}", rel)
        } else {
            format!("{}/{}", dir_prefix, rel)
        };

        out.push(WebdavEntry { name, path, is_dir, size, modified });
    }

    // Sort: directories first, then by name.
    out.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_joins_base_and_path() {
        let w = Webdav::new("https://example.com/remote", "u", "p");
        assert_eq!(w.url("a.txt"), "https://example.com/remote/a.txt");
        assert_eq!(w.url("/a.txt"), "https://example.com/remote/a.txt");
        assert_eq!(w.url("/dir/inner.txt"), "https://example.com/remote/dir/inner.txt");
        assert_eq!(w.url(""), "https://example.com/remote/");
        assert_eq!(w.url("/"), "https://example.com/remote/");
    }

    #[test]
    fn new_normalizes_base() {
        // No scheme -> https is prepended, trailing slash is stripped.
        let w = Webdav::new("example.com/remote/", "u", "p");
        assert_eq!(w.base, "https://example.com/remote");
        let w = Webdav::new("", "u", "p");
        assert_eq!(w.base, "");
        assert_eq!(w.url("f.txt"), "/f.txt");
    }

    #[test]
    fn basic_auth_is_base64() {
        // "user:pass" base64-encodes to a fixed value.
        assert_eq!(basic_auth("user", "pass"), "Basic dXNlcjpwYXNz");
    }
}
