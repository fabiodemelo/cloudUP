//! A compact WebDAV client (PROPFIND / GET / PUT / MKCOL / DELETE).
//!
//! Works against any WebDAV server (Nextcloud, ownCloud, nginx, IIS, ...).
//! Uses HTTP Basic authentication.

use crate::backend::{save_response, send_download, transfer_client, upload_timeout, FileBody};
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
        // Encode each segment ("My File#1" -> "My%20File%231"), keep the slashes.
        let enc: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .map(|seg| {
                seg.bytes()
                    .map(|b| match b {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                        _ => format!("%{b:02X}"),
                    })
                    .collect()
            })
            .collect();
        format!("{}/{}", self.base, enc.join("/"))
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<reqwest::Response> {
        let mut req = self.builder(&self.http, method, path)?;
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.body(b.to_vec());
        }
        check(req.send().await.map_err(Error::http)?).await
    }

    /// An authenticated request for `path` on `http`.
    fn builder(&self, http: &Client, method: &str, path: &str) -> Result<reqwest::RequestBuilder> {
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Other(e.to_string()))?;
        let mut req = http.request(m, self.url(path));
        if !self.username.is_empty() {
            req = req.header(reqwest::header::AUTHORIZATION, basic_auth(&self.username, &self.password));
        }
        Ok(req)
    }

    /// Stream a file into `dest`. Returns its size.
    pub async fn read_to_file(&self, path: &str, dest: &std::path::Path) -> Result<u64> {
        let req = self.builder(&transfer_client(), "GET", path)?;
        let resp = check(send_download(req).await?).await?;
        save_response(resp, dest).await
    }

    /// PUT a local file, streamed from disk.
    pub async fn write_from_file(&self, path: &str, src: &std::path::Path) -> Result<()> {
        let body = FileBody::whole(src).await?;
        let req = self
            .builder(&transfer_client(), "PUT", path)?
            .header(reqwest::header::CONTENT_LENGTH, body.content_len())
            .timeout(upload_timeout(body.content_len()))
            .body(body.body().await?);
        check(req.send().await.map_err(Error::http)?).await?;
        Ok(())
    }

    /// List the children of a directory path. Returns entries (dirs + files).
    pub async fn list(&self, dir: &str) -> Result<Vec<WebdavEntry>> {
        let path = if dir.is_empty() || dir == "/" { "/".to_string() } else { dir.trim_end_matches('/').to_string() };
        let body = br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/><D:getlastmodified/><D:resourcetype/></D:prop></D:propfind>"#;
        let resp = self.request("PROPFIND", &path, &[("Depth", "1"), ("Content-Type", "application/xml")], Some(body)).await?;
        let xml = resp.text().await.map_err(Error::http)?;
        parse_multistatus(&xml, &path, &self.base)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self.request("GET", path, &[], None).await?;
        Ok(resp.bytes().await.map_err(Error::http)?.to_vec())
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

/// Turn a non-2xx response into an `Error::Webdav`.
async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::Webdav { status: status.as_u16(), body: text });
    }
    Ok(resp)
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

/// Decode %XX escapes in an href (names arrive URL-encoded).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Path part of a URL ("https://h/remote" -> "/remote", "" if none).
fn url_path(url: &str) -> &str {
    match url.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or(""),
        None => url,
    }
}

/// Parse a PROPFIND (Depth: 1) reply for `dir` into its children.
/// `base` is the endpoint URL: hrefs are server paths that include its path.
fn parse_multistatus(xml: &str, dir: &str, base: &str) -> Result<Vec<WebdavEntry>> {
    let doc = Document::parse(xml).map_err(|e| Error::Parse(e.to_string()))?;
    let root = doc.root_element();
    let base_path = url_path(base).trim_end_matches('/').to_string();
    let dir = if dir.is_empty() || dir == "/" { String::new() } else { format!("/{}", dir.trim_matches('/')) };

    let mut out = vec![];
    for response in root.descendants().filter(|n| n.has_tag_name("response")) {
        let href = response
            .children()
            .find(|n| n.has_tag_name("href"))
            .and_then(|n| n.text())
            .unwrap_or("");
        // Href -> path relative to the endpoint, e.g. "/docs/My File.txt".
        let href = percent_decode(url_path(href.split('?').next().unwrap_or(href)));
        let rel = href.strip_prefix(&base_path).unwrap_or(&href);
        let rel = format!("/{}", rel.trim_matches('/'));
        let parent = rel.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        if rel == "/" || rel == dir || parent != dir {
            continue; // the folder itself (or anything not directly inside it)
        }
        let name = rel.rsplit('/').next().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }

        // Properties live in <propstat><prop>; failed ones come back empty.
        let text_of = |tag: &str| {
            response
                .descendants()
                .filter(|n| n.has_tag_name(tag))
                .find_map(|n| n.text().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string))
        };
        let is_dir = response.descendants().any(|n| n.has_tag_name("collection"));
        let size = if is_dir { 0 } else { text_of("getcontentlength").and_then(|s| s.parse().ok()).unwrap_or(0) };
        let modified = text_of("getlastmodified")
            .map(|s| chrono::DateTime::parse_from_rfc2822(&s).map(|d| d.to_rfc3339()).unwrap_or(s));

        out.push(WebdavEntry { name, path: rel, is_dir, size, modified });
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
        assert_eq!(w.url("/My Folder/a#1.txt"), "https://example.com/remote/My%20Folder/a%231.txt");
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

    // Apache mod_dav style: propstat/prop, lp1 prefixes, trailing slashes.
    const APACHE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:"><D:href>/remote/docs/</D:href><D:propstat><D:prop><lp1:resourcetype><D:collection/></lp1:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
<D:response xmlns:lp1="DAV:"><D:href>/remote/docs/My%20Folder/</D:href><D:propstat><D:prop><lp1:resourcetype><D:collection/></lp1:resourcetype><lp1:getlastmodified>Tue, 13 Oct 2026 20:47:46 GMT</lp1:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat><D:propstat><D:prop><D:getcontentlength/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response>
<D:response xmlns:lp1="DAV:"><D:href>/remote/docs/a%2Bb.txt</D:href><D:propstat><D:prop><lp1:resourcetype/><lp1:getcontentlength>42</lp1:getcontentlength><lp1:getlastmodified>Tue, 13 Oct 2026 20:47:46 GMT</lp1:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;

    #[test]
    fn parses_apache_listing() {
        let v = parse_multistatus(APACHE, "/docs", "https://h.example/remote").unwrap();
        assert_eq!(v.len(), 2, "the folder itself is skipped");
        assert_eq!(v[0].name, "My Folder");
        assert!(v[0].is_dir);
        assert_eq!(v[0].path, "/docs/My Folder");
        assert_eq!(v[0].modified.as_deref(), Some("2026-10-13T20:47:46+00:00"));
        assert_eq!(v[1].name, "a+b.txt");
        assert!(!v[1].is_dir);
        assert_eq!(v[1].size, 42);
        assert_eq!(v[1].path, "/docs/a+b.txt");
    }

    #[test]
    fn parses_root_listing_with_absolute_hrefs() {
        let xml = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>https://h.example/dav/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response><d:response><d:href>https://h.example/dav/x.bin</d:href><d:propstat><d:prop><d:getcontentlength>7</d:getcontentlength></d:prop></d:propstat></d:response></d:multistatus>"#;
        let v = parse_multistatus(xml, "/", "https://h.example/dav").unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].name.as_str(), v[0].path.as_str(), v[0].size), ("x.bin", "/x.bin", 7));
    }

    #[test]
    fn basic_auth_is_base64() {
        // "user:pass" base64-encodes to a fixed value.
        assert_eq!(basic_auth("user", "pass"), "Basic dXNlcjpwYXNz");
    }
}
