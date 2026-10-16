//! OpenStack Swift (object storage) client.
//!
//! Authenticates against Keystone v3 with a username/password, resolves the
//! object-store endpoint from the service catalog, then speaks plain Swift REST:
//! `GET ?format=json` for listings, PUT/DELETE for objects. Directories are the
//! usual zero-byte `prefix/` marker objects.
//!
//! Connection mapping:
//! - `endpoint`   = Keystone auth URL (e.g. `https://auth.example.com/v3`)
//! - `access_key` = username, `secret` = password
//! - `fields.project` / `user_domain` / `project_domain` = auth scope
//! - `bucket`     = container to mount (`/` = the whole account)

use crate::backend::{save_response, send_download, transfer_client, upload_timeout, FileBody};
use crate::error::{Error, Result};
use reqwest::Client;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Swift {
    pub auth_url: String, // e.g. "https://auth.example.com/v3"
    pub username: String,
    pub password: String,
    pub project: String,
    pub user_domain: String,
    pub project_domain: String,
    pub region: String,
    /// Container to mount; empty = account root (containers are the top level).
    pub container: String,
    http: Client,
    /// Bearer token + resolved storage URL. Filled lazily on first use and
    /// refreshed after a 401 (Keystone tokens expire).
    token: Arc<Mutex<Option<String>>>,
    storage_url: Arc<Mutex<Option<String>>>,
}

impl Swift {
    pub fn new(
        auth_url: &str,
        username: &str,
        password: &str,
        project: &str,
        user_domain: &str,
        project_domain: &str,
        region: &str,
        bucket: &str,
    ) -> Self {
        let auth_url = if auth_url.trim().is_empty() {
            String::new()
        } else {
            let a = if auth_url.contains("://") {
                auth_url.to_string()
            } else {
                format!("https://{}", auth_url)
            };
            a.trim_end_matches('/').to_string()
        };
        let container = bucket.trim_matches('/').to_string();
        Self {
            auth_url,
            username: username.trim().to_string(),
            password: password.to_string(),
            project: project.trim().to_string(),
            user_domain: user_domain.trim().to_string(),
            project_domain: project_domain.trim().to_string(),
            region: region.trim().to_string(),
            container,
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            token: Arc::new(Mutex::new(None)),
            storage_url: Arc::new(Mutex::new(None)),
        }
    }

    /// Authenticate (or reuse a live token). Resolves the storage URL from the
    /// Keystone service catalog.
    async fn ensure_auth(&self) -> Result<()> {
        if self.token.lock().unwrap().is_some() && self.storage_url.lock().unwrap().is_some() {
            return Ok(());
        }

        let mut user = serde_json::json!({
            "name": self.username,
            "password": self.password,
        });
        if !self.user_domain.is_empty() {
            user["domain"] = serde_json::json!({ "name": self.user_domain });
        }
        let mut scope_project = serde_json::json!({});
        if !self.project.is_empty() {
            scope_project["name"] = serde_json::json!(self.project);
        }
        if !self.project_domain.is_empty() {
            scope_project["domain"] = serde_json::json!({ "name": self.project_domain });
        }

        let body = serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": { "user": user }
                },
                "scope": { "project": scope_project }
            }
        });

        let url = format!("{}/v3/auth/tokens", self.auth_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(Error::http)?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api { provider: "OpenStack".into(), status: status.as_u16(), body: text });
        }

        let token = resp
            .headers()
            .get("x-subject-token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Parse(e.to_string()))?;

        let storage_url = find_object_store(&json, &self.region)
            .ok_or_else(|| Error::Api {
                provider: "OpenStack".into(),
                status: 0,
                body: "no object-store endpoint found in the Keystone service catalog".into(),
            })?;

        *self.token.lock().unwrap() = token;
        *self.storage_url.lock().unwrap() = Some(storage_url);
        Ok(())
    }

    /// Perform an authenticated request against the storage service.
    async fn request(
        &self,
        method: &str,
        path_and_query: &str, // e.g. "/container/key?format=json" (already encoded)
        body: Option<&[u8]>,
    ) -> Result<reqwest::Response> {
        self.ensure_auth().await?;

        let do_send = |bearer: String| async move {
            let url = format!("{}{}", self.storage_url.lock().unwrap().as_deref().unwrap_or(""), path_and_query);
            let m = reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|e| Error::Other(e.to_string()))?;
            let mut req = self.http.request(m, &url);
            if !bearer.is_empty() {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", bearer));
            }
            if let Some(b) = body {
                req = req.header(reqwest::header::CONTENT_TYPE, "application/octet-stream").body(b.to_vec());
            }
            req.send().await.map_err(Error::http)
        };

        let bearer = self.token.lock().unwrap().clone().unwrap_or_default();
        let resp = do_send(bearer).await?;
        // Token expired → re-auth once and retry.
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let _ = resp.text().await; // drain
            *self.token.lock().unwrap() = None;
            self.ensure_auth().await?;
            let bearer = self.token.lock().unwrap().clone().unwrap_or_default();
            return do_send(bearer).await;
        }

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api { provider: "OpenStack".into(), status: status.as_u16(), body: text });
        }
        Ok(resp)
    }

    /// A file transfer on the transfer client: GET into `dest`, or PUT
    /// `upload` (reopened from disk if the token has to be renewed).
    async fn transfer(&self, method: reqwest::Method, path: &str, upload: Option<&FileBody>) -> Result<reqwest::Response> {
        self.ensure_auth().await?;
        for attempt in 0..2 {
            let url = format!("{}{}", self.storage_url.lock().unwrap().as_deref().unwrap_or(""), path);
            let bearer = self.token.lock().unwrap().clone().unwrap_or_default();
            let mut req = transfer_client().request(method.clone(), &url);
            if !bearer.is_empty() {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", bearer));
            }
            let resp = match upload {
                Some(b) => req
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .header(reqwest::header::CONTENT_LENGTH, b.content_len())
                    .timeout(upload_timeout(b.content_len()))
                    .body(b.body().await?)
                    .send()
                    .await
                    .map_err(Error::http)?,
                None => send_download(req).await?,
            };
            // Token expired → re-auth once and retry.
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                *self.token.lock().unwrap() = None;
                self.ensure_auth().await?;
                continue;
            }
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Api { provider: "OpenStack".into(), status: status.as_u16(), body: text });
            }
            return Ok(resp);
        }
        Err(Error::Other("OpenStack: could not authenticate".into()))
    }

    // ------------------------------------------------------------- operations

    /// List the children of `dir` (relative to the mount root).
    pub async fn list(&self, dir: &str) -> Result<Vec<SwiftEntry>> {
        if self.container.is_empty() && (dir.is_empty() || dir == "/") {
            return self.list_containers().await;
        }

        // Determine (container, prefix). In account mode the first path segment is the container.
        let rel = dir.trim_start_matches('/').trim_end_matches('/');
        let (container, prefix) = if self.container.is_empty() {
            let mut parts = rel.splitn(2, '/');
            let c = parts.next().unwrap_or("").to_string();
            let rest = parts.next().unwrap_or("");
            (c, if rest.is_empty() { String::new() } else { format!("{}/", rest) })
        } else {
            (self.container.clone(), if rel.is_empty() { String::new() } else { format!("{}/", rel) })
        };

        let mut query = vec![("format".to_string(), "json".to_string()), ("delimiter".to_string(), "/".to_string())];
        if !prefix.is_empty() {
            query.push(("prefix".to_string(), pct(&prefix)));
        }
        let path = format!("/{}?{}", encode_path(&container), query_string(&query));

        let resp = self.request("GET", &path, None).await?;
        let json: serde_json::Value = resp.json().await.map_err(|e| Error::Parse(e.to_string()))?;

        let mut out = vec![];
        // Regular objects.
        if let Some(objects) = json.get("objects").and_then(|v| v.as_array()) {
            for o in objects {
                let name = o.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() || name.ends_with('/') {
                    continue; // zero-byte dir markers are represented via subdirs
                }
                if !prefix.is_empty() && !name.starts_with(&prefix) {
                    continue;
                }
                let tail = &name[prefix.len()..];
                if tail.is_empty() {
                    continue;
                }
                let display = tail.rsplit('/').next().unwrap_or(tail).to_string();
                let size = o.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                let modified = o.get("last_modified").and_then(|v| v.as_str()).map(|s| s.to_string());
                let path = if self.container.is_empty() {
                    format!("/{}", name) // account mode: include the container segment
                } else {
                    format!("/{}", tail)
                };
                out.push(SwiftEntry { name: display, path, is_dir: false, size, modified });
            }
        }
        // Sub-directories.
        if let Some(subs) = json.get("subdirs").and_then(|v| v.as_array()) {
            for s in subs {
                let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let tail = name.trim_end_matches('/');
                if !prefix.is_empty() && !tail.starts_with(&prefix) {
                    continue;
                }
                let rel_tail = tail[prefix.len()..].trim_end_matches('/');
                if rel_tail.is_empty() {
                    continue;
                }
                let display = rel_tail.rsplit('/').next().unwrap_or(rel_tail).to_string();
                let path = if self.container.is_empty() {
                    format!("/{}", tail)
                } else {
                    format!("/{}", rel_tail)
                };
                out.push(SwiftEntry { name: display, path, is_dir: true, size: 0, modified: None });
            }
        }

        out.sort_by(|a, b| {
            b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    /// List containers (account root).
    async fn list_containers(&self) -> Result<Vec<SwiftEntry>> {
        let resp = self.request("GET", "/?format=json", None).await?;
        let json: serde_json::Value = resp.json().await.map_err(|e| Error::Parse(e.to_string()))?;
        let mut out = vec![];
        if let Some(containers) = json.get("containers").and_then(|v| v.as_array()) {
            for c in containers {
                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let size = c.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                let path = format!("/{}", name);
                out.push(SwiftEntry { name, path, is_dir: true, size, modified: None });
            }
        }
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    /// Split a mount-root-relative path into (container, object key).
    fn split(&self, path: &str) -> (String, String) {
        let rel = path.trim_start_matches('/');
        if self.container.is_empty() {
            let mut parts = rel.splitn(2, '/');
            (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string())
        } else {
            (self.container.clone(), rel.to_string())
        }
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let (container, key) = self.split(path);
        let resp = self.request("GET", &format!("/{}{}", encode_path(&container), encode_path(&key)), None).await?;
        Ok(resp.bytes().await.map_err(Error::http)?.to_vec())
    }

    /// Stream an object into a local file. Returns its size.
    pub async fn read_to_file(&self, path: &str, dest: &std::path::Path) -> Result<u64> {
        let (container, key) = self.split(path);
        let url = format!("/{}{}", encode_path(&container), encode_path(&key));
        let resp = self.transfer(reqwest::Method::GET, &url, None).await?;
        save_response(resp, dest).await
    }

    /// PUT a local file as an object, streamed from disk (Swift takes up to
    /// 5 GB in one PUT).
    pub async fn write_from_file(&self, path: &str, src: &std::path::Path) -> Result<()> {
        let (container, key) = self.split(path);
        let url = format!("/{}{}", encode_path(&container), encode_path(&key));
        let body = FileBody::whole(src).await?;
        self.transfer(reqwest::Method::PUT, &url, Some(&body)).await?;
        Ok(())
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let (container, key) = self.split(path);
        self.request("PUT", &format!("/{}{}", encode_path(&container), encode_path(&key)), Some(data)).await?;
        Ok(())
    }

    /// Create a "directory" (zero-byte marker object with a trailing slash).
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let (container, key) = self.split(path);
        let marker = format!("{}/", key.trim_end_matches('/'));
        self.request("PUT", &format!("/{}{}", encode_path(&container), encode_path(&marker)), Some(b"")).await?;
        Ok(())
    }

    /// Delete a file, or (for directories) bulk-delete everything under the prefix.
    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let (container, key) = self.split(path);
        if is_dir || key.ends_with('/') {
            let prefix = pct(&format!("{}/", key.trim_end_matches('/')));
            self.request("POST", &format!("/{}?delete&prefix={}", encode_path(&container), prefix), None).await?;
        } else {
            self.request("DELETE", &format!("/{}{}", encode_path(&container), encode_path(&key)), None).await?;
        }
        Ok(())
    }

    /// List container names (for the "choose bucket" helper).
    pub async fn list_containers_names(&self) -> Result<Vec<String>> {
        Ok(self.list_containers().await?.into_iter().map(|e| e.name).collect())
    }
}

/// Find the object-store service URL in a Keystone v3 token response.
fn find_object_store(json: &serde_json::Value, region: &str) -> Option<String> {
    let services = json.pointer("/token/catalog/services")?.as_array()?;
    for svc in services {
        let is_object_store = svc
            .get("type")
            .and_then(|v| v.as_str())
            .map(|t| t == "object-store")
            .unwrap_or(false)
            || svc.get("name").and_then(|v| v.as_str()).map(|n| n.to_lowercase().contains("swift")).unwrap_or(false);
        if !is_object_store {
            continue;
        }
        let endpoints = svc.get("endpoints").and_then(|v| v.as_array())?;
        // Prefer a public endpoint in the requested region, then any public, then anything.
        let pick = |want_region: bool| {
            endpoints.iter().find(|e| {
                let iface = e.get("interface").and_then(|v| v.as_str()).unwrap_or("");
                let er = e.get("region").and_then(|v| v.as_str()).unwrap_or("");
                let region_ok = !want_region || er.is_empty() || er == region;
                (iface == "public" || iface.is_empty()) && region_ok
            })
        };
        if let Some(e) = pick(true).or_else(|| pick(false)) {
            return e.get("url").and_then(|v| v.as_str()).map(|s| s.trim_end_matches('/').to_string());
        }
    }
    None
}

pub struct SwiftEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

// --------------------------------------------------------------------- helpers

/// Percent-encode a string, encoding '/' too (for query values).
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Percent-encode a path, preserving '/' separators.
fn encode_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let trailing = trimmed.ends_with('/');
    let body = trimmed.trim_end_matches('/');
    let mut out = String::from("/");
    for (i, seg) in body.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        for b in seg.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
    }
    if trailing {
        out.push('/');
    }
    out
}

fn query_string(params: &[(String, String)]) -> String {
    params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_encodes_specials() {
        assert_eq!(pct("a b/c"), "a%20b%2Fc");
        assert_eq!(pct("abc-_.~"), "abc-_.~");
    }

    #[test]
    fn encode_path_preserves_slashes() {
        assert_eq!(encode_path("a b/c.txt"), "/a%20b/c.txt");
        assert_eq!(encode_path("/dir/"), "/dir/");
        assert_eq!(encode_path(""), "");
    }

    #[test]
    fn finds_object_store_endpoint() {
        let json = serde_json::json!({
            "token": {
                "catalog": {
                    "services": [
                        { "type": "compute", "name": "nova",
                          "endpoints": [{ "interface": "public", "url": "http://c/", "region": "" }] },
                        { "type": "object-store", "name": "swift",
                          "endpoints": [
                            { "interface": "internal", "url": "http://internal/", "region": "" },
                            { "interface": "public", "url": "http://public/v1/AUTH_x/", "region": "" }
                          ] }
                    ]
                }
            }
        });
        assert_eq!(find_object_store(&json, "").as_deref(), Some("http://public/v1/AUTH_x"));
    }

    #[test]
    fn finds_region_specific_endpoint() {
        let json = serde_json::json!({
            "token": {
                "catalog": {
                    "services": [
                        { "type": "object-store", "name": "swift",
                          "endpoints": [
                            { "interface": "public", "url": "http://east/", "region": "east" },
                            { "interface": "public", "url": "http://west/", "region": "west" }
                          ] }
                    ]
                }
            }
        });
        assert_eq!(find_object_store(&json, "west").as_deref(), Some("http://west")); // trailing slash is trimmed to avoid double slashes in request URLs
    }
}
