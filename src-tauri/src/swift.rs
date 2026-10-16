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
//!
//! Files over 5 GiB (Swift's limit for one object) are stored as a Static
//! Large Object: segments in `<container>_segments` (the python-swiftclient
//! convention, so they don't show up in the mounted folder) plus a manifest
//! listing each segment with its size and ETag. SLO rather than a Dynamic
//! Large Object because Swift checks that manifest when it is written, and
//! the object is then exactly those segments; a DLO is whatever a prefix
//! listing returns at read time, which an eventually consistent listing can
//! get wrong.

use crate::backend::{chunks, part_size, save_response, send_download, transfer_client, upload_timeout, FileBody};
use crate::error::{Error, Result};
use reqwest::{Client, Method};
use std::sync::{Arc, Mutex};

/// Largest object a single PUT may create (Swift's default `max_file_size`
/// is 5 GiB + 2 bytes).
const SLO_MIN: u64 = 5 * 1024 * 1024 * 1024;
/// Segment size: 1 GiB, or more for files that would need over 1,000
/// segments (SLO's default limit).
const SEGMENT_MIN: u64 = 1024 * 1024 * 1024;
const MAX_SEGMENTS: u64 = 1000;

/// A request body for `Swift::transfer`.
enum Payload<'a> {
    None,
    File(&'a FileBody),
    Json(&'a str),
}

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

    /// A request on the transfer client: a download, a PUT of a file
    /// (reopened from disk if the token has to be renewed), or a small JSON
    /// body (an SLO manifest, which Swift may take a while to check).
    async fn transfer(&self, method: Method, path: &str, payload: Payload<'_>, headers: &[(&str, &str)]) -> Result<reqwest::Response> {
        self.ensure_auth().await?;
        for attempt in 0..2 {
            let url = format!("{}{}", self.storage_url.lock().unwrap().as_deref().unwrap_or(""), path);
            let bearer = self.token.lock().unwrap().clone().unwrap_or_default();
            let mut req = transfer_client().request(method.clone(), &url);
            if !bearer.is_empty() {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", bearer));
            }
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let resp = match payload {
                Payload::File(b) => req
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .header(reqwest::header::CONTENT_LENGTH, b.content_len())
                    .timeout(upload_timeout(b.content_len()))
                    .body(b.body().await?)
                    .send()
                    .await
                    .map_err(Error::http)?,
                Payload::Json(j) => req
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .timeout(std::time::Duration::from_secs(900))
                    .body(j.to_string())
                    .send()
                    .await
                    .map_err(Error::http)?,
                Payload::None => send_download(req).await?,
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
        // `<name>_segments` holds the pieces of large files in `<name>`
        // (see the SLO upload): hide it next to its container.
        let names: std::collections::HashSet<String> = out.iter().map(|e| e.name.clone()).collect();
        out.retain(|e| !e.name.strip_suffix("_segments").is_some_and(|base| names.contains(base)));
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
        let resp = self.transfer(Method::GET, &url, Payload::None, &[]).await?;
        save_response(resp, dest).await
    }

    /// PUT a local file as an object, streamed from disk; over 5 GiB as a
    /// Static Large Object. Segments of a large object it replaces are
    /// deleted afterwards.
    pub async fn write_from_file(&self, path: &str, src: &std::path::Path) -> Result<()> {
        let (container, key) = self.split(path);
        let url = format!("/{}{}", encode_path(&container), encode_path(&key));
        let body = FileBody::whole(src).await?;
        let old = self.slo_segments(&url).await?;
        if body.len > SLO_MIN {
            self.put_slo(&container, &key, src, body.len).await?;
        } else {
            self.transfer(Method::PUT, &url, Payload::File(&body), &[]).await?;
        }
        for seg in old {
            let _ = self.request("DELETE", &encode_path(&seg), None).await;
        }
        Ok(())
    }

    /// Upload `src` as segments, then the manifest. Segments already sent
    /// are deleted if anything fails.
    async fn put_slo(&self, container: &str, key: &str, src: &std::path::Path, len: u64) -> Result<()> {
        let seg_container = format!("{container}_segments");
        // Creating a container that exists is a no-op (202).
        self.request("PUT", &format!("/{}", encode_path(&seg_container)), None).await?;
        let size = part_size(len, SEGMENT_MIN, MAX_SEGMENTS);
        // Time plus a random part: a replaced object's segments are deleted
        // afterwards, so the new ones must never share their names.
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let stamp = format!("{secs}.{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let mut done: Vec<Segment> = vec![];
        let result = async {
            for (i, (offset, n)) in chunks(len, size).into_iter().enumerate() {
                let path = format!("/{seg_container}/{}", segment_name(key, &stamp, len, size, i));
                let resp = self.transfer(Method::PUT, &encode_path(&path), Payload::File(&FileBody::range(src, offset, n)), &[]).await?;
                let etag = resp.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(|e| e.trim_matches('"').to_string());
                done.push(Segment { path, etag, size: n });
            }
            let manifest = manifest_json(&done);
            let url = format!("/{}{}?multipart-manifest=put", encode_path(container), encode_path(key));
            self.transfer(Method::PUT, &url, Payload::Json(&manifest), &[]).await.map(|_| ())
        }
        .await;
        if result.is_err() {
            for seg in &done {
                let _ = self.request("DELETE", &encode_path(&seg.path), None).await;
            }
        }
        result
    }

    /// The segment paths (`/container/object`) of the object at `url` if it
    /// is a Static Large Object; empty if it is a plain object or missing.
    async fn slo_segments(&self, url: &str) -> Result<Vec<String>> {
        let head = match self.transfer(Method::HEAD, url, Payload::None, &[]).await {
            Ok(r) => r,
            Err(Error::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        if !is_slo(head.headers()) {
            return Ok(vec![]);
        }
        let sep = if url.contains('?') { '&' } else { '?' };
        let resp = self.transfer(Method::GET, &format!("{url}{sep}multipart-manifest=get&format=raw"), Payload::None, &[]).await?;
        let json: serde_json::Value = resp.json().await.map_err(|e| Error::Parse(e.to_string()))?;
        Ok(manifest_paths(&json))
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
            let url = format!("/{}{}", encode_path(&container), encode_path(&key));
            let head = self.transfer(Method::HEAD, &url, Payload::None, &[]).await?;
            if is_slo(head.headers()) {
                // The manifest and its segments together. Swift answers 200
                // and reports the outcome in the body.
                let resp = self
                    .transfer(Method::DELETE, &format!("{url}?multipart-manifest=delete"), Payload::None, &[("Accept", "application/json")])
                    .await?;
                let body: serde_json::Value = resp.json().await.map_err(|e| Error::Parse(e.to_string()))?;
                bulk_delete_result(&body)?;
            } else {
                self.request("DELETE", &url, None).await?;
            }
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

/// One uploaded segment of a Static Large Object.
struct Segment {
    /// `/container/object`, not percent-encoded (as the manifest wants it).
    path: String,
    etag: Option<String>,
    size: u64,
}

/// Segment object name: `<key>/slo/<stamp>/<size>/<segment size>/<index>`
/// (python-swiftclient's layout), unique per upload through `stamp`.
fn segment_name(key: &str, stamp: &str, len: u64, size: u64, index: usize) -> String {
    format!("{}/slo/{stamp}/{len}/{size}/{index:08}", key.trim_matches('/'))
}

/// The `?multipart-manifest=put` body.
fn manifest_json(segments: &[Segment]) -> String {
    serde_json::Value::Array(
        segments
            .iter()
            .map(|s| serde_json::json!({ "path": s.path, "etag": s.etag, "size_bytes": s.size }))
            .collect(),
    )
    .to_string()
}

/// Segment paths from a `?multipart-manifest=get&format=raw` reply.
fn manifest_paths(json: &serde_json::Value) -> Vec<String> {
    json.as_array()
        .map(|a| a.iter().filter_map(|s| s.get("path").and_then(|p| p.as_str()).map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Whether HEAD headers describe a Static Large Object manifest.
fn is_slo(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("x-static-large-object")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Check a bulk-delete style JSON reply (`?multipart-manifest=delete`).
fn bulk_delete_result(body: &serde_json::Value) -> Result<()> {
    let status = body.get("Response Status").and_then(|v| v.as_str()).unwrap_or("");
    if status.starts_with('2') {
        return Ok(());
    }
    let code = status.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(0);
    Err(Error::Api { provider: "OpenStack".into(), status: code, body: body.to_string() })
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
    fn slo_manifest_and_segments() {
        let size = part_size(12 << 30, SEGMENT_MIN, MAX_SEGMENTS);
        assert_eq!(size, SEGMENT_MIN);
        assert_eq!(chunks(12 << 30, size).len(), 12);
        // Very large files get bigger segments instead of more than 1,000.
        let huge = 3u64 << 40;
        let size = part_size(huge, SEGMENT_MIN, MAX_SEGMENTS);
        assert!(chunks(huge, size).len() as u64 <= MAX_SEGMENTS);

        assert_eq!(segment_name("/dir/a b.iso", "1700000000.ab12cd34", 99, 10, 3), "dir/a b.iso/slo/1700000000.ab12cd34/99/10/00000003");
        let segs = [
            Segment { path: "/c_segments/x \"q\"/slo/1/2/1/00000000".into(), etag: Some("abc".into()), size: 1 },
            Segment { path: "/c_segments/x/slo/1/2/1/00000001".into(), etag: None, size: 1 },
        ];
        let json: serde_json::Value = serde_json::from_str(&manifest_json(&segs)).unwrap();
        assert_eq!(json[0]["path"], "/c_segments/x \"q\"/slo/1/2/1/00000000");
        assert_eq!(json[0]["etag"], "abc");
        assert_eq!(json[0]["size_bytes"], 1);
        assert!(json[1]["etag"].is_null(), "a missing ETag is sent as null (not checked)");
        assert_eq!(manifest_paths(&json), [segs[0].path.clone(), segs[1].path.clone()]);
    }

    #[test]
    fn slo_detection_and_delete_result() {
        let mut h = reqwest::header::HeaderMap::new();
        assert!(!is_slo(&h));
        h.insert("X-Static-Large-Object", "True".parse().unwrap());
        assert!(is_slo(&h));
        assert!(bulk_delete_result(&serde_json::json!({ "Response Status": "200 OK", "Errors": [] })).is_ok());
        let err = bulk_delete_result(&serde_json::json!({ "Response Status": "409 Conflict", "Errors": [["/c/x", "409"]] }));
        assert!(matches!(err, Err(Error::Api { status: 409, .. })));
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
