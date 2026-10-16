//! pCloud client (account email + password).
//!
//! CloudUp logs in once with `userinfo?getauth=1` (credentials in a POST
//! body, never in a URL) and uses the returned `auth` token for every other
//! call. pCloud keeps US and EU accounts on different API hosts:
//! `https://api.pcloud.com` and `https://eapi.pcloud.com`.
//!
//! Connection mapping:
//! - `endpoint`   = API host (default `https://api.pcloud.com`; the web
//!   addresses `my.pcloud.com` / `e.pcloud.com` are mapped to their API hosts)
//! - `access_key` = account email, `secret` = account password
//! - `bucket`     = folder to mount (e.g. `/photos`; `/` = the whole account)

use crate::error::{Error, Result};
use reqwest::Client;
use std::sync::Arc;

const PROVIDER: &str = "pCloud";
const US_API: &str = "https://api.pcloud.com";
const EU_API: &str = "https://eapi.pcloud.com";
/// pCloud result codes for "log in required" / "log in failed / expired".
const AUTH_ERRORS: [i64; 3] = [1000, 2000, 2094];
/// "This user is on another location": the account lives on the other host.
const OTHER_LOCATION: i64 = 2321;

#[derive(Clone)]
pub struct Pcloud {
    pub base: String,
    pub user: String,
    pub password: String,
    /// Folder to mount (absolute pCloud path, e.g. "/photos").
    pub bucket: String,
    /// Session: (API host, auth token), set on the first call.
    session: Arc<tokio::sync::Mutex<Option<(String, String)>>>,
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
        Self {
            base: api_host(base),
            user: user.trim().to_string(),
            password: password.to_string(),
            bucket: normalize_path(bucket),
            session: Arc::new(tokio::sync::Mutex::new(None)),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(300))
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

    /// Log in and return (host, auth token). Tries the configured host first
    /// and switches to the other region if pCloud says the account is there.
    async fn login(&self) -> Result<(String, String)> {
        let mut host = self.base.clone();
        for _ in 0..2 {
            let form = [
                ("getauth", "1"),
                ("logout", "1"),
                ("username", self.user.as_str()),
                ("password", self.password.as_str()),
            ];
            let req = self.http.post(format!("{host}/userinfo")).form(&form);
            match parse(send(req).await?).await? {
                Ok(json) => {
                    let auth = json
                        .get("auth")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::Parse("pCloud login: no auth token in the reply".into()))?;
                    return Ok((host, auth.to_string()));
                }
                Err((OTHER_LOCATION, _)) => host = if host == EU_API { US_API.into() } else { EU_API.into() },
                Err((code, msg)) => return Err(api_error(code, msg)),
            }
        }
        Err(api_error(OTHER_LOCATION, "the account's API host could not be found".into()))
    }

    async fn session(&self, renew: bool) -> Result<(String, String)> {
        let mut s = self.session.lock().await;
        if renew || s.is_none() {
            *s = Some(self.login().await?);
        }
        Ok(s.clone().unwrap_or_default())
    }

    /// Call a method with form parameters (POST), logging in again once if
    /// the session token has expired.
    async fn call(&self, op: &str, params: &[(&str, &str)]) -> Result<serde_json::Value> {
        for attempt in 0..2 {
            let (host, auth) = self.session(attempt > 0).await?;
            let mut form: Vec<(&str, &str)> = vec![("auth", auth.as_str())];
            form.extend_from_slice(params);
            let req = self.http.post(format!("{host}/{op}")).form(&form);
            match parse(send(req).await?).await? {
                Ok(json) => return Ok(json),
                Err((code, _)) if attempt == 0 && AUTH_ERRORS.contains(&code) => continue,
                Err((code, msg)) => return Err(api_error(code, msg)),
            }
        }
        Err(Error::Other("pCloud: could not log in".into()))
    }

    // ------------------------------------------------------------- operations

    /// List the children of a mount-relative directory.
    pub async fn list(&self, dir: &str) -> Result<Vec<PcloudEntry>> {
        let json = self.call("listfolder", &[("path", &self.abs(dir))]).await?;
        let mut out = vec![];
        if let Some(items) = json.pointer("/metadata/contents").and_then(|v| v.as_array()) {
            for it in items {
                let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() || name == "." || name == ".." {
                    continue;
                }
                let is_dir = it.get("isfolder").and_then(|v| v.as_bool()).unwrap_or(false);
                let size = it.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                let modified = it.get("modified").and_then(|v| v.as_str()).map(|s| s.to_string());
                let path = join_rel(dir, &name);
                out.push(PcloudEntry { name, path, is_dir, size, modified });
            }
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    /// Download a file: ask for a download link, then fetch it.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let json = self.call("getfilelink", &[("path", &self.abs(path)), ("forcedownload", "1")]).await?;
        let host = json.pointer("/hosts/0").and_then(|v| v.as_str());
        let link = json.get("path").and_then(|v| v.as_str());
        let (Some(host), Some(link)) = (host, link) else {
            return Err(Error::Parse("pCloud: no download link in the reply".into()));
        };
        let resp = send(self.http.get(format!("https://{host}{link}"))).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Api { provider: PROVIDER.into(), status: status.as_u16(), body: resp.text().await.unwrap_or_default() });
        }
        Ok(resp.bytes().await.map_err(Error::http)?.to_vec())
    }

    /// Upload a file, replacing any file of the same name (`uploadfile`).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let abs_path = self.abs(path);
        let slash = abs_path.rfind('/').unwrap_or(0);
        let parent = if slash == 0 { "/".to_string() } else { abs_path[..slash].to_string() };
        let name = abs_path[slash + 1..].to_string();
        for attempt in 0..2 {
            let (host, auth) = self.session(attempt > 0).await?;
            let boundary = format!("cloudup{}", uuid::Uuid::new_v4().simple());
            let file_name = name.replace(['"', '\r', '\n'], "_");
            let mut body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .into_bytes();
            body.extend_from_slice(data);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            // With a multipart body, pCloud reads the parameters from the URL.
            let req = self
                .http
                .post(format!("{host}/uploadfile"))
                .query(&[("auth", auth.as_str()), ("path", parent.as_str()), ("filename", name.as_str()), ("nopartial", "1")])
                .header(reqwest::header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
                .body(body);
            match parse(send(req).await?).await? {
                Ok(_) => return Ok(()),
                Err((code, _)) if attempt == 0 && AUTH_ERRORS.contains(&code) => continue,
                Err((code, msg)) => return Err(api_error(code, msg)),
            }
        }
        Err(Error::Other("pCloud: could not log in".into()))
    }

    /// Create a folder.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.call("createfolder", &[("path", &self.abs(path))]).await?;
        Ok(())
    }

    /// Delete a file, or a folder and everything in it.
    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let op = if is_dir { "deletefolderrecursive" } else { "deletefile" };
        self.call(op, &[("path", &self.abs(path))]).await?;
        Ok(())
    }

    /// List top-level folder names (for the "choose bucket" helper).
    pub async fn list_folders_names(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = Pcloud { bucket: "/".into(), ..self.clone() }
            .list("/")
            .await?
            .into_iter()
            .filter(|e| e.is_dir)
            .map(|e| e.name)
            .collect();
        out.sort();
        Ok(out)
    }
}

// --------------------------------------------------------------------- helpers

async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    req.header(reqwest::header::USER_AGENT, concat!("CloudUp/", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(Error::http)
}

/// pCloud answers HTTP 200 with `result: 0` on success, or a non-zero result
/// code and an `error` message.
async fn parse(resp: reqwest::Response) -> Result<std::result::Result<serde_json::Value, (i64, String)>> {
    let status = resp.status();
    let text = resp.text().await.map_err(Error::http)?;
    if !status.is_success() {
        return Err(Error::Api { provider: PROVIDER.into(), status: status.as_u16(), body: text });
    }
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| Error::Parse(e.to_string()))?;
    Ok(match json.get("result").and_then(|v| v.as_i64()).unwrap_or(0) {
        0 => Ok(json),
        code => Err((code, json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error").to_string())),
    })
}

fn api_error(code: i64, msg: String) -> Error {
    Error::Api { provider: PROVIDER.into(), status: u16::try_from(code).unwrap_or(0), body: format!("{msg} (code {code})") }
}

/// API host for what the user typed: the web addresses map to the API hosts.
fn api_host(base: &str) -> String {
    let b = base.trim().trim_end_matches('/');
    let b = if b.is_empty() {
        US_API.to_string()
    } else if b.contains("://") {
        b.to_string()
    } else {
        format!("https://{b}")
    };
    match b.as_str() {
        "https://my.pcloud.com" | "https://www.pcloud.com" | "https://pcloud.com" => US_API.into(),
        "https://e.pcloud.com" | "https://e1.pcloud.com" => EU_API.into(),
        _ => b,
    }
}

fn join_rel(dir: &str, name: &str) -> String {
    let d = dir.trim_matches('/');
    if d.is_empty() {
        format!("/{name}")
    } else {
        format!("/{d}/{name}")
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_path_joining() {
        let p = Pcloud::new("", "u@x.com", "pw", "/photos");
        assert_eq!(p.base, "https://api.pcloud.com");
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
    fn web_addresses_map_to_api_hosts() {
        assert_eq!(api_host(""), "https://api.pcloud.com");
        assert_eq!(api_host("https://my.pcloud.com/"), "https://api.pcloud.com");
        assert_eq!(api_host("e.pcloud.com"), "https://eapi.pcloud.com");
        assert_eq!(api_host("https://eapi.pcloud.com"), "https://eapi.pcloud.com");
    }

    #[test]
    fn child_paths_are_mount_relative() {
        assert_eq!(join_rel("/", "a.txt"), "/a.txt");
        assert_eq!(join_rel("/docs/", "a.txt"), "/docs/a.txt");
    }
}
