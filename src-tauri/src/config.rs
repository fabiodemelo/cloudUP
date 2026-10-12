//! Connection model, persistence and secure credential storage.
//!
//! Secrets (passwords / secret keys) are never written to the plain config file.
//! They live in the OS credential store (macOS Keychain / Windows Credential
//! Manager) via the `keyring` crate. If that store is unavailable (e.g. a
//! headless environment), we transparently fall back to a local file so the app
//! keeps working.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// The kind of cloud / remote storage a connection talks to.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnType {
    S3,
    Webdav,
    Dropbox,
    Onedrive,
    GoogleDrive,
    Box,
    MEGA,
    Backblaze,
    OpenStack,
    Ftp,
    Sftp,
    Pcloud,
}

impl ConnType {
    pub fn label(self) -> &'static str {
        match self {
            ConnType::S3 => "Amazon S3",
            ConnType::Webdav => "WebDAV",
            ConnType::Dropbox => "Dropbox",
            ConnType::Onedrive => "OneDrive",
            ConnType::GoogleDrive => "Google Drive",
            ConnType::Box => "Box",
            ConnType::MEGA => "Mega",
            ConnType::Backblaze => "Backblaze",
            ConnType::OpenStack => "OpenStack Swift",
            ConnType::Ftp => "FTP & SFTP",
            ConnType::Sftp => "FTP & SFTP",
            ConnType::Pcloud => "pCloud",
        }
    }

    /// Whether this connection type is fully implemented in the current build.
    ///
    /// Everything works except SFTP (needs a native SSH library) and MEGA
    /// (proprietary client-side crypto), which remain "coming soon".
    pub fn functional(self) -> bool {
        !matches!(self, ConnType::Sftp | ConnType::MEGA)
    }

    /// True for the providers that authenticate via an OAuth2 PKCE flow.
    pub fn is_oauth(self) -> bool {
        matches!(self, ConnType::Dropbox | ConnType::GoogleDrive | ConnType::Onedrive | ConnType::Box)
    }

    /// Default endpoint hint shown as a placeholder in the form.
    pub fn default_endpoint(self) -> &'static str {
        match self {
            ConnType::S3 => "https://s3.amazonaws.com",
            ConnType::Backblaze => "https://s3.us-west-0.backblazeb2.com",
            ConnType::Webdav => "https://example.com/remote",
            ConnType::OpenStack => "https://auth.example.com/v3",
            ConnType::Ftp => "ftp.example.com",
            ConnType::Pcloud => "https://my.pcloud.com",
            _ => "",
        }
    }
}

/// A saved connection. Note: the secret is NOT stored here (see keyring helpers).
#[derive(Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ctype: ConnType,
    /// S3 server endpoint / WebDAV base URL.
    pub endpoint: String,
    /// S3 region (ignored by WebDAV).
    #[serde(default)]
    pub region: String,
    /// S3 access key id / WebDAV username.
    #[serde(default)]
    pub access_key: String,
    /// S3 bucket to mount / WebDAV sub-path. "/" = root.
    #[serde(default = "default_root")]
    pub bucket: String,
    /// Provider-specific extras (e.g. `project`, `port`, `client_id`).
    /// Common credentials reuse the fields above; this map holds the rest.
    #[serde(default)]
    pub fields: HashMap<String, String>,
}

fn default_root() -> String {
    "/".into()
}

fn empty_fields() -> HashMap<String, String> {
    HashMap::new()
}

impl Connection {
    pub fn new(ctype: ConnType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "New Connection".into(),
            ctype,
            endpoint: ctype.default_endpoint().into(),
            region: "us-east-1".into(),
            access_key: String::new(),
            bucket: "/".into(),
            fields: empty_fields(),
        }
    }

    /// Read a provider-specific extra field (empty string if absent).
    pub fn field(&self, key: &str) -> String {
        self.fields.get(key).cloned().unwrap_or_default()
    }

    /// Human friendly display name, e.g. "My S3 [mybucket]".
    pub fn display_name(&self) -> String {
        let bucket = self.bucket.trim_end_matches('/');
        if bucket.is_empty() || bucket == "/" {
            self.name.clone()
        } else {
            format!("{} [{}]", self.name, bucket)
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    connections: Vec<Connection>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self { connections: vec![] }
    }
}

/// On-disk location of the config + fallback secrets file.
pub fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("net.cloudmounter.app");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

fn secrets_path() -> PathBuf {
    data_dir().join("secrets.json")
}

const KEYRING_SERVICE: &str = "cloudmounter";

/// Load all saved connections.
pub fn load_connections() -> Result<Vec<Connection>, String> {
    let path = config_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: ConfigFile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(cfg.connections)
}

/// Persist all saved connections (secrets are handled separately).
pub fn save_connections(conns: &[Connection]) -> Result<(), String> {
    let cfg = ConfigFile { connections: conns.to_vec() };
    let raw = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(config_path(), raw).map_err(|e| e.to_string())
}

/// Insert or replace a connection (matched by id).
pub fn upsert(conn: Connection) -> Result<(), String> {
    let mut conns = load_connections()?;
    match conns.iter_mut().find(|c| c.id == conn.id) {
        Some(slot) => *slot = conn.clone(),
        None => conns.push(conn),
    }
    save_connections(&conns)
}

/// Remove a connection by id.
pub fn remove(id: &str) -> Result<(), String> {
    let mut conns = load_connections()?;
    conns.retain(|c| c.id != id);
    save_connections(&conns)
}

/// Store a secret in the OS keychain, falling back to a local file.
pub fn store_secret(id: &str, secret: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, id);
    match entry {
        Ok(e) => e.set_password(secret).map_err(|err| err.to_string()),
        Err(_) => write_fallback_secret(id, secret),
    }
}

/// Read a secret from the OS keychain, falling back to a local file.
pub fn read_secret(id: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, id);
    match entry {
        Ok(e) => match e.get_password() {
            Ok(pw) => Ok(Some(pw.to_string())),
            Err(keyring::Error::NoEntry) => read_fallback_secret(id),
            Err(err) => Ok(read_fallback_secret(id).ok().flatten().or(Some(err.to_string()))),
        },
        Err(_) => read_fallback_secret(id),
    }
}

/// Delete a secret from both stores.
pub fn delete_secret(id: &str) {
    let _ = keyring::Entry::new(KEYRING_SERVICE, id).and_then(|e| e.delete_password());
    // also drop from fallback file if present
    if let Ok(mut map) = read_fallback_map() {
        if map.remove(id).is_some() {
            let _ = write_fallback_map(&map);
        }
    }
}

// ---- fallback secret file (used only when the OS keychain is unavailable) ----

type SecretMap = std::collections::HashMap<String, String>;

fn read_fallback_map() -> Result<SecretMap, String> {
    let path = secrets_path();
    if !path.exists() {
        return Ok(std::collections::HashMap::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn write_fallback_map(map: &SecretMap) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(map).map_err(|e| e.to_string())?;
    std::fs::write(secrets_path(), raw).map_err(|e| e.to_string())
}

fn write_fallback_secret(id: &str, secret: &str) -> Result<(), String> {
    let mut map = read_fallback_map()?;
    map.insert(id.to_string(), secret.to_string());
    write_fallback_map(&map)
}

fn read_fallback_secret(id: &str) -> Result<Option<String>, String> {
    let map = read_fallback_map()?;
    Ok(map.get(id).cloned())
}
