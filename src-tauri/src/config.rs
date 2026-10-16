//! Connection model, persistence and secure credential storage.
//!
//! Secrets (passwords / secret keys) are never written to the plain config file.
//! They live in the OS credential store (macOS Keychain / Windows Credential
//! Manager) via the `keyring` crate. If that store is unavailable (e.g. a
//! headless environment), we transparently fall back to a local file so the app
//! keeps working.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    /// Every connection type in a stable order, for iterating/deriving lists.
    pub const ALL: [ConnType; 12] = [
        ConnType::S3,
        ConnType::Webdav,
        ConnType::Dropbox,
        ConnType::Onedrive,
        ConnType::GoogleDrive,
        ConnType::Box,
        ConnType::MEGA,
        ConnType::Backblaze,
        ConnType::OpenStack,
        ConnType::Ftp,
        ConnType::Sftp,
        ConnType::Pcloud,
    ];

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

    /// Whether this connection type is fully implemented in the current build
    /// (the UI hides the others). Every type is, in every build: MEGA runs
    /// natively too (see mega.rs), so the Mac App Store build has it as well.
    pub fn functional(self) -> bool {
        true
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
            ConnType::Sftp => "sftp.example.com",
            ConnType::Pcloud => "https://api.pcloud.com",
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
    /// When these settings last changed (RFC 3339, set by [`upsert`]). Sync
    /// keeps the newer copy of each connection; empty for configs saved
    /// before accounts existed, which then count as the oldest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
    /// When the keychain secret changed without the settings changing (an
    /// OAuth token refresh, see [`touch_secret`]). Sync compares secrets by
    /// the later of this and `updated_at`, so a rotated refresh token reaches
    /// the other Macs without overriding their setting edits.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_updated_at: String,
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
            updated_at: String::new(),
            secret_updated_at: String::new(),
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

/// On-disk location of the config + fallback secrets file. The environment
/// variable `CLOUDUP_DATA_DIR` replaces it (tests simulate several Macs).
pub fn data_dir() -> PathBuf {
    let dir = match std::env::var_os("CLOUDUP_DATA_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("net.cloudup.app"),
    };
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

fn secrets_path() -> PathBuf {
    data_dir().join("secrets.json")
}

const KEYRING_SERVICE: &str = "cloudup";

/// The keychain item for `id`, or None to use the fallback file: when the
/// keychain can't be opened, or when `CLOUDUP_NO_KEYCHAIN` is set (tests,
/// which must not touch the user's keychain).
fn keychain_entry(id: &str) -> Option<keyring::Entry> {
    if std::env::var_os("CLOUDUP_NO_KEYCHAIN").is_some() {
        return None;
    }
    keyring::Entry::new(KEYRING_SERVICE, id).ok()
}

/// SFTP host keys CloudUp trusted on first use (see `sftp.rs`).
pub fn known_hosts_path() -> PathBuf {
    data_dir().join("known_hosts")
}

/// Held while connections are read and written back, so a sync merging in
/// changes from other Macs can't interleave with a save in the app.
pub fn edit_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The current time as RFC 3339 UTC with milliseconds, the `updated_at` format.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Load all saved connections. Field secrets (see [`FIELD_SECRETS`]) are not
/// included: [`with_field_secrets`] adds them where a backend needs them.
pub fn load_connections() -> Result<Vec<Connection>, String> {
    let path = config_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    tighten_permissions();
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: ConfigFile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let mut conns = cfg.connections;
    // Before 1.2 OAuth client secrets were saved in config.json: move them to
    // the keychain the first time it's read.
    let mut moved = false;
    for c in conns.iter_mut() {
        moved |= stash_field_secrets(c);
    }
    if moved {
        save_connections(&conns)?;
    }
    Ok(conns)
}

/// config.json and secrets.json written before 1.1.4 may be readable by
/// other users (0644): make them 0600. Once per run.
fn tighten_permissions() {
    use std::os::unix::fs::PermissionsExt;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for path in [config_path(), secrets_path()] {
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.permissions().mode() & 0o077 != 0 {
                    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
                        eprintln!("[cloudup] could not make {} private: {e}", path.display());
                    }
                }
            }
        }
    });
}

// ---- secrets kept in `fields` by the backends, stored in the keychain ----

/// Connection fields that hold a credential. They live in the keychain under
/// `<id>#<field>`, never in config.json.
pub const FIELD_SECRETS: &[&str] = &["client_secret"];

pub(crate) fn field_secret_id(id: &str, key: &str) -> String {
    format!("{id}#{key}")
}

/// Move a connection's field secrets into the keychain and out of `fields`.
/// An empty value keeps the stored one (the edit form sends what it shows).
/// Returns whether `fields` changed. A secret the keychain refuses stays in
/// `fields`, so it is never lost.
fn stash_field_secrets(conn: &mut Connection) -> bool {
    let mut changed = false;
    for key in FIELD_SECRETS {
        let Some(value) = conn.fields.get(*key).cloned() else { continue };
        if !value.trim().is_empty() {
            if let Err(e) = store_secret(&field_secret_id(&conn.id, key), &value) {
                eprintln!("[cloudup] could not save the {key} of {} in the keychain: {e}", conn.name);
                continue;
            }
        }
        conn.fields.remove(*key);
        changed = true;
    }
    changed
}

/// `conn` with its field secrets filled in from the keychain (OAuth client
/// secret), for building a backend. A value already in `fields` (typed in the
/// form, not saved yet) wins.
pub fn with_field_secrets(mut conn: Connection) -> Connection {
    if !conn.ctype.is_oauth() {
        return conn;
    }
    for key in FIELD_SECRETS {
        if conn.field(key).trim().is_empty() {
            if let Ok(Some(v)) = read_secret(&field_secret_id(&conn.id, key)) {
                conn.fields.insert(key.to_string(), v);
            }
        }
    }
    conn
}

/// A stored field secret (`key` must be one of [`FIELD_SECRETS`]).
pub fn read_field_secret(id: &str, key: &str) -> Option<String> {
    if !FIELD_SECRETS.contains(&key) {
        return None;
    }
    read_secret(&field_secret_id(id, key)).ok().flatten()
}

/// Store a field secret (`key` must be one of [`FIELD_SECRETS`]).
pub fn store_field_secret(id: &str, key: &str, value: &str) -> Result<(), String> {
    if !FIELD_SECRETS.contains(&key) {
        return Err(format!("{key} is not a secret field"));
    }
    store_secret(&field_secret_id(id, key), value)
}

/// Delete a connection's field secrets.
pub fn delete_field_secrets(id: &str) {
    for key in FIELD_SECRETS {
        delete_secret(&field_secret_id(id, key));
    }
}

// ---- SFTP key files ----

/// Field holding a security-scoped bookmark (base64) for the SFTP key file
/// in `fields.key`. The sandboxed build can only reopen the file through it.
pub const KEY_BOOKMARK: &str = "key_bookmark";

/// Bookmark the SFTP key file when a connection is saved. If that isn't
/// possible right now (the unsandboxed build may not need or get one), keep
/// the bookmark saved earlier for the same file.
fn refresh_key_bookmark(conn: &mut Connection, prev: Option<&Connection>) {
    let key = conn.field("key").trim().to_string();
    if conn.ctype != ConnType::Sftp || key.is_empty() {
        conn.fields.remove(KEY_BOOKMARK);
        return;
    }
    #[cfg(target_os = "macos")]
    if let Ok(b) = crate::macos::bookmark(&crate::sftp::expand_tilde(&key)) {
        conn.fields.insert(KEY_BOOKMARK.into(), b);
        return;
    }
    match prev.filter(|p| p.field("key").trim() == key).map(|p| p.field(KEY_BOOKMARK)).filter(|b| !b.is_empty()) {
        Some(b) => conn.fields.insert(KEY_BOOKMARK.into(), b),
        None => conn.fields.remove(KEY_BOOKMARK),
    };
}

/// The bookmark saved for an SFTP key file path, if any connection has one.
pub fn key_bookmark(key_path: &str) -> Option<String> {
    let key_path = key_path.trim();
    if key_path.is_empty() {
        return None;
    }
    load_connections()
        .ok()?
        .into_iter()
        .find(|c| c.ctype == ConnType::Sftp && c.field("key").trim() == key_path && !c.field(KEY_BOOKMARK).is_empty())
        .map(|c| c.field(KEY_BOOKMARK))
}

/// Persist all saved connections (secrets are handled separately).
pub fn save_connections(conns: &[Connection]) -> Result<(), String> {
    let cfg = ConfigFile { connections: conns.to_vec() };
    let raw = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    write_private(&config_path(), raw.as_bytes())
}

/// Write a file readable only by the user (0600), atomically: a crash or a
/// full disk mid-write leaves the previous file intact.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Insert or replace a connection (matched by id) and stamp `updated_at`.
/// Field secrets go to the keychain (an empty one keeps the stored value); an
/// SFTP key file gets a security-scoped bookmark.
pub fn upsert(mut conn: Connection) -> Result<(), String> {
    let _guard = edit_lock();
    let mut conns = load_connections()?;
    conn.updated_at = now_rfc3339();
    stash_field_secrets(&mut conn);
    let prev = conns.iter().find(|c| c.id == conn.id).cloned();
    refresh_key_bookmark(&mut conn, prev.as_ref());
    match conns.iter_mut().find(|c| c.id == conn.id) {
        Some(slot) => *slot = conn,
        None => conns.push(conn),
    }
    save_connections(&conns)
}

/// Record that a connection's keychain secret changed on its own (an OAuth
/// token refresh) by stamping `secret_updated_at`. No-op for an unknown id.
pub fn touch_secret(id: &str) -> Result<(), String> {
    let _guard = edit_lock();
    let mut conns = load_connections()?;
    let Some(c) = conns.iter_mut().find(|c| c.id == id) else { return Ok(()) };
    c.secret_updated_at = now_rfc3339();
    save_connections(&conns)
}

/// Remove a connection by id.
pub fn remove(id: &str) -> Result<(), String> {
    let _guard = edit_lock();
    let mut conns = load_connections()?;
    conns.retain(|c| c.id != id);
    save_connections(&conns)
}

/// Store a secret in the OS keychain, falling back to a local file.
pub fn store_secret(id: &str, secret: &str) -> Result<(), String> {
    match keychain_entry(id) {
        Some(e) => e.set_password(secret).map_err(|err| err.to_string()),
        None => write_fallback_secret(id, secret),
    }
}

/// Read a secret from the OS keychain, falling back to a local file.
pub fn read_secret(id: &str) -> Result<Option<String>, String> {
    match keychain_entry(id) {
        Some(e) => match e.get_password() {
            Ok(pw) => Ok(Some(pw.to_string())),
            Err(keyring::Error::NoEntry) => read_fallback_secret(id),
            // Locked or denied keychain: use the fallback file if it has the
            // secret, otherwise report the error (never pass it on as a password).
            Err(err) => match read_fallback_secret(id) {
                Ok(Some(s)) => Ok(Some(s)),
                _ => Err(format!("could not read the saved password from the keychain: {err}")),
            },
        },
        None => read_fallback_secret(id),
    }
}

/// Delete a secret from both stores.
pub fn delete_secret(id: &str) {
    if let Some(e) = keychain_entry(id) {
        let _ = e.delete_password();
    }
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
    write_private(&secrets_path(), raw.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_serializes_type_and_fields_round_trip() {
        let mut c = Connection::new(ConnType::Dropbox);
        c.id = "conn-1".into();
        c.name = "My Dropbox".into();
        c.endpoint = "https://api.dropboxapi.com/2".into();
        c.bucket = "/".into();
        c.fields.insert("client_id".into(), "abc123".into());
        c.fields.insert("region".into(), "".into());

        let json = serde_json::to_string(&c).unwrap();
        // The `type` rename must appear, not `ctype`.
        assert!(json.contains("\"type\":\"dropbox\""), "expected renamed type field, got: {json}");
        assert!(!json.contains("\"ctype\""));
        // Provider extras must be preserved.
        assert!(json.contains("\"client_id\":\"abc123\""), "fields not serialized: {json}");

        let back: Connection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ctype, ConnType::Dropbox);
        assert_eq!(back.id, "conn-1");
        assert_eq!(back.name, "My Dropbox");
        assert_eq!(back.bucket, "/");
        assert_eq!(back.field("client_id"), "abc123");
    }

    #[test]
    fn missing_optional_fields_default() {
        // `fields` is optional (serde default) — omitting it must deserialize fine.
        let json = r#"{"id":"x","name":"n","type":"s3","endpoint":"e","region":"","access_key":"","bucket":"/"}"#;
        let c: Connection = serde_json::from_str(json).unwrap();
        assert_eq!(c.ctype, ConnType::S3);
        assert!(c.fields.is_empty());
        assert_eq!(c.field("client_id"), "");
    }

    #[test]
    fn field_returns_empty_for_missing_key() {
        let c = Connection::new(ConnType::S3);
        assert_eq!(c.field("does-not-exist"), "");
    }

    #[test]
    fn conn_type_functional_flags() {
        assert!(ConnType::S3.functional());
        assert!(ConnType::Webdav.functional());
        assert!(ConnType::Sftp.functional());
        assert!(ConnType::MEGA.functional());
    }

    #[test]
    fn empty_field_secret_keeps_the_stored_one() {
        // Nothing to store (so no keychain access), but the empty value must
        // not reach config.json.
        let mut c = Connection::new(ConnType::Dropbox);
        c.fields.insert("client_secret".into(), "  ".into());
        c.fields.insert("client_id".into(), "id".into());
        assert!(stash_field_secrets(&mut c));
        assert!(!c.fields.contains_key("client_secret"));
        assert_eq!(c.field("client_id"), "id");
        assert!(!stash_field_secrets(&mut c));
    }

    #[test]
    fn key_bookmark_only_for_sftp_key_files() {
        let mut c = Connection::new(ConnType::Sftp);
        c.fields.insert(KEY_BOOKMARK.into(), "stale".into());
        refresh_key_bookmark(&mut c, None);
        assert!(!c.fields.contains_key(KEY_BOOKMARK), "no key file, no bookmark");

        // A file that can't be bookmarked keeps the earlier bookmark for the
        // same path, and drops it for a different one.
        let mut prev = Connection::new(ConnType::Sftp);
        prev.fields.insert("key".into(), "/nonexistent/id_ed25519".into());
        prev.fields.insert(KEY_BOOKMARK.into(), "b64".into());
        let mut same = prev.clone();
        same.fields.remove(KEY_BOOKMARK);
        refresh_key_bookmark(&mut same, Some(&prev));
        assert_eq!(same.field(KEY_BOOKMARK), "b64");
        let mut other = same.clone();
        other.fields.insert("key".into(), "/nonexistent/other".into());
        refresh_key_bookmark(&mut other, Some(&prev));
        assert!(!other.fields.contains_key(KEY_BOOKMARK));
    }

    #[test]
    fn conn_type_is_oauth_flags() {
        assert!(ConnType::Dropbox.is_oauth());
        assert!(ConnType::Box.is_oauth());
        assert!(!ConnType::S3.is_oauth());
        assert!(!ConnType::Ftp.is_oauth());
    }
}
