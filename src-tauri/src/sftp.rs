//! A minimal SFTP client built on the `ssh2` crate (OpenSSL-backed, via
//! `libssh2`).
//!
//! Connection mapping:
//! - `endpoint` = host, optionally `sftp://host:port` or `host:port`
//!   (`fields.port` overrides)
//! - `access_key` = username, `secret` = password **or** the contents of a
//!   private key (PEM). If `fields.key` points at an existing file, that
//!   file is used as the key instead.
//! - `bucket` = base directory to mount (`/` = root)
//!
//! The authenticated `Session` is established lazily on first use and kept in
//! an `Arc<Mutex>` so repeated browser operations reuse it. Any failure drops
//! the session; the next call reconnects.

use crate::error::{Error, Result};

use std::path::{Path, PathBuf};
use std::io::Read;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Sftp {
    host: String,
    port: u16,
    username: String,
    secret: String,
    /// Optional path to a private key file (wins over `secret` as key material).
    key_path: String,
    /// Base directory on the server; entry paths are relative to it.
    base: String,
    session: Arc<Mutex<Option<ssh2::Session>>>,
}

pub(crate) use crate::ftp::FtpEntry as SftpEntry;

impl Sftp {
    pub fn new(host: &str, port: u16, username: &str, secret: &str, key_path: &str, base: &str) -> Self {
        Self {
            host: host.trim().to_string(),
            port,
            username: username.trim().to_string(),
            secret: secret.to_string(),
            key_path: key_path.trim().to_string(),
            base: normalize_base(base),
            session: Arc::new(Mutex::new(None)),
        }
    }

    /// Turn a mount-relative path ("/a/b.txt") into a server-absolute path.
    fn abs(&self, path: &str) -> String {
        let rel = path.trim_start_matches('/');
        if self.base.is_empty() {
            format!("/{}", rel)
        } else if rel.is_empty() {
            self.base.clone()
        } else {
            format!("{}/{}", self.base, rel)
        }
    }

    fn rel_dir(dir: &str) -> String {
        dir.trim_matches('/').to_string()
    }

    /// Run a blocking op off the async runtime (ssh2 does blocking I/O).
    async fn block<T: Send + 'static>(&self, op: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
        tokio::task::spawn_blocking(op)
            .await
            .map_err(|e| Error::Other(format!("SFTP task: {e}")))?
    }

    /// Run `op` on a live, authenticated session. Reconnects on demand.
    fn run_session<T>(&self, op: impl FnOnce(&mut ssh2::Session) -> Result<T>) -> Result<T> {
        let mut guard = self.session.lock().unwrap();
        if guard.is_none() {
            let s = Self::connect(&self.host, self.port, &self.username, &self.secret, &self.key_path)?;
            *guard = Some(s);
        }
        let s = guard.as_mut().unwrap();
        match op(s) {
            Ok(t) => Ok(t),
            Err(e) => {
                *guard = None; // likely wedged; reconnect next time
                Err(e)
            }
        }
    }

    fn connect(host: &str, port: u16, username: &str, secret: &str, key_path: &str) -> Result<ssh2::Session> {
        let mut s = ssh2::Session::new().map_err(|e| Error::Other(format!("SFTP: {e}")))?;
        s.set_blocking(true);
        s.set_timeout(30_000); // ms
        let stream = std::net::TcpStream::connect((host, port))
            .map_err(|e| Error::Other(format!("SFTP connect: {e}")))?;
        s.set_tcp_stream(stream);
        s.handshake().map_err(|e| Error::Other(format!("SFTP handshake: {e}")))?;
        // Prefer an explicit key file; otherwise treat `secret` as a key if it
        // looks like PEM, else as a password.
        if !key_path.is_empty() && Path::new(key_path).exists() {
            s.userauth_pubkey_file(username, None, Path::new(key_path), None)
                .map_err(|e| Error::Other(format!("SFTP auth (key {key_path}): {e}")))?;
        } else if secret.trim_start().starts_with("-----BEGIN") {
            s.userauth_pubkey_memory(username, None, secret, None)
                .map_err(|e| Error::Other(format!("SFTP auth (key): {e}")))?;
        } else {
            s.userauth_password(username, secret)
                .map_err(|e| Error::Other(format!("SFTP auth: {e}")))?;
        }
        Ok(s)
    }

    fn sftp(s: &ssh2::Session) -> Result<ssh2::Sftp> {
        s.sftp().map_err(|e| Error::Other(format!("SFTP: {e}")))
    }

    // ------------------------------------------------------------- operations

    pub async fn list(&self, dir: &str) -> Result<Vec<SftpEntry>> {
        let rel = Self::rel_dir(dir);
        let server_path = self.abs(dir);
        let sftp = self.clone();
        self.block(
            move || {
                sftp.run_session(|s| {
                    let sftp = Self::sftp(s)?;
                    let mut out = vec![];
                    let items = sftp
                        .readdir(PathBuf::from(server_path).as_path())
                        .map_err(|e| Error::Other(format!("SFTP list: {e}")))?;
                    for (p, meta) in items {
                        let name = p
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .filter(|f| f != "." && f != "..")
                            .unwrap_or_default();
                        if name.is_empty() {
                            continue;
                        }
                        let is_dir = meta.is_dir();
                        let size = if is_dir { 0 } else { meta.size.unwrap_or(0) };
                        let modified = meta
                            .mtime
                            .and_then(|t| {
                                chrono::DateTime::from_timestamp(t as i64, 0).map(|d| d.to_rfc3339())
                            })
                            .or_else(|| {
                                meta.atime.and_then(|t| {
                                    chrono::DateTime::from_timestamp(t as i64, 0).map(|d| d.to_rfc3339())
                                })
                            });
                        let perms = meta.perm.map(|m| mode_string(is_dir, m));
                        out.push(SftpEntry {
                            perms,
                            path: if rel.is_empty() { format!("/{}", name) } else { format!("/{rel}/{}", name) },
                            name,
                            is_dir,
                            size,
                            modified,
                        });
                    }
                    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                    Ok(out)
                })
            }
        )
        .await
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let server_path = self.abs(path);
        let sftp = self.clone();
        self.block(
            move || {
                sftp.run_session(|s| {
                    let sftp = Self::sftp(s)?;
                    let mut file = sftp
                        .open(Path::new(&server_path))
                        .map_err(|e| Error::Other(format!("SFTP open: {e}")))?;
                    let mut buf = Vec::new();
                    file.read_to_end(&mut buf).map_err(|e| Error::Other(format!("SFTP read: {e}")))?;
                    Ok(buf)
                })
            }
        )
        .await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let server_path = self.abs(path);
        let body = data.to_vec();
        let sftp = self.clone();
        self.block(
            move || {
                sftp.run_session(|s| {
                    let sftp = Self::sftp(s)?;
                    // Create (truncating) and write.
                    let mut file = sftp
                        .create(Path::new(&server_path))
                        .map_err(|e| Error::Other(format!("SFTP create: {e}")))?;
                    file.write_all(&body).map_err(|e| Error::Other(format!("SFTP write: {e}")))?;
                    Ok(())
                })
            }
        )
        .await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let server_path = self.abs(path.trim_end_matches('/'));
        let sftp = self.clone();
        self.block(
            move || {
                sftp.run_session(|s| {
                    let sftp = Self::sftp(s)?;
                    sftp.mkdir(Path::new(&server_path), 0o755)
                        .map_err(|e| Error::Other(format!("SFTP mkdir: {e}")))
                })
            }
        )
        .await
    }

    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let server_path = self.abs(path);
        let sftp = self.clone();
        self.block(
            move || {
                sftp.run_session(|s| {
                    let sftp = Self::sftp(s)?;
                    if is_dir {
                        sftp.rmdir(Path::new(&server_path))
                    } else {
                        sftp.unlink(Path::new(&server_path))
                    }
                    .map_err(|e| Error::Other(format!("SFTP remove: {e}")))
                })
            }
        )
        .await
    }
}

fn normalize_base(base: &str) -> String {
    let b = base.trim_matches('/');
    if b.is_empty() {
        String::new()
    } else {
        format!("/{}", b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_path_joining() {
        let sftp = Sftp::new("sftp.example.com", 22, "u", "p", "", "/data");
        assert_eq!(sftp.abs("/x.txt"), "/data/x.txt");
        assert_eq!(sftp.abs("x.txt"), "/data/x.txt");
        assert_eq!(sftp.abs("/"), "/data");
        let root = Sftp::new("h", 22, "u", "p", "", "/");
        assert_eq!(root.abs("/x.txt"), "/x.txt");
    }

    #[test]
    fn normalizes_base() {
        assert_eq!(normalize_base("/a/b/"), "/a/b");
        assert_eq!(normalize_base("a/b"), "/a/b");
        assert_eq!(normalize_base("/"), "");
    }
}

/// Render a Unix mode as `ls -l` style text, e.g. 0o40755 -> "drwxr-xr-x".
fn mode_string(is_dir: bool, mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(if is_dir { 'd' } else if mode & 0o170000 == 0o120000 { 'l' } else { '-' });
    for shift in [6, 3, 0] {
        let b = (mode >> shift) & 7;
        s.push(if b & 4 != 0 { 'r' } else { '-' });
        s.push(if b & 2 != 0 { 'w' } else { '-' });
        s.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    s
}

#[cfg(test)]
mod mode_tests {
    #[test]
    fn mode_string_matches_ls() {
        assert_eq!(super::mode_string(true, 0o40755), "drwxr-xr-x");
        assert_eq!(super::mode_string(false, 0o100640), "-rw-r-----");
    }
}
