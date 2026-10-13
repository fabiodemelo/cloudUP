//! MEGA backend (email + password login with the official mega SDK).
//!
//! MEGA's file format is proprietary (client-side AES-GCM crypto), so instead
//! of re-implementing the protocol we shell out to the `mega` command-line
//! client (https://megatools.gitlab.io/megatools/ or the official `mega`) and
//! copy data through temporary local files. First run triggers the SDK's
//! key derivation (a few seconds).
//!
//! Connection mapping:
//! - `endpoint`   = SDK host (default `https://mega.nz`)
//! - `access_key` = MEGA email, `secret` = MEGA password
//! - `bucket`     = folder to mount (`/` = the whole root)
//!
//! The `mega` binary must be installed for MEGA connections to work; every
//! operation surfaces a clear error if it is missing.

use crate::error::{Error, Result};
use std::process::Command;

#[derive(Clone)]
pub struct Mega {
    host: String,
    email: String,
    password: String,
    /// Folder to mount (absolute MEGA path, e.g. "/photos").
    bucket: String,
    /// Where `mega` stores its derived keys (writable dir).
    config_dir: String,
}

pub struct MegaEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

impl Mega {
    pub fn new(host: &str, email: &str, password: &str, bucket: &str) -> Self {
        let host = if host.trim().is_empty() {
            "https://mega.nz".to_string()
        } else {
            if host.contains("://") { host.to_string() } else { format!("https://{}", host) }
        };
        let config_dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("net.cloudup.app")
            .join("mega");
        let _ = std::fs::create_dir_all(&config_dir);
        Self {
            host: host.trim_end_matches('/').to_string(),
            email: email.trim().to_string(),
            password: password.to_string(),
            bucket: normalize_path(bucket),
            config_dir: config_dir.to_string_lossy().to_string(),
        }
    }

    /// Absolute MEGA path for a mount-relative path.
    fn abs(&self, path: &str) -> String {
        let rel = path.trim_matches('/');
        let b = self.bucket.trim_matches('/');
        if b.is_empty() {
            if rel.is_empty() { "/".into() } else { format!("/{rel}") }
        } else {
            if rel.is_empty() { format!("/{b}") } else { format!("/{b}/{rel}") }
        }
    }

    fn url(&self, path: &str) -> String {
        let abs = self.abs(path);
        format!("mega://{abs}",)
    }

    /// Run a megatools command with our credentials + config dir.
    fn run(&self, args: &[String]) -> Result<String> {
        let out = Command::new("mega")
            .arg("--username").arg(&self.email)
            .arg("--password").arg(&self.password)
            .arg("--config").arg(&self.config_dir)
            .args(args)
            .output()
            .map_err(|e| Error::Other(format!("MEGA: `mega` binary not found or not runnable — install megatools ({e})")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::Api { provider: "MEGA".into(), status: 1, body: stderr.trim().to_string() });
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    fn run_with_file(&self, args: &[String], stdin_file: &str) -> Result<()> {
        let mut a: Vec<String> = vec!["--username".into(), self.email.clone(), "--password".into(), self.password.clone(), "--config".into(), self.config_dir.clone()];
        a.extend_from_slice(args);
        a.push(stdin_file.to_string());
        let out = Command::new("mega").args(&a).output()
            .map_err(|e| Error::Other(format!("MEGA: `mega` binary not found or not runnable — install megatools ({e})")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::Api { provider: "MEGA".into(), status: 1, body: stderr.trim().to_string() });
        }
        Ok(())
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<MegaEntry>> {
        let abs = self.abs(dir);
        let url = format!("mega://{abs}");
        let rel = dir.trim_matches('/').to_string();
        let mega = self.clone();
        self.block(move || {
            let out = mega.run(&["ls".into(), "--long".into(), url])?;
            let mut entries = vec![];
            for line in out.lines() {
                let line = line.trim_end();
                if line.is_empty() { continue; }
                // mega ls --long: [TYPE]  SIZE  mtime  name...
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 { continue; }
                let is_dir = parts[0].ends_with('d') || parts[0].contains('d');
                let size = parts[1].parse::<u64>().unwrap_or(0);
                let modified = Some(parts[2].to_string());
                let name = parts[3..].join(" ");
                if name.is_empty() { continue; }
                entries.push(MegaEntry {
                    name: name.to_string(),
                    path: if rel.is_empty() { format!("/{name}", name = name) } else { format!("/{rel}/{name}") },
                    is_dir,
                    size: if is_dir { 0 } else { size },
                    modified,
                });
            }
            entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
            Ok(entries)
        })
        .await
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let abs = self.abs(path);
        let url = format!("mega://{abs}");
        let mega = self.clone();
        self.block(move || {
            let tmp = temp_path("dl");
            mega.run(&["get".into(), url, tmp.clone()])?;
            let bytes = std::fs::read(&tmp).map_err(|e| Error::Other(format!("MEGA: {e}")))?;
            let _ = std::fs::remove_file(&tmp);
            Ok(bytes)
        })
        .await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let abs = self.abs(path);
        let url = format!("mega://{abs}");
        let data = data.to_vec();
        let mega = self.clone();
        self.block(move || {
            let tmp = temp_path("ul");
            std::fs::write(&tmp, &data).map_err(|e| Error::Other(format!("MEGA: {e}")))?;
            mega.run(&["put".into(), url, tmp.clone()])?;
            let _ = std::fs::remove_file(&tmp);
            Ok(())
        })
        .await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let abs = self.abs(path.trim_end_matches('/'));
        let url = format!("mega://{abs}");
        let mega = self.clone();
        self.block(move || {
            mega.run(&["mkdir".into(), url])?;
            Ok(())
        })
        .await
    }

    /// Delete a file or (empty) folder; recursive removal of a tree via the
    /// SDK isn't exposed, so a non-empty directory removal returns an error.
    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let abs = self.abs(path);
        let url = format!("mega://{abs}");
        let mega = self.clone();
        let cmd = if is_dir { "rmdir" } else { "rm" };
        self.block(move || {
            let cmd = cmd.to_string();
            mega.run(&[cmd, url])?;
            Ok(())
        })
        .await
    }

    async fn block<T: Send + 'static>(&self, op: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
        tokio::task::spawn_blocking(op)
            .await
            .map_err(|e| Error::Other(format!("MEGA task: {e}")))?
    }
}

fn temp_path(kind: &str) -> String {
    let dir = std::env::temp_dir().join("cloudup");
    let _ = std::fs::create_dir_all(&dir);
    let name = format!("mega-{}-{:?}", kind, std::process::id());
    dir.join(name).to_string_lossy().to_string()
}

fn normalize_path(p: &str) -> String {
    let t = p.trim_matches('/');
    if t.is_empty() { String::new() } else { format!("/{}", t) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_path_joining() {
        let m = Mega::new("https://mega.nz", "me@example.com", "pw", "/photos");
        assert_eq!(m.abs("/a.txt"), "/photos/a.txt");
        assert_eq!(m.abs("/"), "/photos");
        let root = Mega::new("", "me@example.com", "pw", "/");
        assert_eq!(root.abs("/a.txt"), "/a.txt");
    }
}
