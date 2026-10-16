//! MEGA backend (email + password login with the official mega SDK).
//!
//! MEGA's file format is proprietary (client-side AES-GCM crypto), so instead
//! of re-implementing the protocol we shell out to the `mega` command-line
//! client (https://megatools.gitlab.io/megatools/ or the official `mega`) and
//! copy data through temporary local files. First run triggers the SDK's
//! key derivation (a few seconds).
//!
//! Credentials never go on the command line (where `ps` would show them):
//! each run gets a megatools config file, readable only by the user, in
//! CloudUp's private temp folder, deleted as soon as the command ends.
//!
//! Connection mapping:
//! - `endpoint`   = SDK host (unused: the CLI picks its own)
//! - `access_key` = MEGA email, `secret` = MEGA password
//! - `bucket`     = folder to mount (`/` = the whole root)
//!
//! The `mega` binary must be installed for MEGA connections to work; every
//! operation surfaces a clear error if it is missing.

use crate::backend::{local_err, TempPath};
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone)]
pub struct Mega {
    email: String,
    password: String,
    /// Folder to mount (absolute MEGA path, e.g. "/photos").
    bucket: String,
}

pub struct MegaEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

impl Mega {
    pub fn new(_host: &str, email: &str, password: &str, bucket: &str) -> Self {
        Self {
            email: email.trim().to_string(),
            password: password.to_string(),
            bucket: normalize_path(bucket),
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

    /// The `mega://` URL of a mount-relative path.
    fn url(&self, path: &str) -> String {
        format!("mega://{}", self.abs(path))
    }

    /// Run a megatools command, logged in through a private config file.
    fn run(&self, args: &[String]) -> Result<String> {
        let rc = TempPath::new("megarc")?;
        write_private(rc.path(), &megarc(&self.email, &self.password))?;
        let out = Command::new("mega")
            .arg("--config")
            .arg(rc.path())
            .args(args)
            .output()
            .map_err(|e| Error::Other(format!("MEGA: `mega` binary not found or not runnable — install megatools ({e})")))?;
        drop(rc);
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::Api { provider: "MEGA".into(), status: 1, body: stderr.trim().to_string() });
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<MegaEntry>> {
        let url = self.url(dir);
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
        let tmp = TempPath::new("mega-dl")?;
        self.read_to_file(path, tmp.path()).await?;
        tokio::fs::read(tmp.path()).await.map_err(|e| local_err(tmp.path(), e))
    }

    /// Download straight into `dest`.
    pub async fn read_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        let url = self.url(path);
        let dest = dest.to_path_buf();
        let mega = self.clone();
        self.block(move || {
            mega.run(&["get".into(), url, dest.to_string_lossy().to_string()])?;
            Ok(std::fs::metadata(&dest).map_err(|e| local_err(&dest, e))?.len())
        })
        .await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let tmp = TempPath::new("mega-ul")?;
        tokio::fs::write(tmp.path(), data).await.map_err(|e| local_err(tmp.path(), e))?;
        self.write_from_file(path, tmp.path()).await
    }

    /// Upload straight from `src`.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let url = self.url(path);
        let src: PathBuf = src.to_path_buf();
        let mega = self.clone();
        self.block(move || {
            mega.run(&["put".into(), url, src.to_string_lossy().to_string()])?;
            Ok(())
        })
        .await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let url = self.url(path.trim_end_matches('/'));
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
        let url = self.url(path);
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

/// A megatools config file (GLib key file) with the login.
fn megarc(email: &str, password: &str) -> String {
    format!("[Login]\nUsername = {}\nPassword = {}\n", keyfile_value(email), keyfile_value(password))
}

/// Escape a GLib key-file value: backslashes and control characters, and a
/// leading space (which the parser would otherwise trim).
fn keyfile_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (i, c) in v.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' ' if i == 0 => out.push_str("\\s"),
            c => out.push(c),
        }
    }
    out
}

/// Create `path` readable only by the user and write `content`.
fn write_private(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| local_err(path, e))?;
    f.write_all(content.as_bytes()).map_err(|e| local_err(path, e))
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
        assert_eq!(m.url("/a.txt"), "mega:///photos/a.txt");
        let root = Mega::new("", "me@example.com", "pw", "/");
        assert_eq!(root.abs("/a.txt"), "/a.txt");
    }

    #[test]
    fn megarc_escapes_values() {
        assert_eq!(keyfile_value(r"a\b"), r"a\\b");
        assert_eq!(keyfile_value(" pw x"), r"\spw x");
        assert_eq!(keyfile_value("l1\nl2"), r"l1\nl2");
        let rc = megarc("me@example.com", "p w");
        assert_eq!(rc, "[Login]\nUsername = me@example.com\nPassword = p w\n");
    }

    #[test]
    fn private_file_mode() {
        let t = TempPath::new("test-megarc").unwrap();
        write_private(t.path(), "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(t.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
