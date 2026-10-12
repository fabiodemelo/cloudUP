//! A minimal, pure-Rust FTP client (passive mode only).
//!
//! No native dependencies: plain `TcpStream` for the control channel, with all
//! blocking work offloaded to `tokio::spawn_blocking`. Supports the commands
//! we need: `USER`, `PASS`, `CWD`, `PASV`, `LIST`, `RETR`, `STOR`, `MKDIR`,
//! `DELE`, `RMD`, `SIZE`, `QUIT`.
//!
//! Connection mapping:
//! - `endpoint` = host, optionally `ftp://host:port` or `host:port`
//!   (`fields.port` overrides)
//! - `access_key` = username, `secret` = password (empty username = anonymous)
//! - `bucket` = base directory to mount (`/` = root)
//!
//! The control connection (a `BufReader<TcpStream>`) is established lazily on
//! first use and kept in the `Arc<Mutex>` so repeated browser operations reuse
//! it. Keeping one reader alive per connection means partially-read responses
//! are not discarded between commands. Any failure drops the connection and the
//! next call reconnects.

use crate::error::{Error, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct FtpEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

#[derive(Clone)]
pub struct Ftp {
    host: String,
    port: u16,
    username: String,
    password: String,
    /// Base directory on the server; entry paths are relative to it.
    base: String,
    ctrl: Arc<Mutex<Option<BufReader<TcpStream>>>>,
}

impl Ftp {
    pub fn new(host: &str, port: u16, username: &str, password: &str, base: &str) -> Self {
        Self {
            host: host.trim().to_string(),
            port,
            username: username.trim().to_string(),
            password: password.to_string(),
            base: normalize_base(base),
            ctrl: Arc::new(Mutex::new(None)),
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

    /// Normalize a directory path to its mount-relative form ("" for root).
    fn rel_dir(dir: &str) -> String {
        dir.trim_matches('/').to_string()
    }

    // ------------------------------------------------------ blocking session

    /// Run a blocking op off the async runtime (blocking socket I/O).
    async fn block<T: Send + 'static>(&self, op: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
        let _ = self;
        tokio::task::spawn_blocking(op)
            .await
            .map_err(|e| Error::Other(format!("FTP task: {e}")))?
    }

    /// Run `op` on a live, authenticated control connection (blocking context).
    fn run_session<T>(&self, op: impl FnOnce(&mut BufReader<TcpStream>) -> Result<T>) -> Result<T> {
        let mut guard = self.ctrl.lock().unwrap();
        if guard.is_none() {
            let stream = Self::connect(&self.host, self.port)?;
            let mut reader = BufReader::new(stream);
            let (code, text) = read_response(&mut reader)?; // 220 greeting
            if code / 100 != 2 {
                *guard = None;
                return Err(api_err(code, text));
            }
            if let Err(e) = self.login(&mut reader) {
                *guard = None;
                return Err(e);
            }
            *guard = Some(reader);
        }
        let reader = guard.as_mut().unwrap();
        match op(reader) {
            Ok(t) => Ok(t),
            Err(e) => {
                // Connection is likely wedged; drop it so the next call reconnects.
                *guard = None;
                Err(e)
            }
        }
    }

    fn connect(host: &str, port: u16) -> Result<TcpStream> {
        let stream = TcpStream::connect((host, port)).map_err(io_err)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(60))))
            .map_err(io_err)?;
        Ok(stream)
    }

    fn login(&self, reader: &mut BufReader<TcpStream>) -> Result<()> {
        let (user, pass) = if self.username.is_empty() {
            ("anonymous", "")
        } else {
            (self.username.as_str(), self.password.as_str())
        };
        send_cmd(reader, &format!("USER {}", user))?;
        let (code, text) = read_response(reader)?; // 230 or 331 (password required)
        if code == 331 {
            send_cmd(reader, &format!("PASS {}", pass))?;
            let (code, text) = read_response(reader)?;
            if code / 100 != 2 {
                return Err(api_err(code, text));
            }
        } else if code / 100 != 2 {
            return Err(api_err(code, text));
        }
        // Best-effort chdir to the base directory; empty base = stay at root.
        if !self.base.is_empty() {
            send_cmd(reader, &format!("CWD {}", self.base))?;
            let (code, text) = read_response(reader)?;
            if code / 100 != 2 {
                return Err(api_err(code, text));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------- operations

    pub async fn list(&self, dir: &str) -> Result<Vec<FtpEntry>> {
        let rel = Self::rel_dir(dir);
        let server_path = self.abs(dir);
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    let mut data = pasv_socket(reader)?;
                    send_cmd(reader, &format!("LIST {}", server_path))?;
                    let (code, text) = read_response(reader)?; // 1xx (data starting)
                    if code / 100 != 1 {
                        return Err(api_err(code, text));
                    }
                    let mut buf = Vec::new();
                    data.read_to_end(&mut buf).map_err(io_err)?;
                    let (code, text) = read_response(reader)?; // 226
                    if code / 100 != 2 {
                        return Err(api_err(code, text));
                    }
                    parse_list(&String::from_utf8_lossy(&buf), &rel)
                })
            }
        )
        .await
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let server_path = self.abs(path);
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    let mut data = pasv_socket(reader)?;
                    send_cmd(reader, &format!("RETR {}", server_path))?;
                    let (code, text) = read_response(reader)?; // 1xx
                    if code / 100 != 1 {
                        return Err(api_err(code, text));
                    }
                    let mut buf = Vec::new();
                    data.read_to_end(&mut buf).map_err(io_err)?;
                    let (code, text) = read_response(reader)?; // 226
                    if code / 100 != 2 {
                        return Err(api_err(code, text));
                    }
                    Ok(buf)
                })
            }
        )
        .await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let server_path = self.abs(path);
        let body = data.to_vec();
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    let mut sock = pasv_socket(reader)?;
                    send_cmd(reader, &format!("STOR {}", server_path))?;
                    let (code, text) = read_response(reader)?; // 1xx or 2xx (binary)
                    if code / 100 != 1 && code / 100 != 2 {
                        return Err(api_err(code, text));
                    }
                    sock.write_all(&body).map_err(io_err)?;
                    // Half-close so the server knows the transfer is done.
                    let _ = sock.shutdown(std::net::Shutdown::Write);
                    if code / 100 != 2 {
                        let (code, text) = read_response(reader)?; // 226
                        if code / 100 != 2 {
                            return Err(api_err(code, text));
                        }
                    }
                    Ok(())
                })
            }
        )
        .await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let server_path = self.abs(path.trim_end_matches('/'));
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    send_cmd(reader, &format!("MKDIR {}", server_path))?;
                    let (code, text) = read_response(reader)?;
                    if code / 100 != 2 {
                        return Err(api_err(code, text));
                    }
                    Ok(())
                })
            }
        )
        .await
    }

    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        let server_path = self.abs(path);
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    let cmd = if is_dir { "RMD" } else { "DELE" };
                    send_cmd(reader, &format!("{} {}", cmd, server_path))?;
                    let (code, text) = read_response(reader)?;
                    if code / 100 != 2 {
                        return Err(api_err(code, text));
                    }
                    Ok(())
                })
            }
        )
        .await
    }

    /// File size via the `SIZE` command (None if the server lacks support).
    pub async fn size(&self, path: &str) -> Result<Option<u64>> {
        let server_path = self.abs(path);
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    send_cmd(reader, &format!("SIZE {}", server_path))?;
                    let (code, text) = read_response(reader)?;
                    if code / 100 != 2 {
                        return Ok(None);
                    }
                    Ok(text.trim().rsplit(' ').next().and_then(|n| n.parse().ok()))
                })
            }
        )
        .await
    }
}

// ------------------------------------------------------------------- protocol

fn normalize_base(base: &str) -> String {
    let b = base.trim_matches('/');
    if b.is_empty() {
        String::new()
    } else {
        format!("/{}", b)
    }
}

fn send_cmd(reader: &mut BufReader<TcpStream>, cmd: &str) -> Result<()> {
    let stream = reader.get_mut();
    stream.write_all(cmd.as_bytes()).map_err(io_err)?;
    stream.write_all(b"\r\n").map_err(io_err)?;
    stream.flush().map_err(io_err)
}

/// Send `PASV`, parse `227 ... (h1,h2,h3,h4,p1,p2)` and open the data socket.
fn pasv_socket(reader: &mut BufReader<TcpStream>) -> Result<TcpStream> {
    send_cmd(reader, "PASV")?;
    let (code, text) = read_response(reader)?;
    if code != 227 {
        return Err(api_err(code, text));
    }
    let open = text.find('(').ok_or_else(|| api_err(code, text.clone()))?;
    let close = text.rfind(')').ok_or_else(|| api_err(code, text.clone()))?;
    if close <= open {
        return Err(api_err(code, text));
    }
    let nums: Vec<u16> = text[open + 1..close]
        .split(',')
        .map(|p| p.trim().parse::<u16>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Other(format!("bad PASV response: {e}")))?;
    if nums.len() != 6 {
        return Err(api_err(code, text));
    }
    let port = (nums[4] as u16) * 256 + nums[5] as u16;
    let addr = format!("{}.{}.{}.{}:{}", nums[0], nums[1], nums[2], nums[3], port);
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| Error::Other(format!("bad PASV address: {e}")))?;
    let data = TcpStream::connect(addr).map_err(io_err)?;
    data.set_read_timeout(Some(Duration::from_secs(300)))
        .and_then(|_| data.set_write_timeout(Some(Duration::from_secs(300))))
        .map_err(io_err)?;
    Ok(data)
}

/// Read one (possibly multi-line) FTP response.
fn read_response(reader: &mut BufReader<TcpStream>) -> Result<(u16, String)> {
    let mut first = String::new();
    reader.read_line(&mut first).map_err(io_err)?;
    if first.len() < 4 {
        return Err(Error::Other(format!("short FTP response: {first:?}")));
    }
    let code: u16 = first[..3]
        .parse()
        .map_err(|_| Error::Other(format!("unparseable FTP response: {first:?}")))?;
    let multiline = first.as_bytes().get(3) == Some(&b'-');
    let mut text = first.trim().to_string();
    if multiline {
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).map_err(io_err)?;
            let line = line.trim().to_string();
            let done = line.len() >= 4
                && line[..3].parse::<u16>().map(|c| c == code).unwrap_or(false)
                && line.as_bytes().get(3) == Some(&b' ');
            text.push('\n');
            text.push_str(&line);
            if done {
                break;
            }
        }
    }
    Ok((code, text))
}

/// Parse `LIST` output into entries. Handles the classic `ls -l` layout with a
/// fallback to bare filenames when the server doesn't send the long format.
/// `prefix` is the mount-relative directory ("" = root); entry paths are built
/// from it so results stay relative to the mount root.
fn parse_list(raw: &str, prefix: &str) -> Result<Vec<FtpEntry>> {
    let mut out = vec![];
    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Classic `ls -l`: perms links owner group size <date 3 fields> name...
        // Some minimal servers omit owner/group: perms links size <date> name...
        // Disambiguate by which candidate slot is numeric. (Rare ambiguity:
        // owner-less lines with 3-word names where the year lands in slot 4.)
        let (is_dir, size, mtime, name) = if parts.len() >= 9 && parts[4].parse::<u64>().is_ok() {
            let is_dir = parts[0].starts_with('d');
            let size = parts[4].parse::<u64>().unwrap_or(0);
            let mtime = Some(format!("{} {} {}", parts[5], parts[6], parts[7]));
            let name = parts[8..].join(" ");
            (is_dir, size, mtime, name)
        } else if parts.len() >= 7 && parts[2].parse::<u64>().is_ok() {
            let is_dir = parts[0].starts_with('d');
            let size = parts[2].parse::<u64>().unwrap_or(0);
            let mtime = Some(format!("{} {} {}", parts[3], parts[4], parts[5]));
            let name = parts[6..].join(" ");
            (is_dir, size, mtime, name)
        } else {
            (false, 0, None, line.to_string())
        };
        // Symlinks show as "name -> target"; list the link name only.
        let name = name.split(" -> ").next().unwrap_or(&name).to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let path = if prefix.is_empty() {
            format!("/{}", name)
        } else {
            format!("/{prefix}/{}", name)
        };
        out.push(FtpEntry { name, path, is_dir, size, modified: mtime });
    }
    out.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

fn io_err(e: std::io::Error) -> Error {
    Error::Other(format!("FTP I/O: {e}"))
}

fn api_err(code: u16, text: String) -> Error {
    Error::Api { provider: "FTP".into(), status: code, body: text }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ls_long_output() {
        let raw = concat!(
            "drwxr-xr-x   2 user group         0 Jan  1  2024 some dir\n",
            "-rw-r--r--   1 user group     1234 Sep  9 2021 my file.txt\n",
            "-rw-r--r--   1 user group        0 Aug 31 12:00 empty\n",
            "dangling plain entry\n"
        );
        let entries = parse_list(raw, "").unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries[0].is_dir); // dirs first
        assert_eq!(entries[0].name, "some dir");
        assert_eq!(entries[0].path, "/some dir");
        let f = entries.iter().find(|e| e.name == "my file.txt").unwrap();
        assert!(!f.is_dir);
        assert_eq!(f.size, 1234);
        assert!(f.modified.is_some());
        let d = entries.iter().find(|e| e.name == "dangling plain entry").unwrap();
        assert_eq!(d.size, 0);
    }

    #[test]
    fn parses_nested_prefix() {
        let entries = parse_list("a.txt\n", "x/y").unwrap();
        assert_eq!(entries[0].path, "/x/y/a.txt");
    }

    #[test]
    fn abs_path_joining() {
        let ftp = Ftp::new("ftp.example.com", 21, "u", "p", "/data");
        assert_eq!(ftp.abs("/x.txt"), "/data/x.txt");
        assert_eq!(ftp.abs("x.txt"), "/data/x.txt");
        assert_eq!(ftp.abs("/"), "/data");
        let root = Ftp::new("h", 21, "u", "p", "/");
        assert_eq!(root.abs("/x.txt"), "/x.txt");
    }

    #[test]
    fn normalize_base_variants() {
        assert_eq!(normalize_base("/"), "");
        assert_eq!(normalize_base(""), "");
        assert_eq!(normalize_base("data/"), "/data");
        assert_eq!(normalize_base("/data/"), "/data");
    }
}
