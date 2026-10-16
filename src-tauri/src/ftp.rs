//! A minimal, pure-Rust FTP client (passive mode only).
//!
//! No native dependencies: plain `TcpStream` for the control channel, with all
//! blocking work offloaded to `tokio::spawn_blocking`. Supports the commands
//! we need: `USER`, `PASS`, `CWD`, `TYPE`, `PASV`, `LIST`, `RETR`, `STOR`,
//! `RNFR`/`RNTO`, `MKD`, `DELE`, `RMD`, `SIZE`, `QUIT`.
//!
//! Uploads go to a hidden temporary name next to the target and are renamed
//! over it once complete, so a failed upload never leaves a truncated file.
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

use crate::backend::{copy_blocking, local_err};
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
    pub perms: Option<String>,
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
        // Binary transfers: the protocol's default (ASCII) may rewrite line
        // endings. A server that refuses is left on its default.
        send_cmd(reader, "TYPE I")?;
        read_response(reader)?;
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

    /// Download a file into `dest`, copying from the data socket in chunks.
    pub async fn read_to_file(&self, path: &str, dest: &std::path::Path) -> Result<u64> {
        let server_path = self.abs(path);
        let dest = dest.to_path_buf();
        let ftp = self.clone();
        self.block(move || {
            let mut out = std::fs::File::create(&dest).map_err(|e| local_err(&dest, e))?;
            ftp.run_session(|reader| {
                let mut data = pasv_socket(reader)?;
                send_cmd(reader, &format!("RETR {}", server_path))?;
                let (code, text) = read_response(reader)?; // 1xx
                if code / 100 != 1 {
                    return Err(api_err(code, text));
                }
                let n = copy_blocking(&mut data, &mut out).map_err(io_err)?;
                drop(data);
                let (code, text) = read_response(reader)?; // 226
                if code / 100 != 2 {
                    return Err(api_err(code, text));
                }
                Ok(n)
            })
        })
        .await
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let body = data.to_vec();
        self.store(path, move || Ok(std::io::Cursor::new(body))).await
    }

    /// Upload a local file, streamed from disk.
    pub async fn write_from_file(&self, path: &str, src: &std::path::Path) -> Result<()> {
        let src = src.to_path_buf();
        self.store(path, move || std::fs::File::open(&src).map_err(|e| local_err(&src, e))).await
    }

    /// Upload what `open` returns to a temporary sibling, then rename it over
    /// `path`. On failure the temporary file is removed and `path` is left
    /// as it was.
    async fn store<R: Read + 'static>(&self, path: &str, open: impl FnOnce() -> Result<R> + Send + 'static) -> Result<()> {
        let target = self.abs(path);
        let tmp = temp_sibling(&target, &temp_tag());
        let ftp = self.clone();
        let tmp2 = tmp.clone();
        let result = self
            .block(move || {
                let mut src = open()?;
                ftp.run_session(|reader| {
                    stor(reader, &tmp2, &mut src)?;
                    rename_over(reader, &tmp2, &target)
                })
            })
            .await;
        if result.is_err() {
            // Best effort, on a fresh connection if the failure dropped it.
            let ftp = self.clone();
            let _ = self
                .block(move || {
                    ftp.run_session(|reader| {
                        send_cmd(reader, &format!("DELE {tmp}"))?;
                        read_response(reader).map(|_| ())
                    })
                })
                .await;
        }
        result
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let server_path = self.abs(path.trim_end_matches('/'));
        let ftp = self.clone();
        self.block(
            move || {
                ftp.run_session(|reader| {
                    send_cmd(reader, &format!("MKD {}", server_path))?;
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

/// `STOR` the contents of `src` at `path`, copying in chunks.
fn stor(reader: &mut BufReader<TcpStream>, path: &str, src: &mut impl Read) -> Result<()> {
    let mut sock = pasv_socket(reader)?;
    send_cmd(reader, &format!("STOR {}", path))?;
    let (code, text) = read_response(reader)?; // 1xx or 2xx (binary)
    if code / 100 != 1 && code / 100 != 2 {
        return Err(api_err(code, text));
    }
    copy_blocking(src, &mut sock).map_err(io_err)?;
    // Half-close so the server knows the transfer is done.
    let _ = sock.shutdown(std::net::Shutdown::Write);
    drop(sock);
    if code / 100 != 2 {
        let (code, text) = read_response(reader)?; // 226
        if code / 100 != 2 {
            return Err(api_err(code, text));
        }
    }
    Ok(())
}

/// Send `cmd` and expect a reply in the `class`xx range.
fn expect(reader: &mut BufReader<TcpStream>, cmd: &str, class: u16) -> Result<()> {
    send_cmd(reader, cmd)?;
    let (code, text) = read_response(reader)?;
    if code / 100 != class {
        return Err(api_err(code, text));
    }
    Ok(())
}

/// Rename `from` onto `to`, replacing it (`RNFR`/`RNTO`). Servers that
/// refuse to rename onto an existing file get the target deleted first.
fn rename_over(reader: &mut BufReader<TcpStream>, from: &str, to: &str) -> Result<()> {
    expect(reader, &format!("RNFR {}", from), 3)?;
    match expect(reader, &format!("RNTO {}", to), 2) {
        Err(Error::Api { .. }) => {
            send_cmd(reader, &format!("DELE {}", to))?;
            read_response(reader)?; // a missing target is fine
            expect(reader, &format!("RNFR {}", from), 3)?;
            expect(reader, &format!("RNTO {}", to), 2)
        }
        r => r,
    }
}

/// Temporary name for an upload to `path`: a hidden sibling in the same
/// folder (so the final rename stays on one filesystem), e.g.
/// `/dir/.report.pdf.cloudup-1a2b3c4d5e6f`. Long names are shortened to
/// stay under the usual 255-byte limit.
pub(crate) fn temp_sibling(path: &str, tag: &str) -> String {
    let (dir, name) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let mut short = String::new();
    for c in name.chars() {
        if short.len() + c.len_utf8() > 200 {
            break;
        }
        short.push(c);
    }
    format!("{dir}.{short}.cloudup-{tag}")
}

/// A random suffix for `temp_sibling`.
pub(crate) fn temp_tag() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

fn send_cmd(reader: &mut BufReader<TcpStream>, cmd: &str) -> Result<()> {
    // A line break in a file name would end the command and start another.
    if cmd.contains(['\r', '\n', '\0']) {
        return Err(Error::Other("FTP: names with line breaks are not supported".into()));
    }
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
    if nums[4] > 255 || nums[5] > 255 {
        return Err(api_err(code, text));
    }
    let port = nums[4] * 256 + nums[5];
    // Connect to the server we're already talking to, not the address in the
    // reply: behind NAT that is a private address, and a hostile server could
    // point it at another machine on our network (like curl and lftp do).
    let host = reader.get_ref().peer_addr().map_err(io_err)?.ip();
    let data = TcpStream::connect((host, port)).map_err(io_err)?;
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
        let (is_dir, size, mtime, name, perms) = if parts.len() >= 9 && parts[4].parse::<u64>().is_ok() {
            let is_dir = parts[0].starts_with('d');
            let size = parts[4].parse::<u64>().unwrap_or(0);
            let mtime = Some(format!("{} {} {}", parts[5], parts[6], parts[7]));
            let name = parts[8..].join(" ");
            (is_dir, size, mtime, name, Some(parts[0].to_string()))
        } else if parts.len() >= 7 && parts[2].parse::<u64>().is_ok() {
            let is_dir = parts[0].starts_with('d');
            let size = parts[2].parse::<u64>().unwrap_or(0);
            let mtime = Some(format!("{} {} {}", parts[3], parts[4], parts[5]));
            let name = parts[6..].join(" ");
            (is_dir, size, mtime, name, Some(parts[0].to_string()))
        } else {
            (false, 0, None, line.to_string(), None)
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
        out.push(FtpEntry { name, path, is_dir, size, modified: mtime, perms });
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
    fn temp_sibling_names() {
        assert_eq!(temp_sibling("/data/report.pdf", "abc"), "/data/.report.pdf.cloudup-abc");
        assert_eq!(temp_sibling("/x", "t"), "/.x.cloudup-t");
        assert_eq!(temp_sibling("x", "t"), ".x.cloudup-t");
        // Long (multi-byte) names are cut on a character boundary.
        let long = format!("/d/{}", "\u{e9}".repeat(200));
        let t = temp_sibling(&long, "t");
        let name = t.rsplit('/').next().unwrap();
        assert!(name.len() <= 255, "{}", name.len());
        assert!(name.ends_with(".cloudup-t"));
        let tag = temp_tag();
        assert_eq!(tag.len(), 12);
        assert_ne!(tag, temp_tag());
    }

    #[test]
    fn normalize_base_variants() {
        assert_eq!(normalize_base("/"), "");
        assert_eq!(normalize_base(""), "");
        assert_eq!(normalize_base("data/"), "/data");
        assert_eq!(normalize_base("/data/"), "/data");
    }

    /// A scripted in-process FTP server: files in memory, every command
    /// logged. With `refuse_overwrite`, RNTO onto an existing file fails
    /// (like some servers); STOR of a name containing "fail" is refused.
    #[derive(Default)]
    struct Fake {
        files: std::collections::HashMap<String, Vec<u8>>,
        log: Vec<String>,
        refuse_overwrite: bool,
    }

    fn fake_server(refuse_overwrite: bool) -> (u16, Arc<Mutex<Fake>>) {
        use std::net::TcpListener;
        let state = Arc::new(Mutex::new(Fake { refuse_overwrite, ..Default::default() }));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let st = state.clone();
        std::thread::spawn(move || {
            // The client reconnects after an error: serve one session at a time.
            while let Ok((ctrl, _)) = listener.accept() {
                let mut r = BufReader::new(ctrl.try_clone().unwrap());
                let mut w = ctrl;
                let _ = w.write_all(b"220 fake\r\n");
                let mut data: Option<TcpListener> = None;
                let mut from: Option<String> = None;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = line.trim_end().to_string();
                    let (cmd, arg) = line.split_once(' ').map(|(c, a)| (c.to_string(), a.to_string())).unwrap_or((line.clone(), String::new()));
                    let mut s = st.lock().unwrap();
                    s.log.push(line.clone());
                    let reply = match cmd.as_str() {
                        "USER" => "331 password".to_string(),
                        "PASS" => "230 in".to_string(),
                        "TYPE" | "CWD" => "200 ok".to_string(),
                        "PASV" => {
                            let l = TcpListener::bind("127.0.0.1:0").unwrap();
                            let p = l.local_addr().unwrap().port();
                            data = Some(l);
                            format!("227 Entering Passive Mode (127,0,0,1,{},{})", p / 256, p % 256)
                        }
                        "STOR" if arg.contains("fail") => "552 quota exceeded".to_string(),
                        "STOR" => {
                            let _ = w.write_all(b"150 go\r\n");
                            let (mut sock, _) = data.take().unwrap().accept().unwrap();
                            let mut buf = vec![];
                            sock.read_to_end(&mut buf).unwrap();
                            s.files.insert(arg, buf);
                            "226 stored".to_string()
                        }
                        "RETR" => match s.files.get(&arg).cloned() {
                            Some(content) => {
                                let _ = w.write_all(b"150 go\r\n");
                                let (mut sock, _) = data.take().unwrap().accept().unwrap();
                                sock.write_all(&content).unwrap();
                                drop(sock);
                                "226 sent".to_string()
                            }
                            None => "550 no such file".to_string(),
                        },
                        "RNFR" if s.files.contains_key(&arg) => {
                            from = Some(arg);
                            "350 ready".to_string()
                        }
                        "RNTO" if s.refuse_overwrite && s.files.contains_key(&arg) => "553 file exists".to_string(),
                        "RNTO" => match from.take().and_then(|f| s.files.remove(&f)) {
                            Some(content) => {
                                s.files.insert(arg, content);
                                "250 renamed".to_string()
                            }
                            None => "503 RNFR first".to_string(),
                        },
                        "DELE" if s.files.remove(&arg).is_some() => "250 deleted".to_string(),
                        _ => "550 no".to_string(),
                    };
                    drop(s);
                    let _ = w.write_all(format!("{reply}\r\n").as_bytes());
                }
            }
        });
        (port, state)
    }

    #[tokio::test]
    async fn uploads_go_through_a_temp_name() {
        let (port, state) = fake_server(true);
        state.lock().unwrap().files.insert("/d/a.txt".into(), b"old".to_vec());
        let ftp = Ftp::new("127.0.0.1", port, "u", "p", "/");

        ftp.write("/d/a.txt", b"new content").await.unwrap();
        {
            let s = state.lock().unwrap();
            assert_eq!(s.files.len(), 1, "temporary file left behind: {:?}", s.files.keys());
            assert_eq!(s.files["/d/a.txt"], b"new content");
            assert!(s.log.contains(&"TYPE I".to_string()));
            let cmds: Vec<&str> = s.log.iter().map(|l| l.split(' ').next().unwrap()).collect();
            let at = cmds.iter().position(|c| *c == "STOR").unwrap();
            // Refused RNTO onto the existing file: delete it, then rename again.
            assert_eq!(&cmds[at..], ["STOR", "RNFR", "RNTO", "DELE", "RNFR", "RNTO"]);
            assert!(s.log[at].starts_with("STOR /d/.a.txt.cloudup-"), "{}", s.log[at]);
        }

        let tmp = crate::backend::TempPath::new("ftp-test").unwrap();
        assert_eq!(ftp.read_to_file("/d/a.txt", tmp.path()).await.unwrap(), 11);
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"new content");

        // A failed upload leaves the original alone and no temporary file.
        state.lock().unwrap().files.insert("/d/fail.txt".into(), b"keep".to_vec());
        assert!(ftp.write("/d/fail.txt", b"x").await.is_err());
        let s = state.lock().unwrap();
        assert_eq!(s.files["/d/fail.txt"], b"keep");
        assert_eq!(s.files.len(), 2, "{:?}", s.files.keys());
        assert!(s.log.last().unwrap().starts_with("DELE /d/.fail.txt.cloudup-"), "{:?}", s.log.last());
    }

    #[tokio::test]
    async fn rename_replaces_directly_when_allowed() {
        let (port, state) = fake_server(false);
        state.lock().unwrap().files.insert("/a.bin".into(), b"old".to_vec());
        let ftp = Ftp::new("127.0.0.1", port, "u", "p", "");
        let src = crate::backend::TempPath::new("ftp-src").unwrap();
        std::fs::write(src.path(), vec![7u8; 300_000]).unwrap();
        ftp.write_from_file("/a.bin", src.path()).await.unwrap();
        let s = state.lock().unwrap();
        assert_eq!(s.files.len(), 1);
        assert_eq!(s.files["/a.bin"], vec![7u8; 300_000]);
        assert!(!s.log.iter().any(|l| l.starts_with("DELE")), "no delete needed: {:?}", s.log);
    }
}
