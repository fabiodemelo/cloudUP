//! FUSE filesystem backed by a [`Backend`]. Only compiled with `--features fuse-mount`.
//!
//! Inode numbers are assigned locally (cloud stores have no stable inodes) and
//! mapped to paths. Directory listings are fetched on demand; file contents are
//! cached per open handle and uploaded on close.

use super::MountInfo;
use crate::backend::{Backend, Entry};
use crate::config::Connection;
use crate::error::{Error, Result};

use fuser::{
    Context, FileAttr, FileHandle, FileSystem, ReplyByteBuf, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const ROOT_INO: u64 = 1;

struct FsState {
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    meta: HashMap<u64, Entry>,
    next_ino: u64,
}

impl FsState {
    fn new() -> Self {
        let mut s = Self {
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            meta: HashMap::new(),
            next_ino: 2,
        };
        s.ino_to_path.insert(ROOT_INO, "/".into());
        s.path_to_ino.insert("/".into(), ROOT_INO);
        s
    }

    fn ino_for_path(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.to_string());
        self.path_to_ino.insert(path.to_string(), ino);
        ino
    }

    fn path_for_ino(&self, ino: u64) -> String {
        if ino == ROOT_INO {
            return "/".into();
        }
        self.ino_to_path.get(&ino).cloned().unwrap_or_else(|| "/".into())
    }

    fn remember(&mut self, ino: u64, entry: &Entry) {
        self.meta.insert(ino, entry.clone());
    }
}

struct CloudFile {
    path: String,
    writable: bool,
    data: Mutex<Option<Vec<u8>>>,
}

impl FileHandle for CloudFile {}

struct CloudFs {
    backend: Arc<Backend>,
    rt: tokio::runtime::Handle,
    state: Mutex<FsState>,
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() || parent == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), name)
    }
}

fn attr_from_entry(ino: u64, e: &Entry) -> FileAttr {
    let now = SystemTime::now();
    FileAttr {
        ino,
        size: if e.is_dir { 4096 } else { e.size },
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        mode: if e.is_dir { 0o040755 } else { 0o100644 },
        nlink: if e.is_dir { 2 } else { 1 },
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn dir_attr(ino: u64) -> FileAttr {
    let now = SystemTime::now();
    FileAttr {
        ino,
        size: 4096,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        mode: 0o040755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

impl FileSystem for CloudFs {
    type Handle = CloudFile;

    fn lookup(&mut self, _ctx: &Context, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        match self.rt.block_on(self.backend.list(&parent_path)) {
            Ok(entries) => {
                if let Some(e) = entries.iter().find(|e| e.name == name) {
                    let ino = self.state.lock().unwrap().ino_for_path(&e.path);
                    self.state.lock().unwrap().remember(ino, e);
                    reply.ok(ino, 0, Duration::from_secs(1), attr_from_entry(ino, e));
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn forget(&mut self, _ctx: &Context, ino: u64, _nlookup: u64) {
        // We keep the mapping (paths are cheap); nothing to free.
    }

    fn getattr(&mut self, _ctx: &Context, ino: u64, fh: Option<&CloudFile>, reply: ReplyEmpty) {
        let path = match fh { Some(f) => f.path.clone(), None => self.state.lock().unwrap().path_for_ino(ino) };
        if ino == ROOT_INO || path.ends_with('/') {
            reply.ok(&dir_attr(ino));
        } else if let Some(e) = self.state.lock().unwrap().meta.get(&ino) {
            reply.ok(&attr_from_entry(ino, e));
        } else {
            // Unknown file: report a zero-size regular file; Finder will re-stat.
            let mut a = dir_attr(ino);
            a.mode = 0o100644;
            a.size = 0;
            reply.ok(&a);
        }
    }

    fn readdir(
        &mut self,
        _ctx: &Context,
        ino: u64,
        _fh: Option<&CloudFile>,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = self.state.lock().unwrap().path_for_ino(ino);
        match self.rt.block_on(self.backend.list(&path)) {
            Ok(entries) => {
                let mut state = self.state.lock().unwrap();
                // "." and ".."
                reply.add(ROOT_INO, 0, ".".into());
                if path != "/" {
                    let parent = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                    let parent_path = if parent.is_empty() { "/".to_string() } else { format!("/{}", parent) };
                    let pino = state.ino_for_path(&parent_path);
                    reply.add(pino, 1, "..".into());
                }
                let mut off = 2i64;
                for e in entries {
                    if reply.full() {
                        break;
                    }
                    let ino = state.ino_for_path(&e.path);
                    state.remember(ino, e);
                    reply.add(ino, off, e.name.clone().into());
                    off += 1;
                }
                let _ = offset;
                reply.ok();
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn open(&mut self, _ctx: &Context, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = self.state.lock().unwrap().path_for_ino(ino);
        let accmode = flags & libc::O_ACCMODE;
        let writable = accmode == libc::O_WRONLY || accmode == libc::O_RDWR;
        let fh = CloudFile { path, writable, data: Mutex::new(None) };
        reply.open(ino, Box::new(fh), 0);
    }

    fn create(&mut self, _ctx: &Context, parent: u64, name: &std::ffi::OsStr, _mode: u32, flags: i32, reply: ReplyEntry) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        // Persist an empty object so the file exists immediately.
        let backend = self.backend.clone();
        match self.rt.block_on(backend.write(&path, b"")) {
            Ok(_) => {
                let accmode = flags & libc::O_ACCMODE;
                let writable = accmode == libc::O_WRONLY || accmode == libc::O_RDWR;
                let entry = Entry { name: name.clone(), path: path.clone(), is_dir: false, size: 0, modified: None };
                let ino = self.state.lock().unwrap().ino_for_path(&path);
                self.state.lock().unwrap().remember(ino, &entry);
                let fh = CloudFile { path, writable, data: Mutex::new(Some(vec![])) };
                reply.opened(ino, Box::new(fh), 0);
            }
            Err(e) => reply.error(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()).raw_os_error().unwrap_or(libc::EIO)),
        }
    }

    fn read(&mut self, _ctx: &Context, ino: u64, fh: &CloudFile, offset: i64, size: u32, reply: ReplyByteBuf) {
        let mut data = fh.data.lock().unwrap();
        if data.is_none() {
            *data = Some(self.rt.block_on(self.backend.read(&fh.path)).unwrap_or_default());
        }
        if let Some(buf) = data.as_ref() {
            let start = offset.max(0) as usize;
            if start >= buf.len() {
                reply.ok();
            } else {
                let end = std::cmp::min(buf.len(), start + size as usize);
                reply.data(&buf[start..end]);
            }
        } else {
            reply.error(libc::EIO);
        }
    }

    fn write(
        &mut self,
        _ctx: &Context,
        ino: u64,
        fh: &CloudFile,
        offset: i64,
        data_in: &[u8],
        _flags: i32,
        reply: ReplyWrite,
    ) {
        if !fh.writable {
            reply.error(libc::EACCES);
            return;
        }
        let mut data = fh.data.lock().unwrap();
        if data.is_none() {
            *data = Some(vec![0u8; 0]);
        }
        if let Some(buf) = data.as_mut() {
            let start = offset.max(0) as usize;
            let end = start + data_in.len();
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf[start..end].copy_from_slice(data_in);
        }
        reply.written(data_in.len());
    }

    fn release(&mut self, _ctx: &Context, ino: u64, fh: &CloudFile, _flags: i32, reply: ReplyEmpty) {
        if fh.writable {
            let buf = fh.data.lock().unwrap().take();
            if let Some(buf) = buf {
                self.rt.block_on(self.backend.write(&fh.path, &buf)).ok();
            }
        }
        reply.ok();
    }

    fn mkdir(&mut self, _ctx: &Context, parent: u64, name: &std::ffi::OsStr, _mode: u32, reply: ReplyEntry) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        match self.rt.block_on(self.backend.mkdir(&path)) {
            Ok(_) => {
                let entry = Entry { name, path: path.clone(), is_dir: true, size: 0, modified: None };
                let ino = self.state.lock().unwrap().ino_for_path(&path);
                self.state.lock().unwrap().remember(ino, &entry);
                reply.ok(ino, 0, Duration::from_secs(1), attr_from_entry(ino, &entry));
            }
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn rmdir(&mut self, _ctx: &Context, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        match self.rt.block_on(self.backend.remove(&path, true)) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn unlink(&mut self, _ctx: &Context, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        match self.rt.block_on(self.backend.remove(&path, false)) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn rename(
        &mut self,
        _ctx: &Context,
        parent: u64,
        name: &std::ffi::OsStr,
        new_parent: u64,
        new_name: &std::ffi::OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let name = name.to_string_lossy().to_string();
        let new_name = new_name.to_string_lossy().to_string();
        let src = join_path(&self.state.lock().unwrap().path_for_ino(parent), &name);
        let dst = join_path(&self.state.lock().unwrap().path_for_ino(new_parent), &new_name);
        // Best-effort move: read + write + delete. (Cloud stores rarely support atomic rename.)
        match self.rt.block_on(async {
            let data = self.backend.read(&src).await?;
            self.backend.write(&dst, &data).await?;
            let is_dir = src.ends_with('/');
            self.backend.remove(&src, is_dir).await?;
            Ok(()) as Result<()>
        }) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(err_code(&e)),
        }
    }
}

fn err_code(e: &Error) -> i32 {
    let s = e.to_string();
    if s.contains("404") || s.to_lowercase().contains("not found") {
        libc::ENOENT
    } else if s.contains("403") || s.to_lowercase().contains("forbidden") {
        libc::EACCES
    } else {
        libc::EIO
    }
}

// --------------------------------------------------------------------- mount API

pub fn mount(conn: &Connection, secret: &str) -> Result<MountInfo> {
    let backend = Arc::new(Backend::from_connection(conn, secret)?);

    let mount_point = choose_mount_point(&conn.display_name());
    std::fs::create_dir_all(&mount_point).map_err(|e| Error::Other(e.to_string()))?;

    let rt = tokio::runtime::Handle::try_current()
        .ok()
        .unwrap_or_else(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .handle()
                .clone()
        });

    let fs = CloudFs { backend, rt, state: Mutex::new(FsState::new()) };
    let mp = mount_point.clone();

    std::thread::spawn(move || {
        let config = fuser::Config { root_mode: 0o755, ..Default::default() };
        if let Err(e) = fuser::mount(fs, &mp, &config) {
            eprintln!("[cloudmounter] FUSE mount of {} failed: {}", mp, e);
        }
    });

    let info = MountInfo { id: conn.id.clone(), name: conn.display_name(), mount_point };
    super::MOUNTS.lock().unwrap().insert(conn.id.clone(), info.clone());
    Ok(info)
}

pub fn unmount(mount_point: &str) -> Result<()> {
    fuser::unmount(mount_point).map_err(|e| Error::Other(e.to_string()))
}

fn choose_mount_point(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == ' ' { c } else { '-' })
        .collect();
    let safe = safe.trim().to_string();
    let label = if safe.is_empty() { "Drive".to_string() } else { safe };
    #[cfg(target_os = "macos")]
    {
        format!("/Volumes/CloudMounter - {}", label)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let dir = std::env::temp_dir().join(format!("cloudmounter-{}", label));
        let _ = std::fs::create_dir_all(&dir);
        dir.to_string_lossy().to_string()
    }
}
