//! FUSE filesystem backed by a [`Backend`]. Only compiled with `--features fuse-mount`.
//!
//! Inode numbers are assigned locally (cloud stores have no stable inodes) and
//! mapped to paths. Directory listings are fetched on demand; file contents are
//! cached per open handle (seeded on the first write) and uploaded on flush/close.
//! Handles are plain `u64`s (fuser 0.15) served out of a `HashMap<u64, OpenFile>`.

use super::{MountInfo, MOUNTS, SESSIONS};
use crate::backend::{Backend, Entry};
use crate::config::Connection;
use crate::error::{Error, Result};

use fuser::{
    FileAttr, Filesystem, FileType, FUSE_ROOT_ID, MountOption, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    Request,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const ROOT_INO: u64 = 1;
/// How long the kernel may cache attributes / directory entries.
const TTL: Duration = Duration::from_secs(1);

// --------------------------------------------------------------------------- state

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

    /// Forget the inode mapping + cached metadata for a path.
    fn forget_path(&mut self, path: &str) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            self.ino_to_path.remove(&ino);
            self.meta.remove(&ino);
        }
    }
}

/// A single open file: path + the in-memory buffer that receives writes.
struct OpenFile {
    path: String,
    writable: bool,
    /// Buffer for written bytes. `None` until the first write seeds it;
    /// seeding fetches the remote object first (so short writes/patches work).
    data: Mutex<Option<Vec<u8>>>,
}

impl OpenFile {
    fn new(path: String, writable: bool) -> Self {
        Self { path, writable, data: Mutex::new(None) }
    }
}

/// Everything a FUSE callback needs to touch one open file. The buffer is
/// locked per access (fuser clones the filesystem per session, so the handle
/// map outlives any single callback and guards cannot be `'static`).
struct Fh {
    id: u64,
    path: String,
    writable: bool,
}

// ------------------------------------------------------------------------- attributes

fn attr_from_entry(ino: u64, e: &Entry, uid: u32, gid: u32) -> FileAttr {
    let now = SystemTime::now();
    let size = if e.is_dir { 4096 } else { e.size };
    FileAttr {
        ino,
        size,
        blocks: (size + 511) / 512,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: if e.is_dir { FileType::Directory } else { FileType::RegularFile },
        perm: if e.is_dir { 0o755 } else { 0o644 },
        nlink: if e.is_dir { 2 } else { 1 },
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn dir_attr(ino: u64, uid: u32, gid: u32) -> FileAttr {
    let now = SystemTime::now();
    FileAttr {
        ino,
        size: 4096,
        blocks: 9,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn is_writable_flags(flags: i32) -> bool {
    matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() || parent == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), name)
    }
}

fn parent_of(path: &str) -> String {
    let base = path.trim_end_matches('/');
    let p = base.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
    if p.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", p)
    }
}

// --------------------------------------------------------------------------- filesystem

struct CloudFs {
    backend: Arc<Backend>,
    rt: tokio::runtime::Handle,
    state: Mutex<FsState>,
    open_files: Mutex<HashMap<u64, OpenFile>>,
    next_fh: u64,
}

impl CloudFs {
    /// Allocate a handle id for an open file.
    fn alloc_fh(&mut self, of: OpenFile) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.open_files.lock().unwrap().insert(fh, of);
        fh
    }

    /// Snapshot a handle's (path, writable) pair, or return `EBADF`.
    fn borrow(&mut self, fh: u64) -> std::result::Result<Fh, i32> {
        let map = self.open_files.lock().unwrap();
        let of = map.get(&fh).ok_or(libc::EBADF)?;
        Ok(Fh { id: fh, path: of.path.clone(), writable: of.writable })
    }

    /// Upload the handle's buffer if it has been written, then drop it.
    fn drop_handle(&mut self, fh: u64) -> io::Result<()> {
        let of = match self.open_files.lock().unwrap().remove(&fh) {
            Some(of) => of,
            None => return Ok(()),
        };
        if of.writable {
            if let Some(buf) = of.data.into_inner().unwrap() {
                self.rt
                    .block_on(self.backend.write(&of.path, &buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Length of the pending-write buffer for a path, if any handle has written it.
    fn pending_len(&self, path: &str) -> Option<u64> {
        let guard = self.open_files.lock().unwrap();
        let of = guard.iter().find(|(_, of)| of.path == path)?;
        let (_, of) = of;
        let buf = of.data.lock().unwrap();
        Some(buf.as_ref()?.len() as u64)
    }

    /// Refresh the kernel's attribute/dentry caches for a path.
    /// The `notify` feature is not enabled, so there is nothing to do — the
    /// kernel's attribute/dentry TTLs expire within a second.
    fn invalidate_path(&mut self, _path: &str) {
        // no-op without the `notify` feature
    }

    /// Truncate the object at `path` to `new_size` bytes.
    fn truncate_file(&mut self, path: &str, new_size: u64) -> Result<()> {
        let mut buf = self.rt.block_on(self.backend.read(path))?;
        if buf.len() > new_size as usize {
            buf.truncate(new_size as usize);
        } else {
            buf.resize(new_size as usize, 0);
        }
        self.rt.block_on(self.backend.write(path, &buf))?;
        Ok(())
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

impl Filesystem for CloudFs {
    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        match self.rt.block_on(self.backend.list(&parent_path)) {
            Ok(entries) => {
                if let Some(e) = entries.iter().find(|e| e.name == name) {
                    let (ino, attr) = {
                        let mut state = self.state.lock().unwrap();
                        let ino = state.ino_for_path(&e.path);
                        state.remember(ino, e);
                        (ino, attr_from_entry(ino, e, req.uid(), req.gid()))
                    };
                    let _ = ino;
                    reply.entry(&TTL, &attr, 0);
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn getattr(&mut self, req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let uid = req.uid();
        let gid = req.gid();
        let path = self.state.lock().unwrap().path_for_ino(ino);
        if ino == ROOT_INO || path.ends_with('/') {
            reply.attr(&TTL, &dir_attr(ino, uid, gid));
        } else if let Some(e) = self.state.lock().unwrap().meta.get(&ino) {
            // If the file is open and has been written, report the new size.
            let size = self.pending_len(&path).unwrap_or(e.size);
            let mut a = attr_from_entry(ino, e, uid, gid);
            a.size = size;
            a.blocks = (size + 511) / 512;
            reply.attr(&TTL, &a);
        } else {
            // Unknown path: report a zero-size regular file; the kernel will re-stat.
            let mut a = dir_attr(ino, uid, gid);
            a.kind = FileType::RegularFile;
            a.perm = 0o644;
            a.nlink = 1;
            a.size = 0;
            a.blocks = 0;
            reply.attr(&TTL, &a);
        }
    }

    fn setattr(
        &mut self,
        req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if ino != ROOT_INO {
            if let Some(new_size) = size {
                let path = self.state.lock().unwrap().path_for_ino(ino);
                // Truncating a file that is currently open: resize its buffer.
                let open_fh = fh.filter(|&fh| {
                    self.open_files.lock().unwrap().get(&fh).map(|of| of.path == path).unwrap_or(false)
                });
                if let Some(fh) = open_fh {
                    {
                        let map = self.open_files.lock().unwrap();
                        if let Some(of) = map.get(&fh) {
                            if of.data.lock().unwrap().is_none() {
                                let map = self.open_files.lock().unwrap();
                                let data = self.rt.block_on(self.backend.read(&path)).unwrap_or_default();
                                *map.get(&fh).unwrap().data.lock().unwrap() = Some(data);
                            }
                        }
                    }
                    let map = self.open_files.lock().unwrap();
                    map.get(&fh).unwrap().data.lock().unwrap().as_mut().unwrap().resize(new_size as usize, 0);
                } else if let Err(e) = self.truncate_file(&path, new_size) {
                    reply.error(err_code(&e));
                    return;
                }
            }
        }
        self.revalidate(ino, reply, req.uid(), req.gid());
    }

    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let path = self.state.lock().unwrap().path_for_ino(ino);
        match self.rt.block_on(self.backend.list(&path)) {
            Ok(entries) => {
                let mut state = self.state.lock().unwrap();
                if offset <= 0 {
                    let dot: &OsStr = ".".as_ref();
                    if !reply.add(FUSE_ROOT_ID, 1, FileType::Directory, dot) {
                        return;
                    }
                    if path != "/" {
                        let pino = state.ino_for_path(&parent_of(&path));
                        let dotdot: &OsStr = "..".as_ref();
                        if !reply.add(pino, 2, FileType::Directory, dotdot) {
                            return;
                        }
                    }
                }
                let mut off = offset.max(1) + 1; // skip "." and ".."
                for e in entries {
                    let ino = state.ino_for_path(&e.path);
                    let kind = if e.is_dir { FileType::Directory } else { FileType::RegularFile };
                    let name = e.name.clone();
                    state.remember(ino, &e);
                    if !reply.add(ino, off, kind, name) {
                        break; // reply buffer full; kernel will refetch
                    }
                    off += 1;
                }
                reply.ok();
            }
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = self.state.lock().unwrap().path_for_ino(ino);
        let writable = is_writable_flags(flags);
        // O_TRUNC on an existing file: truncate up front.
        if writable && (flags & libc::O_TRUNC) != 0 && ino != ROOT_INO {
            if let Err(e) = self.truncate_file(&path, 0) {
                reply.error(err_code(&e));
                return;
            }
        }
        let fh = self.alloc_fh(OpenFile::new(path, writable));
        reply.opened(fh, 0);
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        // Persist an empty object so the file exists immediately.
        if let Err(e) = self.rt.block_on(self.backend.write(&path, b"")) {
            reply.error(err_code(&e));
            return;
        }
        let entry = Entry { name, path: path.clone(), is_dir: false, size: 0, modified: None, perms: None };
        let ino = self.state.lock().unwrap().ino_for_path(&path);
        self.state.lock().unwrap().remember(ino, &entry);
        // Fresh empty buffer so writes don't need to read anything first.
        let of = OpenFile::new(path.clone(), is_writable_flags(flags));
        *of.data.lock().unwrap() = Some(vec![]);
        let fh = self.alloc_fh(of);
        let attr = attr_from_entry(ino, &entry, req.uid(), req.gid());
        self.invalidate_path(&path);
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn read(&mut self, _req: &Request, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
        let fh = match self.borrow(fh) {
            Ok(fh) => fh,
            Err(e) => return reply.error(e),
        };
        // Seed the buffer on first access.
        {
            let map = self.open_files.lock().unwrap();
            if let Some(of) = map.get(&fh.id) {
                if of.data.lock().unwrap().is_none() {
                    drop(map);
                    let data = self.rt.block_on(self.backend.read(&fh.path));
                    let map = self.open_files.lock().unwrap();
                    *map.get(&fh.id).unwrap().data.lock().unwrap() = Some(data.unwrap_or_default());
                }
            }
        }
        let mut out = Vec::new();
        {
            let map = self.open_files.lock().unwrap();
            if let Some(of) = map.get(&fh.id) {
                let buf = of.data.lock().unwrap();
                if let Some(buf) = buf.as_ref() {
                    let start = offset.max(0) as usize;
                    if start < buf.len() {
                        let end = std::cmp::min(buf.len(), start + size as usize);
                        out.extend_from_slice(&buf[start..end]);
                    }
                }
            }
        }
        reply.data(&out);
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data_in: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let fh = match self.borrow(fh) {
            Ok(fh) => fh,
            Err(e) => return reply.error(e),
        };
        if !fh.writable {
            reply.error(libc::EACCES);
            return;
        }
        // Seed the buffer from the remote object before the first write.
        {
            let map = self.open_files.lock().unwrap();
            if let Some(of) = map.get(&fh.id) {
                if of.data.lock().unwrap().is_none() {
                    drop(map);
                    let data = self.rt.block_on(self.backend.read(&fh.path)).unwrap_or_default();
                    let map = self.open_files.lock().unwrap();
                    *map.get(&fh.id).unwrap().data.lock().unwrap() = Some(data);
                }
            }
        }
        let map = self.open_files.lock().unwrap();
        let mut buf = map.get(&fh.id).unwrap().data.lock().unwrap();
        if let Some(buf) = buf.as_mut() {
            let start = offset.max(0) as usize;
            let end = start + data_in.len();
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf[start..end].copy_from_slice(data_in);
        }
        reply.written(data_in.len() as u32);
    }

    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        if let Err(e) = self.drop_handle(fh) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
        } else {
            reply.ok();
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.drop_handle(fh) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
        } else {
            reply.ok();
        }
    }

    fn opendir(&mut self, _req: &Request, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn releasedir(&mut self, _req: &Request, _ino: u64, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn mkdir(&mut self, req: &Request, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        if let Err(e) = self.rt.block_on(self.backend.mkdir(&path)) {
            reply.error(err_code(&e));
            return;
        }
        let entry = Entry { name, path: path.clone(), is_dir: true, size: 0, modified: None, perms: None };
        let ino = self.state.lock().unwrap().ino_for_path(&path);
        self.state.lock().unwrap().remember(ino, &entry);
        self.invalidate_path(&path);
        reply.entry(&TTL, &attr_from_entry(ino, &entry, req.uid(), req.gid()), 0);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        match self.rt.block_on(self.backend.remove(&path, false)) {
            Ok(_) => {
                self.state.lock().unwrap().forget_path(&path);
                self.invalidate_path(&path);
                reply.ok();
            }
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name = name.to_string_lossy().to_string();
        let parent_path = self.state.lock().unwrap().path_for_ino(parent);
        let path = join_path(&parent_path, &name);
        match self.rt.block_on(self.backend.remove(&path, true)) {
            Ok(_) => {
                self.state.lock().unwrap().forget_path(&path);
                self.invalidate_path(&path);
                reply.ok();
            }
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let name = name.to_string_lossy().to_string();
        let new_name = new_name.to_string_lossy().to_string();
        let src = join_path(&self.state.lock().unwrap().path_for_ino(parent), &name);
        let dst = join_path(&self.state.lock().unwrap().path_for_ino(new_parent), &new_name);

        // Best-effort move: read + write + delete. Cloud stores rarely support
        // atomic rename; a busy destination is treated as a successful no-op
        // so renames of files onto themselves don't fail.
        let result = self.rt.block_on(async {
            let mut data = self.backend.read(&src).await?;
            let exists = self.backend.list(&parent_of(&dst)).await.is_ok_and(|es| {
                es.iter().any(|e| e.name == new_name)
            });
            if exists {
                // Only real content is stored; a destination that still exists
                // is either the file itself or a placeholder — keep it and just
                // re-write the content so the destination reflects the source.
                self.backend.write(&dst, &data).await?;
            } else {
                // A S3-style "folder" is a zero-byte object whose key ends in "/".
                let trailing = src.ends_with('/');
                if trailing && !dst.ends_with('/') {
                    data.push(b'/');
                }
                self.backend.write(&dst, &data).await?;
                if !trailing && dst.ends_with('/') {
                    self.backend.remove(&dst.trim_end_matches('/') , true).await?;
                }
            }
            self.backend.remove(&src, src.ends_with('/')).await?;
            Ok(()) as Result<()>
        });
        match result {
            Ok(_) => {
                {
                    let mut state = self.state.lock().unwrap();
                    state.forget_path(&src);
                    if src != dst {
                        state.forget_path(&dst);
                    }
                }
                self.invalidate_path(&dst);
                self.invalidate_path(&src);
                reply.ok();
            }
            Err(e) => reply.error(err_code(&e)),
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        // Fixed, generous values; cloud storage has no real statfs.
        const BSIZE: u32 = 4096;
        const BLOCKS: u64 = 1 << 40; // ~1 PiB
        reply.statfs(BLOCKS, BLOCKS / 2, BLOCKS / 2, 1 << 32, 1 << 32, BSIZE, 255, BSIZE);
    }
}

impl CloudFs {
    fn revalidate(&mut self, ino: u64, reply: ReplyAttr, uid: u32, gid: u32) {
        let path = self.state.lock().unwrap().path_for_ino(ino);
        if ino == ROOT_INO || path.ends_with('/') {
            reply.attr(&TTL, &dir_attr(ino, uid, gid));
        } else if let Some(e) = self.state.lock().unwrap().meta.get(&ino) {
            let mut a = attr_from_entry(ino, e, uid, gid);
            // Reflect pending writes from any open handle on this path.
            if let Some(len) = self.pending_len(&path) {
                a.size = len;
                a.blocks = (len + 511) / 512;
            }
            reply.attr(&TTL, &a);
        } else {
            let mut a = dir_attr(ino, uid, gid);
            a.kind = FileType::RegularFile;
            a.perm = 0o644;
            a.nlink = 1;
            a.size = 0;
            a.blocks = 0;
            reply.attr(&TTL, &a);
        }
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

    let fs = CloudFs {
        backend,
        rt,
        state: Mutex::new(FsState::new()),
        open_files: Mutex::new(HashMap::new()),
        next_fh: 1,
    };
    let mp = mount_point.clone();

    // Spawn the FUSE session on its own thread; keep the BackgroundSession in
    // MOUNTS so unmounting just drops it (dropping it unmounts the filesystem).
    let session = fuser::spawn_mount2(
        fs,
        &mp,
        &[
            MountOption::FSName("cloudup".into()),
            MountOption::DefaultPermissions,
        ],
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let info = MountInfo { id: conn.id.clone(), name: conn.display_name(), mount_point };
    MOUNTS.lock().unwrap().insert(conn.id.clone(), info.clone());
    SESSIONS.lock().unwrap().insert(conn.id.clone(), session);
    Ok(info)
}

/// Drop the background session for `id` — dropping it unmounts the filesystem.
pub fn unmount(id: &str) -> Result<()> {
    SESSIONS.lock().unwrap().remove(id);
    Ok(())
}

/// Remove every session; called on app exit so no stale mounts are left behind.
pub fn unmount_all() {
    SESSIONS.lock().unwrap().drain();
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
        format!("/Volumes/CloudUp - {}", label)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let dir = std::env::temp_dir().join(format!("cloudup-{}", label));
        let _ = std::fs::create_dir_all(&dir);
        dir.to_string_lossy().to_string()
    }
}
