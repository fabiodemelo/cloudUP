//! A WebDAV filesystem view of a cloud `Backend`.
//!
//! macOS mounts it with its built-in WebDAV client (`mount_webdav`), so a
//! connection shows up in Finder as a normal drive with no kernel extension
//! (macFUSE) to install.
//!
//! Files are read whole on first access and written whole when the client
//! flushes them — the same granularity the backends support — spooled
//! through a temporary file, so their size isn't limited by memory.
//! Directory listings are cached for a few seconds because Finder issues
//! many PROPFINDs for every folder it shows. Finder's own metadata files
//! (`._*`, `.DS_Store`) are kept in memory (a few MiB each at most) and
//! never sent to the cloud. Both caches are sized from the memory limit in
//! Settings, and the memory watchdog (`crate::memory`) trims them through
//! `drop_listings` and `trim_finder_files` when CloudUp is over it.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use bytes::{Buf, Bytes};
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
    OpenOptions, ReadDirMeta,
};
use futures_util::{stream, FutureExt};

use crate::backend::{Backend, Entry, TempPath};
use crate::{memory, settings};

const LIST_TTL: Duration = Duration::from_secs(5);

/// Recent folder listings. Expired ones are dropped whenever one is added
/// (before, every folder ever listed stayed in memory), then the oldest
/// beyond the cap.
#[derive(Default)]
struct ListCache {
    map: HashMap<String, (Instant, Vec<Entry>)>,
}

impl ListCache {
    fn get(&self, dir: &str, now: Instant) -> Option<Vec<Entry>> {
        self.map.get(dir).filter(|(at, _)| now.duration_since(*at) < LIST_TTL).map(|(_, v)| v.clone())
    }

    fn insert(&mut self, dir: String, v: Vec<Entry>, cap: usize, now: Instant) {
        self.map.retain(|_, (at, _)| now.duration_since(*at) < LIST_TTL);
        self.map.remove(&dir);
        while self.map.len() >= cap.max(1) {
            let Some(oldest) = self.map.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone()) else {
                break;
            };
            self.map.remove(&oldest);
        }
        self.map.insert(dir, (now, v));
    }

    fn remove(&mut self, dir: &str) {
        self.map.remove(dir);
    }

    /// Drop every listing; how many there were.
    fn clear(&mut self) -> usize {
        let n = self.map.len();
        self.map.clear();
        n
    }
}

/// Finder metadata files, held only in memory: path -> (modified, contents).
type FinderFiles = HashMap<String, (SystemTime, Vec<u8>)>;

/// Drop the oldest side-files until they total at most `budget` bytes; how
/// many were dropped. Losing one only loses a Finder view setting.
fn trim_junk(files: &mut FinderFiles, budget: u64) -> usize {
    let mut total: u64 = files.values().map(|(_, d)| d.len() as u64).sum();
    if total <= budget {
        return 0;
    }
    let mut by_age: Vec<(SystemTime, String)> = files.iter().map(|(k, (t, _))| (*t, k.clone())).collect();
    by_age.sort();
    let mut dropped = 0;
    for (_, k) in by_age {
        if total <= budget {
            break;
        }
        if let Some((_, d)) = files.remove(&k) {
            total -= d.len() as u64;
            dropped += 1;
        }
    }
    dropped
}

/// One drive's caches.
#[derive(Default)]
struct Caches {
    lists: Mutex<ListCache>,
    local: Mutex<FinderFiles>,
}

/// The caches of every drive being served (a drive's go away when it stops).
static ALL_CACHES: LazyLock<Mutex<Vec<Weak<Caches>>>> = LazyLock::new(Default::default);

fn register(c: &Arc<Caches>) {
    let mut all = ALL_CACHES.lock().unwrap();
    all.retain(|w| w.strong_count() > 0);
    all.push(Arc::downgrade(c));
}

fn live_caches() -> Vec<Arc<Caches>> {
    ALL_CACHES.lock().unwrap().iter().filter_map(Weak::upgrade).collect()
}

/// Drop every drive's folder listings; how many were dropped.
pub fn drop_listings() -> usize {
    live_caches().iter().map(|c| c.lists.lock().unwrap().clear()).sum()
}

/// Cut every drive's Finder side-files down to `budget` bytes, oldest first;
/// how many were dropped.
pub fn trim_finder_files(budget: u64) -> usize {
    live_caches().iter().map(|c| trim_junk(&mut c.local.lock().unwrap(), budget)).sum()
}

#[derive(Clone)]
pub struct CloudFs {
    backend: Backend,
    caches: Arc<Caches>,
    /// Shown as the root folder's date (clouds rarely have one).
    started: SystemTime,
}

impl CloudFs {
    pub fn new(backend: Backend) -> Self {
        let caches = Arc::new(Caches::default());
        register(&caches);
        Self { backend, caches, started: SystemTime::now() }
    }

    async fn list(&self, dir: &str) -> FsResult<Vec<Entry>> {
        if let Some(v) = self.caches.lists.lock().unwrap().get(dir, Instant::now()) {
            return Ok(v);
        }
        let v = self.backend.list(dir).await.map_err(map_err)?;
        let cap = memory::listing_cache_entries(settings::memory_limit_mb());
        self.caches.lists.lock().unwrap().insert(dir.to_string(), v.clone(), cap, Instant::now());
        Ok(v)
    }

    fn invalidate(&self, path: &str) {
        let mut l = self.caches.lists.lock().unwrap();
        l.remove(&parent(path));
        l.remove(path);
    }

    async fn lookup(&self, path: &str) -> FsResult<Meta> {
        if path == "/" {
            return Ok(Meta::dir(Some(self.started)));
        }
        if let Some((t, data)) = self.caches.local.lock().unwrap().get(path) {
            return Ok(Meta { len: data.len() as u64, dir: false, modified: Some(*t) });
        }
        let name = path.rsplit('/').next().unwrap_or("");
        let entries = self.list(&parent(path)).await?;
        entries
            .iter()
            .find(|e| e.name == name)
            .map(Meta::from_entry)
            .ok_or(FsError::NotFound)
    }
}

impl CloudFs {
    /// Recreate folder `from` (recursively) at `to`.
    async fn copy_tree(&self, from: &str, to: &str) -> FsResult<()> {
        self.backend.mkdir(to).await.map_err(map_err)?;
        let mut stack = vec![(from.to_string(), to.to_string())];
        while let Some((src, dst)) = stack.pop() {
            for e in self.backend.list(&src).await.map_err(map_err)? {
                let target = format!("{}/{}", dst.trim_end_matches('/'), e.name);
                if e.is_dir {
                    self.backend.mkdir(&target).await.map_err(map_err)?;
                    stack.push((e.path, target));
                } else {
                    self.backend.copy_file(&e.path, &target).await.map_err(map_err)?;
                }
            }
        }
        Ok(())
    }

    /// Delete folder `path` and everything in it (children first, for
    /// backends that only remove empty folders).
    async fn remove_tree(&self, path: &str) -> FsResult<()> {
        let mut dirs = vec![path.to_string()];
        let mut i = 0;
        while i < dirs.len() {
            let d = dirs[i].clone();
            for e in self.backend.list(&d).await.map_err(map_err)? {
                if e.is_dir {
                    dirs.push(e.path);
                } else {
                    self.backend.remove(&e.path, false).await.map_err(map_err)?;
                }
            }
            i += 1;
        }
        for d in dirs.iter().rev() {
            self.backend.remove(d, true).await.map_err(map_err)?;
        }
        Ok(())
    }
}

/// Finder's metadata side-files: keep them local.
fn is_finder_junk(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    name.starts_with("._") || name == ".DS_Store" || name == ".localized"
        || name == ".metadata_never_index" || name == ".Spotlight-V100" || name == ".Trashes"
}

fn parent(path: &str) -> String {
    let t = path.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => t[..i].to_string(),
    }
}

/// Backend-relative path ("/a/b") for a request path.
fn rel(path: &DavPath) -> String {
    let p = String::from_utf8_lossy(path.as_bytes()).trim_end_matches('/').to_string();
    if p.is_empty() { "/".into() } else { p }
}

fn map_err(e: crate::error::Error) -> FsError {
    use crate::error::Error;
    // Prefer the HTTP status; only errors without one (FTP, SFTP, local I/O)
    // are classified by their text. A wrong "not found" makes Finder drop
    // the item, so anything unclear is a general failure (and logged).
    let status = match &e {
        // FTP reply codes aren't HTTP statuses (550 = unavailable, for any reason).
        Error::Api { provider, .. } if provider == "FTP" => None,
        Error::S3 { status, .. } | Error::Webdav { status, .. } | Error::Api { status, .. } => Some(*status),
        _ => None,
    };
    let s = e.to_string().to_lowercase();
    let not_found = match status {
        Some(code) => code == 404 || code == 410,
        None => s.contains("not found") || s.contains("no such file") || s.contains("does not exist"),
    };
    let forbidden = match status {
        Some(code) => code == 401 || code == 403,
        None => s.contains("permission denied") || s.contains("access denied"),
    };
    if not_found {
        FsError::NotFound
    } else if forbidden {
        FsError::Forbidden
    } else {
        eprintln!("cloudup drive: {e}");
        FsError::GeneralFailure
    }
}

// ------------------------------------------------------------------ metadata

#[derive(Debug, Clone)]
struct Meta {
    len: u64,
    dir: bool,
    modified: Option<SystemTime>,
}

impl Meta {
    fn dir(modified: Option<SystemTime>) -> Self {
        Meta { len: 0, dir: true, modified }
    }
    fn from_entry(e: &Entry) -> Self {
        let modified = e
            .modified
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(SystemTime::from);
        Meta { len: if e.is_dir { 0 } else { e.size }, dir: e.is_dir, modified }
    }
}

impl DavMetaData for Meta {
    fn len(&self) -> u64 {
        self.len
    }
    fn modified(&self) -> FsResult<SystemTime> {
        self.modified.ok_or(FsError::NotImplemented)
    }
    fn is_dir(&self) -> bool {
        self.dir
    }
}

struct DirEntry {
    name: String,
    meta: Meta,
}

impl DavDirEntry for DirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }
    fn metadata(&'_ self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let m: Box<dyn DavMetaData> = Box::new(self.meta.clone());
        async move { Ok(m) }.boxed()
    }
}

// ---------------------------------------------------------------------- files

#[derive(Debug)]
enum Store {
    Cloud,
    Local,
}

/// Finder side-files live in memory: cap each so a client can't exhaust RAM
/// through them.
const JUNK_MAX: u64 = 4 * 1024 * 1024;

/// A write may leave a hole past the end of a file (it reads back as
/// zeros), but not an absurd one.
const MAX_GAP: u64 = 1 << 30;

/// An open file's contents, once loaded.
enum Spool {
    /// Finder side-files: in memory, at most `JUNK_MAX` bytes.
    Mem(Vec<u8>),
    /// Cloud files: a temporary file, deleted when the spool is dropped.
    Disk { file: tokio::fs::File, len: u64, tmp: TempPath },
}

impl Spool {
    /// A temporary file holding `len` bytes already written at `tmp`
    /// (created empty if missing).
    async fn disk(tmp: TempPath, len: u64) -> FsResult<Self> {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(tmp.path())
            .await
            .map_err(io_err)?;
        Ok(Spool::Disk { file, len, tmp })
    }

    /// Empty contents for `store`.
    async fn empty(store: &Store) -> FsResult<Self> {
        match store {
            Store::Local => Ok(Spool::Mem(Vec::new())),
            Store::Cloud => Spool::disk(TempPath::new("dav").map_err(map_err)?, 0).await,
        }
    }

    fn len(&self) -> u64 {
        match self {
            Spool::Mem(v) => v.len() as u64,
            Spool::Disk { len, .. } => *len,
        }
    }

    /// Up to `count` bytes from `pos` (fewer at the end of the file).
    async fn read_at(&mut self, pos: u64, count: usize) -> FsResult<Bytes> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let n = (count as u64).min(self.len().saturating_sub(pos)) as usize;
        if n == 0 {
            return Ok(Bytes::new());
        }
        match self {
            Spool::Mem(v) => Ok(Bytes::copy_from_slice(&v[pos as usize..pos as usize + n])),
            Spool::Disk { file, .. } => {
                file.seek(SeekFrom::Start(pos)).await.map_err(io_err)?;
                let mut buf = vec![0u8; n];
                file.read_exact(&mut buf).await.map_err(io_err)?;
                Ok(Bytes::from(buf))
            }
        }
    }

    /// Write `buf` at `pos`, growing the file as needed.
    async fn write_at(&mut self, pos: u64, buf: &[u8]) -> FsResult<()> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        let end = pos.checked_add(buf.len() as u64).ok_or(FsError::TooLarge)?;
        if pos > self.len().saturating_add(MAX_GAP) {
            return Err(FsError::TooLarge);
        }
        match self {
            Spool::Mem(v) => {
                if end > JUNK_MAX {
                    return Err(FsError::TooLarge);
                }
                let (pos, end) = (pos as usize, end as usize);
                if v.len() < end {
                    v.resize(end, 0);
                }
                v[pos..end].copy_from_slice(buf);
            }
            Spool::Disk { file, len, .. } => {
                file.seek(SeekFrom::Start(pos)).await.map_err(io_err)?;
                file.write_all(buf).await.map_err(io_err)?;
                *len = (*len).max(end);
            }
        }
        Ok(())
    }
}

/// Where a seek lands, or `None` before the start (or past `u64::MAX`).
fn seek_target(pos: SeekFrom, current: u64, len: u64) -> Option<u64> {
    match pos {
        SeekFrom::Start(n) => Some(n),
        SeekFrom::End(d) => len.checked_add_signed(d),
        SeekFrom::Current(d) => current.checked_add_signed(d),
    }
}

/// A local spool-file error.
fn io_err(e: std::io::Error) -> FsError {
    eprintln!("cloudup drive: temporary file: {e}");
    if e.raw_os_error() == Some(libc::ENOSPC) {
        FsError::InsufficientStorage
    } else {
        FsError::GeneralFailure
    }
}

/// An open file: contents are loaded on first access (cloud files are
/// downloaded once into a temporary file) and uploaded on flush.
struct CloudFile {
    fs: CloudFs,
    path: String,
    store: Store,
    spool: Option<Spool>,
    pos: u64,
    dirty: bool,
    meta: Meta,
    /// Size announced for a whole-file PUT: a body that ends short is not
    /// uploaded over the file.
    expected: Option<u64>,
}

impl std::fmt::Debug for CloudFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudFile").field("path", &self.path).field("store", &self.store).finish()
    }
}

impl CloudFile {
    async fn load(&mut self) -> FsResult<&mut Spool> {
        if self.spool.is_none() {
            let spool = match self.store {
                Store::Local => {
                    Spool::Mem(self.fs.caches.local.lock().unwrap().get(&self.path).map(|(_, d)| d.clone()).unwrap_or_default())
                }
                Store::Cloud => {
                    let tmp = TempPath::new("dav").map_err(map_err)?;
                    let len = self.fs.backend.read_to_file(&self.path, tmp.path()).await.map_err(map_err)?;
                    Spool::disk(tmp, len).await?
                }
            };
            self.spool = Some(spool);
        }
        Ok(self.spool.as_mut().unwrap())
    }

    async fn write_at_pos(&mut self, buf: &[u8]) -> FsResult<()> {
        let pos = self.pos;
        self.load().await?.write_at(pos, buf).await?;
        self.pos += buf.len() as u64;
        self.dirty = true;
        Ok(())
    }
}

impl DavFile for CloudFile {
    fn metadata(&'_ mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        async move {
            let mut m = self.meta.clone();
            if let Some(s) = &self.spool {
                m.len = s.len();
            }
            Ok(Box::new(m) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn write_buf(&'_ mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        async move {
            while buf.has_remaining() {
                let chunk = buf.chunk().to_vec();
                self.write_at_pos(&chunk).await?;
                buf.advance(chunk.len());
            }
            Ok(())
        }
        .boxed()
    }

    fn write_bytes(&'_ mut self, buf: Bytes) -> FsFuture<'_, ()> {
        async move { self.write_at_pos(&buf).await }.boxed()
    }

    fn read_bytes(&'_ mut self, count: usize) -> FsFuture<'_, Bytes> {
        async move {
            let pos = self.pos;
            let out = self.load().await?.read_at(pos, count).await?;
            self.pos += out.len() as u64;
            Ok(out)
        }
        .boxed()
    }

    fn seek(&'_ mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        async move {
            let len = self.load().await?.len();
            self.pos = seek_target(pos, self.pos, len).ok_or(FsError::GeneralFailure)?;
            Ok(self.pos)
        }
        .boxed()
    }

    fn flush(&'_ mut self) -> FsFuture<'_, ()> {
        async move {
            if !self.dirty {
                return Ok(());
            }
            self.load().await?;
            let spool = self.spool.as_mut().expect("loaded");
            let len = spool.len();
            if self.expected.is_some_and(|n| n != len) {
                eprintln!("cloudup drive: {}: upload ended early ({len} bytes), not saved", self.path);
                return Err(FsError::GeneralFailure);
            }
            match spool {
                Spool::Mem(data) => {
                    let data = data.clone();
                    let budget = memory::finder_files_budget(settings::memory_limit_mb());
                    let mut local = self.fs.caches.local.lock().unwrap();
                    local.insert(self.path.clone(), (SystemTime::now(), data));
                    trim_junk(&mut local, budget);
                }
                Spool::Disk { file, tmp, .. } => {
                    use tokio::io::AsyncWriteExt;
                    // Finish pending writes before the upload reads the file.
                    file.flush().await.map_err(io_err)?;
                    self.fs.backend.write_from_file(&self.path, tmp.path()).await.map_err(map_err)?;
                    self.fs.invalidate(&self.path);
                }
            }
            self.dirty = false;
            Ok(())
        }
        .boxed()
    }
}

// ----------------------------------------------------------------- filesystem

impl DavFileSystem for CloudFs {
    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<'a, Box<dyn DavFile>> {
        async move {
            let p = rel(path);
            let store = if is_finder_junk(&p) { Store::Local } else { Store::Cloud };
            let existing = self.lookup(&p).await;
            let meta = match (&existing, options.write) {
                (Ok(m), _) if m.dir => return Err(FsError::Forbidden),
                (Ok(_), true) if options.create_new => return Err(FsError::Exists),
                (Ok(m), _) => m.clone(),
                (Err(FsError::NotFound), true) if options.create || options.create_new => {
                    Meta { len: 0, dir: false, modified: Some(SystemTime::now()) }
                }
                (Err(e), _) => return Err(*e),
            };
            let truncate = options.write && (options.truncate || existing.is_err());
            let mut file = CloudFile {
                fs: self.clone(),
                spool: if truncate { Some(Spool::empty(&store).await?) } else { None },
                path: p,
                store,
                pos: 0,
                // A new file, or one truncated and closed without writes, must
                // still be saved (empty).
                dirty: truncate,
                meta,
                expected: if truncate { options.size } else { None },
            };
            if options.append {
                file.pos = file.load().await?.len();
            }
            Ok(Box::new(file) as Box<dyn DavFile>)
        }
        .boxed()
    }

    fn read_dir<'a>(&'a self, path: &'a DavPath, _meta: ReadDirMeta) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        async move {
            let p = rel(path);
            let mut items: Vec<FsResult<Box<dyn DavDirEntry>>> = self
                .list(&p)
                .await?
                .iter()
                .map(|e| Ok(Box::new(DirEntry { name: e.name.clone(), meta: Meta::from_entry(e) }) as Box<dyn DavDirEntry>))
                .collect();
            // Finder files created in this folder this session.
            let prefix = if p == "/" { "/".to_string() } else { format!("{p}/") };
            for (k, (t, d)) in self.caches.local.lock().unwrap().iter() {
                if let Some(name) = k.strip_prefix(&prefix) {
                    if !name.contains('/') {
                        items.push(Ok(Box::new(DirEntry {
                            name: name.to_string(),
                            meta: Meta { len: d.len() as u64, dir: false, modified: Some(*t) },
                        })));
                    }
                }
            }
            Ok(Box::pin(stream::iter(items)) as FsStream<Box<dyn DavDirEntry>>)
        }
        .boxed()
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        async move { Ok(Box::new(self.lookup(&rel(path)).await?) as Box<dyn DavMetaData>) }.boxed()
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let p = rel(path);
            if self.lookup(&p).await.is_ok() {
                return Err(FsError::Exists);
            }
            self.backend.mkdir(&p).await.map_err(map_err)?;
            self.invalidate(&p);
            Ok(())
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let p = rel(path);
            // Drop Finder side-files inside it so an "empty" folder really is.
            let prefix = format!("{p}/");
            self.caches.local.lock().unwrap().retain(|k, _| !k.starts_with(&prefix));
            self.backend.remove(&p, true).await.map_err(map_err)?;
            self.invalidate(&p);
            Ok(())
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let p = rel(path);
            if self.caches.local.lock().unwrap().remove(&p).is_some() {
                return Ok(());
            }
            self.backend.remove(&p, false).await.map_err(map_err)?;
            self.invalidate(&p);
            Ok(())
        }
        .boxed()
    }

    // No get_quota: when a server reports quota (any figure) macOS's WebDAV
    // client stalls ~90 s right after mounting. Like Apache, report none.

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let (f, t) = (rel(from), rel(to));
            // Take the value out first: a guard held in the `if let` scrutinee
            // would still be locked inside the body and deadlock the insert.
            let moved = self.caches.local.lock().unwrap().remove(&f);
            if let Some(v) = moved {
                self.caches.local.lock().unwrap().insert(t, v);
                return Ok(());
            }
            // No backend has a native rename yet: copy, then delete the original.
            if self.lookup(&f).await?.dir {
                self.copy_tree(&f, &t).await?;
                self.remove_tree(&f).await?;
            } else {
                self.backend.copy_file(&f, &t).await.map_err(map_err)?;
                self.backend.remove(&f, false).await.map_err(map_err)?;
            }
            self.caches.lists.lock().unwrap().clear();
            Ok(())
        }
        .boxed()
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let (f, t) = (rel(from), rel(to));
            if self.lookup(&f).await?.dir {
                self.copy_tree(&f, &t).await?;
            } else {
                self.backend.copy_file(&f, &t).await.map_err(map_err)?;
            }
            self.invalidate(&t);
            Ok(())
        }
        .boxed()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_and_junk() {
        assert_eq!(parent("/a/b.txt"), "/a");
        assert_eq!(parent("/a"), "/");
        assert!(is_finder_junk("/x/._photo.jpg"));
        assert!(is_finder_junk("/.DS_Store"));
        assert!(!is_finder_junk("/x/photo.jpg"));
    }

    fn entry(name: &str) -> Entry {
        Entry { name: name.into(), path: format!("/{name}"), is_dir: false, size: 1, modified: None, perms: None }
    }

    #[test]
    fn listing_cache_is_capped_and_drops_the_oldest() {
        let t0 = Instant::now();
        let mut c = ListCache::default();
        for (i, dir) in ["/a", "/b", "/c"].iter().enumerate() {
            c.insert(dir.to_string(), vec![entry("x")], 2, t0 + Duration::from_millis(i as u64));
        }
        assert_eq!(c.map.len(), 2);
        assert!(c.get("/a", t0).is_none(), "the oldest went");
        assert!(c.get("/b", t0).is_some() && c.get("/c", t0).is_some());
        // Listing a cached folder again replaces it instead of evicting another.
        c.insert("/c".into(), vec![], 2, t0 + Duration::from_millis(5));
        assert!(c.get("/b", t0).is_some());
        assert_eq!(c.clear(), 2);
        assert!(c.map.is_empty());
    }

    #[test]
    fn listing_cache_expires_and_forgets_stale_listings() {
        let t0 = Instant::now();
        let mut c = ListCache::default();
        c.insert("/old".into(), vec![entry("x")], 100, t0);
        assert!(c.get("/old", t0 + LIST_TTL - Duration::from_millis(1)).is_some());
        assert!(c.get("/old", t0 + LIST_TTL).is_none());
        // Adding another listing removes the expired one from memory.
        c.insert("/new".into(), vec![], 100, t0 + LIST_TTL);
        assert_eq!(c.map.len(), 1);
    }

    #[test]
    fn finder_files_are_trimmed_oldest_first() {
        let t0 = SystemTime::UNIX_EPOCH;
        let mut f: FinderFiles = HashMap::new();
        for (i, p) in ["/1", "/2", "/3"].iter().enumerate() {
            f.insert(p.to_string(), (t0 + Duration::from_secs(i as u64), vec![0u8; 100]));
        }
        assert_eq!(trim_junk(&mut f, 300), 0);
        assert_eq!(trim_junk(&mut f, 150), 2);
        assert!(f.contains_key("/3") && f.len() == 1);
        assert_eq!(trim_junk(&mut f, 0), 1);
        assert!(f.is_empty());
    }

    #[test]
    fn seek_targets_are_checked() {
        assert_eq!(seek_target(SeekFrom::Start(5), 0, 10), Some(5));
        assert_eq!(seek_target(SeekFrom::End(-3), 0, 10), Some(7));
        assert_eq!(seek_target(SeekFrom::End(-11), 0, 10), None);
        assert_eq!(seek_target(SeekFrom::Current(2), 4, 10), Some(6));
        assert_eq!(seek_target(SeekFrom::Current(-5), 4, 10), None);
        // Offsets beyond i64::MAX no longer wrap negative.
        assert_eq!(seek_target(SeekFrom::Start(u64::MAX), 0, 10), Some(u64::MAX));
        assert_eq!(seek_target(SeekFrom::Current(1), u64::MAX, 10), None);
    }

    #[tokio::test]
    async fn junk_files_are_capped() {
        let mut s = Spool::empty(&Store::Local).await.unwrap();
        s.write_at(0, b"hello").await.unwrap();
        assert_eq!(s.len(), 5);
        assert!(s.write_at(JUNK_MAX - 1, b"xy").await.is_err());
        s.write_at(JUNK_MAX - 2, b"xy").await.unwrap();
        assert_eq!(s.len(), JUNK_MAX);
        assert_eq!(&s.read_at(0, 5).await.unwrap()[..], b"hello");
    }

    #[tokio::test]
    async fn disk_spool_reads_writes_and_refuses_huge_gaps() {
        let mut s = Spool::empty(&Store::Cloud).await.unwrap();
        let path = match &s {
            Spool::Disk { tmp, .. } => tmp.path().to_path_buf(),
            Spool::Mem(_) => panic!("cloud files spool to disk"),
        };
        s.write_at(0, b"abcdef").await.unwrap();
        s.write_at(10, b"Z").await.unwrap(); // a small hole is fine
        assert_eq!(s.len(), 11);
        assert_eq!(&s.read_at(4, 100).await.unwrap()[..], b"ef\0\0\0\0Z");
        assert!(s.read_at(11, 10).await.unwrap().is_empty());
        assert!(matches!(s.write_at(11 + MAX_GAP + 1, b"x").await, Err(FsError::TooLarge)));
        assert!(matches!(s.write_at(u64::MAX, b"x").await, Err(FsError::TooLarge)));
        drop(s);
        assert!(!path.exists(), "the temporary file is removed with the spool");
    }

    /// The drive end to end, over a live WebDAV backend (skips unless
    /// CM_TEST_WEBDAV_URL is set, e.g. a local Apache with mod_dav).
    #[tokio::test]
    async fn live_drive_put_get_truncate() {
        let Ok(url) = std::env::var("CM_TEST_WEBDAV_URL") else {
            eprintln!("live_drive_put_get_truncate: skipped (set CM_TEST_WEBDAV_URL)");
            return;
        };
        use dav_server::{fakels::FakeLs, DavHandler};
        let backend = Backend::Webdav(crate::webdav::Webdav::new(&url, "", ""));
        let handler = DavHandler::builder()
            .filesystem(Box::new(CloudFs::new(backend)))
            .locksystem(FakeLs::new())
            .build_handler();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let handler = handler.clone();
                        async move { Ok::<_, std::convert::Infallible>(handler.handle(req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let c = reqwest::Client::new();
        let u = |p: &str| format!("http://127.0.0.1:{port}{p}");
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();

        let r = c.put(u("/drive-test.bin")).body(data.clone()).send().await.unwrap();
        assert!(r.status().is_success(), "PUT: {}", r.status());
        let got = c.get(u("/drive-test.bin")).send().await.unwrap().bytes().await.unwrap();
        assert_eq!(got.len(), data.len());
        assert!(got[..] == data[..], "GET content");
        let r = c.get(u("/drive-test.bin")).header("Range", "bytes=10-19").send().await.unwrap();
        assert_eq!(r.status().as_u16(), 206);
        assert_eq!(&r.bytes().await.unwrap()[..], &data[10..20]);

        // An empty PUT over an existing file must leave it empty.
        let r = c.put(u("/drive-test.bin")).body(Vec::new()).send().await.unwrap();
        assert!(r.status().is_success(), "empty PUT: {}", r.status());
        let got = c.get(u("/drive-test.bin")).send().await.unwrap().bytes().await.unwrap();
        assert!(got.is_empty(), "truncated file still has {} bytes", got.len());

        // Finder side-files stay local and are capped.
        let r = c.put(u("/._drive-test.bin")).body(vec![1u8; 1000]).send().await.unwrap();
        assert!(r.status().is_success());
        let r = c.put(u("/._big")).body(vec![1u8; JUNK_MAX as usize + 1]).send().await.unwrap();
        assert!(!r.status().is_success(), "oversized side-file accepted");

        // MOVE goes through a temp-file copy.
        let r = c.put(u("/drive-src.txt")).body("moved").send().await.unwrap();
        assert!(r.status().is_success());
        let r = c
            .request(reqwest::Method::from_bytes(b"MOVE").unwrap(), u("/drive-src.txt"))
            .header("Destination", u("/drive-dst.txt"))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "MOVE: {}", r.status());
        let got = c.get(u("/drive-dst.txt")).send().await.unwrap().text().await.unwrap();
        assert_eq!(got, "moved");

        for p in ["/drive-test.bin", "/drive-dst.txt"] {
            c.delete(u(p)).send().await.unwrap();
        }
    }
}
