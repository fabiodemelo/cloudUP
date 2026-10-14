//! A WebDAV filesystem view of a cloud `Backend`.
//!
//! macOS mounts it with its built-in WebDAV client (`mount_webdav`), so a
//! connection shows up in Finder as a normal drive with no kernel extension
//! (macFUSE) to install.
//!
//! Files are read whole on first access and written whole when the client
//! flushes them — the same granularity the backends support. Directory
//! listings are cached for a few seconds because Finder issues many PROPFINDs
//! for every folder it shows. Finder's own metadata files (`._*`,
//! `.DS_Store`) are kept in memory and never sent to the cloud.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::{Buf, Bytes};
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
    OpenOptions, ReadDirMeta,
};
use futures_util::{stream, FutureExt};

use crate::backend::{Backend, Entry};

const LIST_TTL: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct CloudFs {
    backend: Backend,
    lists: Arc<Mutex<HashMap<String, (Instant, Vec<Entry>)>>>,
    /// Finder metadata files, held only in memory: path -> contents.
    local: Arc<Mutex<HashMap<String, (SystemTime, Vec<u8>)>>>,
    /// Shown as the root folder's date (clouds rarely have one).
    started: SystemTime,
}

impl CloudFs {
    pub fn new(backend: Backend) -> Self {
        Self { backend, lists: Default::default(), local: Default::default(), started: SystemTime::now() }
    }

    async fn list(&self, dir: &str) -> FsResult<Vec<Entry>> {
        if let Some((at, v)) = self.lists.lock().unwrap().get(dir) {
            if at.elapsed() < LIST_TTL {
                return Ok(v.clone());
            }
        }
        let v = self.backend.list(dir).await.map_err(map_err)?;
        self.lists.lock().unwrap().insert(dir.to_string(), (Instant::now(), v.clone()));
        Ok(v)
    }

    fn invalidate(&self, path: &str) {
        let mut l = self.lists.lock().unwrap();
        l.remove(&parent(path));
        l.remove(path);
    }

    async fn lookup(&self, path: &str) -> FsResult<Meta> {
        if path == "/" {
            return Ok(Meta::dir(Some(self.started)));
        }
        if let Some((t, data)) = self.local.lock().unwrap().get(path) {
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
                    let data = self.backend.read(&e.path).await.map_err(map_err)?;
                    self.backend.write(&target, &data).await.map_err(map_err)?;
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
    let s = e.to_string().to_lowercase();
    if s.contains("not found") || s.contains("404") || s.contains("no such") {
        FsError::NotFound
    } else if s.contains("denied") || s.contains("403") || s.contains("permission") {
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

/// An open file: contents are loaded on first read and uploaded on flush.
struct CloudFile {
    fs: CloudFs,
    path: String,
    store: Store,
    data: Option<Vec<u8>>,
    pos: usize,
    dirty: bool,
    meta: Meta,
}

impl std::fmt::Debug for CloudFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudFile").field("path", &self.path).field("store", &self.store).finish()
    }
}

impl CloudFile {
    async fn load(&mut self) -> FsResult<&mut Vec<u8>> {
        if self.data.is_none() {
            let bytes = match self.store {
                Store::Local => self.fs.local.lock().unwrap().get(&self.path).map(|(_, d)| d.clone()).unwrap_or_default(),
                Store::Cloud => self.fs.backend.read(&self.path).await.map_err(map_err)?,
            };
            self.data = Some(bytes);
        }
        Ok(self.data.as_mut().unwrap())
    }

    async fn write_at_pos(&mut self, buf: &[u8]) -> FsResult<()> {
        let pos = self.pos;
        let data = self.load().await?;
        if data.len() < pos + buf.len() {
            data.resize(pos + buf.len(), 0);
        }
        data[pos..pos + buf.len()].copy_from_slice(buf);
        self.pos += buf.len();
        self.dirty = true;
        Ok(())
    }
}

impl DavFile for CloudFile {
    fn metadata(&'_ mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        async move {
            let mut m = self.meta.clone();
            if let Some(d) = &self.data {
                m.len = d.len() as u64;
            }
            Ok(Box::new(m) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn write_buf(&'_ mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        async move {
            let mut v = Vec::with_capacity(buf.remaining());
            while buf.has_remaining() {
                let chunk = buf.chunk();
                v.extend_from_slice(chunk);
                let n = chunk.len();
                buf.advance(n);
            }
            self.write_at_pos(&v).await
        }
        .boxed()
    }

    fn write_bytes(&'_ mut self, buf: Bytes) -> FsFuture<'_, ()> {
        async move { self.write_at_pos(&buf).await }.boxed()
    }

    fn read_bytes(&'_ mut self, count: usize) -> FsFuture<'_, Bytes> {
        async move {
            let pos = self.pos;
            let data = self.load().await?;
            let start = pos.min(data.len());
            let end = (start + count).min(data.len());
            let out = Bytes::copy_from_slice(&data[start..end]);
            self.pos = end;
            Ok(out)
        }
        .boxed()
    }

    fn seek(&'_ mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        async move {
            let len = self.load().await?.len() as i64;
            let new = match pos {
                SeekFrom::Start(n) => n as i64,
                SeekFrom::End(n) => len + n,
                SeekFrom::Current(n) => self.pos as i64 + n,
            };
            if new < 0 {
                return Err(FsError::GeneralFailure);
            }
            self.pos = new as usize;
            Ok(new as u64)
        }
        .boxed()
    }

    fn flush(&'_ mut self) -> FsFuture<'_, ()> {
        async move {
            if !self.dirty {
                return Ok(());
            }
            let data = self.data.clone().unwrap_or_default();
            match self.store {
                Store::Local => {
                    self.fs.local.lock().unwrap().insert(self.path.clone(), (SystemTime::now(), data));
                }
                Store::Cloud => {
                    self.fs.backend.write(&self.path, &data).await.map_err(map_err)?;
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
                path: p,
                store,
                data: if truncate { Some(Vec::new()) } else { None },
                pos: 0,
                dirty: truncate && existing.is_err(), // a brand-new empty file must still be created
                meta,
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
            for (k, (t, d)) in self.local.lock().unwrap().iter() {
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
            self.local.lock().unwrap().retain(|k, _| !k.starts_with(&prefix));
            self.backend.remove(&p, true).await.map_err(map_err)?;
            self.invalidate(&p);
            Ok(())
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let p = rel(path);
            if self.local.lock().unwrap().remove(&p).is_some() {
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
            if let Some(v) = self.local.lock().unwrap().remove(&f) {
                self.local.lock().unwrap().insert(t, v);
                return Ok(());
            }
            // No backend has a native rename yet: copy, then delete the original.
            if self.lookup(&f).await?.dir {
                self.copy_tree(&f, &t).await?;
                self.remove_tree(&f).await?;
            } else {
                let data = self.backend.read(&f).await.map_err(map_err)?;
                self.backend.write(&t, &data).await.map_err(map_err)?;
                self.backend.remove(&f, false).await.map_err(map_err)?;
            }
            self.lists.lock().unwrap().clear();
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
                let data = self.backend.read(&f).await.map_err(map_err)?;
                self.backend.write(&t, &data).await.map_err(map_err)?;
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
}
