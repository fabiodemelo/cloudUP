//! MEGA backend, native: email + password sign-in, and files encrypted and
//! decrypted on the fly while they stream to and from disk, through the
//! `mega` crate (vendored in `vendor/mega`, MIT OR Apache-2.0).
//!
//! Connection mapping:
//! - `access_key` = MEGA email, `secret` = MEGA password
//! - `fields.mfa` = a current two-factor code, for accounts with 2FA (only
//!   read when signing in)
//! - `bucket`     = folder to mount, under the Cloud Drive (`/` = all of it)
//! - `endpoint` is unused
//!
//! One sign-in per account and password serves the whole app (file browser
//! and Finder drive) until MEGA reports the session expired; then CloudUp
//! signs in again. The account's node tree is cached with the session and
//! kept current through MEGA's event channel, with a full re-fetch now and
//! then (and whenever the events can't be applied).
//!
//! MEGA allows several items with the same name in a folder; CloudUp shows
//! and uses the newest. Deleting moves to the Rubbish Bin (recoverable, like
//! the Google Drive trash). Overwriting a file uploads the new one, then
//! deletes the one it replaces.

use crate::backend::{is_plain_name, local_err, TempPath, IDLE};
use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use mega::{ErrorCode, LastModified, Node, NodeKind, Nodes};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const PROVIDER: &str = "MEGA";
/// How long a node tree is trusted before asking MEGA for changes.
const EVENTS_TTL: Duration = Duration::from_secs(5);
/// Fetch the whole tree again this often, in case an event was missed.
const FULL_TTL: Duration = Duration::from_secs(300);

const MFA_NEEDED: &str = "this account uses two-factor authentication: enter a current code from your \
     authenticator app in the connection's Two-factor code field, then connect again";
const MFA_REJECTED: &str = "the two-factor code was not accepted. Codes change every 30 seconds: enter a \
     current one in the connection's Two-factor code field, then connect again";

/// Run `$body` with a signed-in client `$c`, signing in again (once) when
/// MEGA says the session has expired.
macro_rules! with_client {
    ($self:ident, |$c:ident| $body:expr) => {{
        let mut retried = false;
        loop {
            let $c = $self.client().await?;
            let r: R<_> = $body;
            match r {
                Err(f) if !retried && f.session_expired() => {
                    $self.expire(&$c);
                    retried = true;
                }
                r => break r.map_err(Fail::into_error),
            }
        }
    }};
}

#[derive(Clone)]
pub struct Mega {
    email: String,
    password: String,
    mfa: String,
    /// Folders from the Cloud Drive down to the mounted one.
    base: Vec<String>,
    session: Arc<Session>,
}

pub struct MegaEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

impl Mega {
    pub fn new(email: &str, password: &str, mfa: &str, bucket: &str) -> Self {
        let email = email.trim().to_string();
        let session = session_for(&email, password);
        Self {
            email,
            password: password.to_string(),
            mfa: mfa.trim().to_string(),
            base: split_path(bucket).into_iter().map(String::from).collect(),
            session,
        }
    }

    /// Folder names from the Cloud Drive down to the mount-relative `path`.
    fn segs<'a>(&'a self, path: &'a str) -> Vec<&'a str> {
        self.base.iter().map(String::as_str).chain(split_path(path)).collect()
    }

    // ------------------------------------------------------------- operations

    pub async fn list(&self, dir: &str) -> Result<Vec<MegaEntry>> {
        with_client!(self, |c| self.list_in(&c, dir).await)
    }

    /// Top-level folders of the Cloud Drive (for picking the folder to mount).
    pub async fn list_folders_names(&self) -> Result<Vec<String>> {
        let root = Mega { base: vec![], ..self.clone() };
        let mut out: Vec<String> = root.list("/").await?.into_iter().filter(|e| e.is_dir).map(|e| e.name).collect();
        out.sort();
        Ok(out)
    }

    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let tmp = TempPath::new("mega-dl")?;
        self.read_to_file(path, tmp.path()).await?;
        tokio::fs::read(tmp.path()).await.map_err(|e| local_err(tmp.path(), e))
    }

    /// Download into `dest`, decrypting chunk by chunk.
    pub async fn read_to_file(&self, path: &str, dest: &Path) -> Result<u64> {
        with_client!(self, |c| self.read_in(&c, path, dest).await)
    }

    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        let tmp = TempPath::new("mega-ul")?;
        tokio::fs::write(tmp.path(), data).await.map_err(|e| local_err(tmp.path(), e))?;
        self.write_from_file(path, tmp.path()).await
    }

    /// Upload from `src`, encrypting chunk by chunk.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let (_, name) = split_parent(path);
        if !is_plain_name(name) {
            return Err(api(400, format!("invalid file name: {path}")));
        }
        with_client!(self, |c| self.write_in(&c, path, src).await)
    }

    /// Create the folder `path` (and any missing parents). An existing folder
    /// is fine.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        with_client!(self, |c| self.mkdir_in(&c, path).await)
    }

    /// Move a file or folder (with its contents) to the Rubbish Bin.
    pub async fn remove(&self, path: &str, _is_dir: bool) -> Result<()> {
        if split_path(path).is_empty() {
            return Err(api(400, "won't delete the folder the connection opens at"));
        }
        with_client!(self, |c| self.remove_in(&c, path).await)
    }

    async fn list_in(&self, c: &mega::Client, dir: &str) -> R<Vec<MegaEntry>> {
        let snap = self.snapshot(c).await?;
        let node = snap.resolve(&self.segs(dir)).ok_or_else(|| not_found(dir))?;
        if !is_dir(node.kind()) {
            return Err(api(400, format!("{dir} is not a folder")).into());
        }
        Ok(entries(&snap.nodes, &snap.index, node.handle(), dir))
    }

    async fn read_in(&self, c: &mega::Client, path: &str, dest: &Path) -> R<u64> {
        let snap = self.snapshot(c).await?;
        let node = snap.resolve(&self.segs(path)).ok_or_else(|| not_found(path))?;
        if is_dir(node.kind()) {
            return Err(api(400, format!("{path} is a folder")).into());
        }
        let mut file = tokio::fs::File::create(dest).await.map_err(|e| local_err(dest, e))?;
        // An empty file has nothing to fetch (and no byte range to ask for).
        if node.size() > 0 {
            c.download_node(node, (&mut file).compat_write()).await?;
        }
        file.flush().await.map_err(|e| local_err(dest, e))?;
        drop(file);
        Ok(tokio::fs::metadata(dest).await.map_err(|e| local_err(dest, e))?.len())
    }

    async fn write_in(&self, c: &mega::Client, path: &str, src: &Path) -> R<()> {
        let (dir, name) = split_parent(path);
        let meta = tokio::fs::metadata(src).await.map_err(|e| local_err(src, e))?;
        let modified = meta.modified().ok().map_or(LastModified::Now, |t| LastModified::Set(DateTime::<Utc>::from(t)));
        let file = tokio::fs::File::open(src).await.map_err(|e| local_err(src, e))?;

        let snap = self.snapshot(c).await?;
        let parent = snap
            .resolve(&self.segs(&dir))
            .filter(|n| is_dir(n.kind()))
            .ok_or_else(|| not_found(&dir))?;
        let replaced = same_name(&snap.nodes, &snap.index, parent.handle(), name);
        if replaced.iter().any(|n| is_dir(n.kind())) {
            return Err(api(409, format!("{path} is a folder")).into());
        }
        c.upload_node(parent, name, meta.len(), file.compat(), modified).await?;
        // MEGA would keep both: drop the version this one replaces.
        for old in &replaced {
            c.delete_node(old).await?;
        }

        let parent = parent.handle().to_string();
        let replaced: Vec<String> = replaced.iter().map(|n| n.handle().to_string()).collect();
        drop(snap);
        self.settle(c, |s| {
            child(&s.nodes, &s.index, &parent, name).is_some_and(|n| !replaced.iter().any(|h| h == n.handle()))
                && replaced.iter().all(|h| s.nodes.get_node_by_handle(h).is_none())
        })
        .await
    }

    async fn mkdir_in(&self, c: &mega::Client, path: &str) -> R<()> {
        let segs = self.segs(path);
        loop {
            let snap = self.snapshot(c).await?;
            let mut cur = snap.root().ok_or_else(no_cloud_drive)?;
            let mut depth = 0;
            while let Some(seg) = segs.get(depth) {
                match child(&snap.nodes, &snap.index, cur.handle(), seg) {
                    Some(n) if is_dir(n.kind()) => cur = n,
                    Some(_) => return Err(api(409, format!("{path}: a file is in the way")).into()),
                    None => break,
                }
                depth += 1;
            }
            let Some(name) = segs.get(depth) else { return Ok(()) };
            c.create_folder(cur, name).await?;
            let parent = cur.handle().to_string();
            drop(snap);
            self.settle(c, |s| child(&s.nodes, &s.index, &parent, name).is_some_and(|n| is_dir(n.kind())))
                .await?;
        }
    }

    async fn remove_in(&self, c: &mega::Client, path: &str) -> R<()> {
        let snap = self.snapshot(c).await?;
        let node = snap.resolve(&self.segs(path)).ok_or_else(|| not_found(path))?;
        let bin = snap.nodes.rubbish_bin().ok_or_else(|| Error::Other("MEGA: the account has no Rubbish Bin".into()))?;
        c.move_node(node, bin).await?;

        let handle = node.handle().to_string();
        let parent = node.parent().map(str::to_string);
        drop(snap);
        self.settle(c, |s| s.nodes.get_node_by_handle(&handle).map_or(true, |n| n.parent().map(str::to_string) != parent))
            .await
    }

    // ---------------------------------------------------------------- session

    /// The signed-in client, signing in first if needed (once for all the
    /// callers waiting on it).
    async fn client(&self) -> Result<Arc<mega::Client>> {
        if let Some(c) = self.session.current() {
            return Ok(c);
        }
        let _signing_in = self.session.login.lock().await;
        if let Some(c) = self.session.current() {
            return Ok(c);
        }
        let mut c = mega::Client::builder()
            .timeout(Some(Duration::from_secs(60)))
            .max_retries(6)
            .min_retry_delay(Duration::from_millis(250))
            .https(true)
            .build(http())
            .map_err(mega_err)?;
        let mfa = Some(self.mfa.as_str()).filter(|m| !m.is_empty());
        c.login(&self.email, &self.password, mfa).await.map_err(|e| login_err(e, mfa.is_some()))?;
        let c = Arc::new(c);
        *self.session.client.lock().unwrap() = Some(c.clone());
        Ok(c)
    }

    /// Forget a client whose session MEGA no longer accepts.
    fn expire(&self, failed: &Arc<mega::Client>) {
        let mut slot = self.session.client.lock().unwrap();
        if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, failed)) {
            *slot = None;
        }
    }

    /// A current view of the account's nodes.
    async fn snapshot(&self, c: &mega::Client) -> R<Arc<Snapshot>> {
        let mut tree = self.session.tree.lock().await;
        let fresh = match tree.as_mut() {
            Some(t) if t.fetched.elapsed() < FULL_TTL => t.synced.elapsed() < EVENTS_TTL || catch_up(c, t).await?,
            _ => false,
        };
        if !fresh {
            *tree = Some(fetch(c).await?);
        }
        Ok(tree.as_ref().expect("tree just set").snap.clone())
    }

    /// After a change of ours: wait (briefly) for it to show up in MEGA's
    /// events, so the next lookup sees it; fetch the whole tree otherwise.
    /// The caller must not hold a snapshot (events apply in place).
    async fn settle(&self, c: &mega::Client, done: impl Fn(&Snapshot) -> bool) -> R<()> {
        let mut tree = self.session.tree.lock().await;
        if let Some(t) = tree.as_mut() {
            for attempt in 0..4u64 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(150 * attempt)).await;
                }
                if !catch_up(c, t).await? {
                    break;
                }
                if done(&t.snap) {
                    return Ok(());
                }
            }
        }
        *tree = Some(fetch(c).await?);
        Ok(())
    }
}

// ------------------------------------------------------------------- sessions

/// A signed-in MEGA client and the account's cached node tree, shared by
/// every `Mega` with the same email and password.
#[derive(Default)]
struct Session {
    client: Mutex<Option<Arc<mega::Client>>>,
    /// Held while signing in, so concurrent requests sign in once.
    login: tokio::sync::Mutex<()>,
    tree: tokio::sync::Mutex<Option<Tree>>,
}

impl Session {
    fn current(&self) -> Option<Arc<mega::Client>> {
        self.client.lock().unwrap().clone()
    }
}

/// The session for these credentials (created empty: nothing is sent until
/// the first request).
fn session_for(email: &str, password: &str) -> Arc<Session> {
    use sha2::{Digest, Sha256};
    static SESSIONS: LazyLock<Mutex<HashMap<String, Arc<Session>>>> = LazyLock::new(Default::default);
    let key = hex::encode(Sha256::digest(format!("{}\n{password}", email.to_lowercase())));
    SESSIONS.lock().unwrap().entry(key).or_default().clone()
}

/// HTTP client for MEGA (API calls and file transfers): rustls like the
/// rest of the app. No overall deadline (transfers can take hours); the
/// library bounds API calls itself and a stalled read fails after `IDLE`.
fn http() -> reqwest::Client {
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(IDLE)
            .build()
            .unwrap_or_default()
    });
    CLIENT.clone()
}

struct Tree {
    snap: Arc<Snapshot>,
    /// Last time the events were caught up.
    synced: Instant,
    /// When the whole tree was fetched.
    fetched: Instant,
}

/// The account's nodes, with a folder -> children index.
struct Snapshot {
    nodes: Nodes,
    index: Index,
}

impl Snapshot {
    fn root(&self) -> Option<&Node> {
        self.nodes.get_node_by_handle(self.index.root.as_deref()?)
    }

    fn resolve(&self, segs: &[&str]) -> Option<&Node> {
        resolve(&self.nodes, &self.index, segs)
    }
}

async fn fetch(c: &mega::Client) -> R<Tree> {
    let nodes = c.fetch_own_nodes().await?;
    let index = Index::build(nodes.iter());
    let now = Instant::now();
    Ok(Tree { snap: Arc::new(Snapshot { nodes, index }), synced: now, fetched: now })
}

/// Apply MEGA's pending events to the tree. False when that isn't possible
/// (the caller then fetches the whole tree); an expired session is an error.
async fn catch_up(c: &mega::Client, t: &mut Tree) -> R<bool> {
    match c.poll_events(&t.snap.nodes).await {
        Ok(None) => {}
        Ok(Some(batch)) => {
            // A transfer still holds this snapshot: start a new one instead.
            let Some(snap) = Arc::get_mut(&mut t.snap) else { return Ok(false) };
            if snap.nodes.apply_events(batch).is_err() {
                return Ok(false);
            }
            snap.index = Index::build(snap.nodes.iter());
        }
        Err(e) => {
            let f = Fail::from(e);
            return if f.session_expired() { Err(f) } else { Ok(false) };
        }
    }
    t.synced = Instant::now();
    Ok(true)
}

// ---------------------------------------------------------------- node tree
//
// Lookups are written against two small traits so the tests can run them on
// a hand-made tree (`mega::Node` can't be built outside the crate).

trait Item {
    fn name(&self) -> &str;
    fn handle(&self) -> &str;
    fn parent(&self) -> Option<&str>;
    fn kind(&self) -> NodeKind;
    fn size(&self) -> u64;
    fn modified(&self) -> Option<DateTime<Utc>>;
}

impl Item for Node {
    fn name(&self) -> &str {
        Node::name(self)
    }
    fn handle(&self) -> &str {
        Node::handle(self)
    }
    fn parent(&self) -> Option<&str> {
        Node::parent(self)
    }
    fn kind(&self) -> NodeKind {
        Node::kind(self)
    }
    fn size(&self) -> u64 {
        Node::size(self)
    }
    fn modified(&self) -> Option<DateTime<Utc>> {
        self.modified_at().or_else(|| self.created_at())
    }
}

trait Store {
    type Item: Item;
    fn node(&self, handle: &str) -> Option<&Self::Item>;
}

impl Store for Nodes {
    type Item = Node;
    fn node(&self, handle: &str) -> Option<&Node> {
        self.get_node_by_handle(handle)
    }
}

/// Children by parent handle, and the Cloud Drive root. Built from each
/// node's parent rather than the library's child lists.
#[derive(Default)]
struct Index {
    kids: HashMap<String, Vec<String>>,
    root: Option<String>,
}

impl Index {
    fn build<'a, I: Item + 'a>(items: impl IntoIterator<Item = &'a I>) -> Self {
        let mut ix = Index::default();
        for n in items {
            if n.kind() == NodeKind::Root {
                ix.root = Some(n.handle().to_string());
            }
            if let Some(p) = n.parent() {
                ix.kids.entry(p.to_string()).or_default().push(n.handle().to_string());
            }
        }
        ix
    }
}

fn is_dir(kind: NodeKind) -> bool {
    matches!(kind, NodeKind::Folder | NodeKind::Root)
}

/// Files and folders a path can name (not the Inbox, Rubbish Bin or
/// unknown kinds).
fn visible<I: Item>(n: &I) -> bool {
    matches!(n.kind(), NodeKind::File | NodeKind::Folder) && is_plain_name(n.name())
}

/// The children of `dir` named `name`.
fn same_name<'a, S: Store>(s: &'a S, ix: &Index, dir: &str, name: &str) -> Vec<&'a S::Item> {
    ix.kids
        .get(dir)
        .into_iter()
        .flatten()
        .filter_map(|h| s.node(h))
        .filter(|n| visible(*n) && n.name() == name)
        .collect()
}

/// Of several items with one name: the newest (then the highest handle, so
/// the choice is stable).
fn newest<'a, I: Item>(items: impl IntoIterator<Item = &'a I>) -> Option<&'a I> {
    items.into_iter().max_by(|a, b| a.modified().cmp(&b.modified()).then_with(|| a.handle().cmp(b.handle())))
}

fn child<'a, S: Store>(s: &'a S, ix: &Index, dir: &str, name: &str) -> Option<&'a S::Item> {
    newest(same_name(s, ix, dir, name))
}

/// The node at `segs` below the Cloud Drive root.
fn resolve<'a, S: Store>(s: &'a S, ix: &Index, segs: &[&str]) -> Option<&'a S::Item> {
    let mut cur = s.node(ix.root.as_deref()?)?;
    for seg in segs {
        if !is_dir(cur.kind()) {
            return None;
        }
        cur = child(s, ix, cur.handle(), seg)?;
    }
    Some(cur)
}

/// The listing of folder `dir` (a handle) whose mount-relative path is
/// `rel_dir`: one entry per name, folders first.
fn entries<S: Store>(s: &S, ix: &Index, dir: &str, rel_dir: &str) -> Vec<MegaEntry> {
    let mut by_name: HashMap<&str, Vec<&S::Item>> = HashMap::new();
    for n in ix.kids.get(dir).into_iter().flatten().filter_map(|h| s.node(h)).filter(|n| visible(*n)) {
        by_name.entry(n.name()).or_default().push(n);
    }
    let mut out: Vec<MegaEntry> = by_name
        .into_values()
        .filter_map(newest)
        .map(|n| {
            let dir = is_dir(n.kind());
            MegaEntry {
                name: n.name().to_string(),
                path: join(rel_dir, n.name()),
                is_dir: dir,
                size: if dir { 0 } else { n.size() },
                modified: n.modified().map(|t| t.to_rfc3339()),
            }
        })
        .collect();
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    out
}

// -------------------------------------------------------------------- paths

fn split_path(p: &str) -> Vec<&str> {
    p.split('/').filter(|s| !s.is_empty()).collect()
}

/// `("/a/b", "c")` for `/a/b/c`; the parent of a top-level item is `/`.
fn split_parent(path: &str) -> (String, &str) {
    let rel = path.trim_matches('/');
    match rel.rfind('/') {
        Some(i) => (format!("/{}", &rel[..i]), &rel[i + 1..]),
        None => ("/".to_string(), rel),
    }
}

fn join(dir: &str, name: &str) -> String {
    let d = dir.trim_matches('/');
    if d.is_empty() {
        format!("/{name}")
    } else {
        format!("/{d}/{name}")
    }
}

// ------------------------------------------------------------------- errors

/// An operation's failure: from the library (checked for an expired
/// session) or our own.
enum Fail {
    Mega(mega::Error),
    Ours(Error),
}

type R<T> = std::result::Result<T, Fail>;

impl From<mega::Error> for Fail {
    fn from(e: mega::Error) -> Self {
        Fail::Mega(e)
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Fail::Ours(e)
    }
}

impl Fail {
    fn session_expired(&self) -> bool {
        matches!(self, Fail::Mega(mega::Error::MegaError { code: ErrorCode::ESID }))
    }

    fn into_error(self) -> Error {
        match self {
            Fail::Mega(e) => mega_err(e),
            Fail::Ours(e) => e,
        }
    }
}

fn api(status: u16, body: impl Into<String>) -> Error {
    Error::Api { provider: PROVIDER.into(), status, body: body.into() }
}

fn not_found(path: &str) -> Fail {
    let path = if path.trim_matches('/').is_empty() { "/" } else { path };
    api(404, format!("{path} not found")).into()
}

fn no_cloud_drive() -> Fail {
    Error::Other("MEGA: the account's Cloud Drive is missing".into()).into()
}

fn mega_err(e: mega::Error) -> Error {
    match e {
        mega::Error::MegaError { code } => code_err(code),
        mega::Error::ReqwestError { source } => Error::http(source),
        mega::Error::IoError { source } => Error::Other(format!("MEGA: {source}")),
        mega::Error::MaxRetriesReached => Error::Http("MEGA did not answer (gave up after several tries)".into()),
        mega::Error::CondensedMacMismatch => {
            Error::Other("MEGA: the downloaded file failed its integrity check".into())
        }
        other => api(502, other.to_string()),
    }
}

/// An error code from MEGA's API, with an HTTP-like status so the Finder
/// drive tells "not found" and "denied" apart from other failures.
fn code_err(code: ErrorCode) -> Error {
    use ErrorCode::*;
    match code {
        ENOENT => api(404, "not found"),
        EACCESS => api(403, "access denied"),
        EEXIST => api(409, "already exists"),
        ESID => api(401, "the session has expired; sign in again"),
        EBLOCKED => api(403, "MEGA has blocked this account"),
        EMFAREQUIRED => api(401, MFA_NEEDED),
        EOVERQUOTA | EGOINGOVERQUOTA => api(507, "the account is out of storage space"),
        EAGAIN | ERATELIMIT | ETOOMANY | ETEMPUNAVAIL | ETOOMANYCONNECTIONS => {
            api(503, "MEGA is busy; try again in a moment")
        }
        EPAYWALL | EBUSINESSPASTDUE => api(402, "the account needs attention on mega.nz"),
        other => api(502, format!("{other} (code {})", other as i8)),
    }
}

/// A failed sign-in, in words.
fn login_err(e: mega::Error, mfa_given: bool) -> Error {
    if let mega::Error::MegaError { code } = &e {
        match *code {
            ErrorCode::ENOENT => return api(401, "wrong email or password"),
            ErrorCode::EMFAREQUIRED | ErrorCode::EFAILED if mfa_given => return api(401, MFA_REJECTED),
            ErrorCode::EINCOMPLETE => {
                return api(401, "this account isn't confirmed yet: finish signing up from MEGA's confirmation email")
            }
            ErrorCode::ETOOMANY => return api(429, "too many sign-in attempts; wait a while and try again"),
            _ => {}
        }
    }
    mega_err(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    struct Fake {
        name: &'static str,
        handle: &'static str,
        parent: Option<&'static str>,
        kind: NodeKind,
        size: u64,
        modified: i64,
    }

    impl Item for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn handle(&self) -> &str {
            self.handle
        }
        fn parent(&self) -> Option<&str> {
            self.parent
        }
        fn kind(&self) -> NodeKind {
            self.kind
        }
        fn size(&self) -> u64 {
            self.size
        }
        fn modified(&self) -> Option<DateTime<Utc>> {
            Utc.timestamp_opt(self.modified, 0).single()
        }
    }

    impl Store for HashMap<String, Fake> {
        type Item = Fake;
        fn node(&self, handle: &str) -> Option<&Fake> {
            self.get(handle)
        }
    }

    fn fake(handle: &'static str, parent: Option<&'static str>, name: &'static str, kind: NodeKind, size: u64, modified: i64) -> Fake {
        Fake { name, handle, parent, kind, size, modified }
    }

    /// Cloud Drive:
    ///   photos/ (2024/ (a.jpg), b.jpg, b.jpg [newer], "bad/name")
    ///   notes.txt
    ///   empty/
    /// plus the Rubbish Bin (with a trashed file), the Inbox and an unknown node.
    fn fixture() -> (HashMap<String, Fake>, Index) {
        use NodeKind::*;
        let nodes = vec![
            fake("ROOT", None, "Cloud Drive", Root, 0, 0),
            fake("BIN", None, "Rubbish Bin", Trash, 0, 0),
            fake("INBOX", None, "Inbox", Inbox, 0, 0),
            fake("photos", Some("ROOT"), "photos", Folder, 0, 10),
            fake("y2024", Some("photos"), "2024", Folder, 0, 11),
            fake("a", Some("y2024"), "a.jpg", File, 5, 12),
            fake("b-old", Some("photos"), "b.jpg", File, 1, 13),
            fake("b-new", Some("photos"), "b.jpg", File, 2, 99),
            fake("slash", Some("photos"), "bad/name", File, 3, 14),
            fake("notes", Some("ROOT"), "notes.txt", File, 7, 15),
            fake("empty", Some("ROOT"), "empty", Folder, 0, 16),
            fake("trashed", Some("BIN"), "gone.txt", File, 1, 17),
            fake("odd", Some("ROOT"), "mystery", Unknown, 0, 18),
        ];
        let ix = Index::build(nodes.iter());
        (nodes.into_iter().map(|n| (n.handle.to_string(), n)).collect(), ix)
    }

    fn mega(bucket: &str) -> Mega {
        Mega::new("me@example.com", "pw", "", bucket)
    }

    #[test]
    fn path_segments_include_the_mounted_folder() {
        let m = mega("/photos/2024/");
        assert_eq!(m.segs("/a.jpg"), ["photos", "2024", "a.jpg"]);
        assert_eq!(m.segs("/"), ["photos", "2024"]);
        let root = mega("/");
        assert_eq!(root.segs("/x/y"), ["x", "y"]);
        assert!(root.segs("/").is_empty());
        assert_eq!(split_parent("/a/b/c.txt"), ("/a/b".to_string(), "c.txt"));
        assert_eq!(split_parent("/c.txt"), ("/".to_string(), "c.txt"));
        assert_eq!(join("/", "x"), "/x");
        assert_eq!(join("/a/", "x"), "/a/x");
    }

    #[test]
    fn resolves_paths_from_the_cloud_drive() {
        let (s, ix) = fixture();
        assert_eq!(ix.root.as_deref(), Some("ROOT"));
        assert_eq!(resolve(&s, &ix, &[]).map(|n| n.handle), Some("ROOT"));
        assert_eq!(resolve(&s, &ix, &["photos", "2024", "a.jpg"]).map(|n| n.handle), Some("a"));
        assert_eq!(resolve(&s, &ix, &["notes.txt"]).map(|n| n.handle), Some("notes"));
        // Missing names, paths through a file, and nodes outside the Cloud Drive.
        assert!(resolve(&s, &ix, &["photos", "nope"]).is_none());
        assert!(resolve(&s, &ix, &["notes.txt", "x"]).is_none());
        assert!(resolve(&s, &ix, &["gone.txt"]).is_none());
        assert!(resolve(&s, &ix, &["mystery"]).is_none());
        assert!(resolve(&s, &ix, &["photos", "bad/name"]).is_none());
    }

    #[test]
    fn duplicate_names_resolve_to_the_newest() {
        let (s, ix) = fixture();
        assert_eq!(resolve(&s, &ix, &["photos", "b.jpg"]).map(|n| n.handle), Some("b-new"));
        assert_eq!(same_name(&s, &ix, "photos", "b.jpg").len(), 2);
    }

    #[test]
    fn listing_is_one_entry_per_name_folders_first() {
        let (s, ix) = fixture();
        let root = entries(&s, &ix, "ROOT", "/");
        let names: Vec<_> = root.iter().map(|e| (e.name.as_str(), e.path.as_str(), e.is_dir)).collect();
        assert_eq!(names, [("empty", "/empty", true), ("photos", "/photos", true), ("notes.txt", "/notes.txt", false)]);
        assert_eq!(root[2].size, 7);
        assert_eq!(root[2].modified.as_deref(), Some("1970-01-01T00:00:15+00:00"));

        let photos = entries(&s, &ix, "photos", "/photos");
        let names: Vec<_> = photos.iter().map(|e| (e.name.as_str(), e.size)).collect();
        assert_eq!(names, [("2024", 0), ("b.jpg", 2)]);
        assert_eq!(photos[1].path, "/photos/b.jpg");
        assert!(entries(&s, &ix, "empty", "/empty").is_empty());
    }

    #[test]
    fn sessions_are_shared_per_account() {
        let a = Mega::new("Me@Example.com ", "pw", "", "/");
        let b = Mega::new("me@example.com", "pw", "123456", "/photos");
        let other = Mega::new("me@example.com", "pw2", "", "/");
        assert!(Arc::ptr_eq(&a.session, &b.session));
        assert!(!Arc::ptr_eq(&a.session, &other.session));
    }

    fn status(e: &Error) -> u16 {
        match e {
            Error::Api { provider, status, .. } if provider == PROVIDER => *status,
            other => panic!("not a MEGA API error: {other}"),
        }
    }

    #[test]
    fn error_codes_map_to_statuses() {
        assert_eq!(status(&code_err(ErrorCode::ENOENT)), 404);
        assert_eq!(status(&code_err(ErrorCode::EACCESS)), 403);
        assert_eq!(status(&code_err(ErrorCode::EOVERQUOTA)), 507);
        assert_eq!(status(&code_err(ErrorCode::EINTERNAL)), 502);
        assert!(Fail::from(mega::Error::MegaError { code: ErrorCode::ESID }).session_expired());
        assert!(!Fail::from(mega::Error::MegaError { code: ErrorCode::ENOENT }).session_expired());
        assert!(matches!(mega_err(mega::Error::MaxRetriesReached), Error::Http(_)));
    }

    #[test]
    fn sign_in_errors_explain_themselves() {
        let code = |c| mega::Error::MegaError { code: c };
        let e = login_err(code(ErrorCode::ENOENT), false);
        assert_eq!(status(&e), 401);
        assert!(e.to_string().contains("wrong email or password"));
        assert!(login_err(code(ErrorCode::EMFAREQUIRED), false).to_string().contains("two-factor authentication"));
        assert!(login_err(code(ErrorCode::EMFAREQUIRED), true).to_string().contains("not accepted"));
        assert!(login_err(code(ErrorCode::EFAILED), true).to_string().contains("not accepted"));
        assert_eq!(status(&login_err(code(ErrorCode::ETOOMANY), false)), 429);
    }

    /// The vendored library's fix: tiny (and empty) files get a checksum
    /// instead of an early-EOF error, so they can be uploaded.
    #[tokio::test]
    async fn tiny_file_checksum() {
        let sum = mega::compute_sparse_checksum(std::io::Cursor::new(b"hello".to_vec()).compat(), 5).await.unwrap();
        assert_eq!(&sum[..5], b"hello");
        assert!(sum[5..].iter().all(|b| *b == 0));
        let empty = mega::compute_sparse_checksum(std::io::Cursor::new(Vec::new()).compat(), 0).await.unwrap();
        assert_eq!(empty, [0u8; 16]);
    }

    /// Checks that need no network: refusing to delete the mount root, and
    /// file names that can't be uploaded.
    #[tokio::test]
    async fn refused_before_signing_in() {
        let m = Mega::new("nobody@example.invalid", "x", "", "/");
        assert_eq!(status(&m.remove("/", true).await.unwrap_err()), 400);
        let src = Path::new("/nonexistent");
        assert_eq!(status(&m.write_from_file("/", src).await.unwrap_err()), 400);
        assert_eq!(status(&m.write_from_file("/a/..", src).await.unwrap_err()), 400);
    }
}
