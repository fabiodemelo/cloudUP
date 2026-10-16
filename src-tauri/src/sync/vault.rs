//! The synced vault (docs/sync-api.md, "Vault plaintext"), this Mac's side of
//! it, and the merge between the two.
//!
//! Merge rule: per connection id the copy with the newer `updated_at` wins,
//! both ways. A deleted connection is a tombstone (`deleted: true`, no
//! secrets) kept for 90 days so other Macs remove it too; locally tombstones
//! live in `tombstones.json`. Secrets (the keychain password or OAuth token,
//! and field secrets such as the OAuth client secret) follow their
//! connection. SFTP `known_hosts` lines are unioned.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::{self, Connection, FIELD_SECRETS, KEY_BOOKMARK};

pub const SCHEMA: u32 = 1;
const TOMBSTONE_DAYS: i64 = 90;

/// Connection fields that belong to one Mac and are never synced: the
/// security-scoped bookmark of the SFTP key file (only valid on the Mac that
/// made it) and "mount automatically when I log in".
pub const LOCAL_FIELDS: &[&str] = &[KEY_BOOKMARK, "auto_mount"];

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default = "schema_default")]
    pub schema: u32,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub connections: Vec<VaultEntry>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub field_secrets: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub known_hosts: String,
}

fn schema_default() -> u32 {
    SCHEMA
}

/// A connection in the vault: the fields of [`Connection`] (kept as JSON, so
/// fields a newer CloudUp adds survive this one), or a tombstone.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub deleted: bool,
    #[serde(flatten)]
    pub data: Map<String, Value>,
}

/// This Mac's connections and everything that syncs with them.
#[derive(Clone, Default)]
pub struct LocalState {
    pub conns: Vec<Connection>,
    /// Keychain secret per connection id.
    pub secrets: HashMap<String, String>,
    /// Ids whose keychain secret couldn't be read (locked keychain): the
    /// vault's copy is kept rather than dropped.
    pub unreadable: HashSet<String>,
    pub field_secrets: HashMap<String, BTreeMap<String, String>>,
    /// Deleted connection id -> when (RFC 3339).
    pub tombstones: BTreeMap<String, String>,
    pub known_hosts: String,
}

pub struct Merged {
    /// The vault to upload when `remote_changed`.
    pub vault: Vault,
    /// The new local state, to write when `local_changed`.
    pub local: LocalState,
    pub local_changed: bool,
    pub remote_changed: bool,
    /// Connections removed from this Mac (deleted on another one).
    pub removed: Vec<String>,
}

/// An id we'd store as a keychain account name and in config.json: refuse
/// anything odd rather than let a vault entry overwrite, say, the account item.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id != super::ACCOUNT_ITEM
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse_ts(ts: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(ts).map(|t| t.with_timezone(&Utc)).unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

fn norm_ts(ts: &str) -> String {
    if DateTime::parse_from_rfc3339(ts).is_ok() {
        ts.to_string()
    } else {
        "1970-01-01T00:00:00Z".into()
    }
}

/// The vault form of a local connection (no id, timestamps or local fields
/// in `data`).
pub fn entry_from_conn(conn: &Connection) -> VaultEntry {
    let mut data = match serde_json::to_value(conn) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };
    for k in ["id", "updated_at", "deleted"] {
        data.remove(k);
    }
    if let Some(Value::Object(fields)) = data.get_mut("fields") {
        for k in LOCAL_FIELDS.iter().chain(FIELD_SECRETS) {
            fields.remove(*k);
        }
    }
    VaultEntry { id: conn.id.clone(), updated_at: norm_ts(&conn.updated_at), deleted: false, data }
}

/// The local connection for a vault entry, keeping this Mac's local fields
/// from `prev`. None for a tombstone or a connection type this CloudUp
/// doesn't know (made by a newer version).
pub fn conn_from_entry(entry: &VaultEntry, prev: Option<&Connection>) -> Option<Connection> {
    if entry.deleted {
        return None;
    }
    let mut data = entry.data.clone();
    data.insert("id".into(), Value::String(entry.id.clone()));
    data.insert("updated_at".into(), Value::String(entry.updated_at.clone()));
    let mut conn: Connection = serde_json::from_value(Value::Object(data)).ok()?;
    for k in LOCAL_FIELDS.iter().chain(FIELD_SECRETS) {
        conn.fields.remove(*k);
    }
    if let Some(p) = prev {
        if let Some(v) = p.fields.get("auto_mount") {
            conn.fields.insert("auto_mount".into(), v.clone());
        }
        // A bookmark only stands for the key file it was made for.
        if p.field("key").trim() == conn.field("key").trim() {
            if let Some(v) = p.fields.get(KEY_BOOKMARK) {
                conn.fields.insert(KEY_BOOKMARK.into(), v.clone());
            }
        }
    }
    Some(conn)
}

/// Non-empty lines of `first`, then the lines of `second` not already there.
pub fn union_lines(first: &str, second: &str) -> String {
    let mut seen = HashSet::new();
    let mut out = String::new();
    for line in first.lines().chain(second.lines()) {
        let line = line.trim_end();
        if line.trim().is_empty() || !seen.insert(line.to_string()) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[derive(Clone, Copy, PartialEq)]
enum Side {
    Local,
    Remote,
    Tie,
}

/// Merge this Mac's state with the vault (`None`: nothing uploaded yet).
pub fn merge(local: &LocalState, remote: Option<&Vault>, now: DateTime<Utc>) -> Merged {
    let empty = Vault::default();
    let rv = remote.unwrap_or(&empty);
    let cutoff = now - Duration::days(TOMBSTONE_DAYS);

    let mut vault = Vault {
        schema: SCHEMA,
        updated_at: rv.updated_at.clone(),
        connections: vec![],
        secrets: BTreeMap::new(),
        field_secrets: BTreeMap::new(),
        known_hosts: union_lines(&rv.known_hosts, &local.known_hosts),
    };
    let mut out = local.clone();
    out.known_hosts = union_lines(&local.known_hosts, &rv.known_hosts);
    let mut removed = vec![];

    let rmap: HashMap<&str, &VaultEntry> =
        rv.connections.iter().filter(|e| valid_id(&e.id)).map(|e| (e.id.as_str(), e)).collect();
    // Entries this client can't handle travel on untouched.
    vault.connections.extend(rv.connections.iter().filter(|e| !valid_id(&e.id)).cloned());

    let mut ids: Vec<String> = vec![];
    let mut seen = HashSet::new();
    for id in local.conns.iter().map(|c| &c.id).chain(rv.connections.iter().map(|e| &e.id)).chain(local.tombstones.keys())
    {
        if valid_id(id) && seen.insert(id.clone()) {
            ids.push(id.clone());
        }
    }

    for id in &ids {
        let lconn = local.conns.iter().find(|c| &c.id == id);
        let ltomb = local.tombstones.get(id);
        // (timestamp, alive) on each side.
        let l = lconn.map(|c| (parse_ts(&c.updated_at), true)).or_else(|| ltomb.map(|t| (parse_ts(t), false)));
        let rentry = rmap.get(id.as_str()).copied();
        let r = rentry.map(|e| (parse_ts(&e.updated_at), !e.deleted));

        let side = match (l, r) {
            (Some(_), None) => Side::Local,
            (None, Some(_)) => Side::Remote,
            (Some((lt, la)), Some((rt, ra))) => {
                if lt > rt {
                    Side::Local
                } else if rt > lt {
                    Side::Remote
                } else if la == ra {
                    Side::Tie
                } else if !la {
                    // Same instant, one side deleted it: the delete wins.
                    Side::Local
                } else {
                    Side::Remote
                }
            }
            (None, None) => continue,
        };

        match side {
            Side::Local => {
                if let Some(c) = lconn {
                    vault.connections.push(entry_from_conn(c));
                    if let Some(s) = local.secrets.get(id) {
                        vault.secrets.insert(id.clone(), s.clone());
                    } else if local.unreadable.contains(id) {
                        if let Some(s) = rv.secrets.get(id) {
                            vault.secrets.insert(id.clone(), s.clone());
                        }
                    }
                    if let Some(fs) = local.field_secrets.get(id).filter(|m| !m.is_empty()) {
                        vault.field_secrets.insert(id.clone(), fs.clone());
                    }
                } else if let Some(t) = ltomb {
                    if parse_ts(t) >= cutoff {
                        vault.connections.push(VaultEntry {
                            id: id.clone(),
                            updated_at: norm_ts(t),
                            deleted: true,
                            data: Map::new(),
                        });
                    }
                }
            }
            Side::Remote | Side::Tie => {
                let e = rentry.expect("a remote side has an entry");
                let expired = e.deleted && parse_ts(&e.updated_at) < cutoff;
                if !expired {
                    vault.connections.push(e.clone());
                    if !e.deleted {
                        if let Some(s) = rv.secrets.get(id) {
                            vault.secrets.insert(id.clone(), s.clone());
                        }
                        if let Some(fs) = rv.field_secrets.get(id).filter(|m| !m.is_empty()) {
                            vault.field_secrets.insert(id.clone(), fs.clone());
                        }
                    }
                }
                if side == Side::Tie {
                    continue;
                }
                if e.deleted {
                    if let Some(pos) = out.conns.iter().position(|c| &c.id == id) {
                        out.conns.remove(pos);
                        removed.push(id.clone());
                    }
                    out.secrets.remove(id);
                    out.field_secrets.remove(id);
                    out.unreadable.remove(id);
                    out.tombstones.insert(id.clone(), norm_ts(&e.updated_at));
                } else {
                    let prev = out.conns.iter().position(|c| &c.id == id);
                    // A type this version doesn't know: leave it to the vault.
                    let Some(conn) = conn_from_entry(e, prev.map(|i| &out.conns[i])) else { continue };
                    match prev {
                        Some(i) => out.conns[i] = conn,
                        None => out.conns.push(conn),
                    }
                    if let Some(s) = rv.secrets.get(id) {
                        out.secrets.insert(id.clone(), s.clone());
                        out.unreadable.remove(id);
                    }
                    // Like the secret: without a copy in the vault, keep ours.
                    if let Some(fs) = rv.field_secrets.get(id).filter(|m| !m.is_empty()) {
                        out.field_secrets.insert(id.clone(), fs.clone());
                    }
                    out.tombstones.remove(id);
                }
            }
        }
    }

    out.tombstones.retain(|_, t| parse_ts(t) >= cutoff);
    vault.connections.sort_by(|a, b| a.id.cmp(&b.id));

    let local_changed = !same_local(local, &out);
    let remote_changed = match remote {
        None => true,
        Some(rv) => !same_vault(rv, &vault),
    };
    if remote_changed {
        vault.updated_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    }
    Merged { vault, local: out, local_changed, remote_changed, removed }
}

fn same_local(a: &LocalState, b: &LocalState) -> bool {
    serde_json::to_value(&a.conns).ok() == serde_json::to_value(&b.conns).ok()
        && a.secrets == b.secrets
        && a.field_secrets == b.field_secrets
        && a.tombstones == b.tombstones
        && a.known_hosts == b.known_hosts
}

/// Equal content, ignoring `updated_at`, entry order and known_hosts formatting.
fn same_vault(a: &Vault, b: &Vault) -> bool {
    let canon = |v: &Vault| {
        let mut c = v.clone();
        c.updated_at.clear();
        c.connections.sort_by(|x, y| x.id.cmp(&y.id));
        c.known_hosts = union_lines(&c.known_hosts, "");
        c
    };
    canon(a) == canon(b)
}

// ------------------------------------------------------------------ this Mac

fn tombstones_path() -> std::path::PathBuf {
    config::data_dir().join("tombstones.json")
}

pub fn read_tombstones() -> BTreeMap<String, String> {
    std::fs::read_to_string(tombstones_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn write_tombstones(t: &BTreeMap<String, String>) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(t).map_err(|e| e.to_string())?;
    config::write_private(&tombstones_path(), raw.as_bytes())
}

/// Remember that a connection was deleted on this Mac, so the next sync
/// removes it from the others. Old tombstones (90 days) are dropped.
pub fn add_tombstone(id: &str) -> Result<(), String> {
    let mut t = read_tombstones();
    t.insert(id.to_string(), config::now_rfc3339());
    let cutoff = Utc::now() - Duration::days(TOMBSTONE_DAYS);
    t.retain(|_, ts| parse_ts(ts) >= cutoff);
    write_tombstones(&t)
}

/// Read this Mac's connections, keychain secrets, tombstones and known_hosts.
pub fn read_local() -> Result<LocalState, String> {
    let conns = config::load_connections()?;
    let mut st = LocalState { tombstones: read_tombstones(), ..Default::default() };
    for c in &conns {
        match config::read_secret(&c.id) {
            Ok(Some(s)) => {
                st.secrets.insert(c.id.clone(), s);
            }
            Ok(None) => {}
            Err(_) => {
                st.unreadable.insert(c.id.clone());
            }
        }
        for key in FIELD_SECRETS {
            if let Some(v) = config::read_field_secret(&c.id, key).filter(|v| !v.is_empty()) {
                st.field_secrets.entry(c.id.clone()).or_default().insert(key.to_string(), v);
            }
        }
    }
    st.conns = conns;
    st.known_hosts = std::fs::read_to_string(config::known_hosts_path()).unwrap_or_default();
    Ok(st)
}

/// Write the parts of `new` that differ from `old`. Secrets are stored
/// before the connections that use them appear, and removed after they go.
pub fn write_local(old: &LocalState, new: &LocalState) -> Result<(), String> {
    for (id, s) in &new.secrets {
        if old.secrets.get(id) != Some(s) {
            config::store_secret(id, s)?;
        }
    }
    for (id, fs) in &new.field_secrets {
        for (k, v) in fs {
            if old.field_secrets.get(id).and_then(|m| m.get(k)) != Some(v) {
                config::store_field_secret(id, k, v)?;
            }
        }
    }
    if serde_json::to_value(&old.conns).ok() != serde_json::to_value(&new.conns).ok() {
        config::save_connections(&new.conns)?;
    }
    for c in &old.conns {
        if !new.conns.iter().any(|n| n.id == c.id) {
            config::delete_secret(&c.id);
            config::delete_field_secrets(&c.id);
        }
    }
    if old.tombstones != new.tombstones {
        write_tombstones(&new.tombstones)?;
    }
    if old.known_hosts != new.known_hosts {
        config::write_private(&config::known_hosts_path(), new.known_hosts.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnType;

    const T1: &str = "2026-10-01T10:00:00.000Z";
    const T2: &str = "2026-10-02T10:00:00.000Z";
    const T3: &str = "2026-10-03T10:00:00.000Z";

    fn now() -> DateTime<Utc> {
        parse_ts("2026-10-16T12:00:00Z")
    }

    fn conn(id: &str, name: &str, ts: &str) -> Connection {
        let mut c = Connection::new(ConnType::Webdav);
        c.id = id.into();
        c.name = name.into();
        c.endpoint = "https://dav.example.com".into();
        c.access_key = "me".into();
        c.updated_at = ts.into();
        c
    }

    fn local(conns: Vec<Connection>) -> LocalState {
        let mut st = LocalState::default();
        for c in &conns {
            st.secrets.insert(c.id.clone(), format!("pw-{}", c.name));
        }
        st.conns = conns;
        st
    }

    fn vault_of(st: &LocalState) -> Vault {
        merge(st, None, now()).vault
    }

    #[test]
    fn first_sync_uploads_everything() {
        let st = local(vec![conn("a", "A", T1), conn("b", "B", T2)]);
        let m = merge(&st, None, now());
        assert!(m.remote_changed && !m.local_changed);
        assert_eq!(m.vault.connections.len(), 2);
        assert_eq!(m.vault.secrets["a"], "pw-A");
        assert_eq!(m.vault.schema, 1);
    }

    #[test]
    fn unchanged_state_is_a_no_op_whatever_the_order() {
        let st = local(vec![conn("b", "B", T2), conn("a", "A", T1)]);
        let v = vault_of(&st);
        // Another Mac with the same connections in another order.
        let other = local(vec![conn("a", "A", T1), conn("b", "B", T2)]);
        let m = merge(&other, Some(&v), now());
        assert!(!m.remote_changed && !m.local_changed);
    }

    #[test]
    fn newer_remote_wins_and_brings_its_secret() {
        let mine = local(vec![conn("a", "Old", T1)]);
        let theirs = local(vec![conn("a", "New", T2)]);
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert!(m.local_changed && !m.remote_changed);
        assert_eq!(m.local.conns[0].name, "New");
        assert_eq!(m.local.conns[0].updated_at, T2);
        assert_eq!(m.local.secrets["a"], "pw-New");
    }

    #[test]
    fn newer_local_wins_and_is_uploaded() {
        let mine = local(vec![conn("a", "Mine", T3)]);
        let theirs = local(vec![conn("a", "Theirs", T2)]);
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert!(m.remote_changed && !m.local_changed);
        let e = &m.vault.connections[0];
        assert_eq!(e.data["name"], "Mine");
        assert_eq!(m.vault.secrets["a"], "pw-Mine");
    }

    #[test]
    fn tie_changes_nothing() {
        let mine = local(vec![conn("a", "Same", T2)]);
        let mut theirs = local(vec![conn("a", "Same", T2)]);
        theirs.secrets.insert("a".into(), "rotated-token".into());
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert!(!m.local_changed && !m.remote_changed);
        assert_eq!(m.local.secrets["a"], "pw-Same");
    }

    #[test]
    fn local_delete_becomes_a_tombstone_without_secrets() {
        let before = local(vec![conn("a", "A", T1), conn("b", "B", T1)]);
        let v = vault_of(&before);
        let mut mine = local(vec![conn("b", "B", T1)]);
        mine.tombstones.insert("a".into(), T2.into());
        let m = merge(&mine, Some(&v), now());
        assert!(m.remote_changed && !m.local_changed);
        let a = m.vault.connections.iter().find(|e| e.id == "a").unwrap();
        assert!(a.deleted && a.data.is_empty() && a.updated_at == T2);
        assert!(!m.vault.secrets.contains_key("a"));
    }

    #[test]
    fn remote_tombstone_removes_the_local_connection() {
        let mut theirs = local(vec![]);
        theirs.tombstones.insert("a".into(), T2.into());
        let mut mine = local(vec![conn("a", "A", T1)]);
        mine.field_secrets.insert("a".into(), BTreeMap::from([("client_secret".into(), "cs".into())]));
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert!(m.local_changed);
        assert!(m.local.conns.is_empty());
        assert!(!m.local.secrets.contains_key("a") && !m.local.field_secrets.contains_key("a"));
        assert_eq!(m.local.tombstones["a"], T2);
        assert_eq!(m.removed, vec!["a".to_string()]);
    }

    #[test]
    fn edit_after_delete_brings_it_back() {
        let mut mine = local(vec![]);
        mine.tombstones.insert("a".into(), T1.into());
        let theirs = local(vec![conn("a", "Edited", T2)]);
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert_eq!(m.local.conns.len(), 1);
        assert!(!m.local.tombstones.contains_key("a"));
    }

    #[test]
    fn delete_wins_a_tie() {
        let mut mine = local(vec![]);
        mine.tombstones.insert("a".into(), T2.into());
        let theirs = local(vec![conn("a", "A", T2)]);
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert!(m.vault.connections[0].deleted);
    }

    #[test]
    fn old_tombstones_expire() {
        let mut mine = local(vec![]);
        mine.tombstones.insert("old".into(), "2026-06-01T00:00:00Z".into());
        mine.tombstones.insert("new".into(), T2.into());
        let m = merge(&mine, None, now());
        assert_eq!(m.vault.connections.len(), 1);
        assert!(m.local.tombstones.contains_key("new") && !m.local.tombstones.contains_key("old"));
    }

    #[test]
    fn field_secrets_follow_their_connection() {
        let mut theirs = local(vec![conn("a", "A", T2)]);
        theirs.field_secrets.insert("a".into(), BTreeMap::from([("client_secret".into(), "cs-new".into())]));
        let mine = local(vec![conn("a", "A", T1)]);
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert_eq!(m.local.field_secrets["a"]["client_secret"], "cs-new");
        // The client secret never sits in `fields` in the vault.
        let mut leaked = conn("b", "B", T1);
        leaked.fields.insert("client_secret".into(), "x".into());
        let e = entry_from_conn(&leaked);
        assert!(!e.data["fields"].as_object().unwrap().contains_key("client_secret"));
    }

    #[test]
    fn local_fields_stay_on_this_mac() {
        let mut theirs_c = conn("a", "New", T2);
        theirs_c.fields.insert("auto_mount".into(), "1".into());
        theirs_c.fields.insert(KEY_BOOKMARK.into(), "their-bookmark".into());
        let theirs = local(vec![theirs_c]);
        let v = vault_of(&theirs);
        let f = v.connections[0].data["fields"].as_object().unwrap();
        assert!(!f.contains_key("auto_mount") && !f.contains_key(KEY_BOOKMARK));

        let mut mine_c = conn("a", "Old", T1);
        mine_c.fields.insert(KEY_BOOKMARK.into(), "my-bookmark".into());
        let m = merge(&local(vec![mine_c]), Some(&v), now());
        let c = &m.local.conns[0];
        assert_eq!(c.name, "New");
        assert_eq!(c.field(KEY_BOOKMARK), "my-bookmark");
        assert_eq!(c.field("auto_mount"), "");
    }

    #[test]
    fn known_hosts_lines_are_unioned() {
        let mut a = local(vec![]);
        a.known_hosts = "host1 ssh-ed25519 AAAA1\nshared ssh-ed25519 S\n".into();
        let mut b = local(vec![]);
        b.known_hosts = "shared ssh-ed25519 S\nhost2 ssh-ed25519 AAAA2".into();
        let m = merge(&a, Some(&vault_of(&b)), now());
        assert_eq!(m.local.known_hosts, "host1 ssh-ed25519 AAAA1\nshared ssh-ed25519 S\nhost2 ssh-ed25519 AAAA2\n");
        assert!(m.local_changed && m.remote_changed);
        assert_eq!(m.vault.known_hosts.lines().count(), 3);
    }

    #[test]
    fn unknown_entries_and_types_travel_untouched() {
        let mut v = vault_of(&local(vec![conn("a", "A", T1)]));
        let mut future = v.connections[0].clone();
        future.id = "f".into();
        future.data.insert("type".into(), Value::String("icloud".into()));
        future.data.insert("new_setting".into(), Value::Bool(true));
        v.connections.push(future);
        v.connections.push(VaultEntry { id: "account".into(), updated_at: T3.into(), deleted: false, data: Map::new() });
        let m = merge(&local(vec![conn("a", "A", T1)]), Some(&v), now());
        assert!(!m.remote_changed, "nothing to upload");
        assert!(m.local.conns.iter().all(|c| c.id == "a"));
    }

    #[test]
    fn locked_keychain_keeps_the_vault_secret() {
        let theirs = local(vec![conn("a", "A", T1)]);
        let mut mine = local(vec![conn("a", "A2", T2)]);
        mine.secrets.clear();
        mine.unreadable.insert("a".into());
        let m = merge(&mine, Some(&vault_of(&theirs)), now());
        assert_eq!(m.vault.secrets["a"], "pw-A");
    }

    #[test]
    fn vault_json_round_trip_and_shape() {
        let mut st = local(vec![conn("a", "A", T1)]);
        st.tombstones.insert("gone".into(), T2.into());
        st.field_secrets.insert("a".into(), BTreeMap::from([("client_secret".into(), "cs".into())]));
        st.known_hosts = "h ssh-ed25519 K\n".into();
        let v = vault_of(&st);
        let json = serde_json::to_value(&v).unwrap();
        for k in ["schema", "updated_at", "connections", "secrets", "field_secrets", "known_hosts"] {
            assert!(json.get(k).is_some(), "missing {k}");
        }
        let a = &json["connections"][0];
        assert_eq!(a["id"], "a");
        assert_eq!(a["type"], "webdav");
        assert_eq!(a["deleted"], false);
        assert_eq!(a["updated_at"], T1);
        assert_eq!(json["connections"][1]["deleted"], true);
        let back: Vault = serde_json::from_value(json).unwrap();
        assert!(back == v);
        let c = conn_from_entry(&back.connections[0], None).unwrap();
        assert_eq!(c.name, "A");
        assert_eq!(c.updated_at, T1);
        assert!(conn_from_entry(&back.connections[1], None).is_none());
    }

    #[test]
    fn ids_are_checked() {
        assert!(valid_id("2f1c9a4e-0d1b-4b8e-9c7e-1a2b3c4d5e6f"));
        assert!(!valid_id("account"));
        assert!(!valid_id("a#client_secret"));
        assert!(!valid_id(""));
        assert!(!valid_id("../x"));
    }
}
