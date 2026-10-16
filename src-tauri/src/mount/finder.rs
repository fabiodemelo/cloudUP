//! Finder Locations: register each mounted connection as a File Provider
//! domain, so Finder's sidebar lists it as "CloudUp - <name>" (one click to
//! the files). The bundled extension (fileprovider/Extension.swift) serves
//! the files by talking to this connection's local WebDAV server, whose
//! address we publish in the shared app-group container (drives.json).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AllocAnyThread;
use objc2_file_provider::{
    NSFileProviderDomain, NSFileProviderManager, NSFileProviderRootContainerItemIdentifier,
    NSFileProviderWorkingSetContainerItemIdentifier,
};
use objc2_foundation::{NSArray, NSError, NSFileManager, NSString, NSURL};

const APP_GROUP: &str = "8V6DT796JV.net.cloudup";

/// The app-group container shared with the extension. Asked from macOS (in
/// the sandbox `~` is the app's own container); the usual location if that
/// fails, e.g. in an unsigned development build.
fn group_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        NSFileManager::defaultManager()
            .containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(APP_GROUP))
            .and_then(|u| u.path())
            .map(|p| PathBuf::from(p.to_string()))
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join("Library/Group Containers").join(APP_GROUP))
    })
    .clone()
}

fn drives_file() -> PathBuf {
    group_dir().join("drives.json")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Drive {
    name: String,
    url: String,
}

fn read_drives() -> HashMap<String, Drive> {
    std::fs::read(drives_file()).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default()
}

fn write_drives(d: &HashMap<String, Drive>) -> Result<(), String> {
    std::fs::create_dir_all(group_dir()).map_err(|e| e.to_string())?;
    let tmp = drives_file().with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(d).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(tmp, drives_file()).map_err(|e| e.to_string())
}

/// Tell the extension where a connection's server is.
pub fn publish(id: &str, name: &str, url: &str) -> Result<(), String> {
    let mut d = read_drives();
    d.insert(id.to_string(), Drive { name: name.to_string(), url: url.to_string() });
    write_drives(&d)
}

pub fn unpublish(id: &str) {
    let mut d = read_drives();
    if d.remove(id).is_some() {
        let _ = write_drives(&d);
    }
}

fn domain(id: &str, name: &str) -> Retained<NSFileProviderDomain> {
    unsafe {
        NSFileProviderDomain::initWithIdentifier_displayName(
            NSFileProviderDomain::alloc(),
            &NSString::from_str(id),
            &NSString::from_str(name),
        )
    }
}

/// Run an API that reports through an error-only completion block; wait for it.
fn wait(call: impl FnOnce(&RcBlock<dyn Fn(*mut NSError)>)) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let block = RcBlock::new(move |err: *mut NSError| {
        let msg = unsafe { err.as_ref() }.map(|e| e.localizedDescription().to_string());
        let _ = tx.send(msg);
    });
    call(&block);
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(None) => Ok(()),
        Ok(Some(e)) => Err(e),
        Err(_) => Err("timed out waiting for macOS".into()),
    }
}

/// Identifier of an invisible Location. Finder labels a provider's only
/// Location with just the app name ("CloudUp"); once there are two it shows
/// "CloudUp - <name>". Keeping this hidden one registered while anything is
/// mounted makes every Location show its connection's name.
pub const PLACEHOLDER: &str = "cloudup-placeholder";

/// Add (or rename) the Finder Location for a connection.
pub fn add(id: &str, name: &str) -> Result<(), String> {
    ensure_placeholder();
    let d = domain(id, name);
    wait(|b| unsafe { NSFileProviderManager::addDomain_completionHandler(&d, b) })
}

fn ensure_placeholder() {
    if registered().iter().any(|i| i == PLACEHOLDER) {
        return;
    }
    let d = domain(PLACEHOLDER, "CloudUp");
    unsafe { d.setHidden(true) };
    let _ = wait(|b| unsafe { NSFileProviderManager::addDomain_completionHandler(&d, b) });
}

/// Drop the placeholder once no real Location is left.
pub fn tidy_placeholder() {
    let ids = registered();
    if ids.iter().all(|i| i == PLACEHOLDER) && ids.iter().any(|i| i == PLACEHOLDER) {
        let d = domain(PLACEHOLDER, "");
        let _ = wait(|b| unsafe { NSFileProviderManager::removeDomain_completionHandler(&d, b) });
    }
}

/// Remove the Finder Location for a connection.
pub fn remove(id: &str) -> Result<(), String> {
    // Its folder may differ if a Location of the same name is added again.
    VISIBLE_ROOTS.lock().unwrap().clear();
    let d = domain(id, "");
    wait(|b| unsafe { NSFileProviderManager::removeDomain_completionHandler(&d, b) })
}

/// Identifiers of the Locations currently registered.
pub fn registered() -> Vec<String> {
    let (tx, rx) = mpsc::channel();
    let block = RcBlock::new(move |domains: std::ptr::NonNull<NSArray<NSFileProviderDomain>>, _err: *mut NSError| {
        let list = unsafe { domains.as_ref() };
        let ids: Vec<String> = list.iter().map(|d| unsafe { d.identifier() }.to_string()).collect();
        let _ = tx.send(ids);
    });
    unsafe { NSFileProviderManager::getDomainsWithCompletionHandler(&block) };
    rx.recv_timeout(Duration::from_secs(15)).unwrap_or_default()
}

/// Ask Finder to refresh a Location (the extension re-lists what it shows).
pub fn signal(id: &str) {
    let d = domain(id, "");
    if let Some(m) = unsafe { NSFileProviderManager::managerForDomain(&d) } {
        let block = RcBlock::new(|_err: *mut NSError| {});
        unsafe {
            m.signalEnumeratorForContainerItemIdentifier_completionHandler(
                NSFileProviderWorkingSetContainerItemIdentifier,
                &block,
            )
        };
    }
}

/// Folder Finder shows for a Location (~/Library/CloudStorage/CloudUp-<name>),
/// once macOS has created it. Asked from macOS (the sandbox can't list
/// ~/Library/CloudStorage); the folder is guessed from the name if that fails.
pub fn location_path(name: &str) -> String {
    if let Some(p) = visible_root(name) {
        return p;
    }
    let root = dirs::home_dir().unwrap_or_default().join("Library/CloudStorage");
    let squashed: String = name.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    if let Ok(rd) = std::fs::read_dir(&root) {
        for e in rd.flatten() {
            let f = e.file_name().to_string_lossy().to_string();
            if let Some(rest) = f.strip_prefix("CloudUp-") {
                let r: String = rest.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
                if r == squashed {
                    return e.path().display().to_string();
                }
            }
        }
    }
    root.join(format!("CloudUp-{}", name.replace(' ', ""))).display().to_string()
}

/// Answers of [`visible_root`] by Location name: the folder, or a recent
/// failure (not asked again for a while, the window refreshes often).
static VISIBLE_ROOTS: LazyLock<Mutex<HashMap<String, (Option<String>, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The user-visible root folder of the Location named `name`, from
/// `NSFileProviderManager getUserVisibleURLForItemIdentifier:`.
fn visible_root(name: &str) -> Option<String> {
    if let Some((known, at)) = VISIBLE_ROOTS.lock().unwrap().get(name) {
        if known.is_some() || at.elapsed() < Duration::from_secs(30) {
            return known.clone();
        }
    }
    let found = ask_visible_root(name);
    VISIBLE_ROOTS.lock().unwrap().insert(name.to_string(), (found.clone(), Instant::now()));
    found
}

fn ask_visible_root(name: &str) -> Option<String> {
    // Find the domain by display name (the caller only knows the name).
    let (tx, rx) = mpsc::channel();
    let wanted = name.to_string();
    let block = RcBlock::new(move |domains: std::ptr::NonNull<NSArray<NSFileProviderDomain>>, _err: *mut NSError| {
        let list = unsafe { domains.as_ref() };
        let id = list
            .iter()
            .find(|d| unsafe { d.displayName() }.to_string() == wanted && unsafe { d.identifier() }.to_string() != PLACEHOLDER)
            .map(|d| unsafe { d.identifier() }.to_string());
        let _ = tx.send(id);
    });
    unsafe { NSFileProviderManager::getDomainsWithCompletionHandler(&block) };
    let id = rx.recv_timeout(Duration::from_secs(3)).ok().flatten()?;

    let manager = unsafe { NSFileProviderManager::managerForDomain(&domain(&id, name)) }?;
    let (tx, rx) = mpsc::channel();
    let block = RcBlock::new(move |url: *mut NSURL, _err: *mut NSError| {
        let path = unsafe { url.as_ref() }.and_then(|u| u.path()).map(|p| p.to_string());
        let _ = tx.send(path);
    });
    unsafe {
        manager.getUserVisibleURLForItemIdentifier_completionHandler(NSFileProviderRootContainerItemIdentifier, &block)
    };
    rx.recv_timeout(Duration::from_secs(3)).ok().flatten()
}
