//! Finder Locations: register each mounted connection as a File Provider
//! domain, so Finder's sidebar lists it as "CloudUp - <name>" (one click to
//! the files). The bundled extension (fileprovider/Extension.swift) serves
//! the files by talking to this connection's local WebDAV server, whose
//! address we publish in the shared app-group container (drives.json).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AllocAnyThread;
use objc2_file_provider::{
    NSFileProviderDomain, NSFileProviderManager, NSFileProviderWorkingSetContainerItemIdentifier,
};
use objc2_foundation::{NSArray, NSError, NSString};

const APP_GROUP: &str = "8V6DT796JV.net.cloudup";

fn group_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join("Library/Group Containers").join(APP_GROUP)
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

/// Add (or rename) the Finder Location for a connection.
pub fn add(id: &str, name: &str) -> Result<(), String> {
    let d = domain(id, name);
    wait(|b| unsafe { NSFileProviderManager::addDomain_completionHandler(&d, b) })
}

/// Remove the Finder Location for a connection.
pub fn remove(id: &str) -> Result<(), String> {
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
/// once macOS has created it.
pub fn location_path(name: &str) -> String {
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
