//! macOS services CloudUp uses in both builds (direct download and Mac App
//! Store): the login item (SMAppService), opening web pages and files
//! (NSWorkspace, not a `/usr/bin/open` child process) and security-scoped
//! bookmarks, which let the sandboxed build reopen a file the user picked.

use std::path::{Path, PathBuf};

use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2::{msg_send, AllocAnyThread};
use objc2_app_kit::NSWorkspace;
use objc2_foundation::{
    NSAppleEventDescriptor, NSAppleEventManager, NSArray, NSData, NSDataBase64DecodingOptions,
    NSDataBase64EncodingOptions, NSString, NSURLBookmarkCreationOptions, NSURLBookmarkResolutionOptions,
    NSURL,
};
use objc2_service_management::{SMAppService, SMAppServiceStatus};

// ------------------------------------------------------------------ login item

/// Whether CloudUp opens at login: registered, or registered and waiting for
/// the user to allow it in System Settings → General → Login Items.
pub fn login_item_enabled() -> bool {
    let status = unsafe { SMAppService::mainAppService().status() };
    status == SMAppServiceStatus::Enabled || status == SMAppServiceStatus::RequiresApproval
}

/// Add or remove CloudUp as a login item (SMAppService.mainApp, macOS 13+).
pub fn set_login_item(enabled: bool) -> Result<(), String> {
    let service = unsafe { SMAppService::mainAppService() };
    let status = unsafe { service.status() };
    let result = if enabled {
        if status == SMAppServiceStatus::Enabled {
            return Ok(());
        }
        unsafe { service.registerAndReturnError() }
    } else {
        if status == SMAppServiceStatus::NotRegistered || status == SMAppServiceStatus::NotFound {
            return Ok(());
        }
        unsafe { service.unregisterAndReturnError() }
    };
    match result {
        Ok(()) => Ok(()),
        // Registered, but the user turned it off in System Settings: macOS
        // shows its own notification; nothing more we can do from here.
        Err(_) if enabled && unsafe { service.status() } == SMAppServiceStatus::RequiresApproval => Ok(()),
        Err(e) => Err(e.localizedDescription().to_string()),
    }
}

/// Whether macOS launched this process as a login item. SMAppService can't
/// pass arguments (1.1.x used `--login`), but the launch Apple event ('oapp')
/// then carries `keyAEPropData` = `keyAELaunchedAsLogInItem`. That event is
/// only current while the launch is being handled, i.e. inside
/// `applicationDidFinishLaunching`, which is where Tauri runs `setup`.
pub fn launched_as_login_item() -> bool {
    const KEY_AE_PROP_DATA: u32 = u32::from_be_bytes(*b"prdt");
    const KEY_AE_LAUNCHED_AS_LOG_IN_ITEM: u32 = u32::from_be_bytes(*b"lgit");
    let Some(event) = NSAppleEventManager::sharedAppleEventManager().currentAppleEvent() else {
        return false;
    };
    // msg_send: the typed binding needs the objc2-core-services crate.
    let prop: Option<Retained<NSAppleEventDescriptor>> =
        unsafe { msg_send![&*event, paramDescriptorForKeyword: KEY_AE_PROP_DATA] };
    prop.is_some_and(|p| p.enumCodeValue() == KEY_AE_LAUNCHED_AS_LOG_IN_ITEM)
}

/// 1.1.x registered the login item as `~/Library/LaunchAgents/CloudUp.plist`
/// (tauri-plugin-autostart, labelled with the product name). Replace it with
/// the SMAppService login item. Runs at every start but only acts while that
/// file exists, so it happens once. In the sandbox `~` is the container, where
/// the file never exists.
pub fn migrate_legacy_login_item() {
    let Some(home) = dirs::home_dir() else { return };
    let plist = home.join("Library/LaunchAgents/CloudUp.plist");
    let Ok(text) = std::fs::read_to_string(&plist) else { return };
    // Only the file our plugin wrote: label "CloudUp", started with --login.
    if !text.contains("<string>CloudUp</string>") || !text.contains(&format!("<string>{}</string>", crate::LOGIN_ARG)) {
        return;
    }
    if let Err(e) = std::fs::remove_file(&plist) {
        eprintln!("[cloudup] could not remove the old login item {}: {e}", plist.display());
        return;
    }
    if let Err(e) = set_login_item(true) {
        eprintln!("[cloudup] could not add CloudUp as a login item: {e}");
    }
}

// ------------------------------------------------------------------ NSWorkspace

/// Open a web page in the default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    let u = NSURL::URLWithString(&NSString::from_str(url)).ok_or_else(|| format!("not a valid URL: {url}"))?;
    if NSWorkspace::sharedWorkspace().openURL(&u) {
        Ok(())
    } else {
        Err(format!("macOS could not open {url}"))
    }
}

/// Open a file with its default app, or a folder in Finder.
pub fn open_file(path: &Path) -> Result<(), String> {
    if NSWorkspace::sharedWorkspace().openURL(&file_url(path)) {
        Ok(())
    } else {
        Err(format!("no app could open {}", path.display()))
    }
}

/// Show a file selected in a Finder window.
pub fn reveal(path: &Path) {
    let urls = NSArray::from_retained_slice(&[file_url(path)]);
    NSWorkspace::sharedWorkspace().activateFileViewerSelectingURLs(&urls);
}

fn file_url(path: &Path) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
}

// ------------------------------------------------------------------ bookmarks

/// A read-only security-scoped bookmark for `path`, base64-encoded for
/// config.json. Fails when the app has no access to the file right now (in
/// the sandbox: not picked in an open panel this session) and may fail in
/// the unsandboxed build, which doesn't need one.
pub fn bookmark(path: &Path) -> Result<String, String> {
    let options =
        NSURLBookmarkCreationOptions::WithSecurityScope | NSURLBookmarkCreationOptions::SecurityScopeAllowOnlyReadAccess;
    let data = file_url(path)
        .bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error(options, None, None)
        .map_err(|e| e.localizedDescription().to_string())?;
    Ok(data.base64EncodedStringWithOptions(NSDataBase64EncodingOptions::empty()).to_string())
}

/// A file opened through a security-scoped bookmark. Access ends when this
/// is dropped.
pub struct ScopedFile {
    url: Retained<NSURL>,
    accessing: bool,
    pub path: PathBuf,
}

impl Drop for ScopedFile {
    fn drop(&mut self) {
        if self.accessing {
            unsafe { self.url.stopAccessingSecurityScopedResource() };
        }
    }
}

/// Resolve a bookmark made by [`bookmark`] and start accessing the file.
pub fn resolve_bookmark(b64: &str) -> Option<ScopedFile> {
    let data = NSData::initWithBase64EncodedString_options(
        NSData::alloc(),
        &NSString::from_str(b64.trim()),
        NSDataBase64DecodingOptions::empty(),
    )?;
    let options = NSURLBookmarkResolutionOptions::WithSecurityScope | NSURLBookmarkResolutionOptions::WithoutUI;
    let mut stale = Bool::NO;
    let url = unsafe {
        NSURL::URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error(&data, options, None, &mut stale)
    }
    .ok()?;
    let path = PathBuf::from(url.path()?.to_string());
    let accessing = unsafe { url.startAccessingSecurityScopedResource() };
    Some(ScopedFile { url, accessing, path })
}

/// The user's real home folder. In the sandbox `$HOME` (and `dirs::home_dir`)
/// is the app's container, so a typed `~/.ssh/...` would point inside it.
pub fn real_home() -> Option<PathBuf> {
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(libc::getuid(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }.to_string_lossy().to_string();
    Some(PathBuf::from(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_home_matches_home_outside_the_sandbox() {
        assert_eq!(real_home(), dirs::home_dir());
    }

    #[test]
    fn bookmark_round_trip_when_available() {
        let path = std::env::temp_dir().join(format!("cloudup-bookmark-{}", std::process::id()));
        std::fs::write(&path, b"key").unwrap();
        // Unsandboxed processes may not get a security-scoped bookmark; the
        // SFTP code then uses the path.
        if let Ok(b) = bookmark(&path) {
            let f = resolve_bookmark(&b).expect("resolves");
            assert_eq!(std::fs::read(&f.path).unwrap(), b"key");
        }
        assert!(resolve_bookmark("not base64!").is_none());
        let _ = std::fs::remove_file(&path);
    }
}
