//! Mount management: expose a connection as a real drive.
//!
//! On macOS this uses FUSE (macFUSE); on Windows it would use WinFsp. The whole
//! implementation is optional (feature `fuse-mount`) so the app always builds and
//! runs with its built-in browser even when no filesystem driver is present.

use crate::config::Connection;
use crate::error::{Error, Result};

#[cfg(feature = "fuse-mount")]
mod fuse;

/// Describes an active mount.
#[derive(Clone, serde::Serialize)]
pub struct MountInfo {
    pub id: String, // connection id
    pub name: String, // display name
    pub mount_point: String,
}

static MOUNTS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, MountInfo>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Whether mounting as a drive is possible in this build.
pub fn is_available() -> bool {
    #[cfg(feature = "fuse-mount")]
    { true }
    #[cfg(not(feature = "fuse-mount"))]
    { false }
}

/// Human-readable reason mounting may be unavailable.
pub fn availability_note() -> String {
    #[cfg(feature = "fuse-mount")]
    { "FUSE driver support is compiled in.".to_string() }
    #[cfg(not(feature = "fuse-mount"))]
    {
        "This build does not include drive mounting. Install macFUSE (macOS) or WinFsp \
         (Windows), then rebuild with --features fuse-mount."
            .to_string()
    }
}

/// Mount a connection. Returns the mount info on success.
pub fn mount(conn: &Connection, secret: &str) -> Result<MountInfo> {
    #[cfg(feature = "fuse-mount")]
    {
        fuse::mount(conn, secret)
    }
    #[cfg(not(feature = "fuse-mount"))]
    {
        let _ = (conn, secret);
        Err(Error::Other(availability_note()))
    }
}

/// Unmount a previously mounted connection by id.
pub fn unmount(id: &str) -> Result<()> {
    let mut map = MOUNTS.lock().unwrap();
    if let Some(info) = map.remove(id) {
        #[cfg(feature = "fuse-mount")]
        fuse::unmount(&info.mount_point)?;
        #[cfg(not(feature = "fuse-mount"))]
        {
            let _mount_point = info.mount_point;
        }
        Ok(())
    } else {
        Err(Error::Other("not mounted".into()))
    }
}

/// All active mounts.
pub fn list_mounted() -> Vec<MountInfo> {
    MOUNTS.lock().unwrap().values().cloned().collect()
}
