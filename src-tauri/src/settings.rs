//! App settings for this Mac (`settings.json` in the data folder, 0600).
//!
//! Never synced with the CloudUp account: a memory limit suits one Mac, not
//! all of them. A copy goes to the app-group container (next to
//! drives.json) so the Finder extension reads the same limit.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

pub const DEFAULT_MEMORY_LIMIT_MB: u32 = 512;
pub const MIN_MEMORY_LIMIT_MB: u32 = 128;
pub const MAX_MEMORY_LIMIT_MB: u32 = 4096;

const FILE_NAME: &str = "settings.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// CloudUp and its Finder extension drop cached data above this.
    pub memory_limit_mb: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self { memory_limit_mb: DEFAULT_MEMORY_LIMIT_MB }
    }
}

impl Settings {
    /// The same settings with every value brought into its allowed range
    /// (for a file edited by hand).
    pub fn clamped(self) -> Self {
        Self { memory_limit_mb: self.memory_limit_mb.clamp(MIN_MEMORY_LIMIT_MB, MAX_MEMORY_LIMIT_MB) }
    }

    /// These settings if every value is allowed, else what to fix.
    pub fn validated(self) -> Result<Self, String> {
        if !(MIN_MEMORY_LIMIT_MB..=MAX_MEMORY_LIMIT_MB).contains(&self.memory_limit_mb) {
            return Err(format!(
                "The memory limit must be between {MIN_MEMORY_LIMIT_MB} and {MAX_MEMORY_LIMIT_MB} MB."
            ));
        }
        Ok(self)
    }
}

fn file_in(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// The settings saved in `dir`; defaults when there are none or the file
/// can't be read, and values clamped to their range.
pub fn load_from(dir: &Path) -> Settings {
    let Ok(raw) = std::fs::read(file_in(dir)) else { return Settings::default() };
    match serde_json::from_slice::<Settings>(&raw) {
        Ok(s) => s.clamped(),
        Err(e) => {
            eprintln!("cloudup settings: {FILE_NAME} unreadable, using defaults: {e}");
            Settings::default()
        }
    }
}

/// The JSON written to disk for `s`.
fn encode(s: &Settings) -> Vec<u8> {
    serde_json::to_vec_pretty(s).expect("settings serialize")
}

/// Save `s` in `dir` (0600, atomically).
pub fn save_to(dir: &Path, s: &Settings) -> Result<(), String> {
    crate::config::write_private(&file_in(dir), &encode(s))
}

/// The memory limit in force, in MB (read by the caches and the watchdog).
static MEMORY_LIMIT_MB: AtomicU32 = AtomicU32::new(DEFAULT_MEMORY_LIMIT_MB);

pub fn memory_limit_mb() -> u32 {
    MEMORY_LIMIT_MB.load(Ordering::Relaxed)
}

fn apply(s: &Settings) {
    MEMORY_LIMIT_MB.store(s.memory_limit_mb, Ordering::Relaxed);
    if let Err(e) = crate::mount::publish_settings(&encode(s)) {
        eprintln!("cloudup settings: could not share them with the Finder extension: {e}");
    }
}

/// Load the saved settings at startup and share them with the extension.
pub fn init() {
    apply(&load_from(&crate::config::data_dir()));
}

#[tauri::command]
pub fn get_settings() -> Settings {
    load_from(&crate::config::data_dir())
}

#[tauri::command]
pub fn set_settings(settings: Settings) -> Result<Settings, String> {
    let s = settings.validated()?;
    save_to(&crate::config::data_dir(), &s)?;
    apply(&s);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cloudup-settings-{tag}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn defaults_when_there_is_no_file() {
        let dir = temp_dir("none");
        assert_eq!(load_from(&dir), Settings { memory_limit_mb: 512 });
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn defaults_when_the_file_is_corrupt() {
        let dir = temp_dir("corrupt");
        std::fs::write(file_in(&dir), b"{not json").unwrap();
        assert_eq!(load_from(&dir), Settings::default());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_and_unknown_fields_are_tolerated() {
        let dir = temp_dir("fields");
        std::fs::write(file_in(&dir), br#"{"something_else": true}"#).unwrap();
        assert_eq!(load_from(&dir), Settings::default());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_then_load_round_trips_privately() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("roundtrip");
        let s = Settings { memory_limit_mb: 1024 };
        save_to(&dir, &s).unwrap();
        assert_eq!(load_from(&dir), s);
        let mode = std::fs::metadata(file_in(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn values_out_of_range_are_clamped_on_load() {
        let dir = temp_dir("clamp");
        std::fs::write(file_in(&dir), br#"{"memory_limit_mb": 16}"#).unwrap();
        assert_eq!(load_from(&dir).memory_limit_mb, MIN_MEMORY_LIMIT_MB);
        std::fs::write(file_in(&dir), br#"{"memory_limit_mb": 100000}"#).unwrap();
        assert_eq!(load_from(&dir).memory_limit_mb, MAX_MEMORY_LIMIT_MB);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn saving_refuses_values_out_of_range() {
        assert!(Settings { memory_limit_mb: 127 }.validated().is_err());
        assert!(Settings { memory_limit_mb: 4097 }.validated().is_err());
        assert!(Settings { memory_limit_mb: 0 }.validated().unwrap_err().contains("between 128 and 4096 MB"));
        assert_eq!(Settings { memory_limit_mb: 128 }.validated(), Ok(Settings { memory_limit_mb: 128 }));
        assert_eq!(Settings { memory_limit_mb: 4096 }.validated(), Ok(Settings { memory_limit_mb: 4096 }));
    }
}
