//! Memory watchdog: keep CloudUp under the memory limit set in Settings.
//!
//! Most of CloudUp's memory is caches (file transfers stream through disk):
//! folder listings for the Finder drives, Finder's side-files kept in memory,
//! and the MEGA node tree of each account. The caches are sized from the
//! limit up front; every `CHECK_EVERY` the watchdog also measures the app's
//! memory footprint (what Activity Monitor shows as "Memory") and, above the
//! limit, drops caches in `ORDER` until it is under again. Everything dropped
//! is fetched again when needed.
//!
//! Measuring (`footprint_mb`) and acting (`apply`) are kept apart from the
//! decisions (`over`, `plan`, `Backoff`), which are plain functions.

use std::time::{Duration, Instant};

use crate::settings;

const MIB: u64 = 1024 * 1024;
const CHECK_EVERY: Duration = Duration::from_secs(20);
/// After a pass that dropped the MEGA trees and still ended over the limit,
/// the next such drop waits this long, doubling each time up to
/// `HEAVY_BACKOFF_MAX`: re-fetching a tree is a big download, and a limit
/// below what CloudUp needs anyway would otherwise re-fetch it every 20 s.
const HEAVY_BACKOFF_MIN: Duration = Duration::from_secs(40);
const HEAVY_BACKOFF_MAX: Duration = Duration::from_secs(600);

// ------------------------------------------------------------- cache sizing

/// Folder listings each Finder drive keeps (64 at 128 MB, 256 at 512 MB,
/// 2048 at 4096 MB).
pub fn listing_cache_entries(limit_mb: u32) -> usize {
    (limit_mb / 2).clamp(64, 2048) as usize
}

/// Bytes of Finder side-files (`.DS_Store`, `._*`) each Finder drive keeps in
/// memory: a sixteenth of the limit.
pub fn finder_files_budget(limit_mb: u32) -> u64 {
    limit_mb as u64 * MIB / 16
}

/// What the side-files are cut down to when the app is over the limit.
pub fn finder_files_trimmed(limit_mb: u32) -> u64 {
    limit_mb as u64 * MIB / 64
}

// ---------------------------------------------------------------- decisions

/// A way to free memory, cheapest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trim {
    /// Only hand memory already freed back to macOS.
    ReturnFree,
    /// Every Finder drive's folder listings.
    Listings,
    /// Finder side-files beyond `finder_files_trimmed`, oldest first.
    FinderFiles,
    /// The MEGA node trees (re-fetched on the next request).
    MegaTrees,
}

pub const ORDER: [Trim; 4] = [Trim::ReturnFree, Trim::Listings, Trim::FinderFiles, Trim::MegaTrees];

impl Trim {
    fn what(self) -> &'static str {
        match self {
            Trim::ReturnFree => "freed memory",
            Trim::Listings => "folder listings",
            Trim::FinderFiles => "Finder side-files",
            Trim::MegaTrees => "MEGA file trees",
        }
    }
}

pub fn over(usage_mb: u64, limit_mb: u64) -> bool {
    usage_mb > limit_mb
}

/// The trims to try, in order, while over the limit; the MEGA trees only
/// when `heavy_ok`.
pub fn plan(heavy_ok: bool) -> Vec<Trim> {
    ORDER.iter().copied().filter(|t| heavy_ok || *t != Trim::MegaTrees).collect()
}

/// Spaces out the MEGA tree drops while they don't help.
#[derive(Debug, Default)]
pub struct Backoff {
    misses: u32,
    heavy_after: Option<Instant>,
}

impl Backoff {
    pub fn heavy_ok(&self, now: Instant) -> bool {
        match self.heavy_after {
            Some(t) => now >= t,
            None => true,
        }
    }

    /// Record a pass: whether it dropped the MEGA trees and whether the app
    /// was still over the limit afterwards.
    pub fn record(&mut self, now: Instant, dropped_heavy: bool, still_over: bool) {
        if !still_over {
            *self = Backoff::default();
        } else if dropped_heavy {
            let wait = HEAVY_BACKOFF_MIN.saturating_mul(1 << self.misses.min(8)).min(HEAVY_BACKOFF_MAX);
            self.misses += 1;
            self.heavy_after = Some(now + wait);
        }
    }
}

// ---------------------------------------------------------- measuring, acting

/// The app's physical memory footprint, in bytes.
fn footprint_bytes() -> Option<u64> {
    // SAFETY: rusage_info_v2 is plain data; proc_pid_rusage fills it for the
    // RUSAGE_INFO_V2 flavor (the C API types the buffer as rusage_info_t *).
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            &mut info as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
        )
    };
    (r == 0).then_some(info.ri_phys_footprint)
}

/// The app's memory footprint in MB (rounded), if macOS reports it.
pub fn footprint_mb() -> Option<u64> {
    footprint_bytes().map(|b| (b + MIB / 2) / MIB)
}

extern "C" {
    /// <malloc/malloc.h>: give free pages of `zone` (all zones when null)
    /// back to the system; `goal` 0 means as much as possible.
    fn malloc_zone_pressure_relief(zone: *mut libc::c_void, goal: libc::size_t) -> libc::size_t;
}

/// Return memory the allocator holds but no longer uses to macOS.
fn release_free_memory() {
    // SAFETY: a null zone asks every malloc zone; no pointers are kept.
    unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
}

/// Do one trim; how many cached items it dropped.
fn apply(t: Trim, limit_mb: u32) -> usize {
    match t {
        Trim::ReturnFree => 0,
        Trim::Listings => crate::mount::drop_listings(),
        Trim::FinderFiles => crate::mount::trim_finder_files(finder_files_trimmed(limit_mb)),
        Trim::MegaTrees => crate::mega::drop_trees(),
    }
}

/// One check: measure, and trim while over the limit.
fn check(backoff: &mut Backoff) {
    let limit = settings::memory_limit_mb();
    let Some(start) = footprint_mb() else { return };
    if !over(start, limit as u64) {
        backoff.record(Instant::now(), false, false);
        return;
    }
    let now = Instant::now();
    let mut usage = start;
    let mut dropped: Vec<String> = Vec::new();
    let mut dropped_heavy = false;
    for t in plan(backoff.heavy_ok(now)) {
        if !over(usage, limit as u64) {
            break;
        }
        let n = apply(t, limit);
        release_free_memory();
        usage = footprint_mb().unwrap_or(usage);
        if n > 0 {
            dropped.push(format!("{n} {}", t.what()));
        }
        dropped_heavy |= t == Trim::MegaTrees && n > 0;
    }
    let still_over = over(usage, limit as u64);
    if !dropped.is_empty() {
        eprintln!(
            "cloudup memory: {start} MB, over the {limit} MB limit: dropped {}; now {usage} MB",
            dropped.join(", ")
        );
    }
    backoff.record(now, dropped_heavy, still_over);
}

/// Start the watchdog (from the app's setup).
pub fn start() {
    tauri::async_runtime::spawn(async {
        let mut backoff = Backoff::default();
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            check(&mut backoff);
        }
    });
}

#[derive(Debug, serde::Serialize)]
pub struct MemoryUsage {
    /// The app's footprint, or None if macOS didn't report it.
    pub app_mb: Option<u64>,
    pub limit_mb: u32,
}

#[tauri::command]
pub fn memory_usage() -> MemoryUsage {
    MemoryUsage { app_mb: footprint_mb(), limit_mb: settings::memory_limit_mb() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_scale_with_the_limit() {
        assert_eq!(listing_cache_entries(128), 64);
        assert_eq!(listing_cache_entries(512), 256);
        assert_eq!(listing_cache_entries(4096), 2048);
        assert_eq!(finder_files_budget(512), 32 * MIB);
        assert_eq!(finder_files_budget(128), 8 * MIB);
        assert!(finder_files_trimmed(512) < finder_files_budget(512));
    }

    #[test]
    fn nothing_is_trimmed_at_or_under_the_limit() {
        assert!(!over(512, 512));
        assert!(!over(100, 512));
        assert!(over(513, 512));
    }

    #[test]
    fn trims_run_cheapest_first_and_mega_only_when_allowed() {
        assert_eq!(plan(true), vec![Trim::ReturnFree, Trim::Listings, Trim::FinderFiles, Trim::MegaTrees]);
        assert_eq!(plan(false), vec![Trim::ReturnFree, Trim::Listings, Trim::FinderFiles]);
    }

    #[test]
    fn mega_drops_back_off_while_they_dont_help() {
        let t0 = Instant::now();
        let mut b = Backoff::default();
        assert!(b.heavy_ok(t0));
        // Dropped the trees, still over: wait 40 s, then 80 s.
        b.record(t0, true, true);
        assert!(!b.heavy_ok(t0 + Duration::from_secs(39)));
        assert!(b.heavy_ok(t0 + Duration::from_secs(40)));
        let t1 = t0 + Duration::from_secs(40);
        b.record(t1, true, true);
        assert!(!b.heavy_ok(t1 + Duration::from_secs(79)));
        assert!(b.heavy_ok(t1 + Duration::from_secs(80)));
        // A pass without a tree drop leaves the wait alone.
        b.record(t1, false, true);
        assert!(!b.heavy_ok(t1 + Duration::from_secs(79)));
        // Back under the limit: allowed again at once.
        b.record(t1, false, false);
        assert!(b.heavy_ok(t1));
    }

    #[test]
    fn the_backoff_is_capped() {
        let t0 = Instant::now();
        let mut b = Backoff::default();
        for _ in 0..20 {
            b.record(t0, true, true);
        }
        assert!(!b.heavy_ok(t0 + HEAVY_BACKOFF_MAX - Duration::from_secs(1)));
        assert!(b.heavy_ok(t0 + HEAVY_BACKOFF_MAX));
    }

    #[test]
    fn the_footprint_is_measured() {
        let mb = footprint_mb().expect("macOS reports the footprint");
        assert!(mb > 0 && mb < 64 * 1024, "{mb} MB");
    }
}
