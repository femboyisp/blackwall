//! A hot-reloadable [`BannerStore`] backed by a file on disk.

use crate::banner::BannerStore;
use crate::error::DeceptionError;
use arc_swap::ArcSwap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A banner store that can be atomically swapped when its file changes.
#[derive(Clone)]
pub struct SharedBanners {
    inner: Arc<ArcSwap<BannerStore>>,
    /// Hash of the file text behind the current store. Lets [`reload`] skip the
    /// swap (and the log line) when a filesystem event fires but the content is
    /// byte-for-byte unchanged — which is the common case, since the reload's
    /// own `read_to_string` and duplicate inotify events would otherwise spin
    /// the watcher forever. `0` for stores with no file backing.
    ///
    /// [`reload`]: SharedBanners::reload
    last_hash: Arc<AtomicU64>,
}

impl SharedBanners {
    /// Load the initial store from `path`.
    pub fn load(path: &Path) -> Result<SharedBanners, DeceptionError> {
        let text = std::fs::read_to_string(path)?;
        let hash = hash_text(&text);
        let store = BannerStore::from_text(&text)?;
        Ok(SharedBanners {
            inner: Arc::new(ArcSwap::from_pointee(store)),
            last_hash: Arc::new(AtomicU64::new(hash)),
        })
    }

    /// The current store (cheap, lock-free).
    pub fn current(&self) -> Arc<BannerStore> {
        self.inner.load_full()
    }

    /// Reload from `path`, swapping atomically only when the file's content has
    /// actually changed. Returns `Ok(true)` if a new store was installed,
    /// `Ok(false)` if the content was identical to what is already loaded (a
    /// spurious or duplicate filesystem event — the store is left untouched). A
    /// parse failure leaves the existing store in place and returns the error.
    pub fn reload(&self, path: &Path) -> Result<bool, DeceptionError> {
        let text = std::fs::read_to_string(path)?;
        let hash = hash_text(&text);
        if self.last_hash.load(Ordering::Relaxed) == hash {
            // Content unchanged since the last load; ignore the event. This is
            // the guard that stops the reload storm — without it, every inotify
            // event (including ones the read above can itself provoke) would
            // reparse and re-swap the store and emit a log line.
            return Ok(false);
        }
        let store = BannerStore::from_text(&text)?;
        self.inner.store(Arc::new(store));
        self.last_hash.store(hash, Ordering::Relaxed);
        Ok(true)
    }

    /// Seed a shared store from an in-memory [`BannerStore`] (no file backing).
    pub fn from_store(store: Arc<BannerStore>) -> SharedBanners {
        SharedBanners {
            inner: Arc::new(ArcSwap::new(store)),
            last_hash: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Atomically replace the current store with `store`.
    pub fn swap(&self, store: Arc<BannerStore>) {
        self.inner.store(store);
    }
}

/// Stable per-process hash of the banner file text, used only to detect
/// no-change reloads. Not persisted, so the choice of hasher is an
/// implementation detail.
fn hash_text(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("bw-banners-{}-{}.txt", std::process::id(), tag));
        p
    }

    #[test]
    fn reload_swaps_store_atomically() {
        let path = temp_path("reload");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"80 = ONE\\r\\n\n* = X\\r\\n")
            .unwrap();
        let shared = SharedBanners::load(&path).expect("load");
        assert_eq!(shared.current().banner_for(80), b"ONE\r\n");

        std::fs::write(&path, b"80 = TWO\\r\\n\n* = X\\r\\n").unwrap();
        assert!(shared.reload(&path).expect("reload"), "content changed");
        assert_eq!(shared.current().banner_for(80), b"TWO\r\n");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_is_noop_when_content_unchanged() {
        let path = temp_path("noop");
        std::fs::write(&path, b"80 = SAME\\r\\n\n* = X\\r\\n").unwrap();
        let shared = SharedBanners::load(&path).expect("load");

        // Touch the file (new mtime) without changing a byte, then reload.
        std::fs::write(&path, b"80 = SAME\\r\\n\n* = X\\r\\n").unwrap();
        assert!(
            !shared.reload(&path).expect("reload"),
            "identical content must report no change"
        );
        assert_eq!(shared.current().banner_for(80), b"SAME\r\n");

        // A real change after a no-op still reloads.
        std::fs::write(&path, b"80 = NEW\\r\\n\n* = X\\r\\n").unwrap();
        assert!(shared.reload(&path).expect("reload"), "real change reloads");
        assert_eq!(shared.current().banner_for(80), b"NEW\r\n");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_store_then_swap_changes_current() {
        let a = Arc::new(BannerStore::from_text("80 = A\\r\\n\n* = X\\r\\n").unwrap());
        let b = Arc::new(BannerStore::from_text("80 = B\\r\\n\n* = X\\r\\n").unwrap());
        let shared = SharedBanners::from_store(a);
        assert_eq!(shared.current().banner_for(80), b"A\r\n");
        shared.swap(b);
        assert_eq!(shared.current().banner_for(80), b"B\r\n");
    }
}
