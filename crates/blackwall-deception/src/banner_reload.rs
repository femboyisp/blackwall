//! A hot-reloadable [`BannerStore`] backed by a file on disk.

use crate::banner::BannerStore;
use crate::error::DeceptionError;
use arc_swap::ArcSwap;
use std::path::Path;
use std::sync::Arc;

/// A banner store that can be atomically swapped when its file changes.
#[derive(Clone)]
pub struct SharedBanners {
    inner: Arc<ArcSwap<BannerStore>>,
}

impl SharedBanners {
    /// Load the initial store from `path`.
    pub fn load(path: &Path) -> Result<SharedBanners, DeceptionError> {
        let store = read_store(path)?;
        Ok(SharedBanners {
            inner: Arc::new(ArcSwap::from_pointee(store)),
        })
    }

    /// The current store (cheap, lock-free).
    pub fn current(&self) -> Arc<BannerStore> {
        self.inner.load_full()
    }

    /// Reload from `path` immediately, swapping atomically on success. A parse
    /// failure leaves the existing store in place and returns the error.
    pub fn reload(&self, path: &Path) -> Result<(), DeceptionError> {
        let store = read_store(path)?;
        self.inner.store(Arc::new(store));
        Ok(())
    }
}

fn read_store(path: &Path) -> Result<BannerStore, DeceptionError> {
    let text = std::fs::read_to_string(path)?;
    BannerStore::from_text(&text)
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
        shared.reload(&path).expect("reload");
        assert_eq!(shared.current().banner_for(80), b"TWO\r\n");

        let _ = std::fs::remove_file(&path);
    }
}
