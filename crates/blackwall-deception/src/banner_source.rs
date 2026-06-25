//! Where a banner emulator reads its banners from: a fixed snapshot or a
//! live, hot-reloadable store.

use crate::banner::BannerStore;
use crate::banner_reload::SharedBanners;
use std::sync::Arc;

/// A source of banners for an emulator.
#[derive(Clone)]
pub enum BannerSource {
    /// A fixed snapshot that never changes.
    Fixed(Arc<BannerStore>),
    /// A hot-reloadable store; each read sees the latest loaded banners.
    Live(SharedBanners),
}

impl BannerSource {
    /// The current banner store. For [`BannerSource::Live`] this reflects the
    /// most recent successful reload.
    pub fn current(&self) -> Arc<BannerStore> {
        match self {
            BannerSource::Fixed(store) => store.clone(),
            BannerSource::Live(shared) => shared.current(),
        }
    }
}

impl From<Arc<BannerStore>> for BannerSource {
    fn from(store: Arc<BannerStore>) -> Self {
        BannerSource::Fixed(store)
    }
}

impl From<SharedBanners> for BannerSource {
    fn from(shared: SharedBanners) -> Self {
        BannerSource::Live(shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_source_returns_its_store() {
        let store = Arc::new(BannerStore::from_text("80 = A\\r\\n\n* = X\\r\\n").unwrap());
        let src = BannerSource::from(store.clone());
        assert_eq!(src.current().banner_for(80), b"A\r\n");
    }
}
