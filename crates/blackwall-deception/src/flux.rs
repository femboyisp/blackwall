//! Banner fast-flux: rotate the active [`BannerStore`] persona over time.

use crate::banner::BannerStore;
use crate::banner_reload::SharedBanners;
use crate::error::DeceptionError;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// The pool index active at `now_unix` for a `period_secs` rotation over
/// `pool_len` variants: `(now / period) % len`. Stable within a period,
/// rotates across periods, identical across restarts. Defensive `.max(1)`
/// guards never panic on a zero period or empty pool.
pub fn flux_index(now_unix: u64, period_secs: u64, pool_len: usize) -> usize {
    if pool_len == 0 {
        return 0;
    }
    let bucket = now_unix / period_secs.max(1);
    usize::try_from(bucket % u64::try_from(pool_len).unwrap_or(1)).unwrap_or(0)
}

/// Time until the next period boundary after `now_unix`. At an exact boundary
/// this returns a full `period` (never zero), so a rotation loop never spins.
pub fn next_boundary_delay(now_unix: u64, period_secs: u64) -> Duration {
    let period = period_secs.max(1);
    Duration::from_secs(period - (now_unix % period))
}

/// A pool of banner personas; the active one is chosen by [`flux_index`].
pub struct BannerPool {
    variants: Vec<Arc<BannerStore>>,
}

impl BannerPool {
    /// Build a pool from in-memory variants. `None` if `variants` is empty.
    pub fn new(variants: Vec<Arc<BannerStore>>) -> Option<BannerPool> {
        if variants.is_empty() {
            None
        } else {
            Some(BannerPool { variants })
        }
    }

    /// Load every regular file in `dir` (sorted by file name for a stable
    /// index→persona mapping) as a [`BannerStore`] variant. Errors if the
    /// directory is empty or any file fails to parse.
    pub fn from_dir(dir: &Path) -> Result<BannerPool, DeceptionError> {
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        let mut variants = Vec::with_capacity(entries.len());
        for path in entries {
            let text = std::fs::read_to_string(&path)?;
            variants.push(Arc::new(BannerStore::from_text(&text)?));
        }
        BannerPool::new(variants).ok_or_else(|| {
            DeceptionError::Protocol(format!("banner-flux: no banner files in {}", dir.display()))
        })
    }

    /// Number of variants.
    pub fn len(&self) -> usize {
        self.variants.len()
    }

    /// Whether the pool has no variants (always `false` for a constructed pool).
    pub fn is_empty(&self) -> bool {
        self.variants.is_empty()
    }

    /// The variant at `index` (taken modulo the pool length).
    pub fn variant(&self, index: usize) -> Arc<BannerStore> {
        Arc::clone(&self.variants[index % self.variants.len()])
    }
}

/// Drives banner rotation: holds the pool + period and the shared store the
/// emulators read from.
pub struct BannerFlux {
    pool: BannerPool,
    period: Duration,
    shared: SharedBanners,
}

impl BannerFlux {
    /// Build a flux driver seeded with the persona active at `now_unix`.
    pub fn seeded(pool: BannerPool, period: Duration, now_unix: u64) -> BannerFlux {
        let idx = flux_index(now_unix, period.as_secs(), pool.len());
        let shared = SharedBanners::from_store(pool.variant(idx));
        BannerFlux {
            pool,
            period,
            shared,
        }
    }

    /// The shared store the emulators read from (clone is cheap, lock-free).
    pub fn shared(&self) -> SharedBanners {
        self.shared.clone()
    }

    /// Swap the shared store to the persona active at `now_unix`.
    pub fn apply(&self, now_unix: u64) {
        let idx = flux_index(now_unix, self.period.as_secs(), self.pool.len());
        self.shared.swap(self.pool.variant(idx));
    }

    /// Time until the next rotation boundary after `now_unix`.
    pub fn next_delay(&self, now_unix: u64) -> Duration {
        next_boundary_delay(now_unix, self.period.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tag: &str) -> Arc<BannerStore> {
        Arc::new(BannerStore::from_text(&format!("80 = {tag}\\r\\n\n* = X\\r\\n")).unwrap())
    }

    #[test]
    fn flux_index_buckets_and_wraps() {
        // period 100s, 3 variants
        assert_eq!(flux_index(0, 100, 3), 0);
        assert_eq!(flux_index(99, 100, 3), 0);
        assert_eq!(flux_index(100, 100, 3), 1);
        assert_eq!(flux_index(250, 100, 3), 2);
        assert_eq!(flux_index(300, 100, 3), 0); // wraps
        assert_eq!(flux_index(12345, 100, 1), 0); // single variant always 0
    }

    #[test]
    fn flux_index_defensive_zeros_do_not_panic() {
        assert_eq!(flux_index(50, 0, 3), flux_index(50, 1, 3)); // period 0 -> treated as 1
        assert_eq!(flux_index(50, 100, 0), 0); // pool 0 -> 0, no modulo panic
    }

    #[test]
    fn next_boundary_delay_never_zero_at_boundary() {
        assert_eq!(next_boundary_delay(0, 100), Duration::from_secs(100));
        assert_eq!(next_boundary_delay(30, 100), Duration::from_secs(70));
        assert_eq!(next_boundary_delay(100, 100), Duration::from_secs(100)); // boundary -> full period
        assert_eq!(next_boundary_delay(199, 100), Duration::from_secs(1));
    }

    #[test]
    fn pool_new_rejects_empty_and_indexes_with_wrap() {
        assert!(BannerPool::new(vec![]).is_none());
        let pool = BannerPool::new(vec![store("a"), store("b")]).unwrap();
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.variant(0).banner_for(80), b"a\r\n");
        assert_eq!(pool.variant(1).banner_for(80), b"b\r\n");
        assert_eq!(pool.variant(2).banner_for(80), b"a\r\n"); // wraps
    }

    #[test]
    fn flux_seeded_serves_current_and_apply_swaps() {
        let pool = BannerPool::new(vec![store("a"), store("b")]).unwrap();
        // period 100s, now=0 -> index 0 -> "a"
        let flux = BannerFlux::seeded(pool, Duration::from_secs(100), 0);
        let shared = flux.shared();
        assert_eq!(shared.current().banner_for(80), b"a\r\n");
        // advance into bucket 1 -> "b"
        flux.apply(150);
        assert_eq!(shared.current().banner_for(80), b"b\r\n");
        assert_eq!(flux.next_delay(150), Duration::from_secs(50));
    }
}
