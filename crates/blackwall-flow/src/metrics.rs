//! Live counters for the flow collector, shared with the metrics endpoint.
//!
//! The collector increments these atomics as datagrams arrive and decodes
//! fail; the metrics server reads them at scrape time. Kept out of the
//! coverage-excluded `collector_net.rs` so the accessors stay covered.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters describing collector throughput and decode health.
///
/// Shared via `Arc` between the collector task (which increments) and the
/// metrics scrape (which reads). All operations use `Relaxed` ordering: the
/// values are independent monotonic counters with no cross-counter invariant.
#[derive(Debug, Default)]
pub struct CollectorMetrics {
    datagrams: AtomicU64,
    decode_errors: AtomicU64,
}

impl CollectorMetrics {
    /// Create a fresh set of counters, all zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total sFlow datagrams successfully received by the collector.
    #[must_use]
    pub fn datagrams(&self) -> u64 {
        self.datagrams.load(Ordering::Relaxed)
    }

    /// Total datagrams that failed to decode and were skipped.
    #[must_use]
    pub fn decode_errors(&self) -> u64 {
        self.decode_errors.load(Ordering::Relaxed)
    }

    /// Record one successfully received datagram.
    pub fn incr_datagrams(&self) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one datagram that failed to decode.
    pub fn incr_decode_errors(&self) {
        self.decode_errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::CollectorMetrics;

    #[test]
    fn new_is_zero() {
        let m = CollectorMetrics::new();
        assert_eq!(m.datagrams(), 0);
        assert_eq!(m.decode_errors(), 0);
    }

    #[test]
    fn increment_bumps_counters() {
        let m = CollectorMetrics::new();
        m.incr_datagrams();
        m.incr_datagrams();
        m.incr_decode_errors();
        assert_eq!(m.datagrams(), 2);
        assert_eq!(m.decode_errors(), 1);
    }

    #[test]
    fn default_matches_new() {
        let m = CollectorMetrics::default();
        assert_eq!(m.datagrams(), 0);
        assert_eq!(m.decode_errors(), 0);
    }
}
