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
    sample_decode_errors: AtomicU64,
    unknown_agent_observations: AtomicU64,
    min_sample_suppressed: AtomicU64,
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

    /// Total individual flow/counter *samples* (within an otherwise-decoded
    /// datagram) that failed to decode and were skipped.
    ///
    /// Distinct from [`Self::decode_errors`]: that counter tracks whole
    /// datagrams whose envelope framing was unreadable (discarding every
    /// observation in the datagram), while this one tracks samples inside a
    /// datagram whose envelope decoded fine — e.g. hsflowd batches many flow
    /// samples per datagram, and one malformed sample no longer discards the
    /// rest. Keeping the two separate lets an operator tell "this POP is
    /// sending malformed datagrams" (`decode_errors`) apart from "this POP is
    /// dropping/corrupting individual samples" (`sample_decode_errors`).
    #[must_use]
    pub fn sample_decode_errors(&self) -> u64 {
        self.sample_decode_errors.load(Ordering::Relaxed)
    }

    /// Record one sample that failed to decode within an otherwise-valid
    /// datagram. See [`Self::sample_decode_errors`].
    pub fn incr_sample_decode_errors(&self) {
        self.sample_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Total sample observations attributed to agents absent from the POP
    /// registry (`Detector::unknown_agent_observations`).
    #[must_use]
    pub fn unknown_agent_observations(&self) -> u64 {
        self.unknown_agent_observations.load(Ordering::Relaxed)
    }

    /// Publish the detector's current cumulative unknown-agent observation
    /// count. Unlike `incr_datagrams`/`incr_decode_errors`, which increment
    /// once per event as the collector observes it, this counter mirrors a
    /// total the detector already accumulates internally
    /// (`Detector::unknown_agent_observations`), so the collector calls this
    /// once per tick with that total rather than incrementing per datagram
    /// (which would double count).
    pub fn set_unknown_agent_observations(&self, value: u64) {
        self.unknown_agent_observations
            .store(value, Ordering::Relaxed);
    }

    /// Total detections suppressed solely by the detector's minimum-sample
    /// gate (`Detector::min_sample_suppressed`).
    #[must_use]
    pub fn min_sample_suppressed(&self) -> u64 {
        self.min_sample_suppressed.load(Ordering::Relaxed)
    }

    /// Publish the detector's current cumulative minimum-sample-suppressed
    /// count. Mirrors [`Self::set_unknown_agent_observations`]: the detector
    /// already accumulates this total internally
    /// (`Detector::min_sample_suppressed`), so the collector calls this once
    /// per tick with that total rather than incrementing per event.
    pub fn set_min_sample_suppressed(&self, value: u64) {
        self.min_sample_suppressed.store(value, Ordering::Relaxed);
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
        assert_eq!(m.sample_decode_errors(), 0);
        assert_eq!(m.unknown_agent_observations(), 0);
        assert_eq!(m.min_sample_suppressed(), 0);
    }

    #[test]
    fn set_min_sample_suppressed_overwrites_rather_than_accumulates() {
        let m = CollectorMetrics::new();
        m.set_min_sample_suppressed(3);
        assert_eq!(m.min_sample_suppressed(), 3);
        m.set_min_sample_suppressed(5);
        assert_eq!(m.min_sample_suppressed(), 5);
    }

    #[test]
    fn set_unknown_agent_observations_overwrites_rather_than_accumulates() {
        let m = CollectorMetrics::new();
        m.set_unknown_agent_observations(3);
        assert_eq!(m.unknown_agent_observations(), 3);
        // A later tick with a lower or higher cumulative total simply overwrites.
        m.set_unknown_agent_observations(5);
        assert_eq!(m.unknown_agent_observations(), 5);
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
    fn incr_sample_decode_errors_is_distinct_from_decode_errors() {
        let m = CollectorMetrics::new();
        m.incr_decode_errors();
        m.incr_sample_decode_errors();
        m.incr_sample_decode_errors();
        m.incr_sample_decode_errors();
        assert_eq!(m.decode_errors(), 1, "per-datagram counter unaffected");
        assert_eq!(m.sample_decode_errors(), 3);
    }

    #[test]
    fn default_matches_new() {
        let m = CollectorMetrics::default();
        assert_eq!(m.datagrams(), 0);
        assert_eq!(m.decode_errors(), 0);
    }
}
