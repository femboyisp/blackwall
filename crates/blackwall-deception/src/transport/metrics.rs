//! Counters for the stateless SYN-cookie / UDP responder, shared with the
//! `/metrics` endpoint.
//!
//! Pure, dependency-free bookkeeping: the increments themselves happen in the
//! coverage-excluded NFQUEUE I/O loop (`super::nfqueue`), but the struct and
//! its increment helpers live here so they stay unit-testable.

use std::sync::atomic::{AtomicU64, Ordering};

/// Live counters for the stateless SYN-cookie / UDP responder.
///
/// Every field is an [`AtomicU64`] so a single shared `Arc<StatelessMetrics>`
/// can be incremented from the blocking NFQUEUE loop and read concurrently by
/// the `/metrics` scrape handler. Wraps at `u64::MAX`, which is not reachable
/// in practice at any sustained packet rate.
#[derive(Debug, Default)]
pub struct StatelessMetrics {
    /// SYN-ACKs sent in reply to a SYN on a stateless port (one per SYN).
    syn_cookies_sent: AtomicU64,
    /// Completing ACKs whose cookie validated and whose banner was served.
    acks_validated: AtomicU64,
    /// ACKs whose cookie failed validation (spoofed or stray).
    acks_rejected: AtomicU64,
    /// Stateless UDP responses sent.
    udp_responses: AtomicU64,
}

impl StatelessMetrics {
    /// A fresh set of counters, all zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a SYN-ACK sent for a stateless SYN.
    pub fn record_syn_cookie_sent(&self) {
        self.syn_cookies_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a completing ACK whose cookie validated (banner served).
    pub fn record_ack_validated(&self) {
        self.acks_validated.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an ACK whose cookie failed validation.
    pub fn record_ack_rejected(&self) {
        self.acks_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a stateless UDP response sent.
    pub fn record_udp_response(&self) {
        self.udp_responses.fetch_add(1, Ordering::Relaxed);
    }

    /// SYN-ACKs sent so far.
    #[must_use]
    pub fn syn_cookies_sent(&self) -> u64 {
        self.syn_cookies_sent.load(Ordering::Relaxed)
    }

    /// Completing ACKs validated so far.
    #[must_use]
    pub fn acks_validated(&self) -> u64 {
        self.acks_validated.load(Ordering::Relaxed)
    }

    /// ACKs rejected so far.
    #[must_use]
    pub fn acks_rejected(&self) -> u64 {
        self.acks_rejected.load(Ordering::Relaxed)
    }

    /// Stateless UDP responses sent so far.
    #[must_use]
    pub fn udp_responses(&self) -> u64 {
        self.udp_responses.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::StatelessMetrics;

    #[test]
    fn new_counters_start_at_zero() {
        let m = StatelessMetrics::new();
        assert_eq!(m.syn_cookies_sent(), 0);
        assert_eq!(m.acks_validated(), 0);
        assert_eq!(m.acks_rejected(), 0);
        assert_eq!(m.udp_responses(), 0);
    }

    #[test]
    fn default_is_equivalent_to_new() {
        let m = StatelessMetrics::default();
        assert_eq!(m.syn_cookies_sent(), 0);
    }

    #[test]
    fn record_syn_cookie_sent_bumps_only_that_counter() {
        let m = StatelessMetrics::new();
        m.record_syn_cookie_sent();
        m.record_syn_cookie_sent();
        assert_eq!(m.syn_cookies_sent(), 2);
        assert_eq!(m.acks_validated(), 0);
        assert_eq!(m.acks_rejected(), 0);
        assert_eq!(m.udp_responses(), 0);
    }

    #[test]
    fn record_ack_validated_bumps_only_that_counter() {
        let m = StatelessMetrics::new();
        m.record_ack_validated();
        assert_eq!(m.acks_validated(), 1);
        assert_eq!(m.syn_cookies_sent(), 0);
        assert_eq!(m.acks_rejected(), 0);
        assert_eq!(m.udp_responses(), 0);
    }

    #[test]
    fn record_ack_rejected_bumps_only_that_counter() {
        let m = StatelessMetrics::new();
        m.record_ack_rejected();
        assert_eq!(m.acks_rejected(), 1);
        assert_eq!(m.syn_cookies_sent(), 0);
        assert_eq!(m.acks_validated(), 0);
        assert_eq!(m.udp_responses(), 0);
    }

    #[test]
    fn record_udp_response_bumps_only_that_counter() {
        let m = StatelessMetrics::new();
        m.record_udp_response();
        m.record_udp_response();
        m.record_udp_response();
        assert_eq!(m.udp_responses(), 3);
        assert_eq!(m.syn_cookies_sent(), 0);
        assert_eq!(m.acks_validated(), 0);
        assert_eq!(m.acks_rejected(), 0);
    }
}
