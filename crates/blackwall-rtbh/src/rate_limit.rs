//! Cross-plane rate cap on new mitigations (C6).
//!
//! `max_blackholes`/`max_rules` bound the *steady-state* size of the active
//! set, but neither bounds how fast new entries can arrive: a detection
//! storm (or a bug feeding the detector garbage) can walk either cap up to
//! its ceiling within seconds, mass-blackholing legitimate destinations
//! before an operator can react. [`ArmingRateLimiter`] is a safety ceiling on
//! the *arrival rate* of NEW mitigations (BGP `Announce`s) — orthogonal to,
//! and layered underneath, the existing per-plane count caps.

use std::collections::VecDeque;

/// Width of the sliding window, in milliseconds.
const WINDOW_MS: u64 = 60_000;

/// A sliding 60-second-window rate limiter over new-mitigation timestamps.
///
/// Pure and deterministic: callers pass `now_ms` explicitly rather than the
/// limiter reading the clock itself, so it is unit-testable without real
/// time and reusable across both the RTBH and FlowSpec managers (a single
/// shared instance, behind an `Arc<Mutex<_>>`, governs the combined
/// cross-plane announce rate — see `blackwall_rtbh::manager::RtbhManager`'s
/// and `blackwall_rtbh::flowspec_manager::FlowSpecManager`'s
/// `with_rate_limiter`).
#[derive(Debug)]
pub struct ArmingRateLimiter {
    max_per_min: u32,
    /// Timestamps of admitted announces still inside the trailing window,
    /// oldest first.
    window: VecDeque<u64>,
}

impl ArmingRateLimiter {
    /// A limiter admitting at most `max_per_min` new announces in any
    /// trailing 60_000 ms window.
    #[must_use]
    pub fn new(max_per_min: u32) -> Self {
        Self {
            max_per_min,
            window: VecDeque::new(),
        }
    }

    /// Attempt to admit one new-mitigation announce at `now_ms`.
    ///
    /// Drops timestamps that have aged out of the trailing 60_000 ms window,
    /// then admits (and records) the attempt iff fewer than `max_per_min`
    /// remain; otherwise rejects without recording, so a rejected attempt
    /// never itself counts toward the window.
    pub fn try_acquire(&mut self, now_ms: u64) -> bool {
        let window_start = now_ms.saturating_sub(WINDOW_MS);
        while let Some(&oldest) = self.window.front() {
            if oldest < window_start {
                self.window.pop_front();
            } else {
                break;
            }
        }
        let in_window = u32::try_from(self.window.len()).unwrap_or(u32::MAX);
        if in_window < self.max_per_min {
            self.window.push_back(now_ms);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_cap_rejects_excess_in_window_and_refills() {
        let mut lim = ArmingRateLimiter::new(2); // 2 per minute
        assert!(lim.try_acquire(1_000));
        assert!(lim.try_acquire(1_500));
        assert!(!lim.try_acquire(2_000), "3rd in-window is rejected");
        // 61s later the window has rolled:
        assert!(lim.try_acquire(63_000));
    }

    #[test]
    fn zero_max_rejects_everything() {
        let mut lim = ArmingRateLimiter::new(0);
        assert!(!lim.try_acquire(1_000));
        assert!(!lim.try_acquire(100_000));
    }

    #[test]
    fn rejected_attempt_is_not_recorded() {
        // A rejected attempt must not itself occupy a window slot — otherwise
        // a burst of rejects could wedge the limiter shut even after room
        // frees up within the same window.
        let mut lim = ArmingRateLimiter::new(1);
        assert!(lim.try_acquire(0));
        assert!(!lim.try_acquire(100));
        assert!(!lim.try_acquire(200));
        // Still only the first (admitted) timestamp counts; once it ages out
        // of the window (60_000 ms is still exactly in-window; 60_001 is
        // not), capacity returns.
        assert!(!lim.try_acquire(60_000));
        assert!(lim.try_acquire(60_001));
    }

    #[test]
    fn independent_windows_do_not_interfere() {
        let mut lim = ArmingRateLimiter::new(1);
        assert!(lim.try_acquire(0));
        assert!(!lim.try_acquire(30_000), "still inside the first window");
        assert!(lim.try_acquire(60_001), "window has fully rolled");
        assert!(!lim.try_acquire(90_000), "back inside the new window");
    }
}
