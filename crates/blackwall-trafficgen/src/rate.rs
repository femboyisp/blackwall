//! Pure pacing math: how many frames are due by a given elapsed time, and when
//! a run is finished. No sleeping happens here — the thin send loop does that.

use std::time::Duration;

/// A target send rate.
#[derive(Debug, Clone, Copy)]
pub enum Rate {
    /// Packets per second.
    Pps(u64),
    /// Bits per second, converted to pps using a representative frame size.
    Bps {
        /// Target bitrate in bits per second.
        bits_per_sec: u64,
        /// Representative on-wire frame size in bytes.
        frame_bytes: u64,
    },
}

/// When a run stops.
#[derive(Debug, Clone, Copy)]
pub enum Bound {
    /// Stop after this much wall-clock time.
    Duration(Duration),
    /// Stop after this many frames.
    Count(u64),
}

/// A rate + a stop condition.
#[derive(Debug, Clone, Copy)]
pub struct RatePlan {
    rate: Rate,
    bound: Bound,
}

impl RatePlan {
    /// Construct a plan.
    #[must_use]
    pub fn new(rate: Rate, bound: Bound) -> Self {
        Self { rate, bound }
    }

    /// The effective packets-per-second target.
    #[must_use]
    pub fn target_pps(&self) -> u64 {
        match self.rate {
            Rate::Pps(p) => p,
            Rate::Bps {
                bits_per_sec,
                frame_bytes,
            } => {
                let bits_per_frame = frame_bytes.saturating_mul(8).max(1);
                bits_per_sec / bits_per_frame
            }
        }
    }

    /// Frames that should be sent by `elapsed`, minus `already_sent`, clamped to
    /// any remaining count bound.
    #[must_use]
    pub fn due(&self, elapsed: Duration, already_sent: u64) -> u64 {
        let target_total = self.target_pps().saturating_mul(u64::from(
            u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX),
        )) / 1000;
        let mut due = target_total.saturating_sub(already_sent);
        if let Bound::Count(c) = self.bound {
            due = due.min(c.saturating_sub(already_sent));
        }
        due
    }

    /// Whether the run is complete at `elapsed` / `already_sent`.
    #[must_use]
    pub fn finished(&self, elapsed: Duration, already_sent: u64) -> bool {
        match self.bound {
            Bound::Duration(d) => elapsed >= d,
            Bound::Count(c) => already_sent >= c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pps_due_is_rate_times_elapsed() {
        let plan = RatePlan::new(Rate::Pps(1000), Bound::Duration(Duration::from_secs(5)));
        assert_eq!(plan.due(Duration::from_secs(1), 0), 1000);
        assert_eq!(plan.due(Duration::from_millis(1500), 1000), 500);
    }

    #[test]
    fn bps_converts_to_pps_via_frame_size() {
        // 8000 bits/s / (100 bytes * 8 bits) = 10 pps.
        let plan = RatePlan::new(
            Rate::Bps {
                bits_per_sec: 8000,
                frame_bytes: 100,
            },
            Bound::Duration(Duration::from_secs(1)),
        );
        assert_eq!(plan.target_pps(), 10);
        assert_eq!(plan.due(Duration::from_secs(1), 0), 10);
    }

    #[test]
    fn duration_bound_finishes_after_elapsed() {
        let plan = RatePlan::new(Rate::Pps(10), Bound::Duration(Duration::from_secs(2)));
        assert!(!plan.finished(Duration::from_secs(1), 5));
        assert!(plan.finished(Duration::from_secs(2), 20));
    }

    #[test]
    fn count_bound_finishes_after_count() {
        let plan = RatePlan::new(Rate::Pps(10), Bound::Count(100));
        assert!(!plan.finished(Duration::from_secs(1), 50));
        assert!(plan.finished(Duration::from_secs(1), 100));
        // due never exceeds the remaining count.
        assert_eq!(plan.due(Duration::from_secs(1000), 95), 5);
    }
}
