//! Pure throughput and aggregation math.

use std::time::Duration;

/// Whether a download measurement should keep reading: stop once either the
/// byte cap is reached or the measurement window has elapsed.
pub fn keep_downloading(
    received: u64,
    max_bytes: u64,
    elapsed: Duration,
    window: Duration,
) -> bool {
    received < max_bytes && elapsed < window
}

/// Megabits per second from `bytes` transferred over `elapsed`.
/// Returns `0.0` when `elapsed` is zero (avoids division by zero).
pub fn mbps_from(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    // bytes -> bits -> megabits, per second. f64 from u64 is lossless for the
    // byte counts speedtests realistically transfer.
    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counts transferred in a \
        speedtest are well within f64's 2^53 exact-integer range"
    )]
    let bits = (bytes as f64) * 8.0;
    bits / 1_000_000.0 / secs
}

/// The largest finite value in `values`, or `None` if none are finite.
pub fn max_finite(values: &[f64]) -> Option<f64> {
    values
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.max(v))))
}

/// The smallest finite value in `values`, or `None` if none are finite.
pub fn min_finite(values: &[f64]) -> Option<f64> {
    values
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.min(v))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_downloading_stops_on_cap_or_window() {
        let secs = |s| Duration::from_secs(s);
        // under both limits → keep going
        assert!(keep_downloading(100, 1000, secs(1), secs(10)));
        // received >= max_bytes → stop
        assert!(!keep_downloading(1000, 1000, secs(1), secs(10)));
        assert!(!keep_downloading(1001, 1000, secs(1), secs(10)));
        // elapsed >= window → stop
        assert!(!keep_downloading(100, 1000, secs(10), secs(10)));
        assert!(!keep_downloading(100, 1000, secs(11), secs(10)));
    }

    #[test]
    fn mbps_basic() {
        // 12.5 MB in 1s = 100 Mbit/s.
        let v = mbps_from(12_500_000, Duration::from_secs(1));
        assert!((v - 100.0).abs() < 0.001);
    }

    #[test]
    fn mbps_zero_duration_is_zero() {
        assert_eq!(mbps_from(1000, Duration::from_secs(0)), 0.0);
    }

    #[test]
    fn max_finite_picks_largest_ignoring_non_finite() {
        assert_eq!(max_finite(&[100.0, 500.0, 200.0]), Some(500.0));
        assert_eq!(
            max_finite(&[100.0, f64::NAN, f64::INFINITY, 300.0]),
            Some(300.0)
        );
        assert_eq!(max_finite(&[f64::NAN, f64::INFINITY]), None);
        assert_eq!(max_finite(&[]), None);
    }

    #[test]
    fn min_finite_picks_smallest_ignoring_non_finite() {
        assert_eq!(min_finite(&[100.0, 20.0, 200.0]), Some(20.0));
        assert_eq!(min_finite(&[f64::NAN, 50.0, f64::NEG_INFINITY]), Some(50.0));
        assert_eq!(min_finite(&[f64::NAN]), None);
    }
}
