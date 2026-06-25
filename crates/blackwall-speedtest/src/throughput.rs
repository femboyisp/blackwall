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

/// Trimmed mean: drop one minimum and one maximum when there are at least three
/// values (rejecting a single wild outlier on each side), otherwise the plain
/// mean. `None` for an empty slice. Non-finite values (`NaN`, `±inf`) are
/// discarded before trimming.
pub fn trimmed_mean(values: &[f64]) -> Option<f64> {
    let mut finite: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if finite.is_empty() {
        return None;
    }
    if finite.len() < 3 {
        let sum: f64 = finite.iter().sum();
        #[expect(
            clippy::cast_precision_loss,
            reason = "slice length is a small sample \
            count, well within f64's exact-integer range"
        )]
        return Some(sum / (finite.len() as f64));
    }
    finite.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trimmed = &finite[1..finite.len() - 1];
    let sum: f64 = trimmed.iter().sum();
    #[expect(
        clippy::cast_precision_loss,
        reason = "trimmed slice length is a small \
        sample count, well within f64's exact-integer range"
    )]
    Some(sum / (trimmed.len() as f64))
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
    fn trimmed_mean_drops_extremes() {
        // [50, 870, 905, 920] -> drop 50 and 920 -> mean(870, 905) = 887.5
        let v = trimmed_mean(&[920.0, 50.0, 870.0, 905.0]).unwrap();
        assert!((v - 887.5).abs() < 0.001);
    }

    #[test]
    fn trimmed_mean_small_inputs() {
        assert_eq!(trimmed_mean(&[]), None);
        assert_eq!(trimmed_mean(&[100.0]), Some(100.0));
        assert_eq!(trimmed_mean(&[100.0, 200.0]), Some(150.0));
    }

    #[test]
    fn trimmed_mean_discards_non_finite() {
        // NaN and inf are dropped before trimming.
        let v = trimmed_mean(&[900.0, f64::NAN, 50.0, 870.0, f64::INFINITY]).unwrap();
        assert!(v.is_finite());
        // all non-finite -> None
        assert_eq!(trimmed_mean(&[f64::NAN, f64::INFINITY]), None);
    }
}
