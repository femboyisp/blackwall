//! Pure throughput and aggregation math.

use std::time::Duration;

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
/// mean. `None` for an empty slice.
pub fn trimmed_mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    if values.len() < 3 {
        let sum: f64 = values.iter().sum();
        #[expect(
            clippy::cast_precision_loss,
            reason = "slice length is a small sample \
            count, well within f64's exact-integer range"
        )]
        return Some(sum / (values.len() as f64));
    }
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let trimmed = &sorted[1..sorted.len() - 1];
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
}
