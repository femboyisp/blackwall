//! Combine per-provider readings into a single robust result.

use crate::reading::{Aggregate, ProviderReading};
use crate::throughput::trimmed_mean;

/// Aggregate `readings` with a trimmed mean per metric. Upload is aggregated
/// over only the providers that reported it. Returns `None` for no readings.
pub fn aggregate(readings: Vec<ProviderReading>) -> Option<Aggregate> {
    if readings.is_empty() {
        return None;
    }
    let downloads: Vec<f64> = readings.iter().map(|r| r.download_mbps).collect();
    let latencies: Vec<f64> = readings.iter().map(|r| r.latency_ms).collect();
    let uploads: Vec<f64> = readings.iter().filter_map(|r| r.upload_mbps).collect();

    Some(Aggregate {
        download_mbps: trimmed_mean(&downloads)?,
        latency_ms: trimmed_mean(&latencies)?,
        upload_mbps: trimmed_mean(&uploads),
        samples: readings.len(),
        readings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(name: &str, dl: f64, ul: Option<f64>, lat: f64) -> ProviderReading {
        ProviderReading {
            provider: name.to_owned(),
            download_mbps: dl,
            upload_mbps: ul,
            latency_ms: lat,
        }
    }

    #[test]
    fn aggregates_download_with_trimming() {
        let agg = aggregate(vec![
            reading("a", 920.0, None, 11.0),
            reading("b", 50.0, None, 99.0),
            reading("c", 870.0, None, 12.0),
            reading("d", 905.0, None, 13.0),
        ])
        .unwrap();
        assert!((agg.download_mbps - 887.5).abs() < 0.001);
        assert_eq!(agg.samples, 4);
        assert_eq!(agg.upload_mbps, None);
    }

    #[test]
    fn upload_only_over_reporting_providers() {
        let agg = aggregate(vec![
            reading("a", 900.0, Some(100.0), 10.0),
            reading("b", 800.0, None, 11.0),
        ])
        .unwrap();
        // Only one upload reported -> plain mean of [100.0].
        assert_eq!(agg.upload_mbps, Some(100.0));
    }

    #[test]
    fn empty_is_none() {
        assert!(aggregate(vec![]).is_none());
    }
}
