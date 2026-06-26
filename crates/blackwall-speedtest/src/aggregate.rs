//! Combine per-provider readings into a single result that reflects the link.

use crate::reading::{Aggregate, ProviderReading};
use crate::throughput::{max_finite, min_finite};

/// Aggregate `readings` into a link estimate: the best (fastest) clean download
/// and upload, and the lowest latency. The fastest provider best reflects the
/// link itself — slower providers are limited by distant servers, not the link.
/// Upload is selected only over the providers that reported it. Non-finite
/// readings are ignored. Returns `None` for no readings (or no finite
/// download/latency).
pub fn aggregate(readings: Vec<ProviderReading>) -> Option<Aggregate> {
    if readings.is_empty() {
        return None;
    }
    let downloads: Vec<f64> = readings.iter().map(|r| r.download_mbps).collect();
    let latencies: Vec<f64> = readings.iter().map(|r| r.latency_ms).collect();
    let uploads: Vec<f64> = readings.iter().filter_map(|r| r.upload_mbps).collect();

    Some(Aggregate {
        download_mbps: max_finite(&downloads)?,
        latency_ms: min_finite(&latencies)?,
        upload_mbps: max_finite(&uploads),
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
    fn aggregates_best_download_and_lowest_latency() {
        let agg = aggregate(vec![
            reading("a", 456.0, None, 53.0),
            reading("b", 165.0, None, 267.0),
            reading("c", 207.0, None, 115.0),
            reading("d", 506.0, None, 10.0),
        ])
        .unwrap();
        assert_eq!(agg.download_mbps, 506.0); // best
        assert_eq!(agg.latency_ms, 10.0); // lowest
        assert_eq!(agg.samples, 4);
        assert_eq!(agg.upload_mbps, None);
    }

    #[test]
    fn upload_is_best_over_reporting_providers() {
        let agg = aggregate(vec![
            reading("a", 900.0, Some(100.0), 10.0),
            reading("b", 800.0, Some(250.0), 11.0),
            reading("c", 700.0, None, 12.0),
        ])
        .unwrap();
        assert_eq!(agg.upload_mbps, Some(250.0)); // best upload
    }

    #[test]
    fn empty_is_none() {
        assert!(aggregate(vec![]).is_none());
    }

    #[test]
    fn one_nan_reading_does_not_poison_aggregate() {
        let agg = aggregate(vec![
            reading("a", 900.0, None, 10.0),
            reading("b", f64::NAN, None, f64::NAN),
            reading("c", 800.0, None, 12.0),
        ])
        .unwrap();
        assert_eq!(agg.download_mbps, 900.0);
        assert_eq!(agg.latency_ms, 10.0);
    }
}
