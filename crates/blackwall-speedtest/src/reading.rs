//! Per-provider readings and the aggregated result.

use serde::{Deserialize, Serialize};

/// One provider's measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderReading {
    /// Short provider name (e.g. `"cloudflare"`).
    pub provider: String,
    /// Download throughput in megabits per second.
    pub download_mbps: f64,
    /// Upload throughput in megabits per second, if the provider measured it.
    pub upload_mbps: Option<f64>,
    /// Round-trip latency in milliseconds.
    pub latency_ms: f64,
}

/// The aggregate across all successful provider readings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Aggregate {
    /// Aggregated download throughput (Mbps).
    pub download_mbps: f64,
    /// Aggregated upload throughput (Mbps), if any provider measured upload.
    pub upload_mbps: Option<f64>,
    /// Aggregated latency (ms).
    pub latency_ms: f64,
    /// How many provider readings contributed.
    pub samples: usize,
    /// The individual readings that were aggregated.
    pub readings: Vec<ProviderReading>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_round_trips_through_json() {
        let r = ProviderReading {
            provider: "cloudflare".to_owned(),
            download_mbps: 887.5,
            upload_mbps: Some(120.0),
            latency_ms: 12.3,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ProviderReading = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
