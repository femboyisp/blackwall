//! The speedtest provider abstraction.

use crate::error::SpeedtestError;
use crate::reading::ProviderReading;
use async_trait::async_trait;
use std::time::Duration;

/// Tunables shared by all providers.
///
/// `measure_window` caps how long a single download measurement may run,
/// independent of `max_bytes`. Whichever limit is hit first stops the
/// transfer; throughput is then computed from bytes-received / elapsed.
/// This ensures a slow link yields a low reading rather than a timeout.
#[derive(Debug, Clone, Copy)]
pub struct SpeedtestConfig {
    /// Maximum bytes any single provider may transfer for a download test.
    pub max_bytes: u64,
    /// Per-provider timeout.
    pub timeout: Duration,
    /// Maximum providers to run concurrently.
    pub concurrency: usize,
    /// Maximum wall-clock time spent transferring data for one download
    /// measurement. The download stops at whichever comes first: this
    /// window or `max_bytes`. Throughput is bytes-received / elapsed.
    pub measure_window: Duration,
}

impl Default for SpeedtestConfig {
    fn default() -> Self {
        SpeedtestConfig {
            max_bytes: 100 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            concurrency: 4,
            measure_window: Duration::from_secs(10),
        }
    }
}

/// A source of throughput/latency measurements.
#[async_trait]
pub trait SpeedtestProvider: Send + Sync {
    /// Stable short name (e.g. `"cloudflare"`).
    fn name(&self) -> &str;
    /// Run one measurement.
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubProvider(&'static str, f64);
    #[async_trait]
    impl SpeedtestProvider for StubProvider {
        fn name(&self) -> &str {
            self.0
        }
        async fn measure(&self, _cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
            Ok(ProviderReading {
                provider: self.0.to_owned(),
                download_mbps: self.1,
                upload_mbps: None,
                latency_ms: 10.0,
            })
        }
    }

    #[tokio::test]
    async fn stub_measures() {
        let p = StubProvider("stub", 500.0);
        let r = p.measure(&SpeedtestConfig::default()).await.unwrap();
        assert_eq!(r.provider, "stub");
        assert_eq!(r.download_mbps, 500.0);
    }

    #[test]
    fn default_measure_window_is_10s() {
        let cfg = SpeedtestConfig::default();
        assert_eq!(cfg.measure_window, Duration::from_secs(10));
    }
}
