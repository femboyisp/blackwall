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
    ///
    /// Defaults to `1` (sequential) on purpose: every provider measures the
    /// *same* uplink, so running them at once makes them compete for bandwidth
    /// and each sees only its fraction of the link — badly under-reporting and
    /// giving wildly variable readings. One at a time, each measures the full,
    /// unshared link.
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
            concurrency: 1,
            measure_window: Duration::from_secs(10),
        }
    }
}

/// A source of throughput/latency measurements.
#[async_trait]
pub trait SpeedtestProvider: Send + Sync {
    /// Stable short name (e.g. `"cloudflare"`).
    fn name(&self) -> &str;
    /// Run one measurement (throughput + a latency figure).
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError>;
    /// Measure round-trip latency only, with **no throughput load**.
    ///
    /// The runner calls this in an unloaded phase *before* the (link-saturating)
    /// throughput phase and substitutes the result for the latency reported by
    /// [`measure`](Self::measure), which is otherwise measured on a saturated
    /// link and inflated by bufferbloat. Returns `None` if the provider cannot
    /// cheaply probe idle RTT; the runner then keeps the loaded figure.
    async fn measure_latency(&self, cfg: &SpeedtestConfig) -> Option<f64> {
        let _ = cfg;
        None
    }
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
    fn default_concurrency_is_sequential() {
        assert_eq!(SpeedtestConfig::default().concurrency, 1);
    }

    #[test]
    fn default_measure_window_is_10s() {
        let cfg = SpeedtestConfig::default();
        assert_eq!(cfg.measure_window, Duration::from_secs(10));
    }
}
