//! Run multiple providers concurrently and aggregate, tolerating failures.

use crate::aggregate::aggregate;
use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::{Aggregate, ProviderReading};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// A set of providers run together.
pub struct Speedtest {
    providers: Vec<Arc<dyn SpeedtestProvider>>,
}

impl Speedtest {
    /// Build a runner over `providers`.
    pub fn new(providers: Vec<Arc<dyn SpeedtestProvider>>) -> Self {
        Speedtest { providers }
    }

    /// Measure with every provider (sequentially by default; see
    /// [`SpeedtestConfig::concurrency`]) and aggregate the successes.
    /// Per-provider errors and timeouts are logged and skipped; the run fails
    /// only if no provider produced a reading.
    ///
    /// Runs in two phases: an **unloaded idle-latency phase** (each provider's
    /// [`measure_latency`](SpeedtestProvider::measure_latency), no downloads
    /// anywhere) completes fully before the **throughput phase**
    /// ([`measure`](SpeedtestProvider::measure)). The idle latency, where
    /// available, replaces the loaded latency in each reading, so latency
    /// reflects RTT rather than bufferbloat under a saturated link.
    pub async fn run(&self, cfg: &SpeedtestConfig) -> Result<Aggregate, SpeedtestError> {
        // Phase 1: idle latency, with nothing else transferring.
        let idle = self.measure_idle_latency(cfg).await;

        // Phase 2: throughput (this saturates the link).
        let permits = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
        let mut handles = Vec::new();
        for provider in &self.providers {
            let provider = provider.clone();
            let permits = permits.clone();
            let cfg = *cfg;
            handles.push(tokio::spawn(async move {
                let _permit = permits.acquire_owned().await.ok()?;
                match tokio::time::timeout(cfg.timeout, provider.measure(&cfg)).await {
                    Ok(Ok(reading)) => Some(reading),
                    Ok(Err(err)) => {
                        tracing::debug!(provider = provider.name(), %err, "provider failed");
                        None
                    }
                    Err(_) => {
                        tracing::debug!(provider = provider.name(), "provider timed out");
                        None
                    }
                }
            }));
        }

        let mut readings: Vec<ProviderReading> = Vec::new();
        for handle in handles {
            if let Ok(Some(mut reading)) = handle.await {
                // Prefer the unloaded idle latency over the loaded figure.
                if let Some(&idle_ms) = idle.get(&reading.provider) {
                    reading.latency_ms = idle_ms;
                }
                readings.push(reading);
            }
        }
        aggregate(readings).ok_or(SpeedtestError::NoResult)
    }

    /// Phase 1: probe each provider's idle RTT with no throughput load. Returns
    /// a map from provider name to idle latency (ms) for providers that could
    /// probe. The whole phase completes before any throughput starts.
    async fn measure_idle_latency(
        &self,
        cfg: &SpeedtestConfig,
    ) -> std::collections::HashMap<String, f64> {
        let permits = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
        let mut handles = Vec::new();
        for provider in &self.providers {
            let provider = provider.clone();
            let permits = permits.clone();
            let cfg = *cfg;
            handles.push(tokio::spawn(async move {
                let _permit = permits.acquire_owned().await.ok()?;
                let latency = tokio::time::timeout(cfg.timeout, provider.measure_latency(&cfg))
                    .await
                    .ok()
                    .flatten()?;
                Some((provider.name().to_owned(), latency))
            }));
        }
        let mut idle = std::collections::HashMap::new();
        for handle in handles {
            if let Ok(Some((name, latency))) = handle.await {
                idle.insert(name, latency);
            }
        }
        idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reading::ProviderReading;
    use async_trait::async_trait;
    use std::time::Duration;

    struct Ok1(&'static str, f64);
    #[async_trait]
    impl SpeedtestProvider for Ok1 {
        fn name(&self) -> &str {
            self.0
        }
        async fn measure(&self, _: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
            Ok(ProviderReading {
                provider: self.0.to_owned(),
                download_mbps: self.1,
                upload_mbps: None,
                latency_ms: 10.0,
            })
        }
    }

    struct Boom;
    #[async_trait]
    impl SpeedtestProvider for Boom {
        fn name(&self) -> &str {
            "boom"
        }
        async fn measure(&self, _: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
            Err(SpeedtestError::Http("nope".to_owned()))
        }
    }

    struct Slow;
    #[async_trait]
    impl SpeedtestProvider for Slow {
        fn name(&self) -> &str {
            "slow"
        }
        async fn measure(&self, _: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
            tokio::time::sleep(Duration::from_secs(60)).await;
            unreachable!()
        }
    }

    #[tokio::test]
    async fn aggregates_successes_ignoring_failures_and_timeouts() {
        let cfg = SpeedtestConfig {
            timeout: Duration::from_millis(50),
            ..SpeedtestConfig::default()
        };
        let st = Speedtest::new(vec![
            Arc::new(Ok1("a", 900.0)),
            Arc::new(Ok1("b", 800.0)),
            Arc::new(Boom),
            Arc::new(Slow),
        ]);
        let agg = st.run(&cfg).await.unwrap();
        assert_eq!(agg.samples, 2); // only the two Ok providers
    }

    #[tokio::test]
    async fn no_successes_is_error() {
        let st = Speedtest::new(vec![Arc::new(Boom)]);
        let err = st.run(&SpeedtestConfig::default()).await.unwrap_err();
        assert!(matches!(err, SpeedtestError::NoResult));
    }

    /// A provider reporting a high (loaded) latency but a low idle-phase latency
    /// should have the idle value substituted into the aggregate.
    struct LoadedButIdle;
    #[async_trait]
    impl SpeedtestProvider for LoadedButIdle {
        fn name(&self) -> &str {
            "loaded-idle"
        }
        async fn measure(&self, _: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
            Ok(ProviderReading {
                provider: "loaded-idle".to_owned(),
                download_mbps: 500.0,
                upload_mbps: None,
                latency_ms: 999.0, // bufferbloat-inflated, loaded
            })
        }
        async fn measure_latency(&self, _: &SpeedtestConfig) -> Option<f64> {
            Some(5.0) // true idle RTT
        }
    }

    #[tokio::test]
    async fn idle_latency_replaces_loaded_latency() {
        let st = Speedtest::new(vec![Arc::new(LoadedButIdle)]);
        let agg = st.run(&SpeedtestConfig::default()).await.unwrap();
        assert!(
            (agg.latency_ms - 5.0).abs() < f64::EPSILON,
            "expected idle 5.0, got {}",
            agg.latency_ms
        );
    }

    /// A provider that cannot probe idle latency keeps its loaded figure.
    #[tokio::test]
    async fn loaded_latency_kept_when_no_idle_probe() {
        // Ok1 uses the default measure_latency (None) and reports 10.0.
        let st = Speedtest::new(vec![Arc::new(Ok1("only", 700.0))]);
        let agg = st.run(&SpeedtestConfig::default()).await.unwrap();
        assert!((agg.latency_ms - 10.0).abs() < f64::EPSILON);
    }
}
