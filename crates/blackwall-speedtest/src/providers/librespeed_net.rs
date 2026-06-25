//! LibreSpeed network provider — thin reqwest wrapper; coverage-excluded.
//!
//! All parsing and URL building lives in [`super::librespeed_parse`].

use async_trait::async_trait;
use futures_util::StreamExt;
use std::time::Instant;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::throughput::mbps_from;

use super::librespeed_parse::{download_url, ping_url};

/// Speedtest provider backed by a self-hosted LibreSpeed instance.
pub struct LibreSpeedProvider {
    client: reqwest::Client,
    server: String,
}

impl LibreSpeedProvider {
    /// Create a new [`LibreSpeedProvider`] pointed at `server`.
    pub fn new(server: impl Into<String>) -> Self {
        LibreSpeedProvider {
            client: reqwest::Client::new(),
            server: server.into(),
        }
    }
}

#[async_trait]
impl SpeedtestProvider for LibreSpeedProvider {
    fn name(&self) -> &str {
        "librespeed"
    }

    /// Measure download throughput and latency via a LibreSpeed server.
    ///
    /// Latency is the round-trip time to `empty.php`. Download is timed
    /// against `garbage.php` and capped at `cfg.max_bytes`; the stream is
    /// dropped as soon as enough bytes have been received so that a large or
    /// misbehaving server cannot push unbounded data.
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
        // Ping for latency.
        let ping = ping_url(&self.server);
        let ping_start = Instant::now();
        self.client
            .get(&ping)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;
        let latency_ms = ping_start.elapsed().as_secs_f64() * 1000.0;

        // Download for throughput — stream and stop at the cap.
        let dl = download_url(&self.server);
        let dl_start = Instant::now();
        let resp = self
            .client
            .get(&dl)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        let cap = cfg.max_bytes;
        let mut received: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| SpeedtestError::Http(e.to_string()))?;
            received += u64::try_from(chunk.len()).unwrap_or(0);
            if received >= cap {
                break;
            }
        }
        let elapsed = dl_start.elapsed();

        let download_mbps = mbps_from(received.min(cap), elapsed);

        Ok(ProviderReading {
            provider: self.name().to_owned(),
            download_mbps,
            upload_mbps: None,
            latency_ms,
        })
    }
}
