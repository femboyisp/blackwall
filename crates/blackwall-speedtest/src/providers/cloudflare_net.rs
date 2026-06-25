//! Cloudflare network provider — thin reqwest wrapper; coverage-excluded.
//!
//! All parsing and math lives in [`super::cloudflare_parse`].

use async_trait::async_trait;
use futures_util::StreamExt;
use std::time::Instant;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::throughput::{keep_downloading, mbps_from};

use super::cloudflare_parse::{download_url, server_timing_latency};

/// Maximum download size for a single Cloudflare measurement (25 MiB).
const MAX_CF_BYTES: u64 = 25 * 1024 * 1024;

/// Speedtest provider backed by `speed.cloudflare.com`.
pub struct CloudflareProvider {
    client: reqwest::Client,
}

impl CloudflareProvider {
    /// Create a new [`CloudflareProvider`] with a default [`reqwest::Client`].
    pub fn new() -> Self {
        CloudflareProvider {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for CloudflareProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpeedtestProvider for CloudflareProvider {
    fn name(&self) -> &str {
        "cloudflare"
    }

    /// Measure download throughput and latency via Cloudflare's speed endpoint.
    ///
    /// Download is capped at `min(cfg.max_bytes, 25 MiB)`. Latency is taken
    /// from the `Server-Timing` response header when present, falling back to
    /// the full round-trip duration.
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
        let bytes = cfg.max_bytes.min(MAX_CF_BYTES);
        let url = download_url(bytes);

        let start = Instant::now();
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        let server_timing = resp
            .headers()
            .get("server-timing")
            .and_then(|v| v.to_str().ok())
            .and_then(server_timing_latency);

        let cap = bytes;
        let mut stream = resp.bytes_stream();
        let mut received: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| SpeedtestError::Http(e.to_string()))?;
            received = received.saturating_add(chunk.len() as u64);
            if !keep_downloading(received, cap, start.elapsed(), cfg.measure_window) {
                break;
            }
        }
        let elapsed = start.elapsed();
        let download_mbps = mbps_from(received, elapsed);
        let latency_ms = server_timing.unwrap_or(elapsed.as_secs_f64() * 1000.0);

        Ok(ProviderReading {
            provider: self.name().to_owned(),
            download_mbps,
            upload_mbps: None,
            latency_ms,
        })
    }
}
