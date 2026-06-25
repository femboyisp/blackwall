//! fast.com (Netflix) network provider — thin reqwest wrapper; coverage-excluded.
//!
//! All parsing and URL building lives in [`super::fast_parse`].

use async_trait::async_trait;
use futures_util::StreamExt;
use std::time::Instant;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::source::SpeedtestSource;
use crate::throughput::{keep_downloading, mbps_from};

use super::fast_parse::{api_url, extract_js_url, extract_token, parse_targets};

/// Number of target URLs to request from the fast.com API.
const TARGET_COUNT: u32 = 5;

/// Speedtest provider backed by `fast.com` (Netflix).
pub struct FastProvider {
    client: reqwest::Client,
}

impl FastProvider {
    /// Create a [`FastProvider`] using the host's default route.
    pub fn new() -> Self {
        Self::with_source(SpeedtestSource::Default)
    }

    /// Create a [`FastProvider`] whose connections bind to `source`.
    pub fn with_source(source: SpeedtestSource) -> Self {
        FastProvider {
            client: super::build_client(&source),
        }
    }
}

impl Default for FastProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpeedtestProvider for FastProvider {
    fn name(&self) -> &str {
        "fast"
    }

    /// Measure download throughput and latency via fast.com.
    ///
    /// Fetches the fast.com landing page, locates the application JS bundle,
    /// extracts the API token, queries the measurement API for target URLs,
    /// then times a stream-capped download from the first target. Latency is
    /// the round-trip time of the target download request.
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
        // Fetch the fast.com landing page to find the app JS bundle URL.
        let page = self
            .client
            .get("https://fast.com/")
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?
            .text()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        // Find the app-*.js script src in the page HTML.
        let js_url = extract_js_url(&page)
            .ok_or_else(|| SpeedtestError::Parse("fast.com: app JS URL not found".to_owned()))?;

        // Fetch the JS bundle and extract the API token.
        let js = self
            .client
            .get(&js_url)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?
            .text()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        let token = extract_token(&js)
            .ok_or_else(|| SpeedtestError::Parse("fast.com: token not found in JS".to_owned()))?;

        // Query the measurement API for download targets; time it as latency.
        let url = api_url(&token, TARGET_COUNT);
        let api_start = Instant::now();
        let api_resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;
        let latency_ms = api_start.elapsed().as_secs_f64() * 1000.0;
        let api_json = api_resp
            .text()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        let targets = parse_targets(&api_json)?;
        let target = targets.into_iter().next().ok_or(SpeedtestError::NoResult)?;

        // Download the first target, stream-capped at cfg.max_bytes.
        let dl_start = Instant::now();
        let resp = self
            .client
            .get(&target.url)
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;

        let mut received: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| SpeedtestError::Http(e.to_string()))?;
            received += u64::try_from(chunk.len()).unwrap_or(0);
            if !keep_downloading(
                received,
                cfg.max_bytes,
                dl_start.elapsed(),
                cfg.measure_window,
            ) {
                break;
            }
        }
        let elapsed = dl_start.elapsed();
        let download_mbps = mbps_from(received, elapsed);

        Ok(ProviderReading {
            provider: self.name().to_owned(),
            download_mbps,
            upload_mbps: None,
            latency_ms,
        })
    }
}
