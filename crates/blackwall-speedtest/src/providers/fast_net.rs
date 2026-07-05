//! fast.com (Netflix) network provider — thin reqwest wrapper; coverage-excluded.
//!
//! All parsing and URL building lives in [`super::fast_parse`].

use async_trait::async_trait;
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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

impl FastProvider {
    /// Time-bounded upload POST to `url`.
    ///
    /// Streams 64 KiB zero-filled chunks via a true async stream generator that
    /// stops yielding once the measurement window has elapsed or the byte cap is
    /// reached, so the `.send()` completes naturally within the window.  A
    /// belt-and-suspenders `.timeout(window)` on the request guards against any
    /// server-side delay after all bytes are sent.
    ///
    /// Bytes actually yielded are tracked in a shared [`AtomicU64`]; throughput
    /// is computed from that counter and the real wall-clock elapsed time.
    async fn measure_upload(
        &self,
        url: &str,
        cfg: &SpeedtestConfig,
    ) -> Result<f64, SpeedtestError> {
        /// Single chunk size reused every poll (64 KiB).
        const CHUNK_LEN: usize = 64 * 1024;

        let cap = cfg.max_bytes;
        let window = cfg.measure_window;

        let sent = Arc::new(AtomicU64::new(0));
        let sent_for_stream = Arc::clone(&sent);

        let chunk = vec![0u8; CHUNK_LEN];
        let start = Instant::now();

        // `unfold` drives the stream: each iteration checks the wall-clock and
        // byte counter, then yields exactly as many bytes as remain under the
        // cap.  When either limit is hit the stream terminates with `None`.
        let body_stream = futures_util::stream::unfold(chunk, move |chunk| {
            let sent_ref = Arc::clone(&sent_for_stream);
            async move {
                let so_far = sent_ref.load(Ordering::Relaxed);
                if start.elapsed() >= window || so_far >= cap {
                    return None;
                }
                let remaining = cap - so_far;
                let n = u64::try_from(chunk.len()).unwrap_or(0).min(remaining);
                let n_usize = usize::try_from(n).unwrap_or(0);
                if n_usize == 0 {
                    return None;
                }
                sent_ref.fetch_add(n, Ordering::Relaxed);
                // Slice the reused chunk to exactly `n` bytes.
                let out = chunk[..n_usize].to_vec();
                Some((Ok::<Vec<u8>, std::io::Error>(out), chunk))
            }
        });

        let upload_start = Instant::now();
        self.client
            .post(url)
            .timeout(window)
            .body(reqwest::Body::wrap_stream(body_stream))
            .send()
            .await
            .map_err(|e| SpeedtestError::Http(e.to_string()))?;
        let elapsed = upload_start.elapsed();

        // Note: `sent` counts bytes generated into the body stream (a close proxy for transmitted); on a timeout-abort some buffered bytes may not have hit the wire.
        let total = sent.load(Ordering::Relaxed);
        Ok(mbps_from(total, elapsed))
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

        // Download the first target; read until the measurement window.
        // Use a high byte ceiling so the window — not max_bytes — bounds a fast link.
        let cap = cfg.max_bytes.max(2u64 * 1024 * 1024 * 1024);
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
            if !keep_downloading(received, cap, dl_start.elapsed(), cfg.measure_window) {
                break;
            }
        }
        let elapsed = dl_start.elapsed();
        let download_mbps = mbps_from(received, elapsed);

        // --- Upload measurement ---
        let upload_mbps = match self.measure_upload(&target.url, cfg).await {
            Ok(mbps) => Some(mbps),
            Err(e) => {
                tracing::debug!("fast.com upload measurement failed: {e}");
                None
            }
        };

        Ok(ProviderReading {
            provider: self.name().to_owned(),
            download_mbps,
            upload_mbps,
            latency_ms,
        })
    }

    /// Idle RTT proxy: TTFB of a request to fast.com, with no download running.
    /// (fast.com's own latency figure is the API-query RTT; the landing-page
    /// round-trip is a cheap unloaded stand-in for the idle phase.)
    async fn measure_latency(&self, _cfg: &SpeedtestConfig) -> Option<f64> {
        let start = Instant::now();
        self.client.get("https://fast.com/").send().await.ok()?;
        Some(start.elapsed().as_secs_f64() * 1000.0)
    }
}
