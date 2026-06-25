//! LibreSpeed network provider — thin reqwest wrapper; coverage-excluded.
//!
//! All parsing and URL building lives in [`super::librespeed_parse`].

use async_trait::async_trait;
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::throughput::{keep_downloading, mbps_from};

use super::librespeed_parse::{download_url, ping_url, upload_url};

/// Maximum upload size for a single LibreSpeed measurement (25 MiB).
const MAX_LS_UPLOAD_BYTES: u64 = 25 * 1024 * 1024;

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

impl LibreSpeedProvider {
    /// Time-bounded upload POST to `upload_url(&self.server)`.
    ///
    /// Streams 64 KiB zero-filled chunks via an async stream generator that
    /// stops yielding once the measurement window has elapsed or the byte cap
    /// is reached, so `.send()` completes naturally within the window.
    /// A belt-and-suspenders `.timeout(window)` guards against server-side
    /// delay after all bytes are sent.
    ///
    /// Bytes actually yielded are tracked in a shared [`AtomicU64`]; throughput
    /// is computed from that counter and the real wall-clock elapsed time.
    async fn measure_upload(&self, cfg: &SpeedtestConfig) -> Result<f64, SpeedtestError> {
        /// Single chunk size reused every poll (64 KiB).
        const CHUNK_LEN: usize = 64 * 1024;

        let cap = cfg.max_bytes.min(MAX_LS_UPLOAD_BYTES);
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
            .post(upload_url(&self.server))
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
    ///
    /// Upload is measured via a time-bounded streaming POST to `empty.php`;
    /// errors are non-fatal and leave `upload_mbps` as `None`.
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
            if !keep_downloading(received, cap, dl_start.elapsed(), cfg.measure_window) {
                break;
            }
        }
        let elapsed = dl_start.elapsed();

        let download_mbps = mbps_from(received.min(cap), elapsed);

        // --- Upload measurement ---
        let upload_mbps = match self.measure_upload(cfg).await {
            Ok(mbps) => Some(mbps),
            Err(e) => {
                tracing::debug!("LibreSpeed upload measurement failed: {e}");
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
}
