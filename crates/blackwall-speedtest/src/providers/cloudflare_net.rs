//! Cloudflare network provider — thin reqwest wrapper; coverage-excluded.
//!
//! All parsing and math lives in [`super::cloudflare_parse`].

use async_trait::async_trait;
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::error::SpeedtestError;
use crate::provider::{SpeedtestConfig, SpeedtestProvider};
use crate::reading::ProviderReading;
use crate::source::SpeedtestSource;
use crate::throughput::mbps_from;

use super::cloudflare_parse::{download_url, server_timing_latency, upload_url};

/// Maximum download size for a single Cloudflare measurement (25 MiB).
const MAX_CF_BYTES: u64 = 25 * 1024 * 1024;

/// Speedtest provider backed by `speed.cloudflare.com`.
pub struct CloudflareProvider {
    client: reqwest::Client,
}

impl CloudflareProvider {
    /// Create a [`CloudflareProvider`] using the host's default route.
    pub fn new() -> Self {
        Self::with_source(SpeedtestSource::Default)
    }

    /// Create a [`CloudflareProvider`] whose connections bind to `source`.
    pub fn with_source(source: SpeedtestSource) -> Self {
        CloudflareProvider {
            client: super::build_client(&source),
        }
    }
}

impl Default for CloudflareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflareProvider {
    /// Time-bounded upload POST to `upload_url()`.
    ///
    /// Streams 64 KiB zero-filled chunks via a true async stream generator that
    /// stops yielding once the measurement window has elapsed or the byte cap is
    /// reached, so the `.send()` completes naturally within the window.  A
    /// belt-and-suspenders `.timeout(window)` on the request guards against any
    /// server-side delay after all bytes are sent.
    ///
    /// Bytes actually yielded are tracked in a shared [`AtomicU64`]; throughput
    /// is computed from that counter and the real wall-clock elapsed time.
    async fn measure_upload(&self, cfg: &SpeedtestConfig) -> Result<f64, SpeedtestError> {
        /// Single chunk size reused every poll (64 KiB).
        const CHUNK_LEN: usize = 64 * 1024;

        let cap = cfg.max_bytes.min(MAX_CF_BYTES);
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
            .post(upload_url())
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
impl SpeedtestProvider for CloudflareProvider {
    fn name(&self) -> &str {
        "cloudflare"
    }

    /// Measure download throughput and latency via Cloudflare's speed endpoint.
    ///
    /// Download loops `min(cfg.max_bytes, 25 MiB)` requests until the
    /// measurement window elapses, accumulating total bytes across all
    /// requests. Latency is the `Server-Timing: cfRequestDuration;dur=X`
    /// header value from the first response when present; otherwise it falls
    /// back to the TTFB of a `__down?bytes=1` probe request.
    async fn measure(&self, cfg: &SpeedtestConfig) -> Result<ProviderReading, SpeedtestError> {
        let per_req = cfg.max_bytes.min(MAX_CF_BYTES);
        let url = download_url(per_req);

        let start = Instant::now();
        let mut total: u64 = 0;
        let mut server_timing: Option<f64> = None;
        let mut first = true;
        while start.elapsed() < cfg.measure_window {
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    if first {
                        return Err(SpeedtestError::Http(e.to_string()));
                    }
                    break; // a later request failing just ends the measurement
                }
            };
            if first {
                server_timing = resp
                    .headers()
                    .get("server-timing")
                    .and_then(|v| v.to_str().ok())
                    .and_then(server_timing_latency);
                first = false;
            }
            let before = total;
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(_) => break,
                };
                total = total.saturating_add(u64::try_from(chunk.len()).unwrap_or(0));
                if start.elapsed() >= cfg.measure_window {
                    break;
                }
            }
            // No-progress guard: if a full request delivered no new bytes (a
            // server returning instant empty 200s), stop instead of hot-spinning
            // re-issuing requests until the window expires.
            if total == before {
                break;
            }
        }
        let elapsed = start.elapsed();
        let download_mbps = mbps_from(total, elapsed);

        // Prefer the Server-Timing header (server-side RTT proxy); fall back to
        // TTFB of a 1-byte probe request, which is the real network round-trip time.
        let latency_ms = match server_timing {
            Some(ms) => ms,
            None => {
                let probe_url = download_url(1);
                let probe_start = Instant::now();
                let _ = self.client.get(&probe_url).send().await;
                probe_start.elapsed().as_secs_f64() * 1000.0
            }
        };

        // --- Upload measurement ---
        let upload_mbps = match self.measure_upload(cfg).await {
            Ok(mbps) => Some(mbps),
            Err(e) => {
                tracing::debug!("Cloudflare upload measurement failed: {e}");
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

    /// Idle RTT: TTFB of a 1-byte `__down` request, with no download running.
    async fn measure_latency(&self, _cfg: &SpeedtestConfig) -> Option<f64> {
        let probe_url = download_url(1);
        let start = Instant::now();
        self.client.get(&probe_url).send().await.ok()?;
        Some(start.elapsed().as_secs_f64() * 1000.0)
    }
}
