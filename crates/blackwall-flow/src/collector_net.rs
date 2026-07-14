//! Thin UDP collector: receive sFlow datagrams, decode, feed the detector, and
//! forward detection events to the sink on a timer. Coverage-excluded.

use crate::detector::{AgentStat, Detector};
use crate::error::FlowError;
use crate::metrics::CollectorMetrics;
use crate::sflow::decode_datagram;
use crate::sink::MitigationSink;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tokio::net::UdpSocket;

/// Process-start baseline for the monotonic detector clock.
fn clock_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    *BASE.get_or_init(Instant::now)
}

/// Milliseconds since process start (monotonic). Used for all detector windowing,
/// eviction, and hold-down math — never affected by NTP/wall-clock steps.
///
/// Exposed publicly so the `/metrics` renderer can compute each POP's last-seen
/// age against the **same** clock the collector stamps observations with:
/// `AgentStat.last_seen_ms` is a monotonic timestamp, so subtracting it from an
/// epoch "now" yields a nonsense (~epoch-sized) age.
#[must_use]
pub fn monotonic_now_ms() -> u64 {
    u64::try_from(clock_base().elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn now_ms() -> u64 {
    monotonic_now_ms()
}

/// Run the collector until the process ends. Binds `listen`, decodes each
/// datagram into the `detector`, and every `tick_interval_ms` evaluates the
/// window and forwards events to `sink`. Decode errors are logged and skipped.
///
/// When `metrics` is `Some`, the collector increments `datagrams` per received
/// datagram, `decode_errors` per envelope-level decode failure (the whole
/// datagram discarded), and `sample_decode_errors` once per malformed sample
/// inside an otherwise-decoded datagram (the valid samples in that datagram
/// are still kept), and (after each tick) publishes the detector's cumulative
/// unknown-agent observation count and minimum-sample-suppressed count, for
/// the `/metrics` endpoint. Callers with no metrics endpoint pass `None`.
///
/// When `agent_snapshot` is `Some`, the collector overwrites it with
/// `detector.agent_stats()` after each tick, so `/metrics` can render
/// per-POP gauges without reaching into the detector directly (it is owned
/// here behind `Box<dyn Detector>`). Callers with no per-agent metrics pass
/// `None`.
pub async fn run_collector(
    listen: SocketAddr,
    mut detector: Box<dyn Detector + Send>,
    sink: Arc<dyn MitigationSink>,
    tick_interval_ms: u64,
    metrics: Option<Arc<CollectorMetrics>>,
    agent_snapshot: Option<Arc<Mutex<Vec<AgentStat>>>>,
) -> Result<(), FlowError> {
    let sock = UdpSocket::bind(listen)
        .await
        .map_err(|e| FlowError::Io(format!("bind {listen}: {e}")))?;
    let mut buf = vec![0u8; 65535];
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(tick_interval_ms));
    loop {
        tokio::select! {
            recv = sock.recv_from(&mut buf) => {
                match recv {
                    Ok((n, _from)) => {
                        if let Some(m) = &metrics { m.incr_datagrams(); }
                        match decode_datagram(&buf[..n]) {
                            Ok((observations, sample_errors)) => {
                                if let Some(m) = &metrics {
                                    for _ in 0..sample_errors { m.incr_sample_decode_errors(); }
                                }
                                let t = now_ms();
                                for o in &observations { detector.observe(o, t); }
                            }
                            Err(err) => {
                                if let Some(m) = &metrics { m.incr_decode_errors(); }
                                tracing::debug!(%err, "sflow decode failed; skipping datagram");
                            }
                        }
                    }
                    Err(err) => tracing::warn!(%err, "udp recv error"),
                }
            }
            _ = ticker.tick() => {
                let events = detector.tick(now_ms());
                if let Some(snapshot) = &agent_snapshot {
                    *snapshot.lock().unwrap() = detector.agent_stats();
                }
                if let Some(m) = &metrics {
                    m.set_unknown_agent_observations(detector.unknown_agent_observations());
                    m.set_min_sample_suppressed(detector.min_sample_suppressed());
                    m.set_detections_opened(detector.detections_opened());
                    m.set_detections_cleared(detector.detections_cleared());
                }
                for event in events {
                    sink.handle(&event).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::monotonic_now_ms;

    #[test]
    fn monotonic_now_ms_is_process_uptime_not_epoch() {
        let a = monotonic_now_ms();
        let b = monotonic_now_ms();
        assert!(b >= a, "monotonic clock must be non-decreasing");
        // Process uptime in ms stays far below epoch-ms scale (~1.78e12) for
        // years; this guards against a regression back to a wall-clock source,
        // which is what made pop_last_seen_seconds read ~epoch.
        assert!(
            a < 1_000_000_000,
            "must be process-uptime ms, not epoch ms; got {a}"
        );
    }
}
