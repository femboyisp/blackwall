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
fn now_ms() -> u64 {
    u64::try_from(clock_base().elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Run the collector until the process ends. Binds `listen`, decodes each
/// datagram into the `detector`, and every `tick_interval_ms` evaluates the
/// window and forwards events to `sink`. Decode errors are logged and skipped.
///
/// When `metrics` is `Some`, the collector increments `datagrams` per received
/// datagram and `decode_errors` per decode failure, and (after each tick)
/// publishes the detector's cumulative unknown-agent observation count, for
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
                            Ok(observations) => {
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
                }
                for event in events {
                    sink.handle(&event).await;
                }
            }
        }
    }
}
