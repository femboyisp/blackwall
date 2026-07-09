//! Thin UDP collector: receive sFlow datagrams, decode, feed the detector, and
//! forward detection events to the sink on a timer. Coverage-excluded.

use crate::detector::Detector;
use crate::error::FlowError;
use crate::metrics::CollectorMetrics;
use crate::sflow::decode_datagram;
use crate::sink::MitigationSink;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Run the collector until the process ends. Binds `listen`, decodes each
/// datagram into the `detector`, and every `tick_interval_ms` evaluates the
/// window and forwards events to `sink`. Decode errors are logged and skipped.
///
/// When `metrics` is `Some`, the collector increments `datagrams` per received
/// datagram and `decode_errors` per decode failure, for the `/metrics`
/// endpoint. Callers with no metrics endpoint pass `None`.
pub async fn run_collector(
    listen: SocketAddr,
    mut detector: Box<dyn Detector + Send>,
    sink: Arc<dyn MitigationSink>,
    tick_interval_ms: u64,
    metrics: Option<Arc<CollectorMetrics>>,
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
                for event in detector.tick(now_ms()) {
                    sink.handle(&event).await;
                }
            }
        }
    }
}
