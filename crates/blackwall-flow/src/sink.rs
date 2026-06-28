//! The sink that receives detection events. The concrete sink (Postgres, and
//! later B/C mitigation) plugs in here.

use crate::detector::DetectionEvent;
use async_trait::async_trait;

/// Receives detection lifecycle events.
#[async_trait]
pub trait MitigationSink: Send + Sync {
    /// Handle one detection event (best-effort; implementations must not panic).
    async fn handle(&self, event: &DetectionEvent);
}

/// A sink that logs each event via `tracing` (default standalone visibility).
pub struct LogSink;

#[async_trait]
impl MitigationSink for LogSink {
    async fn handle(&self, event: &DetectionEvent) {
        match event {
            DetectionEvent::Opened(d) => {
                tracing::warn!(target = %d.target, pps = d.observed_pps, "attack detected")
            }
            DetectionEvent::Updated(d) => {
                tracing::info!(target = %d.target, pps = d.observed_pps, "attack ongoing")
            }
            DetectionEvent::Cleared { target, .. } => tracing::info!(%target, "attack cleared"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::DetectionEvent;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    struct CapturingSink(Mutex<Vec<String>>);
    #[async_trait]
    impl MitigationSink for CapturingSink {
        async fn handle(&self, event: &DetectionEvent) {
            let tag = match event {
                DetectionEvent::Opened(_) => "opened",
                DetectionEvent::Updated(_) => "updated",
                DetectionEvent::Cleared { .. } => "cleared",
            };
            self.0.lock().unwrap().push(tag.to_owned());
        }
    }

    #[tokio::test]
    async fn sink_receives_events() {
        let sink = CapturingSink(Mutex::new(Vec::new()));
        sink.handle(&DetectionEvent::Cleared {
            target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            at_ms: 0,
        })
        .await;
        assert_eq!(*sink.0.lock().unwrap(), vec!["cleared".to_owned()]);
    }
}
