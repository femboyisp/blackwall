//! The sink that receives detection events. The concrete sink (Postgres, and
//! later B/C mitigation) plugs in here.

use crate::detector::DetectionEvent;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;

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

/// A sink that forwards each event to every member sink, sequentially.
///
/// Members are handled in order, awaiting each `handle` call before moving
/// on to the next; a slow or misbehaving member delays later members but a
/// panicking member is not caught here (members must themselves be
/// best-effort, per the `MitigationSink` contract).
pub struct FanoutSink(pub Vec<Arc<dyn MitigationSink>>);

#[async_trait]
impl MitigationSink for FanoutSink {
    async fn handle(&self, event: &DetectionEvent) {
        for member in &self.0 {
            member.handle(event).await;
        }
    }
}

/// A sink that forwards events into an `mpsc` channel for consumption
/// elsewhere (e.g. handing detection events off to a manager task).
///
/// Forwarding is best-effort: if the channel is full or the receiver has
/// been dropped, the event is silently dropped and a `warn!` is logged.
/// `handle` never panics and never blocks.
pub struct ChannelSink(mpsc::Sender<DetectionEvent>);

impl ChannelSink {
    /// Build a `ChannelSink` that forwards events into `tx`.
    pub fn new(tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self(tx)
    }
}

#[async_trait]
impl MitigationSink for ChannelSink {
    async fn handle(&self, event: &DetectionEvent) {
        if let Err(err) = self.0.try_send(event.clone()) {
            tracing::warn!(%err, "dropping detection event: channel sink unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::DetectionEvent;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

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

    #[tokio::test]
    async fn fanout_forwards_to_all() {
        let a = Arc::new(CapturingSink(Mutex::new(Vec::new())));
        let b = Arc::new(CapturingSink(Mutex::new(Vec::new())));
        let fan = FanoutSink(vec![a.clone(), b.clone()]);
        fan.handle(&DetectionEvent::Cleared {
            target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            at_ms: 0,
        })
        .await;
        assert_eq!(a.0.lock().unwrap().len(), 1);
        assert_eq!(b.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn channel_sink_forwards_event() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let s = ChannelSink::new(tx);
        s.handle(&DetectionEvent::Cleared {
            target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            at_ms: 0,
        })
        .await;
        assert!(matches!(
            rx.recv().await,
            Some(DetectionEvent::Cleared { .. })
        ));
    }

    #[tokio::test]
    async fn channel_sink_drops_when_closed_without_panic() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let s = ChannelSink::new(tx);
        s.handle(&DetectionEvent::Cleared {
            target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            at_ms: 0,
        })
        .await; // must not panic
    }
}
