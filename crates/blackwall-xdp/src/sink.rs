//! The [`blackwall_flow::MitigationSink`] adapter that forwards detection
//! events into the single-owner [`crate::manager::XdpManager`] task.
//!
//! This is deliberately thin: it holds no eligibility or source-selection
//! logic itself, it just hands each event off to the manager task (which
//! calls [`crate::control::XdpController::on_detection`]). Keeping that logic
//! in the pure controller, reached through a single channel, avoids a shared
//! lock across the sink and the manager.

use async_trait::async_trait;
use blackwall_flow::{DetectionEvent, MitigationSink};
use tokio::sync::mpsc;

/// A sink that forwards each detection event into the `XdpManager` task via
/// an `mpsc` channel.
///
/// Forwarding is best-effort: if the channel is full or the receiver has
/// been dropped, the event is silently dropped and a `warn!` is logged.
/// `handle` never panics and never blocks.
pub struct XdpMitigationSink(mpsc::Sender<DetectionEvent>);

impl XdpMitigationSink {
    /// Build an `XdpMitigationSink` that forwards events into `tx`.
    pub fn new(tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self(tx)
    }
}

#[async_trait]
impl MitigationSink for XdpMitigationSink {
    async fn handle(&self, event: &DetectionEvent) {
        if let Err(err) = self.0.try_send(event.clone()) {
            tracing::warn!(%err, "dropping detection event: xdp manager channel unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_flow::DetectionEvent;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn forwards_event_to_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let s = XdpMitigationSink::new(tx);
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
    async fn closed_channel_does_not_panic() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        XdpMitigationSink::new(tx)
            .handle(&DetectionEvent::Cleared {
                target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                at_ms: 0,
            })
            .await;
    }
}
