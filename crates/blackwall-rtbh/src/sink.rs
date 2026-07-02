//! Thin sink: executes the RTBH controller's decisions on the BGP session.
//! Coverage-excluded (drives `BgpHandle`); validated by the `rtbh-bird` lab gate.

use crate::controller::{RtbhAction, RtbhController};
use async_trait::async_trait;
use blackwall_bgp::BgpHandle;
use blackwall_flow::{DetectionEvent, MitigationSink};
use tokio::sync::Mutex;

/// A [`MitigationSink`] that turns detection events into BGP blackhole
/// announce/withdraw commands via a running BGP session.
pub struct RtbhSink {
    controller: Mutex<RtbhController>,
    bgp: BgpHandle,
}

impl RtbhSink {
    /// Wrap a controller + BGP handle.
    #[must_use]
    pub fn new(controller: RtbhController, bgp: BgpHandle) -> Self {
        Self {
            controller: Mutex::new(controller),
            bgp,
        }
    }
}

#[async_trait]
impl MitigationSink for RtbhSink {
    async fn handle(&self, event: &DetectionEvent) {
        // Compute actions under the lock, then release it before awaiting sends.
        let actions = self.controller.lock().await.on_event(event, now_ms());
        for action in actions {
            match action {
                RtbhAction::Announce(route) => self.bgp.announce(route).await,
                RtbhAction::Withdraw(prefix) => self.bgp.withdraw(prefix).await,
            }
        }
    }
}

/// Milliseconds since the Unix epoch (the controller's injected clock).
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
