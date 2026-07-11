//! The sink that receives detection events. The concrete sink (Postgres, and
//! later B/C mitigation) plugs in here.

use crate::detector::DetectionEvent;
use crate::select::{select, FlowRule, Mitigation, SelectionConfig};
use async_trait::async_trait;
use std::net::IpAddr;
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

/// A mitigation instruction produced by [`SelectorSink`] for the FlowSpec side.
#[derive(Debug, Clone)]
pub enum FlowMitigationEvent {
    /// Install FlowSpec drop rules for `target`.
    Open {
        /// The victim address.
        target: IpAddr,
        /// The flow-scoped rules to install.
        rules: Vec<FlowRule>,
    },
    /// The attack against `target` is still ongoing; refresh/keep-alive it.
    Update {
        /// The victim address.
        target: IpAddr,
    },
    /// The attack against `target` has cleared; withdraw its rules.
    Clear {
        /// The victim address.
        target: IpAddr,
    },
}

/// A sink that routes each detection to the FlowSpec or RTBH manager, using
/// [`select`] to pick the mitigation for newly-opened attacks.
///
/// `Opened` detections are classified via `select` and routed to exactly one
/// of `flowspec_tx` (FlowSpec) or `rtbh_tx` (RTBH). `Updated` and `Cleared`
/// events are broadcast to both, since either manager may be holding state
/// for the target. Forwarding is best-effort via `try_send`: a full or closed
/// channel is logged with `tracing::warn!` and otherwise ignored; `handle`
/// never panics and never blocks.
pub struct SelectorSink {
    flowspec_tx: mpsc::Sender<FlowMitigationEvent>,
    rtbh_tx: mpsc::Sender<DetectionEvent>,
    cfg: SelectionConfig,
}

impl SelectorSink {
    /// Build a `SelectorSink` that routes via `select(_, &cfg)`, forwarding
    /// FlowSpec mitigations into `flowspec_tx` and RTBH mitigations (plus all
    /// `Updated`/`Cleared` events) into `rtbh_tx`.
    pub fn new(
        flowspec_tx: mpsc::Sender<FlowMitigationEvent>,
        rtbh_tx: mpsc::Sender<DetectionEvent>,
        cfg: SelectionConfig,
    ) -> Self {
        Self {
            flowspec_tx,
            rtbh_tx,
            cfg,
        }
    }

    fn send_flowspec(&self, event: FlowMitigationEvent) {
        if let Err(err) = self.flowspec_tx.try_send(event) {
            tracing::warn!(%err, "dropping flowspec mitigation event: channel unavailable");
        }
    }

    fn send_rtbh(&self, event: DetectionEvent) {
        if let Err(err) = self.rtbh_tx.try_send(event) {
            tracing::warn!(%err, "dropping rtbh detection event: channel unavailable");
        }
    }
}

#[async_trait]
impl MitigationSink for SelectorSink {
    async fn handle(&self, event: &DetectionEvent) {
        match event {
            DetectionEvent::Opened(d) => match select(d, &self.cfg) {
                Mitigation::FlowSpec(rules) => self.send_flowspec(FlowMitigationEvent::Open {
                    target: d.target,
                    rules,
                }),
                Mitigation::Rtbh => self.send_rtbh(DetectionEvent::Opened(d.clone())),
            },
            DetectionEvent::Updated(d) => {
                self.send_flowspec(FlowMitigationEvent::Update { target: d.target });
                self.send_rtbh(DetectionEvent::Updated(d.clone()));
            }
            DetectionEvent::Cleared { target, at_ms } => {
                self.send_flowspec(FlowMitigationEvent::Clear { target: *target });
                self.send_rtbh(DetectionEvent::Cleared {
                    target: *target,
                    at_ms: *at_ms,
                });
            }
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

    use crate::detector::{AttackKind, Detection, Severity};

    fn det_base(proto: u8, top_ports: Vec<(u16, f64)>) -> Detection {
        Detection {
            target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            kind: AttackKind::Volumetric,
            observed_pps: 1_000.0,
            observed_bps: 8_000.0,
            proto,
            top_sources: vec![],
            top_ports,
            pops: vec![],
            top_source_blocks: vec![],
            severity: Severity::High,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    /// A concentrated attack: a single dominant port well past the default
    /// concentration threshold, so `select` chooses FlowSpec.
    fn det_concentrated() -> Detection {
        det_base(17, vec![(53, 0.95)])
    }

    /// A diffuse attack: weight spread thin across many ports, so no small
    /// flow set clears the concentration threshold and `select` chooses RTBH.
    fn det_diffuse() -> Detection {
        det_base(
            17,
            vec![
                (1, 0.1),
                (2, 0.1),
                (3, 0.1),
                (4, 0.1),
                (5, 0.1),
                (6, 0.1),
                (7, 0.1),
                (8, 0.1),
            ],
        )
    }

    fn selector_cfg() -> SelectionConfig {
        SelectionConfig {
            concentration: 0.8,
            max_flows: 4,
            rate: 0.0,
        }
    }

    #[tokio::test]
    async fn concentrated_routes_to_flowspec_only() {
        let (ftx, mut frx) = mpsc::channel(8);
        let (rtx, mut rrx) = mpsc::channel(8);
        let s = SelectorSink::new(ftx, rtx, selector_cfg());
        s.handle(&DetectionEvent::Opened(det_concentrated())).await;
        assert!(matches!(
            frx.try_recv(),
            Ok(FlowMitigationEvent::Open { .. })
        ));
        assert!(rrx.try_recv().is_err()); // RTBH not routed
    }

    #[tokio::test]
    async fn diffuse_routes_to_rtbh_only() {
        let (ftx, mut frx) = mpsc::channel(8);
        let (rtx, mut rrx) = mpsc::channel(8);
        let s = SelectorSink::new(ftx, rtx, selector_cfg());
        s.handle(&DetectionEvent::Opened(det_diffuse())).await;
        assert!(matches!(rrx.try_recv(), Ok(DetectionEvent::Opened(_))));
        assert!(frx.try_recv().is_err()); // FlowSpec not routed
    }

    #[tokio::test]
    async fn clear_broadcasts_to_both() {
        let (ftx, mut frx) = mpsc::channel(8);
        let (rtx, mut rrx) = mpsc::channel(8);
        let s = SelectorSink::new(ftx, rtx, selector_cfg());
        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        s.handle(&DetectionEvent::Cleared { target, at_ms: 42 })
            .await;
        assert!(matches!(
            frx.try_recv(),
            Ok(FlowMitigationEvent::Clear { target: t }) if t == target
        ));
        assert!(matches!(
            rrx.try_recv(),
            Ok(DetectionEvent::Cleared { target: t, at_ms: 42 }) if t == target
        ));
    }

    #[tokio::test]
    async fn closed_channel_does_not_panic() {
        let (ftx, frx) = mpsc::channel(8);
        let (rtx, rrx) = mpsc::channel(8);
        drop(frx);
        drop(rrx);
        let s = SelectorSink::new(ftx, rtx, selector_cfg());
        s.handle(&DetectionEvent::Opened(det_concentrated())).await;
        s.handle(&DetectionEvent::Opened(det_diffuse())).await;
        s.handle(&DetectionEvent::Updated(det_concentrated())).await;
        s.handle(&DetectionEvent::Cleared {
            target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            at_ms: 0,
        })
        .await; // must not panic
    }
}
