//! Shadow-mode executor + journal: record what a mitigation *would* do without
//! executing it. Wired in place of the real `BgpExecutor`/journal when the
//! `shadow` config directive is set.

use crate::controller::BlackholeOrigin;
use crate::flowspec_manager::FlowSpecJournal;
use crate::manager::{BgpError, BgpExecutor, BlackholeJournal, JournalError};
use async_trait::async_trait;
use std::net::IpAddr;

/// A mitigation the daemon would have applied, captured for logging/audit.
#[derive(Debug, Clone)]
pub enum ShadowAction {
    /// Would announce a blackhole route.
    RtbhAnnounce(blackwall_bgp::Route),
    /// Would withdraw a blackhole prefix.
    RtbhWithdraw(ipnet::IpNet),
    /// Would announce a FlowSpec rule.
    FlowSpecAnnounce(blackwall_bgp::FlowSpecRule),
    /// Would withdraw a FlowSpec rule.
    FlowSpecWithdraw(blackwall_bgp::FlowSpecRule),
}

/// Sink for shadow actions (the concrete impl in `blackwalld` logs + audits +
/// meters; tests capture into a vec).
#[async_trait]
pub trait ShadowRecorder: Send + Sync {
    /// Record one intended mitigation.
    async fn record(&self, action: ShadowAction);
}

/// Blanket impl so an `Arc<impl ShadowRecorder>` can be shared with other
/// owners (e.g. a test assertion) while also being handed to
/// [`ShadowBgpExecutor::new`].
#[async_trait]
impl<T: ShadowRecorder + ?Sized> ShadowRecorder for std::sync::Arc<T> {
    async fn record(&self, action: ShadowAction) {
        (**self).record(action).await;
    }
}

/// A `BgpExecutor` that records intended announcements instead of sending them.
///
/// Holds no reference to a real BGP session or executor at all — there is no
/// path from any of its methods to live BGP traffic.
pub struct ShadowBgpExecutor<R: ShadowRecorder> {
    recorder: R,
}

impl<R: ShadowRecorder> ShadowBgpExecutor<R> {
    /// Wrap a recorder.
    pub fn new(recorder: R) -> Self {
        Self { recorder }
    }
}

#[async_trait]
impl<R: ShadowRecorder> BgpExecutor for ShadowBgpExecutor<R> {
    async fn announce(&self, route: blackwall_bgp::Route) -> Result<(), BgpError> {
        self.recorder
            .record(ShadowAction::RtbhAnnounce(route))
            .await;
        Ok(())
    }
    async fn withdraw(&self, prefix: ipnet::IpNet) -> Result<(), BgpError> {
        self.recorder
            .record(ShadowAction::RtbhWithdraw(prefix))
            .await;
        Ok(())
    }
    async fn announce_flowspec(&self, rule: blackwall_bgp::FlowSpecRule) -> Result<(), BgpError> {
        self.recorder
            .record(ShadowAction::FlowSpecAnnounce(rule))
            .await;
        Ok(())
    }
    async fn withdraw_flowspec(&self, rule: blackwall_bgp::FlowSpecRule) -> Result<(), BgpError> {
        self.recorder
            .record(ShadowAction::FlowSpecWithdraw(rule))
            .await;
        Ok(())
    }
}

/// A journal that persists nothing — used with [`ShadowBgpExecutor`] so the
/// live mirror tables stay empty (nothing was actually announced).
pub struct NoOpJournal;

#[async_trait]
impl BlackholeJournal for NoOpJournal {
    async fn record_announce(
        &self,
        _target: IpAddr,
        _origin: BlackholeOrigin,
        _at_ms: u64,
    ) -> Result<(), JournalError> {
        Ok(())
    }
    async fn record_withdraw(&self, _target: IpAddr, _at_ms: u64) -> Result<(), JournalError> {
        Ok(())
    }
}

#[async_trait]
impl FlowSpecJournal for NoOpJournal {
    async fn record_announce(
        &self,
        _rule: blackwall_bgp::FlowSpecRule,
        _origin: BlackholeOrigin,
        _at_ms: u64,
    ) -> Result<(), JournalError> {
        Ok(())
    }
    async fn record_withdraw(
        &self,
        _rule: blackwall_bgp::FlowSpecRule,
        _at_ms: u64,
    ) -> Result<(), JournalError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BgpError, BgpExecutor};
    use blackwall_bgp::{FlowAction, FlowSpecRule, Origin, Route};
    use std::sync::Mutex;

    #[derive(Default)]
    struct CapturingRecorder(Mutex<Vec<ShadowAction>>);
    #[async_trait::async_trait]
    impl ShadowRecorder for CapturingRecorder {
        async fn record(&self, action: ShadowAction) {
            self.0.lock().unwrap().push(action);
        }
    }

    /// Never constructed: its whole point is to prove `ShadowBgpExecutor`
    /// holds no path to a real `BgpExecutor` for the tests below to wire in.
    #[expect(
        dead_code,
        reason = "documents the absent BGP path; never instantiated on purpose"
    )]
    struct PanicExecutor;
    #[async_trait::async_trait]
    impl BgpExecutor for PanicExecutor {
        async fn announce(&self, _r: Route) -> Result<(), BgpError> {
            panic!("announced in shadow!")
        }
        async fn withdraw(&self, _p: ipnet::IpNet) -> Result<(), BgpError> {
            panic!("withdrew in shadow!")
        }
        async fn announce_flowspec(&self, _r: FlowSpecRule) -> Result<(), BgpError> {
            panic!("announced flowspec in shadow!")
        }
        async fn withdraw_flowspec(&self, _r: FlowSpecRule) -> Result<(), BgpError> {
            panic!("withdrew flowspec in shadow!")
        }
    }

    /// Build a minimal /32 blackhole route the same way
    /// `RtbhController::build_route` does (see `controller.rs`).
    fn route(target: &str) -> Route {
        Route {
            prefix: format!("{target}/32").parse().unwrap(),
            next_hop: "10.0.0.1".parse().unwrap(),
            origin: Origin::Igp,
            communities: vec![(65535, 666)],
            large_communities: Vec::new(),
        }
    }

    /// Build a `FlowSpecRule` the same way `flowspec_controller.rs`'s tests do.
    fn flowspec_rule() -> FlowSpecRule {
        FlowSpecRule {
            dst: "203.0.113.7/32".parse().unwrap(),
            protocol: Some(17),
            dst_port: Some(53),
            action: FlowAction::TrafficRate(1000.0),
        }
    }

    #[tokio::test]
    async fn announce_records_and_never_calls_bgp() {
        let rec = std::sync::Arc::new(CapturingRecorder::default());
        let exec = ShadowBgpExecutor::new(rec.clone());
        exec.announce(route("203.0.113.7")).await.unwrap();
        let captured = rec.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(matches!(captured[0], ShadowAction::RtbhAnnounce(_)));
        // PanicExecutor is never constructed into the executor -> proves no BGP path.
    }

    #[tokio::test]
    async fn withdraw_and_flowspec_record_the_right_variants() {
        let rec = std::sync::Arc::new(CapturingRecorder::default());
        let exec = ShadowBgpExecutor::new(rec.clone());
        exec.withdraw("203.0.113.7/32".parse().unwrap())
            .await
            .unwrap();
        exec.announce_flowspec(flowspec_rule()).await.unwrap();
        let c = rec.0.lock().unwrap();
        assert!(matches!(c[0], ShadowAction::RtbhWithdraw(_)));
        assert!(matches!(c[1], ShadowAction::FlowSpecAnnounce(_)));
    }

    #[tokio::test]
    async fn withdraw_flowspec_records_the_right_variant() {
        let rec = std::sync::Arc::new(CapturingRecorder::default());
        let exec = ShadowBgpExecutor::new(rec.clone());
        exec.withdraw_flowspec(flowspec_rule()).await.unwrap();
        let c = rec.0.lock().unwrap();
        assert!(matches!(c[0], ShadowAction::FlowSpecWithdraw(_)));
    }

    #[tokio::test]
    async fn no_op_journal_never_errors() {
        let j = NoOpJournal;
        BlackholeJournal::record_announce(
            &j,
            "203.0.113.7".parse().unwrap(),
            BlackholeOrigin::Auto,
            0,
        )
        .await
        .unwrap();
        BlackholeJournal::record_withdraw(&j, "203.0.113.7".parse().unwrap(), 0)
            .await
            .unwrap();
        FlowSpecJournal::record_announce(&j, flowspec_rule(), BlackholeOrigin::Auto, 0)
            .await
            .unwrap();
        FlowSpecJournal::record_withdraw(&j, flowspec_rule(), 0)
            .await
            .unwrap();
    }
}
