//! Single-owner RTBH manager: executes controller decisions on BGP and
//! mirrors auto/manual state into a persistence journal.
//!
//! The [`RtbhController`] is pure (no I/O); this module owns the controller
//! plus the I/O boundary (BGP session + journal), via two dependency-inversion
//! traits so `blackwall-rtbh` stays free of any DB dependency.

use crate::controller::{BlackholeOrigin, RtbhAction, RtbhController};
use async_trait::async_trait;
use blackwall_bgp::Route;
use blackwall_flow::DetectionEvent;
use ipnet::IpNet;
use std::net::IpAddr;

/// Executes BGP announce/withdraw commands.
///
/// Implemented for [`blackwall_bgp::BgpHandle`] in this crate's `lib.rs`;
/// fakeable in tests to exercise [`RtbhManager`] without a live BGP session.
#[async_trait]
pub trait BgpExecutor: Send + Sync {
    /// Announce a blackhole route.
    async fn announce(&self, route: Route) -> Result<(), BgpError>;
    /// Withdraw a previously-announced blackhole prefix.
    async fn withdraw(&self, prefix: IpNet) -> Result<(), BgpError>;
    /// Announce a FlowSpec traffic-filter rule.
    async fn announce_flowspec(&self, rule: blackwall_bgp::FlowSpecRule) -> Result<(), BgpError>;
    /// Withdraw a previously-announced FlowSpec rule.
    async fn withdraw_flowspec(&self, rule: blackwall_bgp::FlowSpecRule) -> Result<(), BgpError>;
}

/// Mirrors blackhole state into persistent storage.
///
/// This is the sole seam through which `blackwall-rtbh` would touch a
/// database — the crate itself never depends on one. Implemented elsewhere
/// (e.g. the control-plane crate that owns the DB) and injected here.
#[async_trait]
pub trait BlackholeJournal: Send + Sync {
    /// Record that `target` is now blackholed, with the given origin.
    async fn record_announce(
        &self,
        target: IpAddr,
        origin: BlackholeOrigin,
        at_ms: u64,
    ) -> Result<(), JournalError>;
    /// Record that `target` is no longer blackholed.
    async fn record_withdraw(&self, target: IpAddr, at_ms: u64) -> Result<(), JournalError>;
}

/// A BGP executor operation failed.
#[derive(Debug, Default, thiserror::Error)]
#[error("BGP executor error")]
pub struct BgpError;

impl From<blackwall_bgp::BgpSendError> for BgpError {
    fn from(_: blackwall_bgp::BgpSendError) -> Self {
        Self
    }
}

/// A journal write failed.
#[derive(Debug, thiserror::Error)]
#[error("journal error: {0}")]
pub struct JournalError(pub String);

/// Outcome of [`RtbhManager::apply_add`].
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The target is now (or remains) an active blackhole.
    Applied,
    /// The target was not applied because the manager is at capacity; retry later.
    Deferred,
    /// The target was rejected outright (ineligible prefix or no next-hop for its family).
    Rejected(String),
}

/// Single-owner RTBH manager.
///
/// Owns the pure [`RtbhController`] plus the I/O boundary: it executes the
/// controller's decisions on a [`BgpExecutor`] and mirrors auto/manual state
/// via a [`BlackholeJournal`]. A BGP failure is logged and the action is not
/// journaled — but note this is a known limitation, not a retry mechanism:
/// on a failed first announce the controller entry is kept in memory while
/// the route itself is never re-announced automatically. A journal failure
/// after a successful BGP operation is logged, never causes a live
/// blackhole to be withdrawn, and is queued as a [`MirrorOp`] for a bounded
/// self-heal retry on the next [`RtbhManager::tick`] — the BGP outcome is
/// never re-issued, only the mirror write.
pub struct RtbhManager<B: BgpExecutor, J: BlackholeJournal> {
    controller: RtbhController,
    bgp: B,
    journal: J,
    /// Journal writes that failed after their BGP operation already
    /// succeeded; retried (never re-issued to BGP) by
    /// [`RtbhManager::retry_pending_mirror`] on the next tick.
    pending_mirror: Vec<MirrorOp>,
}

/// A journal mirror write that failed and is queued for a self-heal retry.
///
/// The BGP side of the operation already succeeded when this is queued, so
/// retrying only ever re-attempts the journal write — never BGP.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MirrorOp {
    /// Re-attempt `record_announce` for `target`.
    Announce {
        target: IpAddr,
        origin: BlackholeOrigin,
        at_ms: u64,
    },
    /// Re-attempt `record_withdraw` for `target`.
    Withdraw { target: IpAddr, at_ms: u64 },
}

impl MirrorOp {
    /// The blackhole target this mirror op concerns.
    fn target(&self) -> IpAddr {
        match *self {
            MirrorOp::Announce { target, .. } | MirrorOp::Withdraw { target, .. } => target,
        }
    }
}

impl<B: BgpExecutor, J: BlackholeJournal> RtbhManager<B, J> {
    /// Wrap a controller with a BGP executor and a journal.
    pub fn new(controller: RtbhController, bgp: B, journal: J) -> Self {
        Self {
            controller,
            bgp,
            journal,
            pending_mirror: Vec::new(),
        }
    }

    /// Feed one detection event through the controller and execute + journal
    /// the resulting actions.
    ///
    /// Announces are journaled as [`BlackholeOrigin::Auto`] (the only origin
    /// `on_event` can produce). A BGP error is logged and the action is not
    /// journaled. A journal error after a successful BGP operation is logged
    /// and queued for a self-heal retry on the next tick (the controller
    /// entry is kept — never withdraw a live blackhole because the DB write
    /// failed).
    pub async fn apply_event(&mut self, event: &DetectionEvent, mono_now: u64, wall_now: u64) {
        let actions = self.controller.on_event(event, mono_now);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Process time-driven withdrawals (deferred clears, TTL expiry) and
    /// execute + journal each one.
    ///
    /// Starts by retrying any journal mirror writes queued by a previous
    /// tick's transient failure (see [`RtbhManager::retry_pending_mirror`]),
    /// so a self-heal converges within one tick interval of the DB
    /// recovering.
    pub async fn tick(&mut self, mono_now: u64, wall_now: u64) {
        self.retry_pending_mirror().await;
        let actions = self.controller.tick(mono_now);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Manually blackhole a target.
    ///
    /// Returns [`ApplyOutcome::Applied`] if newly installed or upgraded from
    /// `Auto` to `Manual` (re-journaled as `Manual` in the latter case),
    /// [`ApplyOutcome::Deferred`] if the manager is at capacity, or
    /// [`ApplyOutcome::Rejected`] if the target is ineligible or has no
    /// next-hop for its address family.
    pub async fn apply_add(
        &mut self,
        target: IpAddr,
        mono_now: u64,
        wall_now: u64,
    ) -> ApplyOutcome {
        let actions = self.controller.manual_add(target, mono_now);
        if let Some(RtbhAction::Announce(route)) = actions.into_iter().next() {
            self.execute_and_journal_announce(target, route, BlackholeOrigin::Manual, wall_now)
                .await;
            return ApplyOutcome::Applied;
        }
        // Empty result: either already active (upgrade), at cap, or rejected.
        if self.is_active(target) {
            // Upgrade: promote the mirror to Manual.
            if let Err(e) = self
                .journal
                .record_announce(target, BlackholeOrigin::Manual, wall_now)
                .await
            {
                tracing::error!(%target, error = %e, "RTBH: journal write failed after manual upgrade; keeping active");
                // Self-heal the mirror on a later tick (issue #80).
                self.queue_mirror(MirrorOp::Announce {
                    target,
                    origin: BlackholeOrigin::Manual,
                    at_ms: wall_now,
                });
            }
            return ApplyOutcome::Applied;
        }
        if !self.controller.is_eligible(target) {
            return ApplyOutcome::Rejected(format!("{target} is outside eligible prefixes"));
        }
        if !self.controller.has_next_hop(target) {
            return ApplyOutcome::Rejected(format!("no next-hop configured for {target}'s family"));
        }
        ApplyOutcome::Deferred
    }

    /// Manually withdraw a target (bypasses hold-down).
    pub async fn apply_remove(&mut self, target: IpAddr, wall_now: u64) {
        let actions = self.controller.manual_remove(target);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Re-install persisted blackholes on a fresh session (rehydration).
    ///
    /// For each row, calls [`RtbhController::resume`] and re-announces on BGP
    /// (without journaling — the row already exists in the journal). If
    /// `resume` returns no action (over cap, ineligible, or no next-hop),
    /// this logs a warning naming the target; a row is never silently
    /// dropped.
    pub async fn rehydrate(&mut self, rows: Vec<(IpAddr, u64, BlackholeOrigin)>, mono_now: u64) {
        for (target, _persisted_at, origin) in rows {
            let actions = self.controller.resume(target, mono_now, origin);
            if let Some(RtbhAction::Announce(route)) = actions.into_iter().next() {
                if let Err(e) = self.bgp.announce(route).await {
                    tracing::warn!(%target, error = %e, "RTBH: rehydrate re-announce failed");
                }
                continue;
            }
            // resume() returned nothing: over cap, ineligible, or no next-hop.
            // A persisted row must never be silently dropped — always warn.
            let reason = if !self.controller.is_eligible(target) {
                "ineligible"
            } else if !self.controller.has_next_hop(target) {
                "no next-hop"
            } else {
                "at cap"
            };
            tracing::warn!(%target, reason, "RTBH: rehydrate dropped a persisted blackhole");
        }
    }

    /// Snapshot the active set (for reconcile mirroring, `list`, and tests).
    #[must_use]
    pub fn active(&self) -> Vec<(IpAddr, u64, BlackholeOrigin)> {
        self.controller.active_blackholes()
    }

    fn is_active(&self, target: IpAddr) -> bool {
        self.controller
            .active_blackholes()
            .iter()
            .any(|(t, ..)| *t == target)
    }

    /// Queue a failed mirror write for self-heal, coalescing by target.
    ///
    /// The mirror only needs to reflect the current active set, so keeping just
    /// the latest op per target is both correct (journal ops converge to a final
    /// state) and bounds the queue to one entry per target — a target that flaps
    /// while the DB is down can never grow the queue without bound.
    fn queue_mirror(&mut self, op: MirrorOp) {
        let target = op.target();
        self.pending_mirror.retain(|o| o.target() != target);
        self.pending_mirror.push(op);
    }

    /// Execute one controller action on BGP and mirror it into the journal.
    async fn execute_and_journal(&mut self, action: RtbhAction, wall_now: u64) {
        match action {
            RtbhAction::Announce(route) => {
                self.execute_and_journal_announce(
                    ip_of(&route.prefix),
                    route,
                    BlackholeOrigin::Auto,
                    wall_now,
                )
                .await;
            }
            RtbhAction::Withdraw(prefix) => {
                let target = ip_of(&prefix);
                if let Err(e) = self.bgp.withdraw(prefix).await {
                    tracing::warn!(%target, error = %e, "RTBH: BGP withdraw failed; not journaling");
                    return;
                }
                if let Err(e) = self.journal.record_withdraw(target, wall_now).await {
                    tracing::error!(%target, error = %e, "RTBH: journal withdraw-mirror failed; route already withdrawn from BGP (mirror row will be stale)");
                    self.queue_mirror(MirrorOp::Withdraw {
                        target,
                        at_ms: wall_now,
                    });
                }
            }
        }
    }

    async fn execute_and_journal_announce(
        &mut self,
        target: IpAddr,
        route: Route,
        origin: BlackholeOrigin,
        wall_now: u64,
    ) {
        if let Err(e) = self.bgp.announce(route).await {
            tracing::warn!(%target, error = %e, "RTBH: BGP announce failed; not journaling");
            return;
        }
        if let Err(e) = self.journal.record_announce(target, origin, wall_now).await {
            tracing::error!(%target, error = %e, "RTBH: journal write failed after announce; keeping active");
            self.queue_mirror(MirrorOp::Announce {
                target,
                origin,
                at_ms: wall_now,
            });
        }
    }

    /// Drain-retry queued mirror writes left over from a transient journal
    /// failure.
    ///
    /// The BGP side of each queued op already succeeded when it was queued,
    /// so this only ever re-attempts the matching journal call — it never
    /// re-announces or re-withdraws on BGP. Ops that still fail are kept
    /// (retried again on the next call); ops that succeed are dropped.
    /// Queued ops are retried in order, so an Announce followed by a later
    /// Withdraw for the same target converge correctly.
    async fn retry_pending_mirror(&mut self) {
        if self.pending_mirror.is_empty() {
            return;
        }
        let ops = std::mem::take(&mut self.pending_mirror);
        for op in ops {
            let result = match &op {
                MirrorOp::Announce {
                    target,
                    origin,
                    at_ms,
                } => self.journal.record_announce(*target, *origin, *at_ms).await,
                MirrorOp::Withdraw { target, at_ms } => {
                    self.journal.record_withdraw(*target, *at_ms).await
                }
            };
            if let Err(e) = result {
                tracing::warn!(op = ?op, error = %e, "RTBH: mirror self-heal retry failed; re-queuing");
                self.pending_mirror.push(op);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn bgp(&self) -> &B {
        &self.bgp
    }

    /// Number of journal mirror writes currently queued for self-heal retry.
    #[cfg(test)]
    pub(crate) fn pending_mirror_len(&self) -> usize {
        self.pending_mirror.len()
    }

    #[cfg(test)]
    pub(crate) fn journal(&self) -> &J {
        &self.journal
    }
}

/// Extract the host address out of a `/32` or `/128` prefix.
fn ip_of(prefix: &IpNet) -> IpAddr {
    prefix.addr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlackholeOrigin, RtbhConfig, RtbhController};
    use blackwall_flow::{AttackKind, Detection, DetectionEvent, Severity};
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeBgp {
        announced: Mutex<Vec<IpNet>>,
        withdrawn: Mutex<Vec<IpNet>>,
        fail: bool,
    }
    #[async_trait]
    impl BgpExecutor for FakeBgp {
        async fn announce(&self, route: Route) -> Result<(), BgpError> {
            if self.fail {
                return Err(BgpError);
            }
            self.announced.lock().unwrap().push(route.prefix);
            Ok(())
        }
        async fn withdraw(&self, prefix: IpNet) -> Result<(), BgpError> {
            if self.fail {
                return Err(BgpError);
            }
            self.withdrawn.lock().unwrap().push(prefix);
            Ok(())
        }
        // RtbhManager never calls the FlowSpec side of BgpExecutor; these two
        // arms exist only so this fake still implements the (now-shared)
        // trait. FlowSpecManager's own tests exercise a dedicated fake that
        // records these calls.
        async fn announce_flowspec(
            &self,
            _rule: blackwall_bgp::FlowSpecRule,
        ) -> Result<(), BgpError> {
            if self.fail {
                return Err(BgpError);
            }
            Ok(())
        }
        async fn withdraw_flowspec(
            &self,
            _rule: blackwall_bgp::FlowSpecRule,
        ) -> Result<(), BgpError> {
            if self.fail {
                return Err(BgpError);
            }
            Ok(())
        }
    }
    #[derive(Default)]
    struct FakeJournal {
        announced: Mutex<Vec<(IpAddr, BlackholeOrigin)>>,
        withdrawn: Mutex<Vec<IpAddr>>,
        fail: bool,
        /// Number of upcoming calls (announce or withdraw, whichever comes
        /// first) that should fail before the journal starts succeeding —
        /// simulates a transient DB blip that self-heals.
        fail_calls_remaining: Mutex<usize>,
    }
    #[async_trait]
    impl BlackholeJournal for FakeJournal {
        async fn record_announce(
            &self,
            t: IpAddr,
            o: BlackholeOrigin,
            _at: u64,
        ) -> Result<(), JournalError> {
            if self.fail || self.take_transient_failure() {
                return Err(JournalError("boom".into()));
            }
            self.announced.lock().unwrap().push((t, o));
            Ok(())
        }
        async fn record_withdraw(&self, t: IpAddr, _at: u64) -> Result<(), JournalError> {
            if self.fail || self.take_transient_failure() {
                return Err(JournalError("boom".into()));
            }
            self.withdrawn.lock().unwrap().push(t);
            Ok(())
        }
    }
    impl FakeJournal {
        /// Consume one remaining scheduled transient failure, if any.
        fn take_transient_failure(&self) -> bool {
            let mut remaining = self.fail_calls_remaining.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                true
            } else {
                false
            }
        }
    }
    fn cfg() -> RtbhConfig {
        RtbhConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            blackhole_communities: vec![(65535, 666)],
            next_hop_v4: Some("10.0.0.1".parse().unwrap()),
            next_hop_v6: None,
            max_blackholes: 2,
            hold_down: Duration::from_secs(10),
            max_ttl: None,
        }
    }
    fn det(ip: &str) -> Detection {
        Detection {
            target: ip.parse().unwrap(),
            kind: AttackKind::Volumetric,
            observed_pps: 1.0,
            observed_bps: 1.0,
            proto: 17,
            top_sources: vec![],
            top_ports: vec![],
            severity: Severity::High,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn mgr(fail_bgp: bool, fail_j: bool) -> RtbhManager<FakeBgp, FakeJournal> {
        RtbhManager::new(
            RtbhController::new(cfg()),
            FakeBgp {
                fail: fail_bgp,
                ..Default::default()
            },
            FakeJournal {
                fail: fail_j,
                ..Default::default()
            },
        )
    }

    /// A manager whose journal fails its first `n` calls (BGP transient
    /// blip), then succeeds — used to exercise the mirror self-heal retry.
    fn mgr_transient_journal_failures(n: usize) -> RtbhManager<FakeBgp, FakeJournal> {
        RtbhManager::new(
            RtbhController::new(cfg()),
            FakeBgp::default(),
            FakeJournal {
                fail_calls_remaining: Mutex::new(n),
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn opened_announces_and_journals_auto() {
        let mut m = mgr(false, false);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 1000, 5000)
            .await;
        assert_eq!(m.active().len(), 1);
        assert_eq!(m.bgp().announced.lock().unwrap().len(), 1);
        assert_eq!(
            m.journal().announced.lock().unwrap()[0],
            (ip("203.0.113.7"), BlackholeOrigin::Auto)
        );
    }

    #[tokio::test]
    async fn manual_add_then_auto_clear_keeps_it() {
        let mut m = mgr(false, false);
        assert_eq!(
            m.apply_add(ip("203.0.113.7"), 0, 0).await,
            ApplyOutcome::Applied
        );
        m.apply_event(
            &DetectionEvent::Cleared {
                target: ip("203.0.113.7"),
                at_ms: 100_000,
            },
            100_000,
            0,
        )
        .await;
        m.tick(200_000, 0).await;
        assert_eq!(m.active().len(), 1, "manual survives auto-clear + tick");
    }

    #[tokio::test]
    async fn tick_completes_deferred_withdraw() {
        let mut m = mgr(false, false);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 0)
            .await;
        m.apply_event(
            &DetectionEvent::Cleared {
                target: ip("203.0.113.7"),
                at_ms: 5000,
            },
            5000,
            0,
        )
        .await;
        assert_eq!(m.active().len(), 1, "deferred, not yet withdrawn");
        m.tick(10_000, 0).await;
        assert!(m.active().is_empty(), "tick withdraws after hold-down");
        assert_eq!(m.bgp().withdrawn.lock().unwrap().len(), 1);
        assert_eq!(m.journal().withdrawn.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn journal_failure_keeps_active() {
        let mut m = mgr(false, true); // journal fails
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 0)
            .await;
        assert_eq!(
            m.active().len(),
            1,
            "a journal error must not drop a live blackhole"
        );
    }

    #[tokio::test]
    async fn bgp_failure_does_not_journal() {
        let mut m = mgr(true, false); // BGP fails
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 0)
            .await;
        assert!(
            m.journal().announced.lock().unwrap().is_empty(),
            "a BGP failure must not be journaled"
        );
    }

    #[tokio::test]
    async fn apply_add_rejects_ineligible_and_defers_at_cap() {
        let mut m = mgr(false, false);
        assert!(matches!(
            m.apply_add(ip("198.51.100.9"), 0, 0).await,
            ApplyOutcome::Rejected(_)
        ));
        assert_eq!(
            m.apply_add(ip("203.0.113.1"), 0, 0).await,
            ApplyOutcome::Applied
        );
        assert_eq!(
            m.apply_add(ip("203.0.113.2"), 0, 0).await,
            ApplyOutcome::Applied
        ); // cap=2
        assert_eq!(
            m.apply_add(ip("203.0.113.3"), 0, 0).await,
            ApplyOutcome::Deferred
        );
    }

    #[tokio::test]
    async fn apply_add_upgrade_rejournals_as_manual() {
        let mut m = mgr(false, false);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 0)
            .await;
        assert_eq!(
            m.apply_add(ip("203.0.113.7"), 1000, 2000).await,
            ApplyOutcome::Applied
        );
        let recorded = m.journal().announced.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].1, BlackholeOrigin::Auto);
        assert_eq!(recorded[1].1, BlackholeOrigin::Manual);
    }

    #[tokio::test]
    async fn apply_remove_withdraws_and_journals() {
        let mut m = mgr(false, false);
        m.apply_add(ip("203.0.113.7"), 0, 0).await;
        m.apply_remove(ip("203.0.113.7"), 1000).await;
        assert!(m.active().is_empty());
        assert_eq!(m.journal().withdrawn.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rehydrate_reannounces() {
        let mut m = mgr(false, false);
        m.rehydrate(
            vec![(ip("203.0.113.5"), 111, BlackholeOrigin::Manual)],
            9000,
        )
        .await;
        assert_eq!(m.active().len(), 1);
        assert_eq!(m.bgp().announced.lock().unwrap().len(), 1);
        // rehydrate never journals — the row already exists.
        assert!(m.journal().announced.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rehydrate_warns_and_does_not_drop_silently_when_ineligible() {
        // Ineligible target: resume() returns empty and is not active either.
        // We can't assert on the log directly, but we can assert it does not panic
        // and the row is simply absent from active() (documented, not a silent drop
        // from the caller's perspective since a warning is emitted).
        let mut m = mgr(false, false);
        m.rehydrate(
            vec![(ip("198.51.100.9"), 111, BlackholeOrigin::Manual)],
            9000,
        )
        .await;
        assert!(m.active().is_empty());
    }

    #[tokio::test]
    async fn journal_failure_queues_pending_mirror() {
        // journal fails its one and only scheduled call (the announce).
        let mut m = mgr_transient_journal_failures(1);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 1234)
            .await;
        assert_eq!(
            m.active().len(),
            1,
            "a journal error must not drop a live blackhole"
        );
        assert!(
            m.journal().announced.lock().unwrap().is_empty(),
            "the failed announce must not have been recorded"
        );
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "the failed mirror write must be queued for self-heal retry"
        );
    }

    #[tokio::test]
    async fn tick_drains_pending_mirror_once_journal_recovers() {
        // journal fails only the first call (the announce); by the time
        // tick() retries, it's healthy again.
        let mut m = mgr_transient_journal_failures(1);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 1234)
            .await;
        assert_eq!(m.pending_mirror_len(), 1);
        assert!(m.journal().announced.lock().unwrap().is_empty());

        // Journal is healthy now (the scheduled failure was already
        // consumed); the tick's leading retry_pending_mirror() should drain
        // the queued announce.
        m.tick(1000, 5000).await;

        assert_eq!(
            m.pending_mirror_len(),
            0,
            "the self-heal retry must drain the queue once the journal recovers"
        );
        assert_eq!(
            m.journal().announced.lock().unwrap()[0],
            (ip("203.0.113.7"), BlackholeOrigin::Auto),
            "the retried announce must have been recorded with its original origin"
        );
    }

    #[tokio::test]
    async fn retry_pending_mirror_requeues_on_repeat_failure() {
        // journal fails every call: the queued op must survive repeated
        // retries rather than being silently dropped.
        let mut m = mgr(false, true);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 1234)
            .await;
        assert_eq!(m.pending_mirror_len(), 1);

        m.tick(1000, 5000).await;

        assert_eq!(
            m.pending_mirror_len(),
            1,
            "a still-failing journal must keep the op queued, not drop it"
        );
        assert!(m.journal().announced.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn queued_announce_then_withdraw_for_same_target_coalesces_to_withdraw() {
        // Announce fails and is queued; a later withdraw for the SAME target
        // also fails. Coalescing keeps only the latest op (the withdraw): the
        // mirror only needs to reflect the final state (target no longer active),
        // and this bounds the queue to one entry per target.
        let mut m = mgr_transient_journal_failures(2);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 1000)
            .await;
        assert_eq!(m.pending_mirror_len(), 1);

        m.apply_remove(ip("203.0.113.7"), 2000).await;
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "the withdraw coalesces with the queued announce for the same target"
        );
        assert!(m.active().is_empty(), "BGP withdraw must still take effect");

        m.tick(3000, 4000).await;

        assert_eq!(m.pending_mirror_len(), 0);
        // Only the withdraw is replayed; the superseded announce is dropped.
        assert!(m.journal().announced.lock().unwrap().is_empty());
        assert_eq!(m.journal().withdrawn.lock().unwrap()[0], ip("203.0.113.7"));
    }

    #[tokio::test]
    async fn queue_mirror_coalesces_repeated_failures_for_one_target() {
        // A single target flapping while the journal is down must never grow
        // the queue past one entry for that target.
        let mut m = mgr(false, true); // BGP ok, journal always fails
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 1000)
            .await;
        m.apply_remove(ip("203.0.113.7"), 2000).await;
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 3000, 3000)
            .await;
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "repeated failures for one target coalesce to a single queued op"
        );
    }

    #[tokio::test]
    async fn manual_upgrade_journal_failure_self_heals_as_manual() {
        // An Auto entry is active but its mirror write failed; the operator
        // upgrades it to Manual and THAT journal write also fails. The self-heal
        // must record the upgrade as Manual (issue #80), not leave the mirror
        // stuck as Auto.
        let mut m = mgr_transient_journal_failures(2); // announce + upgrade fail, then heal
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 100)
            .await;
        assert_eq!(
            m.apply_add(ip("203.0.113.7"), 200, 200).await,
            ApplyOutcome::Applied
        );
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "the upgrade's failed mirror write is queued for self-heal"
        );

        m.tick(1000, 1000).await; // journal healthy now -> drains

        assert_eq!(m.pending_mirror_len(), 0);
        assert_eq!(
            *m.journal().announced.lock().unwrap(),
            vec![(ip("203.0.113.7"), BlackholeOrigin::Manual)],
            "self-heal recorded the Manual upgrade, not the stale Auto origin"
        );
    }
}
