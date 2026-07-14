//! Single-owner FlowSpec manager: executes controller decisions on BGP and
//! mirrors auto/manual rule state into a persistence journal.
//!
//! The FlowSpec analogue of [`crate::manager::RtbhManager`]: the pure
//! [`FlowSpecController`] decides; this module owns the I/O boundary (BGP
//! session + journal), reusing [`crate::manager::BgpExecutor`] (extended with
//! the FlowSpec announce/withdraw methods) and a dedicated [`FlowSpecJournal`]
//! seam so `blackwall-rtbh` stays free of any DB dependency. Every invariant
//! of `RtbhManager` carries over, adapted from a single blackholed IP to a
//! target's multiple `(protocol, port)` rules keyed by [`FlowKey`]: the
//! `pending_mirror` self-heal is coalesced by `FlowKey` instead of by target
//! IP, a fallible journal write keeps the rule active on failure, and a BGP
//! failure is never journaled (no phantom rule).

use crate::controller::BlackholeOrigin;
use crate::flowspec_controller::{key_of, FlowKey, FlowSpecAction, FlowSpecController};
use crate::manager::{ApplyOutcome, BgpExecutor, JournalError};
use async_trait::async_trait;
use blackwall_bgp::FlowSpecRule;
use blackwall_flow::FlowRule;
use std::net::IpAddr;

/// Mirrors FlowSpec rule state into persistent storage.
///
/// This is the sole seam through which the FlowSpec side of `blackwall-rtbh`
/// would touch a database — the crate itself never depends on one.
/// Implemented elsewhere (e.g. the control-plane crate that owns the DB) and
/// injected here. See [`crate::manager::BlackholeJournal`] for the RTBH
/// analogue.
#[async_trait]
pub trait FlowSpecJournal: Send + Sync {
    /// Record that `rule` is now announced, with the given origin.
    async fn record_announce(
        &self,
        rule: FlowSpecRule,
        origin: BlackholeOrigin,
        at_ms: u64,
    ) -> Result<(), JournalError>;
    /// Record that `rule` is no longer announced.
    async fn record_withdraw(&self, rule: FlowSpecRule, at_ms: u64) -> Result<(), JournalError>;
}

/// A journal mirror write that failed and is queued for a self-heal retry.
///
/// The BGP side of the operation already succeeded when this is queued, so
/// retrying only ever re-attempts the journal write — never BGP. Mirrors
/// [`crate::manager`]'s private `MirrorOp`, keyed by [`FlowKey`] instead of
/// target IP (a target may have several concurrently-queued rules).
#[derive(Debug, Clone, PartialEq)]
enum MirrorOp {
    /// Re-attempt `record_announce` for `rule`.
    Announce {
        rule: FlowSpecRule,
        origin: BlackholeOrigin,
        at_ms: u64,
    },
    /// Re-attempt `record_withdraw` for `rule`.
    Withdraw { rule: FlowSpecRule, at_ms: u64 },
}

impl MirrorOp {
    /// The `FlowKey` this mirror op concerns.
    fn key(&self) -> FlowKey {
        match self {
            MirrorOp::Announce { rule, .. } | MirrorOp::Withdraw { rule, .. } => key_of(rule),
        }
    }
}

/// Single-owner FlowSpec manager.
///
/// Owns the pure [`FlowSpecController`] plus the I/O boundary: it executes the
/// controller's decisions on a [`BgpExecutor`] and mirrors auto/manual rule
/// state via a [`FlowSpecJournal`]. A BGP failure is logged and the action is
/// not journaled — but note this is a known limitation, not a retry
/// mechanism: on a failed first announce the controller entry is kept in
/// memory while the rule itself is never re-announced automatically. A
/// journal failure after a successful BGP operation is logged, never causes a
/// live rule to be withdrawn, and is queued as a `MirrorOp` for a bounded
/// self-heal retry on the next [`FlowSpecManager::tick`] — the BGP outcome is
/// never re-issued, only the mirror write.
pub struct FlowSpecManager<B: BgpExecutor, J: FlowSpecJournal> {
    controller: FlowSpecController,
    bgp: B,
    journal: J,
    /// Journal writes that failed after their BGP operation already
    /// succeeded; retried (never re-issued to BGP) by
    /// `FlowSpecManager::retry_pending_mirror` on the next tick.
    pending_mirror: Vec<MirrorOp>,
}

impl<B: BgpExecutor, J: FlowSpecJournal> FlowSpecManager<B, J> {
    /// Wrap a controller with a BGP executor and a journal.
    pub fn new(controller: FlowSpecController, bgp: B, journal: J) -> Self {
        Self {
            controller,
            bgp,
            journal,
            pending_mirror: Vec::new(),
        }
    }

    /// Install the flow-scoped rules selected for `target` (from a
    /// [`blackwall_flow::FlowMitigationEvent::Open`]) and execute + journal
    /// the resulting announces.
    ///
    /// Announces are journaled as [`BlackholeOrigin::Auto`] (the only origin
    /// this path can produce). A BGP error is logged and the action is not
    /// journaled. A journal error after a successful BGP operation is logged
    /// and queued for a self-heal retry on the next tick (the controller
    /// entry is kept — never withdraw a live rule because the DB write
    /// failed).
    pub async fn apply_open(
        &mut self,
        target: IpAddr,
        rules: &[FlowRule],
        mono_now: u64,
        wall_now: u64,
    ) {
        let tuples: Vec<(u8, u16, f32)> = rules
            .iter()
            .map(|r| (r.proto, r.dst_port, r.rate))
            .collect();
        let actions = self.controller.install(target, &tuples, mono_now);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Clear every active rule for `target` (from a
    /// [`blackwall_flow::FlowMitigationEvent::Clear`]) and execute + journal
    /// the withdraws that clear immediately (hold-down permitting; the rest
    /// are deferred to a later [`Self::tick`]).
    pub async fn apply_clear(&mut self, target: IpAddr, mono_now: u64, wall_now: u64) {
        let actions = self.controller.clear_target(target, mono_now);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Re-assert `target`'s active rules (from a
    /// [`blackwall_flow::FlowMitigationEvent::Update`]), cancelling any
    /// pending deferred clear and refreshing the TTL anchor.
    ///
    /// `Update` carries only the target IP (not the concrete rules), so unlike
    /// `apply_open` this cannot re-run `install`; it instead calls
    /// [`FlowSpecController::refresh_target`], a minimal target-refresh entry
    /// point added for this purpose. No BGP call or journal write is needed —
    /// the rule is already announced and already mirrored; only the
    /// controller's in-memory bookkeeping changes.
    pub fn apply_updated(&mut self, target: IpAddr, mono_now: u64) {
        self.controller.refresh_target(target, mono_now);
    }

    /// Process time-driven withdrawals (deferred clears, TTL expiry) and
    /// execute + journal each one.
    ///
    /// Starts by retrying any journal mirror writes queued by a previous
    /// tick's transient failure (see
    /// `FlowSpecManager::retry_pending_mirror`), so a self-heal converges
    /// within one tick interval of the DB recovering.
    pub async fn tick(&mut self, mono_now: u64, wall_now: u64) {
        self.retry_pending_mirror().await;
        let actions = self.controller.tick(mono_now);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Manually install a FlowSpec rule.
    ///
    /// Returns [`ApplyOutcome::Applied`] if newly installed or upgraded from
    /// `Auto` to `Manual` (re-journaled as `Manual` in the latter case),
    /// [`ApplyOutcome::Deferred`] if the manager is at capacity, or
    /// [`ApplyOutcome::Rejected`] if the target is protected or ineligible.
    /// Unlike RTBH, FlowSpec carries no next-hop, so there is no next-hop
    /// rejection case.
    pub async fn apply_add(
        &mut self,
        rule: FlowSpecRule,
        mono_now: u64,
        wall_now: u64,
    ) -> ApplyOutcome {
        let key = key_of(&rule);
        let target = rule.dst.addr();
        let actions = self.controller.manual_add(rule.clone(), mono_now);
        if let Some(FlowSpecAction::Announce(r)) = actions.into_iter().next() {
            self.execute_and_journal_announce(r, BlackholeOrigin::Manual, wall_now)
                .await;
            return ApplyOutcome::Applied;
        }
        // Empty result: either already active (upgrade), at cap, or rejected.
        if self.is_active(key) {
            // Upgrade: promote the mirror to Manual.
            if let Err(e) = self
                .journal
                .record_announce(rule.clone(), BlackholeOrigin::Manual, wall_now)
                .await
            {
                tracing::error!(%target, error = %e, "FlowSpec: journal write failed after manual upgrade; keeping active");
                self.queue_mirror(MirrorOp::Announce {
                    rule,
                    origin: BlackholeOrigin::Manual,
                    at_ms: wall_now,
                });
            }
            return ApplyOutcome::Applied;
        }
        // Checked before eligibility: a protected target is typically ALSO
        // eligible (that's the point — protected VIPs live inside eligible
        // prefixes), so it must be rejected outright here rather than falling
        // through to Deferred, which would retry forever and never resolve.
        if self.controller.is_protected(target) {
            return ApplyOutcome::Rejected(format!(
                "{target} is inside a protected prefix and is never mitigated"
            ));
        }
        if !self.controller.is_eligible(target) {
            return ApplyOutcome::Rejected(format!("{target} is outside eligible prefixes"));
        }
        ApplyOutcome::Deferred
    }

    /// Manually withdraw a rule (bypasses hold-down).
    pub async fn apply_remove(&mut self, rule: FlowSpecRule, wall_now: u64) {
        let actions = self.controller.manual_remove(rule);
        for action in actions {
            self.execute_and_journal(action, wall_now).await;
        }
    }

    /// Re-install persisted FlowSpec rules on a fresh session (rehydration).
    ///
    /// For each row, calls [`FlowSpecController::resume`] and re-announces on
    /// BGP (without journaling — the row already exists in the journal). If
    /// `resume` returns no action (over cap or ineligible), this logs a
    /// warning naming the target; a row is never silently dropped.
    pub async fn rehydrate(
        &mut self,
        rows: Vec<(FlowSpecRule, u64, BlackholeOrigin)>,
        mono_now: u64,
    ) {
        for (rule, _persisted_at, origin) in rows {
            let target = rule.dst.addr();
            let actions = self.controller.resume(rule.clone(), mono_now, origin);
            if let Some(FlowSpecAction::Announce(r)) = actions.into_iter().next() {
                if let Err(e) = self.bgp.announce_flowspec(r).await {
                    tracing::warn!(%target, error = %e, "FlowSpec: rehydrate re-announce failed");
                }
                continue;
            }
            // resume() returned nothing: over cap or ineligible. A persisted
            // row must never be silently dropped — always warn.
            let reason = if self.controller.is_eligible(target) {
                "at cap"
            } else {
                "ineligible"
            };
            tracing::warn!(%target, reason, "FlowSpec: rehydrate dropped a persisted rule");
        }
    }

    /// Snapshot the active set (for reconcile mirroring, `list`, and tests).
    #[must_use]
    pub fn active(&self) -> Vec<(FlowKey, u64, BlackholeOrigin)> {
        self.controller.active_rules()
    }

    /// Number of targets skipped by the controller's protected-prefix guard
    /// (own anycast VIPs never mitigated). Surfaced for `/metrics`; see
    /// [`crate::manager::RtbhManager::protected_skipped`] for the analogous
    /// RTBH accessor.
    #[must_use]
    pub fn protected_skipped(&self) -> u64 {
        self.controller.protected_skipped()
    }

    fn is_active(&self, key: FlowKey) -> bool {
        self.controller
            .active_rules()
            .iter()
            .any(|(k, ..)| *k == key)
    }

    /// Queue a failed mirror write for self-heal, coalescing by [`FlowKey`].
    ///
    /// The mirror only needs to reflect the current active set, so keeping just
    /// the latest op per key is both correct (journal ops converge to a final
    /// state) and bounds the queue to one entry per rule — a rule that flaps
    /// while the DB is down can never grow the queue without bound.
    fn queue_mirror(&mut self, op: MirrorOp) {
        let key = op.key();
        self.pending_mirror.retain(|o| o.key() != key);
        self.pending_mirror.push(op);
    }

    /// Execute one controller action on BGP and mirror it into the journal.
    async fn execute_and_journal(&mut self, action: FlowSpecAction, wall_now: u64) {
        match action {
            FlowSpecAction::Announce(rule) => {
                self.execute_and_journal_announce(rule, BlackholeOrigin::Auto, wall_now)
                    .await;
            }
            FlowSpecAction::Withdraw(rule) => {
                let key = key_of(&rule);
                if let Err(e) = self.bgp.withdraw_flowspec(rule.clone()).await {
                    tracing::warn!(?key, error = %e, "FlowSpec: BGP withdraw failed; not journaling");
                    return;
                }
                if let Err(e) = self.journal.record_withdraw(rule.clone(), wall_now).await {
                    tracing::error!(?key, error = %e, "FlowSpec: journal withdraw-mirror failed; rule already withdrawn from BGP (mirror row will be stale)");
                    self.queue_mirror(MirrorOp::Withdraw {
                        rule,
                        at_ms: wall_now,
                    });
                }
            }
        }
    }

    async fn execute_and_journal_announce(
        &mut self,
        rule: FlowSpecRule,
        origin: BlackholeOrigin,
        wall_now: u64,
    ) {
        let key = key_of(&rule);
        if let Err(e) = self.bgp.announce_flowspec(rule.clone()).await {
            tracing::warn!(?key, error = %e, "FlowSpec: BGP announce failed; not journaling");
            return;
        }
        if let Err(e) = self
            .journal
            .record_announce(rule.clone(), origin, wall_now)
            .await
        {
            tracing::error!(?key, error = %e, "FlowSpec: journal write failed after announce; keeping active");
            self.queue_mirror(MirrorOp::Announce {
                rule,
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
    /// Withdraw for the same key converge correctly.
    async fn retry_pending_mirror(&mut self) {
        if self.pending_mirror.is_empty() {
            return;
        }
        let ops = std::mem::take(&mut self.pending_mirror);
        for op in ops {
            let result = match &op {
                MirrorOp::Announce {
                    rule,
                    origin,
                    at_ms,
                } => {
                    self.journal
                        .record_announce(rule.clone(), *origin, *at_ms)
                        .await
                }
                MirrorOp::Withdraw { rule, at_ms } => {
                    self.journal.record_withdraw(rule.clone(), *at_ms).await
                }
            };
            if let Err(e) = result {
                tracing::warn!(op = ?op, error = %e, "FlowSpec: mirror self-heal retry failed; re-queuing");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flowspec_controller::FlowSpecConfig;
    use blackwall_bgp::FlowAction;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeBgp {
        announced: Mutex<Vec<FlowSpecRule>>,
        withdrawn: Mutex<Vec<FlowSpecRule>>,
        fail: bool,
    }
    #[async_trait]
    impl BgpExecutor for FakeBgp {
        async fn announce(
            &self,
            _route: blackwall_bgp::Route,
        ) -> Result<(), crate::manager::BgpError> {
            unreachable!("FlowSpecManager never calls the RTBH side of BgpExecutor")
        }
        async fn withdraw(&self, _prefix: ipnet::IpNet) -> Result<(), crate::manager::BgpError> {
            unreachable!("FlowSpecManager never calls the RTBH side of BgpExecutor")
        }
        async fn announce_flowspec(
            &self,
            rule: FlowSpecRule,
        ) -> Result<(), crate::manager::BgpError> {
            if self.fail {
                return Err(crate::manager::BgpError);
            }
            self.announced.lock().unwrap().push(rule);
            Ok(())
        }
        async fn withdraw_flowspec(
            &self,
            rule: FlowSpecRule,
        ) -> Result<(), crate::manager::BgpError> {
            if self.fail {
                return Err(crate::manager::BgpError);
            }
            self.withdrawn.lock().unwrap().push(rule);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeJournal {
        announced: Mutex<Vec<(FlowSpecRule, BlackholeOrigin)>>,
        withdrawn: Mutex<Vec<FlowSpecRule>>,
        fail: bool,
        /// Number of upcoming calls (announce or withdraw, whichever comes
        /// first) that should fail before the journal starts succeeding —
        /// simulates a transient DB blip that self-heals.
        fail_calls_remaining: Mutex<usize>,
    }
    #[async_trait]
    impl FlowSpecJournal for FakeJournal {
        async fn record_announce(
            &self,
            rule: FlowSpecRule,
            origin: BlackholeOrigin,
            _at: u64,
        ) -> Result<(), JournalError> {
            if self.fail || self.take_transient_failure() {
                return Err(JournalError("boom".into()));
            }
            self.announced.lock().unwrap().push((rule, origin));
            Ok(())
        }
        async fn record_withdraw(&self, rule: FlowSpecRule, _at: u64) -> Result<(), JournalError> {
            if self.fail || self.take_transient_failure() {
                return Err(JournalError("boom".into()));
            }
            self.withdrawn.lock().unwrap().push(rule);
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

    fn cfg() -> FlowSpecConfig {
        FlowSpecConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            max_rules: 2,
            hold_down: Duration::from_secs(10),
            max_ttl: None,
            protected_prefixes: Vec::new(),
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn flow_rule(dst: &str, proto: u8, dst_port: u16, rate: f32) -> FlowRule {
        FlowRule {
            dst: ip(dst),
            proto,
            dst_port,
            rate,
        }
    }
    fn rule(dst: &str, protocol: u8, dst_port: u16, rate: f32) -> FlowSpecRule {
        FlowSpecRule {
            dst: dst.parse().unwrap(),
            protocol: Some(protocol),
            dst_port: Some(dst_port),
            action: FlowAction::TrafficRate(rate),
        }
    }
    fn mgr(fail_bgp: bool, fail_j: bool) -> FlowSpecManager<FakeBgp, FakeJournal> {
        FlowSpecManager::new(
            FlowSpecController::new(cfg()),
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
    fn mgr_transient_journal_failures(n: usize) -> FlowSpecManager<FakeBgp, FakeJournal> {
        FlowSpecManager::new(
            FlowSpecController::new(cfg()),
            FakeBgp::default(),
            FakeJournal {
                fail_calls_remaining: Mutex::new(n),
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn apply_open_announces_and_journals_each_rule() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[
                flow_rule("203.0.113.7", 17, 53, 0.0),
                flow_rule("203.0.113.7", 6, 80, 500.0),
            ],
            0,
            5000,
        )
        .await;
        assert_eq!(m.active().len(), 2);
        assert_eq!(m.bgp().announced.lock().unwrap().len(), 2);
        assert_eq!(m.journal().announced.lock().unwrap().len(), 2);
        for (_, origin) in m.journal().announced.lock().unwrap().iter() {
            assert_eq!(*origin, BlackholeOrigin::Auto);
        }
    }

    #[tokio::test]
    async fn apply_clear_withdraws_all_target_flows() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[
                flow_rule("203.0.113.7", 17, 53, 0.0),
                flow_rule("203.0.113.7", 6, 80, 0.0),
            ],
            0,
            0,
        )
        .await;
        // past the 10s hold-down: withdraws immediately.
        m.apply_clear(ip("203.0.113.7"), 10_000, 10_000).await;
        assert!(m.active().is_empty());
        assert_eq!(m.bgp().withdrawn.lock().unwrap().len(), 2);
        assert_eq!(m.journal().withdrawn.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn apply_clear_defers_within_hold_down_then_tick_withdraws() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            0,
        )
        .await;
        m.apply_clear(ip("203.0.113.7"), 5000, 0).await;
        assert_eq!(m.active().len(), 1, "deferred, not yet withdrawn");
        m.tick(10_000, 0).await;
        assert!(m.active().is_empty(), "tick withdraws after hold-down");
    }

    #[tokio::test]
    async fn apply_updated_cancels_pending_clear() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            0,
        )
        .await;
        m.apply_clear(ip("203.0.113.7"), 5000, 0).await;
        assert_eq!(m.active().len(), 1, "deferred, not yet withdrawn");
        m.apply_updated(ip("203.0.113.7"), 6000);
        m.tick(10_000, 0).await;
        assert_eq!(
            m.active().len(),
            1,
            "Update cancelled the pending clear before the deferred hold-down elapsed"
        );
    }

    #[tokio::test]
    async fn journal_failure_keeps_active_and_queues_pending_mirror() {
        let mut m = mgr(false, true); // journal fails
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            0,
        )
        .await;
        assert_eq!(
            m.active().len(),
            1,
            "a journal error must not drop a live FlowSpec rule"
        );
        assert!(
            m.journal().announced.lock().unwrap().is_empty(),
            "the failed announce must not have been recorded"
        );
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "the failed mirror write must be queued for self-heal"
        );
    }

    #[tokio::test]
    async fn bgp_failure_does_not_journal() {
        let mut m = mgr(true, false); // BGP fails
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            0,
        )
        .await;
        assert!(
            m.journal().announced.lock().unwrap().is_empty(),
            "a BGP failure must not be journaled (no phantom rule)"
        );
        assert!(
            m.bgp().announced.lock().unwrap().is_empty(),
            "and of course BGP itself recorded nothing"
        );
    }

    #[tokio::test]
    async fn tick_drains_pending_mirror_once_journal_recovers() {
        let mut m = mgr_transient_journal_failures(1);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            1234,
        )
        .await;
        assert_eq!(m.pending_mirror_len(), 1);
        assert!(m.journal().announced.lock().unwrap().is_empty());

        m.tick(1000, 5000).await;

        assert_eq!(m.pending_mirror_len(), 0);
        assert_eq!(m.journal().announced.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retry_pending_mirror_requeues_on_repeat_failure() {
        let mut m = mgr(false, true); // journal always fails
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            1234,
        )
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
    async fn apply_add_then_remove() {
        let mut m = mgr(false, false);
        let r = rule("203.0.113.7/32", 17, 53, 0.0);
        assert_eq!(m.apply_add(r.clone(), 0, 0).await, ApplyOutcome::Applied);
        assert_eq!(m.active().len(), 1);
        assert_eq!(
            m.journal().announced.lock().unwrap()[0].1,
            BlackholeOrigin::Manual
        );
        m.apply_remove(r, 1000).await;
        assert!(m.active().is_empty());
        assert_eq!(m.journal().withdrawn.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apply_add_upgrade_rejournals_as_manual() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            0,
        )
        .await;
        let r = rule("203.0.113.7/32", 17, 53, 0.0);
        assert_eq!(m.apply_add(r, 1000, 2000).await, ApplyOutcome::Applied);
        let recorded = m.journal().announced.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].1, BlackholeOrigin::Auto);
        assert_eq!(recorded[1].1, BlackholeOrigin::Manual);
    }

    #[tokio::test]
    async fn apply_add_rejects_ineligible_and_defers_at_cap() {
        let mut m = mgr(false, false); // cap = 2
        assert!(matches!(
            m.apply_add(rule("198.51.100.9/32", 17, 53, 0.0), 0, 0)
                .await,
            ApplyOutcome::Rejected(_)
        ));
        assert_eq!(
            m.apply_add(rule("203.0.113.1/32", 17, 53, 0.0), 0, 0).await,
            ApplyOutcome::Applied
        );
        assert_eq!(
            m.apply_add(rule("203.0.113.1/32", 6, 80, 0.0), 0, 0).await,
            ApplyOutcome::Applied
        ); // cap=2
        assert_eq!(
            m.apply_add(rule("203.0.113.1/32", 6, 443, 0.0), 0, 0).await,
            ApplyOutcome::Deferred
        );
    }

    #[tokio::test]
    async fn apply_add_protected_target_is_rejected_not_deferred() {
        // Target sits inside BOTH an eligible prefix and a protected prefix —
        // exactly the overlap the protected-prefix guard exists for (an
        // anycast VIP inside a customer-eligible block). A manual add must be
        // classified as Rejected, not Deferred: a Deferred outcome leaves the
        // request row 'pending' forever, retried every tick, indistinguishable
        // from a transient capacity wait that will never resolve (C1 follow-up).
        let mut m = FlowSpecManager::new(
            FlowSpecController::new(FlowSpecConfig {
                protected_prefixes: vec!["203.0.113.53/32".parse().unwrap()],
                ..cfg()
            }),
            FakeBgp::default(),
            FakeJournal::default(),
        );
        let outcome = m
            .apply_add(rule("203.0.113.53/32", 17, 53, 0.0), 0, 0)
            .await;
        match &outcome {
            ApplyOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("protected"),
                    "reason should mention 'protected': {reason}"
                );
            }
            other => panic!("protected target must be Rejected, not {other:?}"),
        }
        assert!(m.active().is_empty());
        assert!(
            m.bgp().announced.lock().unwrap().is_empty(),
            "no Announce may be executed for a protected target"
        );
    }

    #[tokio::test]
    async fn rehydrate_reannounces() {
        let mut m = mgr(false, false);
        m.rehydrate(
            vec![(
                rule("203.0.113.5/32", 17, 53, 0.0),
                111,
                BlackholeOrigin::Manual,
            )],
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
        let mut m = mgr(false, false);
        m.rehydrate(
            vec![(
                rule("198.51.100.9/32", 17, 53, 0.0),
                111,
                BlackholeOrigin::Manual,
            )],
            9000,
        )
        .await;
        assert!(m.active().is_empty());
    }

    #[tokio::test]
    async fn queue_mirror_coalesces_repeated_failures_for_one_key() {
        // A single rule flapping while the journal is down must never grow
        // the queue past one entry for that key.
        let mut m = mgr(false, true); // BGP ok, journal always fails
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            1000,
        )
        .await;
        m.apply_remove(rule("203.0.113.7/32", 17, 53, 0.0), 2000)
            .await;
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            3000,
            3000,
        )
        .await;
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "repeated failures for one key coalesce to a single queued op"
        );
    }

    #[tokio::test]
    async fn queued_announce_then_withdraw_for_same_key_coalesces_to_withdraw() {
        let mut m = mgr_transient_journal_failures(2);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            0,
            1000,
        )
        .await;
        assert_eq!(m.pending_mirror_len(), 1);

        m.apply_remove(rule("203.0.113.7/32", 17, 53, 0.0), 2000)
            .await;
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "the withdraw coalesces with the queued announce for the same key"
        );
        assert!(m.active().is_empty(), "BGP withdraw must still take effect");

        m.tick(3000, 4000).await;

        assert_eq!(m.pending_mirror_len(), 0);
        assert!(m.journal().announced.lock().unwrap().is_empty());
        assert_eq!(m.journal().withdrawn.lock().unwrap().len(), 1);
    }
}
