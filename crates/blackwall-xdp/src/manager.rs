//! Single-owner XDP manager: executes controller decisions on the eBPF maps
//! and mirrors auto/manual state into a persistence journal.
//!
//! The [`XdpController`] is pure (no I/O); this module owns the controller
//! plus the I/O boundary (map writer + journal), via two dependency-inversion
//! traits so `blackwall-xdp`'s control-plane logic stays free of any DB or
//! live-map dependency and is fully unit-testable with fakes.

use crate::control::{XdpAction, XdpController, XdpOrigin};
use async_trait::async_trait;
use ipnet::IpNet;
use std::net::IpAddr;

/// Applies an [`XdpAction`] to the live eBPF maps.
///
/// Implemented against the real `BLOCK_V4`/`BLOCK_V6`/`RATE` maps elsewhere in
/// this crate; fakeable in tests to exercise [`XdpManager`] without a live map.
#[async_trait]
pub trait XdpExecutor: Send + Sync {
    /// Apply one action to the data plane.
    async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError>;
}

/// Mirrors XDP entry state into persistent storage.
///
/// This is the sole seam through which `blackwall-xdp`'s control plane would
/// touch a database — the crate itself never depends on one. Implemented
/// elsewhere (e.g. the control-plane crate that owns the DB) and injected here.
#[async_trait]
pub trait XdpJournal: Send + Sync {
    /// Record that `action` is now (or still) in effect, with the given origin.
    async fn record(
        &self,
        action: &XdpAction,
        origin: XdpOrigin,
        at_ms: u64,
    ) -> Result<(), XdpJournalError>;
}

/// An executor (map-write) operation failed.
#[derive(Debug, Default, thiserror::Error)]
#[error("XDP executor error")]
pub struct XdpExecError;

/// A journal write failed.
#[derive(Debug, thiserror::Error)]
#[error("XDP journal error: {0}")]
pub struct XdpJournalError(pub String);

/// An [`XdpJournal`] that persists nothing.
///
/// Installed in place of the real persistence journal when the `shadow`
/// config directive is set, so the `xdp_entries` mirror stays empty: in
/// shadow mode no block or rate-limit is ever written to the eBPF maps, so
/// nothing must be journaled that a later live restart could rehydrate (via
/// [`XdpManager::reapply_active`]) and install for real. Mirrors
/// `blackwall_rtbh::NoOpJournal`.
pub struct NoOpXdpJournal;

#[async_trait]
impl XdpJournal for NoOpXdpJournal {
    async fn record(
        &self,
        _action: &XdpAction,
        _origin: XdpOrigin,
        _at_ms: u64,
    ) -> Result<(), XdpJournalError> {
        Ok(())
    }
}

/// Outcome of a manual [`XdpManager`] apply call.
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The action is now (or remains) in effect.
    Applied,
    /// The action was not applied because the manager is at capacity; retry later.
    Deferred,
    /// The action was rejected outright (e.g. a block of an own prefix).
    Rejected(String),
}

/// A journal mirror write that failed and is queued for a self-heal retry.
///
/// The executor side of the operation already succeeded when this is queued,
/// so retrying only ever re-attempts the journal write — never the map write.
#[derive(Debug, Clone, PartialEq)]
struct MirrorOp {
    action: XdpAction,
    origin: XdpOrigin,
    at_ms: u64,
}

impl MirrorOp {
    /// The identity this mirror op concerns, for coalescing purposes.
    fn key(&self) -> MirrorKey {
        match self.action {
            XdpAction::RateLimit { src, .. } | XdpAction::ClearRate { src } => MirrorKey::Src(src),
            XdpAction::Block { net } | XdpAction::Unblock { net } => MirrorKey::Net(net),
        }
    }
}

/// The identity a queued mirror op is coalesced on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorKey {
    Src(IpAddr),
    Net(IpNet),
}

/// Single-owner XDP manager.
///
/// Owns the pure [`XdpController`] plus the I/O boundary: it executes the
/// controller's decisions on an [`XdpExecutor`] and mirrors state via an
/// [`XdpJournal`]. An executor failure is logged, the action is not
/// journaled, and — for a brand-new insert (a fresh `RateLimit`/`Block`,
/// never a re-assertion or param upgrade of an already-active entry) — the
/// controller's freshly-added active entry is rolled back via
/// [`XdpController::rollback`] (C2: commit-after-confirm), mirroring
/// `RtbhManager`'s BGP-failure rollback. This is not a retry mechanism: the
/// map write itself is never retried automatically, but a future detection
/// for the same source is no longer deduped against a phantom active entry.
/// A journal failure after a successful executor operation is logged, never
/// causes a live entry to be removed, and is queued as a `MirrorOp` for a
/// bounded self-heal retry on the next [`XdpManager::tick`] — the executor
/// outcome is never re-issued, only the mirror write.
pub struct XdpManager<E: XdpExecutor, J: XdpJournal> {
    controller: XdpController,
    executor: E,
    journal: J,
    /// Journal writes that failed after their executor operation already
    /// succeeded; retried (never re-issued to the executor) by
    /// [`XdpManager::retry_pending_mirror`] on the next tick.
    pending_mirror: Vec<MirrorOp>,
    /// Count of executor applies that failed, each counted here (see
    /// [`Self::apply_failures`]); a fresh insert among them is also rolled
    /// back (see [`XdpController::rollback`]).
    apply_failures: u64,
}

impl<E: XdpExecutor, J: XdpJournal> XdpManager<E, J> {
    /// Wrap a controller with an executor and a journal.
    pub fn new(controller: XdpController, executor: E, journal: J) -> Self {
        Self {
            controller,
            executor,
            journal,
            pending_mirror: Vec::new(),
            apply_failures: 0,
        }
    }

    /// Feed one detection event through the controller and execute + journal
    /// the resulting (auto) actions.
    pub async fn on_detection(&mut self, ev: &blackwall_flow::DetectionEvent, wall_now: u64) {
        let actions = self.controller.on_detection(ev);
        for action in actions {
            // `XdpController::on_detection` only ever emits a `RateLimit`
            // for a source it just freshly inserted (an already-active
            // source is deduplicated before an action is produced — see
            // `XdpController::handle_detection`), so every action reaching
            // here is always a fresh insert.
            self.execute_and_journal(action, XdpOrigin::Auto, wall_now, true)
                .await;
        }
    }

    /// Manually block a network.
    ///
    /// Returns [`ApplyOutcome::Applied`] if newly installed (or re-affirmed),
    /// [`ApplyOutcome::Rejected`] if `net` overlaps an own prefix, or
    /// [`ApplyOutcome::Deferred`] if the manager is at capacity.
    pub async fn apply_add(&mut self, net: IpNet, wall_now: u64) -> ApplyOutcome {
        let fresh = !self.controller.is_blocked(net);
        match self.controller.manual_block(net) {
            Ok(action) => {
                self.execute_and_journal(action, XdpOrigin::Manual, wall_now, fresh)
                    .await;
                ApplyOutcome::Applied
            }
            Err(e) if self.controller.overlaps_own_prefix(net) => ApplyOutcome::Rejected(e),
            Err(_) => ApplyOutcome::Deferred,
        }
    }

    /// Manually unblock a network (always applies — see
    /// [`XdpController::manual_unblock`]).
    pub async fn apply_remove(&mut self, net: IpNet, wall_now: u64) -> ApplyOutcome {
        match self.controller.manual_unblock(net) {
            Ok(action) => {
                // `Unblock` is a removal, not an insert — nothing for a
                // failed apply to roll back (`XdpController::rollback` is a
                // no-op for this variant regardless).
                self.execute_and_journal(action, XdpOrigin::Manual, wall_now, false)
                    .await;
                ApplyOutcome::Applied
            }
            Err(e) => ApplyOutcome::Rejected(e),
        }
    }

    /// Manually clear a rate limit on a source address (always applies — see
    /// [`XdpController::manual_clear_rate`]).
    pub async fn apply_clear_rate(&mut self, src: IpAddr, wall_now: u64) -> ApplyOutcome {
        match self.controller.manual_clear_rate(src) {
            Ok(action) => {
                // `ClearRate` is a removal, not an insert — see the
                // `apply_remove` comment above.
                self.execute_and_journal(action, XdpOrigin::Manual, wall_now, false)
                    .await;
                ApplyOutcome::Applied
            }
            Err(e) => ApplyOutcome::Rejected(e),
        }
    }

    /// Manually rate-limit a source address.
    ///
    /// Returns [`ApplyOutcome::Applied`] if newly installed (or upgraded to
    /// `Manual`), or [`ApplyOutcome::Deferred`] if the manager is at capacity.
    pub async fn apply_rate_limit(
        &mut self,
        src: IpAddr,
        pps: u64,
        burst: u64,
        wall_now: u64,
    ) -> ApplyOutcome {
        let fresh = !self.controller.is_rate_limited(src);
        match self.controller.manual_rate_limit(src, pps, burst) {
            Ok(action) => {
                self.execute_and_journal(action, XdpOrigin::Manual, wall_now, fresh)
                    .await;
                ApplyOutcome::Applied
            }
            Err(_) => ApplyOutcome::Deferred,
        }
    }

    /// Drain-retry any journal mirror writes queued by a previous transient
    /// failure. Call periodically.
    ///
    /// The executor side of each queued op already succeeded when it was
    /// queued, so this only ever re-attempts the matching journal call — it
    /// never re-applies to the executor.
    pub async fn tick(&mut self) {
        self.retry_pending_mirror().await;
    }

    /// Re-install persisted active entries on a fresh session (rehydration).
    ///
    /// For each row, folds it into the controller's active-state bookkeeping
    /// (via [`XdpController::mark_resumed`]) and re-issues the executor call —
    /// but does **not** re-journal, since the row already exists in the
    /// journal. An executor failure here is logged; the entry is still kept
    /// in the controller's active set (matching `RtbhManager::rehydrate`'s
    /// "never silently drop a persisted row" invariant).
    pub async fn reapply_active(&mut self, rows: Vec<(XdpAction, XdpOrigin)>) {
        for (action, origin) in rows {
            self.controller.mark_resumed(&action, origin);
            if let Err(e) = self.executor.apply(action).await {
                tracing::warn!(error = %e, ?action, "XDP: reapply_active executor call failed");
            }
        }
    }

    /// Snapshot the active set (for reconcile mirroring, `list`, and tests).
    #[must_use]
    pub fn active(&self) -> Vec<(XdpAction, XdpOrigin)> {
        self.controller.active_entries()
    }

    /// Number of detections skipped by the controller's protected-prefix
    /// guard (own anycast VIPs never mitigated). Surfaced for `/metrics`;
    /// see `blackwall_rtbh::manager::RtbhManager::protected_skipped` for the
    /// analogous RTBH accessor.
    #[must_use]
    pub fn protected_skipped(&self) -> u64 {
        self.controller.protected_skipped()
    }

    /// Count of executor (eBPF-map) applies that failed (C2). A failure for
    /// a brand-new insert also rolls back the controller's freshly-added
    /// active entry (see [`XdpController::rollback`]) so the control plane
    /// never believes an unconfirmed map write is active. Surfaced for
    /// `/metrics` as `blackwall_xdp_apply_failures_total`, mirroring
    /// `blackwall_rtbh::manager::RtbhManager::apply_failures`.
    #[must_use]
    pub fn apply_failures(&self) -> u64 {
        self.apply_failures
    }

    /// Queue a failed mirror write for self-heal, coalescing by identity
    /// (source or network).
    ///
    /// The mirror only needs to reflect the current active state, so keeping
    /// just the latest op per identity is both correct (journal ops converge
    /// to a final state) and bounds the queue to one entry per identity — an
    /// entry that flaps while the DB is down can never grow the queue
    /// without bound.
    fn queue_mirror(&mut self, op: MirrorOp) {
        let key = op.key();
        self.pending_mirror.retain(|o| o.key() != key);
        self.pending_mirror.push(op);
    }

    /// Execute one controller action on the executor and mirror it into the journal.
    ///
    /// `fresh` marks whether `action` is a brand-new insert (a first-time
    /// `RateLimit`/`Block`) rather than a re-assertion or param upgrade of an
    /// already-active entry, or a removal (`Unblock`/`ClearRate`). On an
    /// executor failure, a fresh insert's freshly-added active entry is
    /// rolled back (C2: commit-after-confirm) so the control plane never
    /// believes an unconfirmed map write is active; a non-fresh action has no
    /// just-inserted entry to undo, so nothing is rolled back. Either way the
    /// failure is counted in `apply_failures`.
    async fn execute_and_journal(
        &mut self,
        action: XdpAction,
        origin: XdpOrigin,
        wall_now: u64,
        fresh: bool,
    ) {
        if let Err(e) = self.executor.apply(action).await {
            self.apply_failures = self.apply_failures.saturating_add(1);
            if fresh {
                tracing::warn!(
                    error = %e,
                    ?action,
                    "XDP: executor apply failed; rolling back active entry, not journaling"
                );
                self.controller.rollback(&action);
            } else {
                tracing::warn!(error = %e, ?action, "XDP: executor apply failed; not journaling");
            }
            return;
        }
        if let Err(e) = self.journal.record(&action, origin, wall_now).await {
            tracing::error!(error = %e, ?action, "XDP: journal write failed after apply; keeping active");
            self.queue_mirror(MirrorOp {
                action,
                origin,
                at_ms: wall_now,
            });
        }
    }

    /// Drain-retry queued mirror writes left over from a transient journal failure.
    ///
    /// The executor side of each queued op already succeeded when it was
    /// queued, so this only ever re-attempts the matching journal call — it
    /// never re-applies to the executor. Ops that still fail are kept
    /// (retried again on the next call); ops that succeed are dropped.
    async fn retry_pending_mirror(&mut self) {
        if self.pending_mirror.is_empty() {
            return;
        }
        let ops = std::mem::take(&mut self.pending_mirror);
        for op in ops {
            if let Err(e) = self.journal.record(&op.action, op.origin, op.at_ms).await {
                tracing::warn!(error = %e, ?op, "XDP: mirror self-heal retry failed; re-queuing");
                self.pending_mirror.push(op);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn executor(&self) -> &E {
        &self.executor
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
    use blackwall_flow::{AttackKind, Detection, DetectionEvent, Severity};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeExecutor {
        applied: Mutex<Vec<XdpAction>>,
        fail: bool,
    }
    #[async_trait]
    impl XdpExecutor for FakeExecutor {
        async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError> {
            if self.fail {
                return Err(XdpExecError);
            }
            self.applied.lock().unwrap().push(action);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeJournal {
        recorded: Mutex<Vec<(XdpAction, XdpOrigin)>>,
        fail: bool,
        /// Number of upcoming calls that should fail before the journal
        /// starts succeeding — simulates a transient DB blip that self-heals.
        fail_calls_remaining: Mutex<usize>,
    }
    #[async_trait]
    impl XdpJournal for FakeJournal {
        async fn record(
            &self,
            action: &XdpAction,
            origin: XdpOrigin,
            _at_ms: u64,
        ) -> Result<(), XdpJournalError> {
            if self.fail || self.take_transient_failure() {
                return Err(XdpJournalError("boom".into()));
            }
            self.recorded.lock().unwrap().push((*action, origin));
            Ok(())
        }
    }
    impl FakeJournal {
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

    fn own() -> Vec<IpNet> {
        vec!["203.0.113.0/24".parse().unwrap()]
    }

    fn det(target: &str, sources: Vec<&str>) -> Detection {
        Detection {
            target: target.parse().unwrap(),
            kind: AttackKind::Volumetric,
            observed_pps: 1e6,
            observed_bps: 8e6,
            proto: 17,
            top_sources: sources
                .into_iter()
                .map(|s| (s.parse::<IpAddr>().unwrap(), 1.0))
                .collect(),
            top_ports: vec![],
            pops: vec![],
            top_source_blocks: vec![],
            severity: Severity::High,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    fn mgr(fail_exec: bool, fail_journal: bool) -> XdpManager<FakeExecutor, FakeJournal> {
        XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            FakeExecutor {
                fail: fail_exec,
                ..Default::default()
            },
            FakeJournal {
                fail: fail_journal,
                ..Default::default()
            },
        )
    }

    fn mgr_transient_journal_failures(n: usize) -> XdpManager<FakeExecutor, FakeJournal> {
        XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            FakeExecutor::default(),
            FakeJournal {
                fail_calls_remaining: Mutex::new(n),
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn add_applies_on_executor_then_journals() {
        let mut m = mgr(false, false);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert_eq!(m.active().len(), 1);
        assert_eq!(m.executor().applied.lock().unwrap().len(), 1);
        let recorded = m.journal().recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1, XdpOrigin::Auto);
    }

    #[tokio::test]
    async fn journal_failure_keeps_entry_active_and_queues_retry_that_succeeds_on_tick() {
        // Journal fails only its first scheduled call (the record), then heals.
        let mut m = mgr_transient_journal_failures(1);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert_eq!(
            m.active().len(),
            1,
            "a journal error must not drop a live entry"
        );
        assert!(m.journal().recorded.lock().unwrap().is_empty());
        assert_eq!(m.pending_mirror_len(), 1);

        m.tick().await;

        assert_eq!(
            m.pending_mirror_len(),
            0,
            "the self-heal retry must drain the queue once the journal recovers"
        );
        assert_eq!(
            m.journal().recorded.lock().unwrap()[0].1,
            XdpOrigin::Auto,
            "the retried record must have been recorded with its original origin"
        );
    }

    #[tokio::test]
    async fn executor_failure_does_not_journal() {
        let mut m = mgr(true, false);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert!(
            m.journal().recorded.lock().unwrap().is_empty(),
            "an executor failure must not be journaled"
        );
    }

    #[tokio::test]
    async fn executor_failure_does_not_leave_a_phantom_active_entry() {
        // The executor (map write) fails: the kernel never installed the
        // rate limit, so the control plane must NOT believe it did (C2) —
        // the freshly-inserted active entry must be rolled back, not left as
        // a phantom "active" mitigation that dedupes future detections.
        let mut m = mgr(true, false); // executor fails
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert!(
            m.active().is_empty(),
            "a failed executor apply must not leave a phantom active entry"
        );
        assert_eq!(m.apply_failures(), 1);

        // A subsequent identical detection re-attempts (not deduped against
        // a phantom active entry).
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            2000,
        )
        .await;
        assert_eq!(m.apply_failures(), 2);
    }

    #[tokio::test]
    async fn successful_apply_activates_with_no_apply_failures() {
        let mut m = mgr(false, false);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert_eq!(m.active().len(), 1);
        assert_eq!(m.apply_failures(), 0);
    }

    #[tokio::test]
    async fn reapply_active_reissues_executor_calls_but_not_journal() {
        let mut m = mgr(false, false);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        let rows = m.active();
        assert_eq!(rows.len(), 1);

        let mut fresh = mgr(false, false);
        fresh.reapply_active(rows).await;

        assert_eq!(fresh.active().len(), 1, "reapply restores the active set");
        assert_eq!(
            fresh.executor().applied.lock().unwrap().len(),
            1,
            "reapply re-issues the executor call"
        );
        assert!(
            fresh.journal().recorded.lock().unwrap().is_empty(),
            "reapply must never re-journal"
        );
    }

    #[tokio::test]
    async fn apply_add_rejects_own_prefix_and_applies_foreign_net() {
        let mut m = mgr(false, false);
        assert!(matches!(
            m.apply_add("203.0.113.0/24".parse().unwrap(), 0).await,
            ApplyOutcome::Rejected(_)
        ));
        assert_eq!(
            m.apply_add("198.51.100.0/24".parse().unwrap(), 0).await,
            ApplyOutcome::Applied
        );
    }

    #[tokio::test]
    async fn apply_add_defers_at_capacity() {
        let mut m = XdpManager::new(
            XdpController::new(own(), 1, 1000, Vec::new()),
            FakeExecutor::default(),
            FakeJournal::default(),
        );
        assert_eq!(
            m.apply_add("198.51.100.0/24".parse().unwrap(), 0).await,
            ApplyOutcome::Applied
        );
        assert_eq!(
            m.apply_add("198.51.101.0/24".parse().unwrap(), 0).await,
            ApplyOutcome::Deferred
        );
    }

    #[tokio::test]
    async fn apply_remove_withdraws_and_journals() {
        let mut m = mgr(false, false);
        let net = "198.51.100.0/24".parse().unwrap();
        m.apply_add(net, 0).await;
        m.apply_remove(net, 1000).await;
        assert!(m.active().is_empty());
        let recorded = m.journal().recorded.lock().unwrap();
        assert!(matches!(
            recorded.last().unwrap().0,
            XdpAction::Unblock { .. }
        ));
    }

    #[tokio::test]
    async fn apply_clear_rate_removes_and_journals() {
        let mut m = mgr(false, false);
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        m.apply_rate_limit(addr, 500, 500, 0).await;
        assert_eq!(m.active().len(), 1);

        let outcome = m.apply_clear_rate(addr, 1000).await;
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert!(m.active().is_empty(), "clear-rate must remove the entry");

        let recorded = m.journal().recorded.lock().unwrap();
        assert!(matches!(
            recorded.last().unwrap().0,
            XdpAction::ClearRate { .. }
        ));
    }

    #[tokio::test]
    async fn retry_pending_mirror_requeues_on_repeat_failure() {
        let mut m = mgr(false, true);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert_eq!(m.pending_mirror_len(), 1);

        m.tick().await;

        assert_eq!(
            m.pending_mirror_len(),
            1,
            "a still-failing journal must keep the op queued, not drop it"
        );
        assert!(m.journal().recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mirror_retry_coalesces_repeated_failures() {
        // A single source flapping (re-issued) while the journal is down
        // must never grow the queue past one entry for that source.
        let mut m = mgr(false, true); // executor ok, journal always fails
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        m.apply_rate_limit(addr, 500, 500, 1000).await;
        m.apply_rate_limit(addr, 500, 500, 2000).await;
        m.apply_rate_limit(addr, 500, 500, 3000).await;
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "repeated failures for one source coalesce to a single queued op"
        );
    }

    #[tokio::test]
    async fn noop_journal_records_nothing_and_succeeds() {
        // The shadow-mode journal must accept every record call without error
        // and persist nothing — it holds no state, so a `Block` and a
        // `RateLimit` record both simply return Ok, leaving no observable
        // mirror behind for a later live restart to rehydrate.
        let journal = NoOpXdpJournal;
        let block = XdpAction::Block {
            net: "198.51.100.0/24".parse().unwrap(),
        };
        let rate = XdpAction::RateLimit {
            src: "198.51.100.9".parse().unwrap(),
            pps: 500,
            burst: 500,
            victim: Some("203.0.113.7".parse().unwrap()),
        };
        assert!(journal.record(&block, XdpOrigin::Manual, 0).await.is_ok());
        assert!(journal.record(&rate, XdpOrigin::Auto, 1000).await.is_ok());
    }
}
