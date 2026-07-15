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
        mirror_key_of(&self.action)
    }
}

/// The identity a queued mirror/reapply op is coalesced on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorKey {
    Src(IpAddr),
    Net(IpNet),
}

/// The coalescing identity of `action` — shared by [`MirrorOp::key`] and
/// [`ReapplyOp::key`].
fn mirror_key_of(action: &XdpAction) -> MirrorKey {
    match *action {
        XdpAction::RateLimit { src, .. } | XdpAction::ClearRate { src } => MirrorKey::Src(src),
        XdpAction::Block { net } | XdpAction::Unblock { net } => MirrorKey::Net(net),
    }
}

/// A [`XdpManager::reapply_active`] re-apply that failed at the
/// [`XdpExecutor`] and is queued for a self-heal retry (issue #194).
///
/// Unlike [`MirrorOp`] (which only ever replays a journal write, the
/// executor side already having succeeded), a queued `ReapplyOp` re-attempts
/// the executor `apply` itself — `reapply_active`'s failure happens on the
/// executor side, not the journal side (`reapply_active` never re-journals
/// in the first place).
///
/// Holds only the coalescing [`MirrorKey`] identity, not the action that was
/// captured when the op was queued: [`XdpManager::retry_pending_reapply`]
/// re-derives the CURRENT action from [`XdpController::current_rate_limit`]/
/// [`XdpController::current_block`] at retry time rather than replaying a
/// snapshot, so a fresh, successful re-apply of the same identity with
/// different parameters (e.g. an operator or detection tightening a
/// `RateLimit`'s `pps`) that lands between the failed reapply and the retry
/// is never clobbered by the stale queued content (#194 C1 follow-up).
/// Mirrors `blackwall_rtbh::manager::RtbhManager`'s private `ReapplyOp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReapplyOp {
    /// The identity of the action to re-apply; the current action content
    /// is looked up fresh from the controller at retry time.
    key: MirrorKey,
}

impl ReapplyOp {
    /// The identity this reapply op concerns, for coalescing purposes.
    fn key(&self) -> MirrorKey {
        self.key
    }
}

/// Outcome of [`XdpManager::execute_and_journal`].
///
/// The auto path (`on_detection`, which always passes `fresh = true`)
/// ignores this — auto re-detection naturally compensates for a skip on its
/// next tick. [`XdpManager::apply_add`] and [`XdpManager::apply_rate_limit`]
/// (the manual insert paths) consume it to report a truthful
/// [`ApplyOutcome`] rather than always claiming [`ApplyOutcome::Applied`].
/// There is no rate-capped variant here: unlike `RtbhManager`/
/// `FlowSpecManager`, `XdpManager` has no [`crate`]-level cross-plane rate
/// limiter attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecOutcome {
    /// The action reached the executor; a journal-mirror failure afterward
    /// is still `Applied` (self-healed via
    /// [`XdpManager::retry_pending_mirror`]) — the live entry is active
    /// either way.
    Applied,
    /// Skipped: the manager is [`XdpManager::disarm`]ed (C5), record-only.
    /// A fresh insert's controller entry was rolled back.
    Disarmed,
    /// Attempted and failed at the [`XdpExecutor`] (C2). A fresh insert's
    /// controller entry was rolled back.
    Failed,
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
    /// [`Self::reapply_active`] re-applies that failed at the
    /// [`XdpExecutor`]; retried by [`Self::retry_pending_reapply`] on the
    /// next tick (issue #194). The controller's active entry from
    /// [`XdpController::mark_resumed`] is kept (never rolled back) while
    /// queued — a re-installed entry is a known-good persisted mitigation
    /// with no fresh detection to naturally re-attempt it, so rollback would
    /// strand the control plane believing nothing is installed while the
    /// journal still says otherwise (mirrors
    /// `blackwall_rtbh::manager::RtbhManager`'s private `pending_reapply`).
    pending_reapply: Vec<ReapplyOp>,
    /// Count of executor applies that failed, each counted here (see
    /// [`Self::apply_failures`]); a fresh insert among them is also rolled
    /// back (see [`XdpController::rollback`]).
    apply_failures: u64,
    /// One-way in-daemon disarm kill switch (C5), flipped by [`Self::disarm`].
    /// While set, [`Self::execute_and_journal`] skips every new install
    /// (`Block`/`RateLimit`, never reaching [`Self::executor`]) while
    /// detection keeps running unchanged. There is no re-arm entry point; a
    /// fresh process (restart) is the only way back to armed. Mirrors
    /// `blackwall_rtbh::manager::RtbhManager::disarmed`.
    disarmed: bool,
    /// Count of installs skipped because [`Self::disarmed`] was set (C5) —
    /// a SKIP (never attempted), distinct from [`Self::apply_failures`]
    /// (attempted and failed at the executor). See [`Self::disarmed_skips`].
    disarmed_skips: u64,
}

impl<E: XdpExecutor, J: XdpJournal> XdpManager<E, J> {
    /// Wrap a controller with an executor and a journal.
    pub fn new(controller: XdpController, executor: E, journal: J) -> Self {
        Self {
            controller,
            executor,
            journal,
            pending_mirror: Vec::new(),
            pending_reapply: Vec::new(),
            apply_failures: 0,
            disarmed: false,
            disarmed_skips: 0,
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
                match self
                    .execute_and_journal(action, XdpOrigin::Manual, wall_now, fresh)
                    .await
                {
                    ExecOutcome::Applied => ApplyOutcome::Applied,
                    // One-way: retrying is pointless until re-armed via restart.
                    ExecOutcome::Disarmed => ApplyOutcome::Rejected(format!(
                        "{net} was not applied: manager is disarmed (C5)"
                    )),
                    // No auto re-detection exists for a manual request, so a
                    // failed executor apply must be retried, not marked applied.
                    ExecOutcome::Failed => ApplyOutcome::Deferred,
                }
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
                match self
                    .execute_and_journal(action, XdpOrigin::Manual, wall_now, fresh)
                    .await
                {
                    ExecOutcome::Applied => ApplyOutcome::Applied,
                    // One-way: retrying is pointless until re-armed via restart.
                    ExecOutcome::Disarmed => ApplyOutcome::Rejected(format!(
                        "{src} was not rate-limited: manager is disarmed (C5)"
                    )),
                    // No auto re-detection exists for a manual request, so a
                    // failed executor apply must be retried, not marked applied.
                    ExecOutcome::Failed => ApplyOutcome::Deferred,
                }
            }
            Err(_) => ApplyOutcome::Deferred,
        }
    }

    /// Drain-retry any journal mirror writes queued by a previous transient
    /// failure. Call periodically.
    ///
    /// The executor side of each queued mirror op already succeeded when it
    /// was queued, so that retry only ever re-attempts the matching journal
    /// call — it never re-applies to the executor. Then retries any
    /// `reapply_active` re-applies queued by a previous tick's transient
    /// executor failure (see [`Self::retry_pending_reapply`], issue #194),
    /// so both self-heals converge within one tick interval of the
    /// respective dependency recovering.
    pub async fn tick(&mut self) {
        self.retry_pending_mirror().await;
        self.retry_pending_reapply().await;
    }

    /// Re-install persisted active entries on a fresh session (rehydration).
    ///
    /// For each row, folds it into the controller's active-state bookkeeping
    /// (via [`XdpController::mark_resumed`]) and re-issues the executor call —
    /// but does **not** re-journal, since the row already exists in the
    /// journal. An executor failure here is logged; the entry is still kept
    /// in the controller's active set (matching `RtbhManager::rehydrate`'s
    /// "never silently drop a persisted row" invariant) and queued via
    /// [`Self::queue_reapply`] for a retry on the next [`Self::tick`] (issue
    /// #194): unlike a live detection, a re-installed entry has no natural
    /// re-detection to compensate for a dropped map write.
    pub async fn reapply_active(&mut self, rows: Vec<(XdpAction, XdpOrigin)>) {
        for (action, origin) in rows {
            self.controller.mark_resumed(&action, origin);
            if let Err(e) = self.executor.apply(action).await {
                tracing::warn!(error = %e, ?action, "XDP: reapply_active executor call failed; queuing for retry");
                self.queue_reapply(ReapplyOp {
                    key: mirror_key_of(&action),
                });
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

    /// Number of [`Self::reapply_active`] re-applies currently queued for a
    /// self-heal retry after a failed executor apply on restart (issue
    /// #194). Each queued entry is still active in the controller (kept, not
    /// rolled back) but not yet confirmed on the map; drained by
    /// [`Self::retry_pending_reapply`] on the next [`Self::tick`]. Surfaced
    /// for `/metrics` as `blackwall_xdp_reapply_pending`, mirroring
    /// `blackwall_rtbh::manager::RtbhManager::reapply_pending`.
    #[must_use]
    pub fn reapply_pending(&self) -> usize {
        self.pending_reapply.len()
    }

    /// In-daemon disarm kill switch (C5): withdraw every currently-active
    /// block/rate-limit and switch to record-only for the rest of this
    /// process's life.
    ///
    /// Mirrors `blackwall_rtbh::manager::RtbhManager::disarm`: each active
    /// entry is undone on the executor best-effort (an apply `Err` is logged
    /// and the sweep continues), no journal write happens (disarm is
    /// runtime-only — a restart re-arms and [`Self::reapply_active`]s the
    /// same active set), and once disarmed every subsequent new
    /// `Block`/`RateLimit` install is skipped in [`Self::execute_and_journal`]
    /// and counted in [`Self::disarmed_skips`] — an `Unblock`/`ClearRate`
    /// (a removal, not an install) is never gated. One-way and idempotent.
    ///
    /// `mono_now` is accepted for symmetry with the RTBH/FlowSpec managers'
    /// `disarm` entry points; it is unused here.
    pub async fn disarm(&mut self, _mono_now: u64) {
        if self.disarmed {
            return;
        }
        self.disarmed = true;
        let actives: Vec<XdpAction> = self
            .controller
            .active_entries()
            .into_iter()
            .map(|(action, _origin)| action)
            .collect();
        for action in actives {
            let inverse = match action {
                XdpAction::Block { net } => self.controller.manual_unblock(net),
                XdpAction::RateLimit { src, .. } => self.controller.manual_clear_rate(src),
                // `active_entries` never yields a removal variant.
                XdpAction::Unblock { .. } | XdpAction::ClearRate { .. } => continue,
            };
            if let Ok(inv) = inverse {
                if let Err(e) = self.executor.apply(inv).await {
                    tracing::warn!(error = %e, ?action, "XDP: disarm apply (withdraw) failed; continuing best-effort");
                }
            }
        }
        tracing::warn!("XDP: DISARMED — mitigations withdrawn, now recording only");
    }

    /// Count of new installs (`Block`/`RateLimit`) skipped because the
    /// manager was [`Self::disarm`]ed (C5) — a SKIP (never attempted),
    /// distinct from [`Self::apply_failures`] (attempted and failed at the
    /// executor).
    #[must_use]
    pub fn disarmed_skips(&self) -> u64 {
        self.disarmed_skips
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

    /// Queue a failed [`Self::reapply_active`] re-apply for retry, coalescing
    /// by identity (source or network), same as [`Self::queue_mirror`]
    /// (issue #194).
    fn queue_reapply(&mut self, op: ReapplyOp) {
        let key = op.key();
        self.pending_reapply.retain(|o| o.key() != key);
        self.pending_reapply.push(op);
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
    ) -> ExecOutcome {
        if self.disarmed
            && matches!(
                action,
                XdpAction::Block { .. } | XdpAction::RateLimit { .. }
            )
        {
            tracing::warn!(
                ?action,
                "XDP: disarmed (C5); skipping install, recording only"
            );
            if fresh {
                self.controller.rollback(&action);
            }
            self.disarmed_skips = self.disarmed_skips.saturating_add(1);
            return ExecOutcome::Disarmed;
        }
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
            return ExecOutcome::Failed;
        }
        if let Err(e) = self.journal.record(&action, origin, wall_now).await {
            tracing::error!(error = %e, ?action, "XDP: journal write failed after apply; keeping active");
            self.queue_mirror(MirrorOp {
                action,
                origin,
                at_ms: wall_now,
            });
        }
        ExecOutcome::Applied
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

    /// Drain-retry queued [`Self::reapply_active`] re-applies left over from
    /// a transient executor failure (issue #194).
    ///
    /// Each queued op re-derives the CURRENT action for its identity from
    /// [`XdpController::current_rate_limit`]/[`XdpController::current_block`]
    /// rather than replaying the action snapshot captured when the op was
    /// queued: if the identity is no longer active (e.g. cleared by a manual
    /// remove between the failed reapply and this tick), the lookup returns
    /// `None` and the op is dropped — re-applying an entry the control plane
    /// no longer wants live would itself create a phantom. If the identity
    /// is still active but a fresh, successful re-apply changed its
    /// parameters in the meantime (e.g. tightening a `RateLimit`'s `pps`),
    /// re-deriving picks up that CURRENT action instead of replaying the
    /// stale queued one, which would otherwise silently revert the fresh
    /// update (#194 C1 follow-up). Otherwise the apply is re-attempted; ops
    /// that still fail are kept (retried again on the next call), ops that
    /// succeed are dropped.
    async fn retry_pending_reapply(&mut self) {
        if self.pending_reapply.is_empty() {
            return;
        }
        let ops = std::mem::take(&mut self.pending_reapply);
        for op in ops {
            let current = match op.key {
                MirrorKey::Src(src) => self.controller.current_rate_limit(src),
                MirrorKey::Net(net) => self.controller.current_block(net),
            };
            let Some(action) = current else {
                tracing::info!(key = ?op.key, "XDP: dropping queued reapply; entry no longer active");
                continue;
            };
            if let Err(e) = self.executor.apply(action).await {
                tracing::warn!(error = %e, ?action, "XDP: reapply retry failed; re-queuing");
                self.pending_reapply.push(op);
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
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct FakeExecutor {
        applied: Arc<Mutex<Vec<XdpAction>>>,
        fail: Arc<Mutex<bool>>,
        /// If `Some(n)`, the n-th call (1-indexed) onward fails; earlier
        /// calls succeed. Used to simulate a successful fresh insert
        /// followed by a failing upgrade apply (Fix 2 regression test).
        fail_from_call: Option<usize>,
        call_count: Arc<Mutex<usize>>,
    }
    impl FakeExecutor {
        /// Build a fake whose `apply` fails from the start.
        fn with_fail(fail: bool) -> Self {
            let f = Self::default();
            f.set_fail(fail);
            f
        }
        /// Flip the failure toggle at runtime — lets a test simulate the
        /// executor recovering mid-scenario (a clone shares the same
        /// underlying flag with whatever manager holds this fake).
        fn set_fail(&self, fail: bool) {
            *self.fail.lock().unwrap() = fail;
        }
    }
    #[async_trait]
    impl XdpExecutor for FakeExecutor {
        async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError> {
            let call_no = {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                *count
            };
            if *self.fail.lock().unwrap() || self.fail_from_call.is_some_and(|from| call_no >= from)
            {
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
            FakeExecutor::with_fail(fail_exec),
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
    async fn disarm_withdraws_all_and_switches_to_record_only() {
        let mut m = mgr(false, false);
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            1000,
        )
        .await;
        assert_eq!(m.active().len(), 1);

        m.disarm(2_000).await;

        assert!(m.active().is_empty(), "disarm must clear the active set");
        // The withdraw (ClearRate) reached the executor.
        assert!(m
            .executor()
            .applied
            .lock()
            .unwrap()
            .iter()
            .any(|a| matches!(a, XdpAction::ClearRate { .. })));

        // A subsequent detection is recorded, not executed.
        let applied_before = m.executor().applied.lock().unwrap().len();
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.10"])),
            3000,
        )
        .await;
        assert!(m.active().is_empty());
        assert_eq!(m.executor().applied.lock().unwrap().len(), applied_before);
        assert_eq!(m.apply_failures(), 0);
        assert_eq!(m.disarmed_skips(), 1);
    }

    #[tokio::test]
    async fn disarm_tolerates_a_withdraw_error() {
        // Best-effort: an executor Err on disarm's withdraw (ClearRate) apply
        // must not abort the sweep (a second active entry is still swept) or
        // stop the manager from switching to record-only. Mirrors
        // `blackwall_rtbh::manager::RtbhManager`'s
        // `disarm_tolerates_a_withdraw_error`.
        let mut m = XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            FakeExecutor {
                // Calls 1-2 (the two fresh rate-limit installs) succeed;
                // call 3 onward (disarm's ClearRate withdraws) fail.
                fail_from_call: Some(3),
                ..Default::default()
            },
            FakeJournal::default(),
        );
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.7", vec!["198.51.100.9"])),
            0,
        )
        .await;
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.8", vec!["198.51.100.10"])),
            0,
        )
        .await;
        assert_eq!(m.active().len(), 2);

        m.disarm(1_000).await;

        assert!(
            !m.executor()
                .applied
                .lock()
                .unwrap()
                .iter()
                .any(|a| matches!(a, XdpAction::ClearRate { .. })),
            "every withdraw errored, so no ClearRate was recorded by the fake"
        );
        assert!(
            m.active().is_empty(),
            "disarm clears the active set even when every withdraw errors (best-effort)"
        );

        // Record-only holds even though disarm itself never got a
        // confirmed withdraw.
        m.on_detection(
            &DetectionEvent::Opened(det("203.0.113.9", vec!["198.51.100.11"])),
            2_000,
        )
        .await;
        assert!(m.active().is_empty());
    }

    #[tokio::test]
    async fn apply_add_while_disarmed_is_rejected_not_applied() {
        // C5 + final-review fix: a manual add while disarmed must be
        // classified Rejected (retrying is pointless — there is no re-arm
        // entry point), never Applied — an "applied" operator-request row
        // is never retried, which would silently lose operator intent.
        let mut m = mgr(false, false);
        m.disarm(0).await;

        let outcome = m.apply_add("198.51.100.0/24".parse().unwrap(), 1_000).await;
        match &outcome {
            ApplyOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("disarmed"),
                    "reason should mention 'disarmed': {reason}"
                );
            }
            other => panic!("disarmed manual add must be Rejected, not {other:?}"),
        }
        assert!(
            m.active().is_empty(),
            "a disarmed manual add must not leave a phantom active entry"
        );
    }

    #[tokio::test]
    async fn apply_rate_limit_while_disarmed_is_rejected_not_applied() {
        // Same as above, for the apply_rate_limit manual path.
        let mut m = mgr(false, false);
        m.disarm(0).await;

        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        let outcome = m.apply_rate_limit(addr, 500, 500, 1_000).await;
        match &outcome {
            ApplyOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("disarmed"),
                    "reason should mention 'disarmed': {reason}"
                );
            }
            other => panic!("disarmed manual rate-limit must be Rejected, not {other:?}"),
        }
        assert!(m.active().is_empty());
    }

    #[tokio::test]
    async fn apply_add_when_executor_fails_is_deferred_not_applied() {
        // final-review fix: a manual add whose executor apply fails has no
        // auto re-detection to compensate — it must be Deferred (retried
        // next tick), not marked Applied.
        let mut m = mgr(true, false); // executor always fails
        let outcome = m.apply_add("198.51.100.0/24".parse().unwrap(), 0).await;
        assert_eq!(
            outcome,
            ApplyOutcome::Deferred,
            "a failed executor apply on a manual add must be Deferred, not Applied"
        );
        assert!(m.active().is_empty());
        assert_eq!(m.apply_failures(), 1);
    }

    #[tokio::test]
    async fn upgrade_apply_failure_does_not_evict_existing_active_entry() {
        // Fix 2 (final-review regression test): an already-active
        // (successfully-applied) rate-limit entry, then an UPGRADE apply
        // (same source, new pps/burst) whose executor FAILS must NOT evict
        // the pre-existing active entry — only a FRESH insert's rollback
        // undoes anything (`fresh` is computed BEFORE the controller call
        // and rollback only fires `if fresh`).
        let mut m = XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            FakeExecutor {
                // 1st call (the fresh insert) succeeds; 2nd call (the
                // upgrade) and onward fail.
                fail_from_call: Some(2),
                ..Default::default()
            },
            FakeJournal::default(),
        );
        let addr: IpAddr = "198.51.100.9".parse().unwrap();

        let first = m.apply_rate_limit(addr, 500, 500, 0).await;
        assert_eq!(first, ApplyOutcome::Applied, "the fresh insert succeeds");
        assert_eq!(m.active().len(), 1);

        let second = m.apply_rate_limit(addr, 999, 999, 1_000).await;
        assert_eq!(
            second,
            ApplyOutcome::Deferred,
            "a failed upgrade apply must be Deferred, not Applied"
        );
        assert_eq!(
            m.active().len(),
            1,
            "the pre-existing entry must still be active, not evicted by a failed upgrade"
        );
        assert!(
            m.active().iter().any(
                |(action, _)| matches!(action, XdpAction::RateLimit { src, .. } if *src == addr)
            ),
            "the surviving entry must still be for the same source"
        );
        assert_eq!(m.apply_failures(), 1);
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

    #[tokio::test]
    async fn reapply_active_failure_queues_reapply_and_tick_reconverges() {
        // #194 C1: a persisted, active entry whose reapply fails at the
        // executor must NOT be left stranded (active in the controller but
        // never written to the eBPF map) — it is queued for retry and the
        // queue drains once the executor recovers.
        let executor = FakeExecutor::with_fail(true); // apply errors
        let mut m = XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            executor.clone(),
            FakeJournal::default(),
        );
        let net: IpNet = "198.51.100.0/24".parse().unwrap();
        let action = XdpAction::Block { net };
        m.reapply_active(vec![(action, XdpOrigin::Manual)]).await;
        assert!(
            m.active().iter().any(|(a, _)| *a == action),
            "entry kept (not dropped)"
        );
        assert_eq!(m.reapply_pending(), 1, "failed reapply queued for retry");

        // Executor recovers; the next tick re-applies and drains the queue.
        executor.set_fail(false);
        m.tick().await;
        assert_eq!(m.reapply_pending(), 0);
        assert!(m.executor().applied.lock().unwrap().contains(&action));
    }

    #[tokio::test]
    async fn queue_reapply_dedupes_and_drops_if_cleared() {
        // A still-failing tick must coalesce (not double-enqueue) the retry
        // for the same entry; and once the entry is cleared before it ever
        // succeeds, the queued reapply must be dropped rather than
        // re-applying a no-longer-wanted action.
        let executor = FakeExecutor::with_fail(true);
        let mut m = XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            executor.clone(),
            FakeJournal::default(),
        );
        let net: IpNet = "198.51.100.0/24".parse().unwrap();
        let action = XdpAction::Block { net };
        m.reapply_active(vec![(action, XdpOrigin::Manual)]).await;
        m.tick().await; // still failing -> re-queued, NOT double-enqueued
        assert_eq!(m.reapply_pending(), 1, "coalesced, not doubled");

        // Cleared before it ever succeeded (manual unblock).
        m.apply_remove(net, 3_000).await;
        executor.set_fail(false);
        m.tick().await;
        assert_eq!(m.reapply_pending(), 0, "dropped: entry no longer active");
        assert!(
            !m.executor().applied.lock().unwrap().contains(&action),
            "not re-applied after clear"
        );
    }

    #[tokio::test]
    async fn stale_reapply_does_not_clobber_a_fresh_successful_update() {
        // #194 C1 follow-up: `retry_pending_reapply` must re-derive the
        // controller's CURRENT action for the identity at retry time, not
        // replay the action snapshot captured when the op was queued.
        // Otherwise a fresh, successful re-apply of the SAME source with
        // DIFFERENT parameters that lands between the failed reapply and
        // the retry gets silently reverted by the stale queued content — a
        // mitigation-weakening regression (e.g. a fresh `pps:1000` reverted
        // back to a stale queued `pps:500`).
        let executor = FakeExecutor::with_fail(true); // reapply_active apply fails
        let mut m = XdpManager::new(
            XdpController::new(own(), 100, 1000, Vec::new()),
            executor.clone(),
            FakeJournal::default(),
        );
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        let old = XdpAction::RateLimit {
            src: addr,
            pps: 500,
            burst: 500,
            victim: None,
        };
        m.reapply_active(vec![(old, XdpOrigin::Manual)]).await;
        assert!(
            m.active().iter().any(|(a, _)| *a == old),
            "entry kept (not dropped)"
        );
        assert_eq!(m.reapply_pending(), 1, "failed reapply queued for retry");

        // Executor recovers just in time for a FRESH, successful re-apply
        // with DIFFERENT parameters for the SAME source, landing before the
        // next tick drains the stale queue.
        executor.set_fail(false);
        let outcome = m.apply_rate_limit(addr, 1000, 1000, 1_500).await;
        assert_eq!(outcome, ApplyOutcome::Applied);
        let new = XdpAction::RateLimit {
            src: addr,
            pps: 1000,
            burst: 1000,
            victim: None,
        };
        assert!(
            m.executor().applied.lock().unwrap().contains(&new),
            "the fresh update reached the executor"
        );

        // The next tick drains the (now-stale) queued reapply. It must
        // re-derive and re-apply the CURRENT action (pps 1000), not replay
        // the stale queued snapshot (pps 500) — which would silently revert
        // the fresh update.
        m.tick().await;
        assert_eq!(m.reapply_pending(), 0);

        let applied = m.executor().applied.lock().unwrap();
        let last = applied.last().expect("at least one apply recorded");
        assert_eq!(
            *last, new,
            "the drained retry must re-apply the CURRENT action, not the stale queued one"
        );
    }
}
