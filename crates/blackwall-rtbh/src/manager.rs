//! Single-owner RTBH manager: executes controller decisions on BGP and
//! mirrors auto/manual state into a persistence journal.
//!
//! The [`RtbhController`] is pure (no I/O); this module owns the controller
//! plus the I/O boundary (BGP session + journal), via two dependency-inversion
//! traits so `blackwall-rtbh` stays free of any DB dependency.

use crate::controller::{BlackholeOrigin, RtbhAction, RtbhController};
use crate::rate_limit::ArmingRateLimiter;
use async_trait::async_trait;
use blackwall_bgp::Route;
use blackwall_flow::DetectionEvent;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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
/// via a [`BlackholeJournal`]. A BGP announce failure is logged, the action
/// is not journaled, and the controller's freshly-inserted active entry is
/// rolled back via [`RtbhController::rollback`] (C2: commit-after-confirm) —
/// the control plane never believes an unconfirmed announce succeeded, so a
/// future detection for the same target is not deduped against a phantom
/// entry. There is no retry queue for this: while the underlying attack
/// persists, the detector naturally re-emits the detection on its next tick
/// and the manager re-attempts through the same path. This differs from a
/// *journal* failure after a successful BGP operation, which is logged,
/// never causes a live blackhole to be withdrawn, and is queued as a
/// `MirrorOp` for a bounded self-heal retry on the next [`RtbhManager::tick`]
/// — the BGP outcome is never re-issued, only the mirror write.
pub struct RtbhManager<B: BgpExecutor, J: BlackholeJournal> {
    controller: RtbhController,
    bgp: B,
    journal: J,
    /// Journal writes that failed after their BGP operation already
    /// succeeded; retried (never re-issued to BGP) by
    /// `RtbhManager::retry_pending_mirror` on the next tick.
    pending_mirror: Vec<MirrorOp>,
    /// `rehydrate` re-announces that failed at the [`BgpExecutor`]; retried
    /// by [`Self::retry_pending_reapply`] on the next tick (issue #194). The
    /// controller's active entry from [`RtbhController::resume`] is kept
    /// (never rolled back) while queued — unlike a live BGP failure on the
    /// `apply_event`/`apply_add` path (see the module docs), a rehydrated row
    /// is a known-good persisted mitigation with no fresh detection to
    /// naturally re-attempt it, so rollback would strand the control plane
    /// believing nothing is announced while the journal still says otherwise.
    pending_reapply: Vec<ReapplyOp>,
    /// Count of announces that failed at the BGP executor, each rolled back
    /// (see [`Self::apply_failures`]).
    apply_failures: u64,
    /// Cross-plane cap (C6) on the arrival rate of NEW mitigations, shared
    /// with the sibling `FlowSpecManager` via the same `Arc<Mutex<_>>` so ONE
    /// limiter governs the combined RTBH+FlowSpec announce rate. `None` (the
    /// default from [`Self::new`]) is unlimited — [`main`](../../bin/blackwalld)
    /// only attaches `Some` via [`Self::with_rate_limiter`] on the live path
    /// (never under shadow, where nothing is really announced).
    rate_limiter: Option<Arc<Mutex<ArmingRateLimiter>>>,
    /// Count of announces skipped because [`Self::rate_limiter`] was at
    /// capacity (C6) — a SKIP (never attempted), distinct from
    /// [`Self::apply_failures`] (attempted and failed at BGP). See
    /// [`Self::ratecapped`].
    ratecapped: u64,
    /// One-way in-daemon disarm kill switch (C5), flipped by [`Self::disarm`].
    /// While set, [`Self::execute_and_journal_announce`] skips every new
    /// `Announce` (never reaches [`Self::bgp`]) while detection + selection
    /// keep running unchanged — the manager keeps recording, it just stops
    /// applying. There is no re-arm entry point; a fresh process (restart)
    /// is the only way back to armed.
    disarmed: bool,
    /// Count of announces skipped because [`Self::disarmed`] was set (C5) —
    /// a SKIP (never attempted), distinct from both [`Self::apply_failures`]
    /// (attempted and failed) and [`Self::ratecapped`] (skipped for a
    /// different reason). See [`Self::disarmed_skips`].
    disarmed_skips: u64,
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

/// A [`RtbhManager::rehydrate`] re-announce that failed at the
/// [`BgpExecutor`] and is queued for a self-heal retry (issue #194).
///
/// Unlike [`MirrorOp`] (which only ever replays a journal write, the BGP
/// side already having succeeded), a queued `ReapplyOp` re-attempts the BGP
/// `announce` itself — rehydrate's failure happens on the BGP side, not the
/// journal side (rehydrate never journals in the first place).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReapplyOp {
    /// The blackhole target this re-announce concerns.
    target: IpAddr,
    /// The route to re-announce.
    route: Route,
}

/// Outcome of [`RtbhManager::execute_and_journal_announce`].
///
/// The auto path (`apply_event`/`tick`, via [`RtbhManager::execute_and_journal`])
/// ignores this — auto re-detection naturally compensates for a skip on its
/// next tick. [`RtbhManager::apply_add`] (the manual path) consumes it to
/// report a truthful [`ApplyOutcome`] rather than always claiming
/// [`ApplyOutcome::Applied`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnnounceOutcome {
    /// The announce reached BGP; a journal-mirror failure afterward is still
    /// `Applied` (self-healed via [`RtbhManager::retry_pending_mirror`]) —
    /// the live blackhole is active either way.
    Applied,
    /// Skipped: the shared cross-plane [`ArmingRateLimiter`] (C6) was at
    /// capacity. The controller entry was rolled back.
    RateCapped,
    /// Skipped: the manager is [`RtbhManager::disarm`]ed (C5), record-only.
    /// The controller entry was rolled back.
    Disarmed,
    /// Attempted and failed at the [`BgpExecutor`] (C2). The controller
    /// entry was rolled back.
    Failed,
}

impl<B: BgpExecutor, J: BlackholeJournal> RtbhManager<B, J> {
    /// Wrap a controller with a BGP executor and a journal.
    pub fn new(controller: RtbhController, bgp: B, journal: J) -> Self {
        Self {
            controller,
            bgp,
            journal,
            pending_mirror: Vec::new(),
            pending_reapply: Vec::new(),
            apply_failures: 0,
            rate_limiter: None,
            ratecapped: 0,
            disarmed: false,
            disarmed_skips: 0,
        }
    }

    /// Attach a shared cross-plane rate cap (C6) on new mitigations.
    ///
    /// Non-breaking: absent (the default from [`Self::new`]) is unlimited.
    /// `main.rs` wires `Some` only on the live path (`!policy.shadow`) — the
    /// shadow-mode construction never calls this, so shadow sessions are
    /// always unlimited (rate-capping a mitigation that is never really
    /// announced would only corrupt the would-mitigate signal).
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: Arc<Mutex<ArmingRateLimiter>>) -> Self {
        self.rate_limiter = Some(limiter);
        self
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
            self.execute_and_journal(action, mono_now, wall_now).await;
        }
    }

    /// Process time-driven withdrawals (deferred clears, TTL expiry) and
    /// execute + journal each one.
    ///
    /// Starts by retrying any journal mirror writes queued by a previous
    /// tick's transient failure (see `RtbhManager::retry_pending_mirror`),
    /// then any `rehydrate` re-announces queued by a previous tick's
    /// transient BGP failure (see `RtbhManager::retry_pending_reapply`,
    /// issue #194), so both self-heals converge within one tick interval of
    /// the respective dependency recovering.
    pub async fn tick(&mut self, mono_now: u64, wall_now: u64) {
        self.retry_pending_mirror().await;
        self.retry_pending_reapply().await;
        let actions = self.controller.tick(mono_now);
        for action in actions {
            self.execute_and_journal(action, mono_now, wall_now).await;
        }
    }

    /// Manually blackhole a target.
    ///
    /// Returns [`ApplyOutcome::Applied`] if newly installed or upgraded from
    /// `Auto` to `Manual` (re-journaled as `Manual` in the latter case),
    /// [`ApplyOutcome::Deferred`] if the manager is at capacity, or
    /// [`ApplyOutcome::Rejected`] if the target is protected, ineligible, or
    /// has no next-hop for its address family.
    pub async fn apply_add(
        &mut self,
        target: IpAddr,
        mono_now: u64,
        wall_now: u64,
    ) -> ApplyOutcome {
        let actions = self.controller.manual_add(target, mono_now);
        if let Some(RtbhAction::Announce(route)) = actions.into_iter().next() {
            let outcome = self
                .execute_and_journal_announce(
                    target,
                    route,
                    BlackholeOrigin::Manual,
                    mono_now,
                    wall_now,
                )
                .await;
            return match outcome {
                AnnounceOutcome::Applied => ApplyOutcome::Applied,
                // The window will have room again; the request row stays
                // `pending` and is retried next tick.
                AnnounceOutcome::RateCapped => ApplyOutcome::Deferred,
                // One-way: retrying is pointless until re-armed via restart.
                AnnounceOutcome::Disarmed => ApplyOutcome::Rejected(format!(
                    "{target} was not announced: manager is disarmed (C5)"
                )),
                // No auto re-detection exists for a manual request, so a
                // failed BGP announce must be retried, not marked applied.
                AnnounceOutcome::Failed => ApplyOutcome::Deferred,
            };
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
        if !self.controller.has_next_hop(target) {
            return ApplyOutcome::Rejected(format!("no next-hop configured for {target}'s family"));
        }
        ApplyOutcome::Deferred
    }

    /// Manually withdraw a target (bypasses hold-down).
    ///
    /// `mono_now` is accepted for symmetry with the other entry points that
    /// funnel through [`Self::execute_and_journal`] (it is unused here: a
    /// manual removal only ever produces a `Withdraw`, never an `Announce`,
    /// so the shared rate limiter — which only gates `Announce` — is never
    /// consulted on this path).
    pub async fn apply_remove(&mut self, target: IpAddr, mono_now: u64, wall_now: u64) {
        let actions = self.controller.manual_remove(target);
        for action in actions {
            self.execute_and_journal(action, mono_now, wall_now).await;
        }
    }

    /// Re-install persisted blackholes on a fresh session (rehydration).
    ///
    /// For each row, calls [`RtbhController::resume`] and re-announces on BGP
    /// (without journaling — the row already exists in the journal). If the
    /// re-announce fails, the controller's entry is kept active (it is a
    /// known-good persisted mitigation, not rolled back the way a fresh
    /// `apply_event`/`apply_add` failure is — see the module docs) and
    /// queued via [`Self::queue_reapply`] for a retry on the next
    /// [`Self::tick`] (issue #194): unlike a live detection, a rehydrated row
    /// has no natural re-detection to compensate for a dropped announce. If
    /// `resume` returns no action (over cap, ineligible, or no next-hop),
    /// this logs a warning naming the target; a row is never silently
    /// dropped.
    pub async fn rehydrate(&mut self, rows: Vec<(IpAddr, u64, BlackholeOrigin)>, mono_now: u64) {
        for (target, _persisted_at, origin) in rows {
            let actions = self.controller.resume(target, mono_now, origin);
            if let Some(RtbhAction::Announce(route)) = actions.into_iter().next() {
                if let Err(e) = self.bgp.announce(route.clone()).await {
                    tracing::warn!(%target, error = %e, "RTBH: rehydrate re-announce failed; queuing for retry");
                    self.queue_reapply(ReapplyOp { target, route });
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

    /// Number of targets skipped by the controller's protected-prefix guard
    /// (own anycast VIPs never mitigated). Surfaced for `/metrics`; the
    /// owning task periodically copies this into a shared counter read by
    /// the metrics endpoint, mirroring how `min_sample_suppressed` reaches
    /// `/metrics` from the flow detector.
    #[must_use]
    pub fn protected_skipped(&self) -> u64 {
        self.controller.protected_skipped()
    }

    /// Count of announces that failed at the [`BgpExecutor`] (C2). Each
    /// failure rolls back the controller's freshly-inserted active entry
    /// (see [`RtbhController::rollback`]) so the control plane never
    /// believes an unconfirmed announce is active. Surfaced for `/metrics`
    /// as `blackwall_rtbh_apply_failures_total`, mirroring how
    /// [`Self::protected_skipped`] reaches the endpoint.
    #[must_use]
    pub fn apply_failures(&self) -> u64 {
        self.apply_failures
    }

    /// Count of announces skipped because the shared cross-plane
    /// [`ArmingRateLimiter`] (C6) was at capacity. Each skip rolls back the
    /// controller's freshly-inserted active entry (never left as a phantom
    /// active mitigation) and is distinct from [`Self::apply_failures`] — a
    /// rate-cap skip was never attempted at all. Surfaced for `/metrics` as
    /// `blackwall_mitigations_ratecapped_total{plane="rtbh"}`.
    #[must_use]
    pub fn ratecapped(&self) -> u64 {
        self.ratecapped
    }

    /// Number of `rehydrate` re-announces currently queued for a self-heal
    /// retry after a failed BGP announce on restart (issue #194). Each
    /// queued target is still active in the controller (kept, not rolled
    /// back) but not yet confirmed on the wire; drained by
    /// [`Self::retry_pending_reapply`] on the next [`Self::tick`]. Surfaced
    /// for `/metrics` as `blackwall_rtbh_reapply_pending`, mirroring how
    /// [`Self::apply_failures`] reaches the endpoint.
    #[must_use]
    pub fn reapply_pending(&self) -> usize {
        self.pending_reapply.len()
    }

    /// In-daemon disarm kill switch (C5): withdraw every currently-active
    /// blackhole and switch to record-only for the rest of this process's
    /// life.
    ///
    /// Each active target is withdrawn on BGP best-effort — a withdraw
    /// `Err` is logged and the sweep continues with the next target (never
    /// aborts), mirroring how [`Self::execute_and_journal`] already treats a
    /// withdraw failure elsewhere: log and move on. No journal write happens
    /// here, unlike a normal withdraw: disarm is a *runtime-only* state, not
    /// a persisted decision — a restart re-arms and [`Self::rehydrate`]s the
    /// very same active set from the journal, exactly as if disarm had never
    /// happened. Once disarmed, every subsequent `Announce` reaching
    /// [`Self::execute_and_journal_announce`] is skipped (never sent to
    /// [`Self::bgp`]) and counted in [`Self::disarmed_skips`] — detection
    /// and selection keep running unchanged (visibility retained), only the
    /// apply step is gated. One-way: calling this again is a no-op (idempotent
    /// under a repeated SIGUSR1), and there is no re-arm entry point.
    ///
    /// `mono_now` is accepted for symmetry with the other entry points that
    /// funnel through the execute path; it is unused here (a disarm withdraw
    /// bypasses hold-down via [`RtbhController::manual_remove`] and needs no
    /// time arithmetic).
    pub async fn disarm(&mut self, _mono_now: u64) {
        if self.disarmed {
            return;
        }
        self.disarmed = true;
        let targets: Vec<IpAddr> = self
            .controller
            .active_blackholes()
            .into_iter()
            .map(|(target, ..)| target)
            .collect();
        for target in targets {
            for action in self.controller.manual_remove(target) {
                if let RtbhAction::Withdraw(prefix) = action {
                    if let Err(e) = self.bgp.withdraw(prefix).await {
                        tracing::warn!(%target, error = %e, "RTBH: disarm withdraw failed; continuing best-effort");
                    }
                }
            }
        }
        tracing::warn!("RTBH: DISARMED — mitigations withdrawn, now recording only");
    }

    /// Count of new-mitigation announces skipped because the manager was
    /// [`Self::disarm`]ed (C5) — a SKIP (never attempted), distinct from
    /// both [`Self::apply_failures`] (attempted and failed at BGP) and
    /// [`Self::ratecapped`] (skipped for a different reason).
    #[must_use]
    pub fn disarmed_skips(&self) -> u64 {
        self.disarmed_skips
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

    /// Queue a failed `rehydrate` re-announce for retry, coalescing by
    /// target (issue #194).
    ///
    /// Mirrors [`Self::queue_mirror`]'s coalescing: only the latest queued
    /// op per target is kept, since a repeat rehydrate failure for the same
    /// target during an outage should never grow the queue past one entry.
    fn queue_reapply(&mut self, op: ReapplyOp) {
        self.pending_reapply.retain(|o| o.target != op.target);
        self.pending_reapply.push(op);
    }

    /// Execute one controller action on BGP and mirror it into the journal.
    async fn execute_and_journal(&mut self, action: RtbhAction, mono_now: u64, wall_now: u64) {
        match action {
            RtbhAction::Announce(route) => {
                self.execute_and_journal_announce(
                    ip_of(&route.prefix),
                    route,
                    BlackholeOrigin::Auto,
                    mono_now,
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

    /// Execute one NEW-mitigation `Announce` on BGP and mirror it into the
    /// journal.
    ///
    /// First consults the shared [`ArmingRateLimiter`] (C6), if attached: a
    /// rejection rolls back the controller's freshly-inserted active entry
    /// (same "commit-after-confirm" discipline as a BGP failure, see the
    /// module docs) and counts against [`Self::ratecapped`] — never
    /// [`Self::apply_failures`], since the announce was never attempted, not
    /// attempted-and-failed. Only reached for `Announce` actions (never a
    /// `Withdraw` or a controller re-assertion/refresh, which don't produce
    /// `Announce` at all).
    async fn execute_and_journal_announce(
        &mut self,
        target: IpAddr,
        route: Route,
        origin: BlackholeOrigin,
        mono_now: u64,
        wall_now: u64,
    ) -> AnnounceOutcome {
        if self.disarmed {
            tracing::warn!(%target, "RTBH: disarmed (C5); skipping announce, recording only");
            self.controller.rollback(target);
            self.disarmed_skips = self.disarmed_skips.saturating_add(1);
            return AnnounceOutcome::Disarmed;
        }
        if let Some(limiter) = &self.rate_limiter {
            let allowed = limiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .try_acquire(mono_now);
            if !allowed {
                tracing::warn!(%target, "RTBH: cross-plane new-mitigation rate cap exceeded (C6); skipping announce, not activating");
                self.controller.rollback(target);
                self.ratecapped = self.ratecapped.saturating_add(1);
                return AnnounceOutcome::RateCapped;
            }
        }
        if let Err(e) = self.bgp.announce(route).await {
            tracing::warn!(%target, error = %e, "RTBH: BGP announce failed; rolling back active entry, not journaling");
            self.controller.rollback(target);
            self.apply_failures = self.apply_failures.saturating_add(1);
            return AnnounceOutcome::Failed;
        }
        if let Err(e) = self.journal.record_announce(target, origin, wall_now).await {
            tracing::error!(%target, error = %e, "RTBH: journal write failed after announce; keeping active");
            self.queue_mirror(MirrorOp::Announce {
                target,
                origin,
                at_ms: wall_now,
            });
        }
        AnnounceOutcome::Applied
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

    /// Drain-retry queued `rehydrate` re-announces left over from a
    /// transient BGP failure (issue #194).
    ///
    /// Each queued op is first re-checked against the current active set:
    /// if the target is no longer active (e.g. cleared by a manual remove
    /// or a hold-down expiry between the failed rehydrate and this tick),
    /// the op is dropped — re-announcing a route the control plane no
    /// longer wants live would itself create a phantom. Otherwise the
    /// announce is re-attempted; ops that still fail are kept (retried
    /// again on the next call), ops that succeed are dropped.
    async fn retry_pending_reapply(&mut self) {
        if self.pending_reapply.is_empty() {
            return;
        }
        let ops = std::mem::take(&mut self.pending_reapply);
        for op in ops {
            if !self.is_active(op.target) {
                tracing::info!(target = %op.target, "RTBH: dropping queued rehydrate reapply; entry no longer active");
                continue;
            }
            if let Err(e) = self.bgp.announce(op.route.clone()).await {
                tracing::warn!(target = %op.target, error = %e, "RTBH: rehydrate reapply retry failed; re-queuing");
                self.pending_reapply.push(op);
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
    use crate::{BlackholeOrigin, NoOpJournal, RtbhConfig, RtbhController};
    use blackwall_flow::{AttackKind, Detection, DetectionEvent, Severity};
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default, Clone)]
    struct FakeBgp {
        announced: Arc<Mutex<Vec<IpNet>>>,
        withdrawn: Arc<Mutex<Vec<IpNet>>>,
        fail: Arc<Mutex<bool>>,
        /// Independent withdraw-only failure toggle, for exercising disarm's
        /// best-effort tolerance of a withdraw `Err` without also blocking
        /// the announce that must precede it (unlike `fail`, which fails
        /// both).
        fail_withdraw: Arc<Mutex<bool>>,
    }
    impl FakeBgp {
        /// Build a fake whose `announce`/`withdraw` fail from the start.
        fn with_fail(fail: bool) -> Self {
            let f = Self::default();
            f.set_fail(fail);
            f
        }
        /// Build a fake whose `withdraw` alone fails from the start
        /// (`announce` still succeeds).
        fn with_fail_withdraw(fail_withdraw: bool) -> Self {
            let f = Self::default();
            *f.fail_withdraw.lock().unwrap() = fail_withdraw;
            f
        }
        /// Flip the announce/withdraw failure toggle at runtime — lets a test
        /// simulate a BGP session recovering mid-scenario (a clone shares the
        /// same underlying flag with whatever manager holds this fake).
        fn set_fail(&self, fail: bool) {
            *self.fail.lock().unwrap() = fail;
        }
        /// Whether `prefix` (e.g. `"203.0.113.7/32"`) was ever announced.
        fn announced_contains(&self, prefix: &str) -> bool {
            let net: IpNet = prefix.parse().expect("valid prefix in test");
            self.announced.lock().unwrap().contains(&net)
        }
    }
    #[async_trait]
    impl BgpExecutor for FakeBgp {
        async fn announce(&self, route: Route) -> Result<(), BgpError> {
            if *self.fail.lock().unwrap() {
                return Err(BgpError);
            }
            self.announced.lock().unwrap().push(route.prefix);
            Ok(())
        }
        async fn withdraw(&self, prefix: IpNet) -> Result<(), BgpError> {
            if *self.fail.lock().unwrap() || *self.fail_withdraw.lock().unwrap() {
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
            if *self.fail.lock().unwrap() {
                return Err(BgpError);
            }
            Ok(())
        }
        async fn withdraw_flowspec(
            &self,
            _rule: blackwall_bgp::FlowSpecRule,
        ) -> Result<(), BgpError> {
            if *self.fail.lock().unwrap() {
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
            protected_prefixes: Vec::new(),
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
            pops: vec![],
            top_source_blocks: vec![],
            severity: Severity::High,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    /// A fresh controller over the same eligible-prefix config `mgr` uses —
    /// named for readability at rehydrate-focused call sites that build a
    /// [`RtbhManager`] directly rather than through `mgr`.
    fn controller_eligible() -> RtbhController {
        RtbhController::new(cfg())
    }
    fn mgr(fail_bgp: bool, fail_j: bool) -> RtbhManager<FakeBgp, FakeJournal> {
        RtbhManager::new(
            RtbhController::new(cfg()),
            FakeBgp::with_fail(fail_bgp),
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
    async fn failed_announce_does_not_leave_a_phantom_active_entry() {
        // BGP fails: the router never took the route, so the control plane
        // must NOT believe it did (C2) — the freshly-inserted active entry
        // must be rolled back, not left as a phantom "active" mitigation.
        let mut m = mgr(true, false); // BGP fails
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 1_000, 1_000)
            .await;
        assert!(
            !m.is_active(ip("203.0.113.7")),
            "a failed announce must not leave a phantom active entry"
        );
        assert_eq!(m.apply_failures(), 1);

        // A subsequent identical detection re-attempts (not deduped against
        // a phantom active entry) — no retry queue, just the natural
        // re-detection on the next tick.
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 2_000, 2_000)
            .await;
        assert_eq!(m.apply_failures(), 2);
    }

    #[tokio::test]
    async fn successful_announce_activates_and_journals_no_apply_failures() {
        let mut m = mgr(false, false);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 1_000, 1_000)
            .await;
        assert!(m.is_active(ip("203.0.113.7")));
        assert_eq!(m.apply_failures(), 0);
    }

    #[tokio::test]
    async fn rate_capped_announce_is_skipped_not_activated_and_not_an_apply_failure() {
        // C6: a shared limiter admitting only 1 announce per minute. The
        // second Opened in the same window must be SKIPPED (never reach
        // BGP), rolled back so it is not left as a phantom active entry, and
        // counted as `ratecapped` — NOT `apply_failures` (it was never
        // attempted, unlike a BGP failure).
        let mut m =
            mgr(false, false).with_rate_limiter(Arc::new(Mutex::new(ArmingRateLimiter::new(1))));
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 1_000, 1_000)
            .await;
        assert!(m.is_active(ip("203.0.113.7")), "first announce is admitted");

        m.apply_event(&DetectionEvent::Opened(det("203.0.113.8")), 1_500, 1_500)
            .await;
        assert!(
            !m.is_active(ip("203.0.113.8")),
            "rate-capped announce must not leave a phantom active entry"
        );
        assert!(
            m.bgp().announced.lock().unwrap().len() == 1,
            "the rate-capped announce must never reach BGP"
        );
        assert_eq!(m.ratecapped(), 1);
        assert_eq!(
            m.apply_failures(),
            0,
            "a rate-cap skip is not an apply_failure (never attempted)"
        );

        // Once the window rolls, the target is admitted normally.
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.8")), 61_500, 61_500)
            .await;
        assert!(m.is_active(ip("203.0.113.8")));
        assert_eq!(m.ratecapped(), 1);
    }

    #[tokio::test]
    async fn no_rate_limiter_attached_is_unlimited() {
        // Non-breaking: a manager with no limiter attached (the default from
        // `new`) behaves exactly as before this feature existed.
        let mut m = mgr(false, false);
        for i in 0..10u8 {
            let target = format!("203.0.113.{}", i + 1);
            m.apply_add(target.parse().unwrap(), u64::from(i), u64::from(i))
                .await;
        }
        assert_eq!(
            m.bgp().announced.lock().unwrap().len(),
            2,
            "still bounded by max_blackholes=2 in cfg(), not by any rate cap"
        );
        assert_eq!(m.ratecapped(), 0);
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
    async fn apply_add_protected_target_is_rejected_not_deferred() {
        // Target sits inside BOTH an eligible prefix and a protected prefix —
        // exactly the overlap the protected-prefix guard exists for (an
        // anycast VIP inside a customer-eligible block). A manual add must be
        // classified as Rejected, not Deferred: a Deferred outcome leaves the
        // request row 'pending' forever, retried every tick, indistinguishable
        // from a transient capacity wait that will never resolve (C1 follow-up).
        let mut m = RtbhManager::new(
            RtbhController::new(RtbhConfig {
                protected_prefixes: vec!["203.0.113.53/32".parse().unwrap()],
                ..cfg()
            }),
            FakeBgp::default(),
            FakeJournal::default(),
        );
        let outcome = m.apply_add(ip("203.0.113.53"), 0, 0).await;
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
        m.apply_remove(ip("203.0.113.7"), 1000, 1000).await;
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

        m.apply_remove(ip("203.0.113.7"), 2000, 2000).await;
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
        m.apply_remove(ip("203.0.113.7"), 2000, 2000).await;
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 3000, 3000)
            .await;
        assert_eq!(
            m.pending_mirror_len(),
            1,
            "repeated failures for one target coalesce to a single queued op"
        );
    }

    #[tokio::test]
    async fn disarm_withdraws_all_and_switches_to_record_only() {
        // C5: disarm must withdraw every active blackhole on BGP (best
        // effort), clear the active set, and thereafter skip every new
        // Announce (record-only) — detection/selection keep running (the
        // manager still accepts events), only the apply step is gated.
        let mut m = mgr(false, false);
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 1_000, 1_000)
            .await;
        assert!(m.is_active(ip("203.0.113.7")));

        m.disarm(2_000).await;

        assert!(
            m.bgp()
                .withdrawn
                .lock()
                .unwrap()
                .contains(&"203.0.113.7/32".parse::<IpNet>().unwrap()),
            "disarm must withdraw every active target"
        );
        assert!(
            !m.is_active(ip("203.0.113.7")),
            "disarm must clear the active set"
        );

        // A subsequent detection is recorded (the controller still runs),
        // but must NOT be announced — record-only.
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.8")), 3_000, 3_000)
            .await;
        assert_eq!(
            m.bgp().announced.lock().unwrap().len(),
            1,
            "no new announce may execute once disarmed"
        );
        assert!(
            !m.is_active(ip("203.0.113.8")),
            "a disarmed skip must not leave a phantom active entry"
        );
        assert_eq!(
            m.apply_failures(),
            0,
            "a disarmed skip is not an apply_failure (never attempted)"
        );
        assert_eq!(m.ratecapped(), 0, "a disarmed skip is not a rate-cap skip");
        assert_eq!(m.disarmed_skips(), 1);
    }

    #[tokio::test]
    async fn disarm_tolerates_a_withdraw_error() {
        // Best-effort: a withdraw Err during disarm must not abort the
        // sweep (a second active target is still withdrawn) or stop the
        // manager from switching to record-only.
        let mut m = RtbhManager::new(
            RtbhController::new(cfg()),
            FakeBgp::with_fail_withdraw(true),
            FakeJournal::default(),
        );
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 0, 0)
            .await;
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.8")), 0, 0)
            .await;
        assert_eq!(m.active().len(), 2);

        m.disarm(1_000).await;

        assert!(
            m.bgp().withdrawn.lock().unwrap().is_empty(),
            "every withdraw errored, so none was recorded by the fake"
        );
        assert!(
            m.active().is_empty(),
            "disarm clears the active set even when every withdraw errors (best-effort)"
        );

        // Record-only holds even though disarm itself never got a
        // confirmed withdraw.
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.9")), 2_000, 2_000)
            .await;
        assert!(!m.is_active(ip("203.0.113.9")));
    }

    #[tokio::test]
    async fn apply_add_while_disarmed_is_rejected_not_applied() {
        // C5 + final-review fix: a manual add while disarmed must be
        // classified Rejected (retrying is pointless — there is no re-arm
        // entry point), never Applied — an "applied" operator-request row
        // is never retried, which would silently lose operator intent.
        let mut m = mgr(false, false);
        m.disarm(0).await;

        let outcome = m.apply_add(ip("203.0.113.7"), 1_000, 1_000).await;
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
            !m.is_active(ip("203.0.113.7")),
            "a disarmed manual add must not leave a phantom active entry"
        );
        assert!(m.bgp().announced.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_add_while_rate_capped_is_deferred_not_applied() {
        // C6 + final-review fix: a manual add rejected by the shared rate
        // limiter must be classified Deferred (the request row stays
        // `pending` and is retried next tick, once the window has room),
        // never Applied.
        let mut m =
            mgr(false, false).with_rate_limiter(Arc::new(Mutex::new(ArmingRateLimiter::new(1))));
        // Exhaust the limiter's one slot for this window via an auto path.
        m.apply_event(&DetectionEvent::Opened(det("203.0.113.7")), 1_000, 1_000)
            .await;
        assert!(m.is_active(ip("203.0.113.7")));

        let outcome = m.apply_add(ip("203.0.113.8"), 1_500, 1_500).await;
        assert_eq!(
            outcome,
            ApplyOutcome::Deferred,
            "a rate-capped manual add must be Deferred, not Applied"
        );
        assert!(
            !m.is_active(ip("203.0.113.8")),
            "a rate-capped manual add must not leave a phantom active entry"
        );
        assert_eq!(m.ratecapped(), 1);
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

    #[tokio::test]
    async fn rehydrate_failure_queues_reapply_and_tick_reconverges() {
        // #194 C1: a persisted, eligible row whose rehydrate re-announce
        // fails must NOT be left stranded (active in the controller but
        // never on the wire) — it is queued for retry and the queue drains
        // once the BGP session recovers.
        let bgp = FakeBgp::default();
        bgp.set_fail(true); // announce errors
        let mut mgr = RtbhManager::new(controller_eligible(), bgp.clone(), NoOpJournal);
        mgr.rehydrate(
            vec![(ip("203.0.113.7"), 1_000, BlackholeOrigin::Auto)],
            1_000,
        )
        .await;
        assert!(mgr.is_active(ip("203.0.113.7")), "entry kept (not dropped)");
        assert_eq!(
            mgr.reapply_pending(),
            1,
            "failed re-announce queued for retry"
        );

        // Session recovers; the next tick re-announces and drains the queue.
        bgp.set_fail(false);
        mgr.tick(2_000, 2_000).await;
        assert_eq!(mgr.reapply_pending(), 0);
        assert!(bgp.announced_contains("203.0.113.7/32"));
    }

    #[tokio::test]
    async fn queue_reapply_dedupes_and_drops_if_cleared() {
        // A still-failing tick must coalesce (not double-enqueue) the retry
        // for the same target; and once the entry is cleared before it ever
        // succeeds, the queued reapply must be dropped rather than
        // re-announcing a no-longer-wanted route.
        let bgp = FakeBgp::default();
        bgp.set_fail(true);
        let mut mgr = RtbhManager::new(controller_eligible(), bgp.clone(), NoOpJournal);
        mgr.rehydrate(
            vec![(ip("203.0.113.7"), 1_000, BlackholeOrigin::Auto)],
            1_000,
        )
        .await;
        mgr.tick(2_000, 2_000).await; // still failing -> re-queued, NOT double-enqueued
        assert_eq!(mgr.reapply_pending(), 1, "coalesced, not doubled");

        // Cleared before it ever succeeded (manual withdraw).
        mgr.apply_remove(ip("203.0.113.7"), 3_000, 3_000).await;
        bgp.set_fail(false);
        mgr.tick(4_000, 4_000).await;
        assert_eq!(mgr.reapply_pending(), 0, "dropped: entry no longer active");
        assert!(
            !bgp.announced_contains("203.0.113.7/32"),
            "not re-announced after clear"
        );
    }
}
