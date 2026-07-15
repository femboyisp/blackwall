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
use crate::rate_limit::ArmingRateLimiter;
use async_trait::async_trait;
use blackwall_bgp::FlowSpecRule;
use blackwall_flow::FlowRule;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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

/// A [`FlowSpecManager::rehydrate`] re-announce that failed at the
/// [`BgpExecutor`] and is queued for a self-heal retry (issue #194).
///
/// Mirrors [`crate::manager`]'s private `ReapplyOp`, keyed by [`FlowKey`]
/// instead of target IP — unlike [`MirrorOp`] (which only ever replays a
/// journal write, the BGP side already having succeeded), a queued
/// `ReapplyOp` re-attempts the BGP `announce_flowspec` itself: rehydrate's
/// failure happens on the BGP side, not the journal side (rehydrate never
/// journals in the first place).
///
/// Holds only the [`FlowKey`], not the rule that was captured when the op
/// was queued: [`FlowSpecManager::retry_pending_reapply`] re-derives the
/// CURRENT rule from [`FlowSpecController::active_rule`] at retry time
/// rather than replaying a snapshot, so a fresh, successful re-assertion of
/// the same key with a changed action (C4 — e.g. `manual_add`'s
/// `changed_action_re_announces`) that lands between the failed rehydrate
/// and the retry is never clobbered by the stale queued content (#194 C1
/// follow-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReapplyOp {
    /// The key of the rule to re-announce; the current rule content is
    /// looked up fresh from the controller at retry time.
    key: FlowKey,
}

impl ReapplyOp {
    /// The `FlowKey` this reapply op concerns.
    fn key(&self) -> FlowKey {
        self.key
    }
}

/// Outcome of [`FlowSpecManager::execute_and_journal_announce`].
///
/// Mirrors [`crate::manager`]'s private `AnnounceOutcome`. The auto path
/// (`apply_open`/`tick`, via [`FlowSpecManager::execute_and_journal`])
/// ignores this — auto re-detection naturally compensates for a skip on its
/// next tick. [`FlowSpecManager::apply_add`] (the manual path) consumes it
/// to report a truthful [`ApplyOutcome`] rather than always claiming
/// [`ApplyOutcome::Applied`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnnounceOutcome {
    /// The announce reached BGP; a journal-mirror failure afterward is still
    /// `Applied` (self-healed via [`FlowSpecManager::retry_pending_mirror`])
    /// — the live rule is active either way.
    Applied,
    /// Skipped: the shared cross-plane [`ArmingRateLimiter`] (C6) was at
    /// capacity. The controller entry was rolled back.
    RateCapped,
    /// Skipped: the manager is [`FlowSpecManager::disarm`]ed (C5),
    /// record-only. The controller entry was rolled back.
    Disarmed,
    /// Attempted and failed at the [`BgpExecutor`] (C2). The controller
    /// entry was rolled back.
    Failed,
}

/// Single-owner FlowSpec manager.
///
/// Owns the pure [`FlowSpecController`] plus the I/O boundary: it executes the
/// controller's decisions on a [`BgpExecutor`] and mirrors auto/manual rule
/// state via a [`FlowSpecJournal`]. A BGP announce failure is logged, the
/// action is not journaled, and the controller's freshly-inserted active
/// entry is rolled back via [`FlowSpecController::rollback`] (C2:
/// commit-after-confirm) — the control plane never believes an unconfirmed
/// announce succeeded, so a future detection for the same rule is not deduped
/// against a phantom entry. There is no retry queue for this: while the
/// underlying attack persists, the detector naturally re-emits the detection
/// on its next tick and the manager re-attempts through the same path. This
/// differs from a *journal* failure after a successful BGP operation, which
/// is logged, never causes a live rule to be withdrawn, and is queued as a
/// `MirrorOp` for a bounded self-heal retry on the next
/// [`FlowSpecManager::tick`] — the BGP outcome is never re-issued, only the
/// mirror write.
pub struct FlowSpecManager<B: BgpExecutor, J: FlowSpecJournal> {
    controller: FlowSpecController,
    bgp: B,
    journal: J,
    /// Journal writes that failed after their BGP operation already
    /// succeeded; retried (never re-issued to BGP) by
    /// `FlowSpecManager::retry_pending_mirror` on the next tick.
    pending_mirror: Vec<MirrorOp>,
    /// `rehydrate` re-announces that failed at the [`BgpExecutor`]; retried
    /// by [`Self::retry_pending_reapply`] on the next tick (issue #194). The
    /// controller's active entry from [`FlowSpecController::resume`] is kept
    /// (never rolled back) while queued — unlike a live BGP failure on the
    /// `apply_open`/`apply_add` path, a rehydrated rule is a known-good
    /// persisted mitigation with no fresh detection to naturally re-attempt
    /// it, so rollback would strand the control plane believing nothing is
    /// announced while the journal still says otherwise (mirrors
    /// `blackwall_rtbh::manager::RtbhManager`'s private `pending_reapply`).
    pending_reapply: Vec<ReapplyOp>,
    /// Count of announces that failed at the BGP executor, each rolled back
    /// (see [`Self::apply_failures`]).
    apply_failures: u64,
    /// Cross-plane cap (C6) on the arrival rate of NEW mitigations, shared
    /// with the sibling `RtbhManager` via the same `Arc<Mutex<_>>` so ONE
    /// limiter governs the combined RTBH+FlowSpec announce rate. `None` (the
    /// default from [`Self::new`]) is unlimited — `main.rs` only attaches
    /// `Some` via [`Self::with_rate_limiter`] on the live path (never under
    /// shadow, where nothing is really announced).
    rate_limiter: Option<Arc<Mutex<ArmingRateLimiter>>>,
    /// Count of announces skipped because [`Self::rate_limiter`] was at
    /// capacity (C6) — a SKIP (never attempted), distinct from
    /// [`Self::apply_failures`] (attempted and failed at BGP). See
    /// [`Self::ratecapped`].
    ratecapped: u64,
    /// One-way in-daemon disarm kill switch (C5), flipped by [`Self::disarm`].
    /// While set, [`Self::execute_and_journal_announce`] skips every new
    /// `Announce` (never reaches [`Self::bgp`]) while detection + selection
    /// keep running unchanged. There is no re-arm entry point; a fresh
    /// process (restart) is the only way back to armed. Mirrors
    /// [`crate::manager::RtbhManager::disarmed`].
    disarmed: bool,
    /// Count of announces skipped because [`Self::disarmed`] was set (C5) —
    /// a SKIP (never attempted), distinct from both [`Self::apply_failures`]
    /// and [`Self::ratecapped`]. See [`Self::disarmed_skips`].
    disarmed_skips: u64,
}

impl<B: BgpExecutor, J: FlowSpecJournal> FlowSpecManager<B, J> {
    /// Wrap a controller with a BGP executor and a journal.
    pub fn new(controller: FlowSpecController, bgp: B, journal: J) -> Self {
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
            self.execute_and_journal(action, mono_now, wall_now).await;
        }
    }

    /// Clear every active rule for `target` (from a
    /// [`blackwall_flow::FlowMitigationEvent::Clear`]) and execute + journal
    /// the withdraws that clear immediately (hold-down permitting; the rest
    /// are deferred to a later [`Self::tick`]).
    pub async fn apply_clear(&mut self, target: IpAddr, mono_now: u64, wall_now: u64) {
        let actions = self.controller.clear_target(target, mono_now);
        for action in actions {
            self.execute_and_journal(action, mono_now, wall_now).await;
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
    /// `FlowSpecManager::retry_pending_mirror`), then any `rehydrate`
    /// re-announces queued by a previous tick's transient BGP failure (see
    /// [`Self::retry_pending_reapply`], issue #194), so both self-heals
    /// converge within one tick interval of the respective dependency
    /// recovering.
    pub async fn tick(&mut self, mono_now: u64, wall_now: u64) {
        self.retry_pending_mirror().await;
        self.retry_pending_reapply().await;
        let actions = self.controller.tick(mono_now);
        for action in actions {
            self.execute_and_journal(action, mono_now, wall_now).await;
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
            let outcome = self
                .execute_and_journal_announce(r, BlackholeOrigin::Manual, mono_now, wall_now)
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
    ///
    /// `mono_now` is accepted for symmetry with the other entry points that
    /// funnel through [`Self::execute_and_journal`] (it is unused here: a
    /// manual removal only ever produces a `Withdraw`, never an `Announce`,
    /// so the shared rate limiter — which only gates `Announce` — is never
    /// consulted on this path).
    pub async fn apply_remove(&mut self, rule: FlowSpecRule, mono_now: u64, wall_now: u64) {
        let actions = self.controller.manual_remove(rule);
        for action in actions {
            self.execute_and_journal(action, mono_now, wall_now).await;
        }
    }

    /// Re-install persisted FlowSpec rules on a fresh session (rehydration).
    ///
    /// For each row, calls [`FlowSpecController::resume`] and re-announces on
    /// BGP (without journaling — the row already exists in the journal). If
    /// the re-announce fails, the controller's entry is kept active (it is a
    /// known-good persisted mitigation, not rolled back the way a fresh
    /// `apply_open`/`apply_add` failure is — see the module docs) and queued
    /// via [`Self::queue_reapply`] for a retry on the next [`Self::tick`]
    /// (issue #194): unlike a live detection, a rehydrated rule has no
    /// natural re-detection to compensate for a dropped announce. If
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
                if let Err(e) = self.bgp.announce_flowspec(r.clone()).await {
                    tracing::warn!(%target, error = %e, "FlowSpec: rehydrate re-announce failed; queuing for retry");
                    self.queue_reapply(ReapplyOp { key: key_of(&r) });
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

    /// Count of announces that failed at the [`BgpExecutor`] (C2). Each
    /// failure rolls back the controller's freshly-inserted active entry
    /// (see [`FlowSpecController::rollback`]) so the control plane never
    /// believes an unconfirmed announce is active. Surfaced for `/metrics`
    /// as `blackwall_flowspec_apply_failures_total`, mirroring
    /// [`crate::manager::RtbhManager::apply_failures`].
    #[must_use]
    pub fn apply_failures(&self) -> u64 {
        self.apply_failures
    }

    /// Count of announces skipped because the shared cross-plane
    /// [`ArmingRateLimiter`] (C6) was at capacity. Each skip rolls back the
    /// controller's freshly-inserted active entry (never left as a phantom
    /// active rule) and is distinct from [`Self::apply_failures`] — a
    /// rate-cap skip was never attempted at all. Surfaced for `/metrics` as
    /// `blackwall_mitigations_ratecapped_total{plane="flowspec"}`.
    #[must_use]
    pub fn ratecapped(&self) -> u64 {
        self.ratecapped
    }

    /// Number of `rehydrate` re-announces currently queued for a self-heal
    /// retry after a failed BGP announce on restart (issue #194). Each
    /// queued rule is still active in the controller (kept, not rolled back)
    /// but not yet confirmed on the wire; drained by
    /// [`Self::retry_pending_reapply`] on the next [`Self::tick`]. Surfaced
    /// for `/metrics` as `blackwall_flowspec_reapply_pending`, mirroring
    /// `blackwall_rtbh::manager::RtbhManager::reapply_pending`.
    #[must_use]
    pub fn reapply_pending(&self) -> usize {
        self.pending_reapply.len()
    }

    /// In-daemon disarm kill switch (C5): withdraw every currently-active
    /// rule and switch to record-only for the rest of this process's life.
    ///
    /// Mirrors [`crate::manager::RtbhManager::disarm`]: each active rule is
    /// withdrawn on BGP best-effort (a withdraw `Err` is logged and the
    /// sweep continues), no journal write happens (disarm is runtime-only —
    /// a restart re-arms and [`Self::rehydrate`]s the same active set), and
    /// once disarmed every subsequent `Announce` is skipped in
    /// [`Self::execute_and_journal_announce`] and counted in
    /// [`Self::disarmed_skips`]. One-way and idempotent.
    ///
    /// `mono_now` is accepted for symmetry with the other entry points that
    /// funnel through the execute path; it is unused here.
    pub async fn disarm(&mut self, _mono_now: u64) {
        if self.disarmed {
            return;
        }
        self.disarmed = true;
        let keys: Vec<FlowKey> = self
            .controller
            .active_rules()
            .into_iter()
            .map(|(key, ..)| key)
            .collect();
        for key in keys {
            // The action on this synthetic rule is never read: `manual_remove`
            // looks the entry up by `(dst, protocol, dst_port)` only (see
            // `key_of`) and withdraws the *stored* rule, action included.
            let placeholder = FlowSpecRule {
                dst: key.0,
                protocol: Some(key.1),
                dst_port: Some(key.2),
                action: blackwall_bgp::FlowAction::TrafficRate(0.0),
            };
            for action in self.controller.manual_remove(placeholder) {
                if let FlowSpecAction::Withdraw(rule) = action {
                    if let Err(e) = self.bgp.withdraw_flowspec(rule).await {
                        tracing::warn!(?key, error = %e, "FlowSpec: disarm withdraw failed; continuing best-effort");
                    }
                }
            }
        }
        tracing::warn!("FlowSpec: DISARMED — mitigations withdrawn, now recording only");
    }

    /// Count of new-mitigation announces skipped because the manager was
    /// [`Self::disarm`]ed (C5) — a SKIP (never attempted), distinct from
    /// both [`Self::apply_failures`] and [`Self::ratecapped`].
    #[must_use]
    pub fn disarmed_skips(&self) -> u64 {
        self.disarmed_skips
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

    /// Queue a failed `rehydrate` re-announce for retry, coalescing by
    /// [`FlowKey`] (issue #194).
    ///
    /// Mirrors [`Self::queue_mirror`]'s coalescing: only the latest queued
    /// op per key is kept, since a repeat rehydrate failure for the same
    /// rule during an outage should never grow the queue past one entry.
    fn queue_reapply(&mut self, op: ReapplyOp) {
        let key = op.key();
        self.pending_reapply.retain(|o| o.key() != key);
        self.pending_reapply.push(op);
    }

    /// Execute one controller action on BGP and mirror it into the journal.
    async fn execute_and_journal(&mut self, action: FlowSpecAction, mono_now: u64, wall_now: u64) {
        match action {
            FlowSpecAction::Announce(rule) => {
                self.execute_and_journal_announce(rule, BlackholeOrigin::Auto, mono_now, wall_now)
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

    /// Execute one NEW-mitigation `Announce` on BGP and mirror it into the
    /// journal.
    ///
    /// First consults the shared [`ArmingRateLimiter`] (C6), if attached: a
    /// rejection rolls back the controller's freshly-inserted active entry
    /// (same "commit-after-confirm" discipline as a BGP failure, see the
    /// module docs) and counts against [`Self::ratecapped`] — never
    /// [`Self::apply_failures`], since the announce was never attempted, not
    /// attempted-and-failed. Only reached for `Announce` actions.
    async fn execute_and_journal_announce(
        &mut self,
        rule: FlowSpecRule,
        origin: BlackholeOrigin,
        mono_now: u64,
        wall_now: u64,
    ) -> AnnounceOutcome {
        let key = key_of(&rule);
        if self.disarmed {
            tracing::warn!(
                ?key,
                "FlowSpec: disarmed (C5); skipping announce, recording only"
            );
            self.controller.rollback(key);
            self.disarmed_skips = self.disarmed_skips.saturating_add(1);
            return AnnounceOutcome::Disarmed;
        }
        if let Some(limiter) = &self.rate_limiter {
            let allowed = limiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .try_acquire(mono_now);
            if !allowed {
                tracing::warn!(?key, "FlowSpec: cross-plane new-mitigation rate cap exceeded (C6); skipping announce, not activating");
                self.controller.rollback(key);
                self.ratecapped = self.ratecapped.saturating_add(1);
                return AnnounceOutcome::RateCapped;
            }
        }
        if let Err(e) = self.bgp.announce_flowspec(rule.clone()).await {
            tracing::warn!(?key, error = %e, "FlowSpec: BGP announce failed; rolling back active entry, not journaling");
            self.controller.rollback(key);
            self.apply_failures = self.apply_failures.saturating_add(1);
            return AnnounceOutcome::Failed;
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

    /// Drain-retry queued `rehydrate` re-announces left over from a
    /// transient BGP failure (issue #194).
    ///
    /// Each queued op re-derives the CURRENT rule for its key from
    /// [`FlowSpecController::active_rule`] rather than replaying the rule
    /// snapshot captured when the op was queued: if the key is no longer
    /// active (e.g. cleared by a manual remove or a hold-down expiry between
    /// the failed rehydrate and this tick), `active_rule` returns `None` and
    /// the op is dropped — re-announcing a rule the control plane no longer
    /// wants live would itself create a phantom. If the key is still active
    /// but a fresh, successful re-assertion changed its action in the
    /// meantime (C4 — e.g. a detection or operator call tightening the
    /// rate), re-deriving picks up that CURRENT action instead of replaying
    /// the stale queued one, which would otherwise silently revert the fresh
    /// update (#194 C1 follow-up). Otherwise the announce is re-attempted;
    /// ops that still fail are kept (retried again on the next call), ops
    /// that succeed are dropped.
    async fn retry_pending_reapply(&mut self) {
        if self.pending_reapply.is_empty() {
            return;
        }
        let ops = std::mem::take(&mut self.pending_reapply);
        for op in ops {
            let key = op.key();
            let Some(rule) = self.controller.active_rule(key) else {
                tracing::info!(
                    ?key,
                    "FlowSpec: dropping queued rehydrate reapply; entry no longer active"
                );
                continue;
            };
            if let Err(e) = self.bgp.announce_flowspec(rule).await {
                tracing::warn!(?key, error = %e, "FlowSpec: rehydrate reapply retry failed; re-queuing");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flowspec_controller::FlowSpecConfig;
    use blackwall_bgp::FlowAction;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default, Clone)]
    struct FakeBgp {
        announced: Arc<Mutex<Vec<FlowSpecRule>>>,
        withdrawn: Arc<Mutex<Vec<FlowSpecRule>>>,
        fail: Arc<Mutex<bool>>,
    }
    impl FakeBgp {
        /// Build a fake whose `announce_flowspec`/`withdraw_flowspec` fail
        /// from the start.
        fn with_fail(fail: bool) -> Self {
            let f = Self::default();
            f.set_fail(fail);
            f
        }
        /// Flip the announce/withdraw failure toggle at runtime — lets a
        /// test simulate a BGP session recovering mid-scenario (a clone
        /// shares the same underlying flag with whatever manager holds this
        /// fake).
        fn set_fail(&self, fail: bool) {
            *self.fail.lock().unwrap() = fail;
        }
        /// Whether `rule` was ever announced.
        fn announced_contains(&self, rule: &FlowSpecRule) -> bool {
            self.announced.lock().unwrap().contains(rule)
        }
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
            if *self.fail.lock().unwrap() {
                return Err(crate::manager::BgpError);
            }
            self.announced.lock().unwrap().push(rule);
            Ok(())
        }
        async fn withdraw_flowspec(
            &self,
            rule: FlowSpecRule,
        ) -> Result<(), crate::manager::BgpError> {
            if *self.fail.lock().unwrap() {
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
            FakeBgp::with_fail(fail_bgp),
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
    async fn failed_announce_does_not_leave_a_phantom_active_entry() {
        // BGP fails: the router never took the rule, so the control plane
        // must NOT believe it did (C2) — the freshly-inserted active entry
        // must be rolled back, not left as a phantom "active" rule.
        let mut m = mgr(true, false); // BGP fails
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            1_000,
            1_000,
        )
        .await;
        let key = key_of(&rule("203.0.113.7/32", 17, 53, 0.0));
        assert!(
            !m.is_active(key),
            "a failed announce must not leave a phantom active entry"
        );
        assert_eq!(m.apply_failures(), 1);

        // A subsequent identical detection re-attempts (not deduped against
        // a phantom active entry) — no retry queue, just the natural
        // re-detection on the next tick.
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            2_000,
            2_000,
        )
        .await;
        assert_eq!(m.apply_failures(), 2);
    }

    #[tokio::test]
    async fn successful_announce_activates_and_journals_no_apply_failures() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            1_000,
            1_000,
        )
        .await;
        let key = key_of(&rule("203.0.113.7/32", 17, 53, 0.0));
        assert!(m.is_active(key));
        assert_eq!(m.apply_failures(), 0);
    }

    #[tokio::test]
    async fn rate_capped_announce_is_skipped_not_activated_and_not_an_apply_failure() {
        // C6: mirrors `manager::tests::rate_capped_announce_is_skipped_...`
        // for the FlowSpec side of the SAME shared limiter type.
        let mut m =
            mgr(false, false).with_rate_limiter(Arc::new(Mutex::new(ArmingRateLimiter::new(1))));
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            1_000,
            1_000,
        )
        .await;
        let key1 = key_of(&rule("203.0.113.7/32", 17, 53, 0.0));
        assert!(m.is_active(key1), "first announce is admitted");

        m.apply_open(
            ip("203.0.113.8"),
            &[flow_rule("203.0.113.8", 17, 53, 0.0)],
            1_500,
            1_500,
        )
        .await;
        let key2 = key_of(&rule("203.0.113.8/32", 17, 53, 0.0));
        assert!(
            !m.is_active(key2),
            "rate-capped announce must not leave a phantom active entry"
        );
        assert_eq!(
            m.bgp().announced.lock().unwrap().len(),
            1,
            "the rate-capped announce must never reach BGP"
        );
        assert_eq!(m.ratecapped(), 1);
        assert_eq!(
            m.apply_failures(),
            0,
            "a rate-cap skip is not an apply_failure (never attempted)"
        );
    }

    #[tokio::test]
    async fn no_rate_limiter_attached_is_unlimited() {
        // Non-breaking: a manager with no limiter attached (the default from
        // `new`) behaves exactly as before this feature existed.
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
        assert_eq!(
            m.bgp().announced.lock().unwrap().len(),
            2,
            "still bounded by max_rules=2 in cfg(), not by any rate cap"
        );
        assert_eq!(m.ratecapped(), 0);
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
        m.apply_remove(r, 1000, 1000).await;
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
        m.apply_remove(rule("203.0.113.7/32", 17, 53, 0.0), 2000, 2000)
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
    async fn disarm_withdraws_all_and_switches_to_record_only() {
        let mut m = mgr(false, false);
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            1_000,
            1_000,
        )
        .await;
        let key = key_of(&rule("203.0.113.7/32", 17, 53, 0.0));
        assert!(m.is_active(key));

        m.disarm(2_000).await;

        assert_eq!(
            m.bgp().withdrawn.lock().unwrap().len(),
            1,
            "disarm must withdraw every active rule"
        );
        assert!(!m.is_active(key), "disarm must clear the active set");

        // A subsequent detection is recorded, not executed.
        m.apply_open(
            ip("203.0.113.8"),
            &[flow_rule("203.0.113.8", 17, 53, 0.0)],
            3_000,
            3_000,
        )
        .await;
        let key2 = key_of(&rule("203.0.113.8/32", 17, 53, 0.0));
        assert!(!m.is_active(key2));
        assert_eq!(m.bgp().announced.lock().unwrap().len(), 1);
        assert_eq!(m.apply_failures(), 0);
        assert_eq!(m.ratecapped(), 0);
        assert_eq!(m.disarmed_skips(), 1);
    }

    #[tokio::test]
    async fn apply_add_while_disarmed_is_rejected_not_applied() {
        // C5 + final-review fix: a manual add while disarmed must be
        // classified Rejected (retrying is pointless — there is no re-arm
        // entry point), never Applied — an "applied" operator-request row
        // is never retried, which would silently lose operator intent.
        let mut m = mgr(false, false);
        m.disarm(0).await;

        let outcome = m
            .apply_add(rule("203.0.113.7/32", 17, 53, 0.0), 1_000, 1_000)
            .await;
        match &outcome {
            ApplyOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("disarmed"),
                    "reason should mention 'disarmed': {reason}"
                );
            }
            other => panic!("disarmed manual add must be Rejected, not {other:?}"),
        }
        let key = key_of(&rule("203.0.113.7/32", 17, 53, 0.0));
        assert!(
            !m.is_active(key),
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
        m.apply_open(
            ip("203.0.113.7"),
            &[flow_rule("203.0.113.7", 17, 53, 0.0)],
            1_000,
            1_000,
        )
        .await;
        let key1 = key_of(&rule("203.0.113.7/32", 17, 53, 0.0));
        assert!(m.is_active(key1));

        let outcome = m
            .apply_add(rule("203.0.113.8/32", 17, 53, 0.0), 1_500, 1_500)
            .await;
        assert_eq!(
            outcome,
            ApplyOutcome::Deferred,
            "a rate-capped manual add must be Deferred, not Applied"
        );
        let key2 = key_of(&rule("203.0.113.8/32", 17, 53, 0.0));
        assert!(
            !m.is_active(key2),
            "a rate-capped manual add must not leave a phantom active entry"
        );
        assert_eq!(m.ratecapped(), 1);
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

        m.apply_remove(rule("203.0.113.7/32", 17, 53, 0.0), 2000, 2000)
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

    #[tokio::test]
    async fn rehydrate_failure_queues_reapply_and_tick_reconverges() {
        // #194 C1: a persisted, eligible rule whose rehydrate re-announce
        // fails must NOT be left stranded (active in the controller but
        // never on the wire) — it is queued for retry and the queue drains
        // once the BGP session recovers.
        let bgp = FakeBgp::with_fail(true); // announce errors
        let mut m = FlowSpecManager::new(
            FlowSpecController::new(cfg()),
            bgp.clone(),
            FakeJournal::default(),
        );
        let r = rule("203.0.113.7/32", 17, 53, 0.0);
        m.rehydrate(vec![(r.clone(), 1_000, BlackholeOrigin::Auto)], 1_000)
            .await;
        let key = key_of(&r);
        assert!(m.is_active(key), "entry kept (not dropped)");
        assert_eq!(
            m.reapply_pending(),
            1,
            "failed re-announce queued for retry"
        );

        // Session recovers; the next tick re-announces and drains the queue.
        bgp.set_fail(false);
        m.tick(2_000, 2_000).await;
        assert_eq!(m.reapply_pending(), 0);
        assert!(bgp.announced_contains(&r));
    }

    #[tokio::test]
    async fn queue_reapply_dedupes_and_drops_if_cleared() {
        // A still-failing tick must coalesce (not double-enqueue) the retry
        // for the same rule; and once the rule is cleared before it ever
        // succeeds, the queued reapply must be dropped rather than
        // re-announcing a no-longer-wanted rule.
        let bgp = FakeBgp::with_fail(true);
        let mut m = FlowSpecManager::new(
            FlowSpecController::new(cfg()),
            bgp.clone(),
            FakeJournal::default(),
        );
        let r = rule("203.0.113.7/32", 17, 53, 0.0);
        m.rehydrate(vec![(r.clone(), 1_000, BlackholeOrigin::Auto)], 1_000)
            .await;
        m.tick(2_000, 2_000).await; // still failing -> re-queued, NOT double-enqueued
        assert_eq!(m.reapply_pending(), 1, "coalesced, not doubled");

        // Cleared before it ever succeeded (manual withdraw).
        m.apply_remove(r.clone(), 3_000, 3_000).await;
        bgp.set_fail(false);
        m.tick(4_000, 4_000).await;
        assert_eq!(m.reapply_pending(), 0, "dropped: entry no longer active");
        assert!(!bgp.announced_contains(&r), "not re-announced after clear");
    }

    #[tokio::test]
    async fn stale_reapply_does_not_clobber_a_fresh_successful_update() {
        // #194 C1 follow-up: `retry_pending_reapply` must re-derive the
        // controller's CURRENT rule for the key at retry time, not replay
        // the rule snapshot captured when the op was queued. Otherwise a
        // fresh, successful re-assertion of the SAME key with a CHANGED
        // action (C4 — a re-assert may legitimately change the action, see
        // `manual_add_upgrade_with_changed_action_re_announces`) that lands
        // between the failed rehydrate and the retry gets silently reverted
        // by the stale queued content — a mitigation-weakening regression.
        let bgp = FakeBgp::with_fail(true); // rehydrate re-announce fails
        let mut m = FlowSpecManager::new(
            FlowSpecController::new(cfg()),
            bgp.clone(),
            FakeJournal::default(),
        );
        let old = rule("203.0.113.7/32", 17, 53, 500.0);
        m.rehydrate(vec![(old.clone(), 1_000, BlackholeOrigin::Auto)], 1_000)
            .await;
        let key = key_of(&old);
        assert!(m.is_active(key), "entry kept (not dropped)");
        assert_eq!(m.reapply_pending(), 1, "failed rehydrate queued for retry");

        // BGP recovers just in time for a FRESH, successful re-assertion
        // with a tighter (different) action for the SAME key, landing
        // before the next tick drains the stale queue.
        bgp.set_fail(false);
        let new = rule("203.0.113.7/32", 17, 53, 100.0);
        let outcome = m.apply_add(new.clone(), 1_500, 1_500).await;
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert!(
            bgp.announced_contains(&new),
            "the fresh, tighter update reached BGP"
        );

        // The next tick drains the (now-stale) queued reapply. It must
        // re-derive and re-announce the CURRENT rule (rate 100.0), not
        // replay the stale queued snapshot (rate 500.0) — which would
        // silently revert the fresh tightening.
        m.tick(2_000, 2_000).await;
        assert_eq!(m.reapply_pending(), 0);

        let announced = m.bgp().announced.lock().unwrap();
        let last = announced.last().expect("at least one announce recorded");
        assert_eq!(
            last.action,
            FlowAction::TrafficRate(100.0),
            "the drained retry must re-announce the CURRENT rule, not the stale queued one"
        );
    }
}
