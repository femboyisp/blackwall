//! The pure XDP decision engine. No I/O; deterministic and unit-testable.
//!
//! Unlike RTBH (which blackholes the *victim*), the XDP data plane acts on
//! the *attacker source*: detections identify a victim (`target`) but the
//! resulting mitigation rate-limits the sources flooding it. Eligibility is
//! therefore gated on the victim (only own prefixes are protected), while
//! the resulting action addresses the source.

use blackwall_flow::{Detection, DetectionEvent};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Why an active XDP entry exists — governs whether an auto-clear may remove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpOrigin {
    /// Installed automatically by the detector.
    Auto,
    /// Installed (or upgraded) by an operator; never auto-cleared.
    Manual,
}

/// A tracked rate-limited source: the origin that installed it plus its
/// currently-effective rate/burst, so `active_entries` can report a manually
/// customized limit (e.g. `manual_rate_limit(addr, 500, 500)`) faithfully
/// instead of reconstructing it from the auto default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateLimitEntry {
    origin: XdpOrigin,
    pps: u64,
    burst: u64,
    /// The victim this source was rate-limited on behalf of, for an
    /// auto-installed entry (`None` for a manual one). Persisted alongside
    /// the rate limit so a restart can rebuild `by_target` (see
    /// [`XdpController::mark_resumed`]); only the first victim a shared
    /// source was installed for is retained, matching the one-row-per-source
    /// granularity of the `xdp_entries` mirror.
    victim: Option<IpAddr>,
}

/// A decision the [`XdpController`] emits for the executor to apply.
///
/// Actions are keyed by the attacker source (`RateLimit`/`ClearRate`) or by an
/// arbitrary network (`Block`/`Unblock`) for operator-driven blocks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpAction {
    /// Rate-limit traffic from `src` to at most `pps` packets/second (bucket size `burst`).
    RateLimit {
        /// The attacker source address to rate-limit.
        src: IpAddr,
        /// Sustained packets-per-second cap.
        pps: u64,
        /// Burst bucket size, in packets.
        burst: u64,
        /// The victim this rate limit was installed for, when auto-installed
        /// from a detection (`None` for a manual, operator-issued rate
        /// limit). Carried end-to-end so the journal can persist it and a
        /// restart can rebuild [`XdpController`]'s victim -> sources map.
        victim: Option<IpAddr>,
    },
    /// Drop all traffic matching `net`.
    Block {
        /// The network to drop.
        net: IpNet,
    },
    /// Remove a previously-installed drop for `net`.
    Unblock {
        /// The network to stop dropping.
        net: IpNet,
    },
    /// Remove a previously-installed rate limit for `src`.
    ClearRate {
        /// The attacker source address to stop rate-limiting.
        src: IpAddr,
    },
}

/// The pure XDP decision engine.
///
/// A stateful controller that maps detection events from [`DetectionEvent`] to
/// source-keyed XDP actions ([`XdpAction`]). Eligibility is gated on the
/// detection's *victim* (`target`) falling inside an own prefix — detections
/// against foreign space are ignored outright, since this control plane only
/// protects its own network. The resulting mitigation, however, addresses the
/// *attacker source(s)* reported in the detection, not the victim. Pure-core:
/// no I/O, no injected clock (XDP entries have no hold-down/TTL of their own;
/// lifecycle is driven entirely by `Opened`/`Updated`/`Cleared` events).
#[derive(Debug)]
pub struct XdpController {
    prefixes: Vec<IpNet>,
    max_entries: usize,
    default_rate_pps: u64,
    /// Prefixes whose victim traffic must never trigger auto-mitigation (own
    /// anycast VIPs and similar always-safe destinations), from
    /// `Policy.protected_prefixes`. Empty (the default) protects nothing
    /// extra. Unrelated to `XdpDataplane::set_protected_prefixes`, which
    /// guards the SYN-cookie fast path's protected *ports* — a different
    /// subsystem.
    protected_prefixes: Vec<IpNet>,
    /// All currently rate-limited sources, with the origin and effective
    /// rate/burst that installed them.
    rate_limited: HashMap<IpAddr, RateLimitEntry>,
    /// All currently blocked networks, with the origin that installed them.
    blocked_nets: HashMap<IpNet, XdpOrigin>,
    /// Victim target -> the (auto) sources currently rate-limited on its
    /// behalf, so a `Cleared` for that target knows which sources to release.
    by_target: HashMap<IpAddr, HashSet<IpAddr>>,
    /// Count of detections skipped by the protected-prefix guard (see
    /// [`Self::protected_skipped`]).
    protected_skipped: u64,
}

impl XdpController {
    /// Create a controller with no active entries.
    ///
    /// # Arguments
    ///
    /// * `prefixes` - Own address space; only detections whose victim falls
    ///   inside one of these are acted on.
    /// * `max_entries` - Hard cap on the combined count of active rate-limit
    ///   and block entries (mirrors the fixed-size eBPF maps).
    /// * `default_rate_pps` - The packets/second cap (and burst size) applied
    ///   to sources rate-limited automatically from a detection.
    /// * `protected_prefixes` - Own anycast VIPs (and similar) that must
    ///   never trigger auto-mitigation even when the victim also falls
    ///   inside `prefixes`; from `Policy.protected_prefixes`.
    #[must_use]
    pub fn new(
        prefixes: Vec<IpNet>,
        max_entries: usize,
        default_rate_pps: u64,
        protected_prefixes: Vec<IpNet>,
    ) -> Self {
        Self {
            prefixes,
            max_entries,
            default_rate_pps,
            protected_prefixes,
            rate_limited: HashMap::new(),
            blocked_nets: HashMap::new(),
            by_target: HashMap::new(),
            protected_skipped: 0,
        }
    }

    /// Map one detection event to source-keyed XDP actions.
    ///
    /// * `Opened`/`Updated`: ignored outright if `detection.target` is outside
    ///   every configured own prefix. Otherwise, for each of the detection's
    ///   `top_sources`, emits a `RateLimit` — sources already active are
    ///   deduplicated (no repeat action), and emission stops once the
    ///   combined active-entry cap is reached (remaining sources are simply
    ///   not mitigated this round).
    /// * `Cleared`: emits `ClearRate` for each auto-installed source recorded
    ///   against that target and drops them from the active set. A source
    ///   upgraded (or installed) manually is never auto-cleared.
    pub fn on_detection(&mut self, ev: &DetectionEvent) -> Vec<XdpAction> {
        match ev {
            DetectionEvent::Opened(d) | DetectionEvent::Updated(d) => self.handle_detection(d),
            DetectionEvent::Cleared { target, .. } => self.handle_cleared(*target),
        }
    }

    /// Manually block a network.
    ///
    /// Refuses (`Err`) to block a network that overlaps one of our own
    /// prefixes — blocking your own address space is a self-inflicted
    /// denial of service. Also refuses if the controller is at its combined
    /// entry cap. Re-blocking an already-blocked network is idempotent and
    /// always succeeds.
    pub fn manual_block(&mut self, net: IpNet) -> Result<XdpAction, String> {
        if self.overlaps_own_prefix(net) {
            return Err(format!(
                "{net} is inside an own prefix; refusing to self-block"
            ));
        }
        let at_cap = self.total_active() >= self.max_entries;
        match self.blocked_nets.entry(net) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(XdpOrigin::Manual);
                Ok(XdpAction::Block { net })
            }
            std::collections::hash_map::Entry::Vacant(_) if at_cap => Err(format!(
                "at capacity ({} entries); cannot block {net}",
                self.max_entries
            )),
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(XdpOrigin::Manual);
                Ok(XdpAction::Block { net })
            }
        }
    }

    /// Manually unblock a previously-blocked network.
    ///
    /// Always succeeds (idempotent even if `net` was not blocked) — removing
    /// an entry only frees capacity, so there is nothing to cap-check.
    pub fn manual_unblock(&mut self, net: IpNet) -> Result<XdpAction, String> {
        self.blocked_nets.remove(&net);
        Ok(XdpAction::Unblock { net })
    }

    /// Manually rate-limit a source address.
    ///
    /// Cap-checked like `manual_block`. Re-issuing for an already-active
    /// source updates its rate/burst and (idempotently) upgrades it to
    /// `Manual` origin so it survives a later auto-clear.
    pub fn manual_rate_limit(
        &mut self,
        addr: IpAddr,
        pps: u64,
        burst: u64,
    ) -> Result<XdpAction, String> {
        let at_cap = self.total_active() >= self.max_entries;
        let entry = RateLimitEntry {
            origin: XdpOrigin::Manual,
            pps,
            burst,
            victim: None,
        };
        match self.rate_limited.entry(addr) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(entry);
                return Ok(XdpAction::RateLimit {
                    src: addr,
                    pps,
                    burst,
                    victim: None,
                });
            }
            std::collections::hash_map::Entry::Vacant(_) if at_cap => {
                return Err(format!(
                    "at capacity ({} entries); cannot rate-limit {addr}",
                    self.max_entries
                ));
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(entry);
            }
        }
        Ok(XdpAction::RateLimit {
            src: addr,
            pps,
            burst,
            victim: None,
        })
    }

    /// Manually clear a rate limit on a source address.
    ///
    /// Always succeeds (idempotent even if `src` was not rate-limited) — like
    /// `manual_unblock`, removing an entry only frees capacity, so there is
    /// nothing to cap-check. Also drops `src` from every target's `by_target`
    /// source-set so a later auto `Cleared` for that target does not attempt
    /// to double-handle (and re-emit a `ClearRate` for) an already-cleared
    /// source.
    pub fn manual_clear_rate(&mut self, src: IpAddr) -> Result<XdpAction, String> {
        self.rate_limited.remove(&src);
        for sources in self.by_target.values_mut() {
            sources.remove(&src);
        }
        Ok(XdpAction::ClearRate { src })
    }

    /// Whether `net` overlaps one of the configured own prefixes, in either
    /// direction.
    ///
    /// Catches both a subnet-or-equal of an own prefix (`net` inside `p`) and
    /// a supernet that swallows one (`p` inside `net`) — an operator block of
    /// e.g. `203.0.0.0/16` when own space is `203.0.113.0/24` is just as much
    /// a self-inflicted denial of service as blocking the /24 directly.
    /// Pure accessor; lets a caller (e.g. the manager) classify a rejected
    /// `manual_block` without duplicating the controller's eligibility logic.
    #[must_use]
    pub fn overlaps_own_prefix(&self, net: IpNet) -> bool {
        self.prefixes
            .iter()
            .any(|p| p.contains(&net) || net.contains(p))
    }

    /// Whether the controller is at its combined active-entry cap.
    #[must_use]
    pub fn at_capacity(&self) -> bool {
        self.total_active() >= self.max_entries
    }

    /// Whether `net` is currently blocked (manually or automatically).
    ///
    /// Lets a caller (e.g. the manager) check freshness *before* calling
    /// [`Self::manual_block`], to decide whether a subsequent executor
    /// failure should [`Self::rollback`] a brand-new insert or leave an
    /// already-active entry untouched.
    #[must_use]
    pub fn is_blocked(&self, net: IpNet) -> bool {
        self.blocked_nets.contains_key(&net)
    }

    /// Whether `src` is currently rate-limited (manually or automatically).
    ///
    /// See [`Self::is_blocked`] for why this is exposed.
    #[must_use]
    pub fn is_rate_limited(&self, src: IpAddr) -> bool {
        self.rate_limited.contains_key(&src)
    }

    /// Look up the CURRENTLY effective rate-limit action for `src`, rather
    /// than trusting a possibly-stale snapshot captured elsewhere and
    /// earlier (e.g. by a queued [`crate::manager::XdpManager`] reapply
    /// retry). `None` if `src` is no longer rate-limited.
    #[must_use]
    pub fn current_rate_limit(&self, src: IpAddr) -> Option<XdpAction> {
        self.rate_limited.get(&src).map(|e| XdpAction::RateLimit {
            src,
            pps: e.pps,
            burst: e.burst,
            victim: e.victim,
        })
    }

    /// Look up whether `net` is CURRENTLY blocked, rather than trusting a
    /// possibly-stale snapshot captured elsewhere and earlier. `None` if
    /// `net` is no longer blocked. See [`Self::current_rate_limit`] for why
    /// this is exposed.
    #[must_use]
    pub fn current_block(&self, net: IpNet) -> Option<XdpAction> {
        self.blocked_nets
            .contains_key(&net)
            .then_some(XdpAction::Block { net })
    }

    /// Undo a just-inserted active entry after its executor apply failed
    /// (C2: commit-after-confirm).
    ///
    /// Removes the entry `action` describes from the active set and emits
    /// nothing — the map write never took, so there is nothing to unwind on
    /// the data-plane side. Only meaningful for [`XdpAction::RateLimit`] and
    /// [`XdpAction::Block`] (the two "insert" variants); called on an
    /// [`XdpAction::Unblock`] or [`XdpAction::ClearRate`] it is a no-op,
    /// since those represent a removal that already happened in the
    /// controller's bookkeeping regardless of the executor outcome.
    ///
    /// Callers must only invoke this for an `action` known to be a brand-new
    /// insert (see [`Self::is_blocked`]/[`Self::is_rate_limited`]) — calling
    /// it after a re-assertion or a param upgrade of an already-active entry
    /// would incorrectly drop state that predates this call. Mirrors
    /// `blackwall_rtbh::controller::RtbhController::rollback`.
    pub fn rollback(&mut self, action: &XdpAction) {
        match *action {
            XdpAction::RateLimit { src, victim, .. } => {
                self.rate_limited.remove(&src);
                if let Some(victim) = victim {
                    if let Some(sources) = self.by_target.get_mut(&victim) {
                        sources.remove(&src);
                    }
                }
            }
            XdpAction::Block { net } => {
                self.blocked_nets.remove(&net);
            }
            XdpAction::Unblock { .. } | XdpAction::ClearRate { .. } => {}
        }
    }

    /// Number of detections skipped because the victim fell inside a
    /// configured protected prefix (own anycast VIP or similar always-safe
    /// destination) — the anycast self-protection guard in
    /// [`Self::handle_detection`]. Surfaced for `/metrics`
    /// (`blackwall_mitigations_protected_skipped_total{plane="xdp"}`).
    #[must_use]
    pub fn protected_skipped(&self) -> u64 {
        self.protected_skipped
    }

    /// Snapshot the active set (for reconcile mirroring and restart rehydration).
    #[must_use]
    pub fn active_entries(&self) -> Vec<(XdpAction, XdpOrigin)> {
        let mut entries: Vec<(XdpAction, XdpOrigin)> = self
            .rate_limited
            .iter()
            .map(|(src, entry)| {
                (
                    XdpAction::RateLimit {
                        src: *src,
                        pps: entry.pps,
                        burst: entry.burst,
                        victim: entry.victim,
                    },
                    entry.origin,
                )
            })
            .collect();
        entries.extend(
            self.blocked_nets
                .iter()
                .map(|(net, origin)| (XdpAction::Block { net: *net }, *origin)),
        );
        entries
    }

    /// Fold a persisted active entry into the controller's bookkeeping
    /// (cap accounting + dedup) on restart, without emitting an action of its
    /// own — the caller (the manager) re-issues the executor call directly.
    ///
    /// For a resumed `RateLimit` with a known `victim`, also repopulates
    /// `by_target[victim]` with `src` — this is what lets a later `Cleared`
    /// for that victim correctly find and release the source, closing the
    /// restart-orphan gap that motivated persisting `victim` in the first
    /// place (see the module-level `xdp_entries.victim` column).
    pub fn mark_resumed(&mut self, action: &XdpAction, origin: XdpOrigin) {
        match *action {
            XdpAction::RateLimit {
                src,
                pps,
                burst,
                victim,
            } => {
                self.rate_limited.insert(
                    src,
                    RateLimitEntry {
                        origin,
                        pps,
                        burst,
                        victim,
                    },
                );
                if let Some(victim) = victim {
                    self.by_target.entry(victim).or_default().insert(src);
                }
            }
            XdpAction::Block { net } => {
                self.blocked_nets.insert(net, origin);
            }
            XdpAction::Unblock { .. } | XdpAction::ClearRate { .. } => {}
        }
    }

    fn total_active(&self) -> usize {
        self.rate_limited.len() + self.blocked_nets.len()
    }

    fn handle_detection(&mut self, d: &Detection) -> Vec<XdpAction> {
        // Anycast self-protection (C1): a protected victim (own VIP) must
        // never trigger auto-mitigation, even when it also falls inside an
        // own prefix — checked BEFORE the own-prefix eligibility check, and
        // decisive.
        if self
            .protected_prefixes
            .iter()
            .any(|p| p.contains(&d.target))
        {
            tracing::warn!(
                target = %d.target,
                "XDP: victim in a protected prefix; skipping (never mitigate own service)"
            );
            self.protected_skipped = self.protected_skipped.saturating_add(1);
            return Vec::new();
        }
        if !self.prefixes.iter().any(|p| p.contains(&d.target)) {
            return Vec::new();
        }
        let mut actions = Vec::new();
        for (src, _pps) in &d.top_sources {
            if self.rate_limited.contains_key(src) {
                self.by_target.entry(d.target).or_default().insert(*src);
                continue;
            }
            if self.total_active() >= self.max_entries {
                tracing::warn!(
                    target = %d.target,
                    cap = self.max_entries,
                    "XDP: at cap; not rate-limiting further sources"
                );
                break;
            }
            self.rate_limited.insert(
                *src,
                RateLimitEntry {
                    origin: XdpOrigin::Auto,
                    pps: self.default_rate_pps,
                    burst: self.default_rate_pps,
                    victim: Some(d.target),
                },
            );
            self.by_target.entry(d.target).or_default().insert(*src);
            actions.push(XdpAction::RateLimit {
                src: *src,
                pps: self.default_rate_pps,
                burst: self.default_rate_pps,
                victim: Some(d.target),
            });
        }
        actions
    }

    fn handle_cleared(&mut self, target: IpAddr) -> Vec<XdpAction> {
        let Some(sources) = self.by_target.remove(&target) else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        for src in sources {
            // A source shared with another still-open victim must not be
            // cleared here: doing so would re-expose that other victim to
            // the very source it's still under attack from. Only clear once
            // no *other* remaining target still references this source.
            let still_needed = self.by_target.values().any(|others| others.contains(&src));
            if still_needed {
                continue;
            }
            match self.rate_limited.get(&src).map(|e| e.origin) {
                Some(XdpOrigin::Manual) => {
                    // A manually-installed (or upgraded) rate limit is never
                    // auto-cleared, mirroring RTBH's manual-survives-auto-clear rule.
                }
                Some(XdpOrigin::Auto) => {
                    self.rate_limited.remove(&src);
                    actions.push(XdpAction::ClearRate { src });
                }
                None => {}
            }
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_flow::{AttackKind, Detection, DetectionEvent, Severity};
    use std::net::IpAddr;

    fn own() -> Vec<ipnet::IpNet> {
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

    #[test]
    fn opened_on_own_victim_rate_limits_each_source() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9", "198.51.100.10"],
        )));
        assert_eq!(acts.len(), 2);
        assert!(acts
            .iter()
            .all(|a| matches!(a, XdpAction::RateLimit { pps: 1000, .. })));
    }

    #[test]
    fn detection_on_foreign_victim_is_ignored() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "8.8.8.8",
            vec!["198.51.100.9"],
        )));
        assert!(acts.is_empty());
    }

    #[test]
    fn protected_victim_is_skipped_even_when_own() {
        // 203.0.113.53 is inside own address space but is carved out as a
        // protected VIP: a detection against it must never rate-limit
        // sources on its behalf.
        let mut c = XdpController::new(own(), 100, 1000, vec!["203.0.113.53/32".parse().unwrap()]);
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.53",
            vec!["198.51.100.9"],
        )));
        assert!(acts.is_empty(), "protected VIP must not trigger mitigation");
        assert!(c.active_entries().is_empty());
        assert_eq!(c.protected_skipped(), 1);
    }

    #[test]
    fn unprotected_own_victim_still_mitigates() {
        let mut c = XdpController::new(own(), 100, 1000, vec!["203.0.113.53/32".parse().unwrap()]);
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9"],
        )));
        assert_eq!(acts.len(), 1);
        assert_eq!(c.protected_skipped(), 0);
    }

    #[test]
    fn manual_block_of_own_prefix_is_rejected() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        assert!(c.manual_block("203.0.113.5/32".parse().unwrap()).is_err());
    }

    #[test]
    fn cap_defers_beyond_max_entries() {
        let mut c = XdpController::new(own(), 1, 1000, Vec::new());
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9", "198.51.100.10"],
        )));
        assert_eq!(acts.len(), 1); // second source over the cap is dropped
    }

    #[test]
    fn cleared_emits_clear_rate_for_each_recorded_source() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9", "198.51.100.10"],
        )));
        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: "203.0.113.7".parse().unwrap(),
            at_ms: 1000,
        });
        assert_eq!(acts.len(), 2);
        assert!(acts
            .iter()
            .all(|a| matches!(a, XdpAction::ClearRate { .. })));
        assert!(c.active_entries().is_empty());
    }

    #[test]
    fn manual_rate_limit_survives_auto_clear() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9"],
        )));
        c.manual_rate_limit("198.51.100.9".parse().unwrap(), 500, 500)
            .unwrap();
        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: "203.0.113.7".parse().unwrap(),
            at_ms: 1000,
        });
        assert!(acts.is_empty(), "manual upgrade must not be auto-cleared");
        assert_eq!(c.active_entries().len(), 1);
    }

    #[test]
    fn manual_block_at_capacity_is_rejected() {
        let mut c = XdpController::new(own(), 1, 1000, Vec::new());
        c.manual_block("198.51.100.0/24".parse().unwrap()).unwrap();
        assert!(c.manual_block("198.51.101.0/24".parse().unwrap()).is_err());
    }

    #[test]
    fn manual_unblock_is_idempotent() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let net = "198.51.100.0/24".parse().unwrap();
        c.manual_block(net).unwrap();
        assert!(c.manual_unblock(net).is_ok());
        assert!(c.manual_unblock(net).is_ok());
        assert!(c.active_entries().is_empty());
    }

    #[test]
    fn shared_source_kept_until_last_victim_clears() {
        // Source X floods two of our own victims, A and B, simultaneously.
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7", // A
            vec!["198.51.100.9"],
        )));
        c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.8", // B
            vec!["198.51.100.9"],
        )));

        // Clearing A alone must not release X: B is still under attack from it.
        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: "203.0.113.7".parse().unwrap(),
            at_ms: 1000,
        });
        assert!(
            acts.is_empty(),
            "shared source must not be cleared while another victim is still active"
        );
        assert_eq!(
            c.active_entries().len(),
            1,
            "X must remain rate-limited for B's sake"
        );

        // Clearing B (the last remaining victim) must now release X.
        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: "203.0.113.8".parse().unwrap(),
            at_ms: 2000,
        });
        assert_eq!(acts.len(), 1);
        assert!(matches!(acts[0], XdpAction::ClearRate { .. }));
        assert!(c.active_entries().is_empty());
    }

    #[test]
    fn manual_block_of_supernet_covering_own_space_is_rejected() {
        // Own space is 203.0.113.0/24; a supernet block of 203.0.0.0/16 would
        // swallow it — the self-block guard must catch this direction too.
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        assert!(c.manual_block("203.0.0.0/16".parse().unwrap()).is_err());
    }

    #[test]
    fn manual_clear_rate_removes_source() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        c.manual_rate_limit(addr, 500, 500).unwrap();
        assert_eq!(c.active_entries().len(), 1);

        let act = c.manual_clear_rate(addr).unwrap();
        assert!(matches!(act, XdpAction::ClearRate { src } if src == addr));
        assert!(
            c.active_entries().is_empty(),
            "cleared source must no longer be active"
        );
    }

    #[test]
    fn manual_clear_rate_is_idempotent_for_unknown_source() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        let act = c.manual_clear_rate(addr).unwrap();
        assert!(matches!(act, XdpAction::ClearRate { src } if src == addr));
        assert!(c.active_entries().is_empty());
    }

    #[test]
    fn manual_clear_rate_drops_source_from_by_target_so_later_clear_is_noop() {
        // Rate-limit a source via a detection (populates by_target), then
        // manually clear it. A later `Cleared` for that target must not
        // re-emit a ClearRate for the already-cleared source.
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9"],
        )));
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        c.manual_clear_rate(addr).unwrap();
        assert!(c.active_entries().is_empty());

        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: "203.0.113.7".parse().unwrap(),
            at_ms: 1000,
        });
        assert!(
            acts.is_empty(),
            "manually cleared source must not be double-handled by a later Cleared"
        );
    }

    #[test]
    fn manual_rate_limit_preserved_in_active_entries() {
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let addr: IpAddr = "198.51.100.9".parse().unwrap();
        c.manual_rate_limit(addr, 500, 500).unwrap();

        let entries = c.active_entries();
        let (action, origin) = entries
            .iter()
            .find(|(a, _)| matches!(a, XdpAction::RateLimit { src, .. } if *src == addr))
            .expect("manually rate-limited source must be in active_entries");
        assert_eq!(*origin, XdpOrigin::Manual);
        match action {
            XdpAction::RateLimit { pps, burst, .. } => {
                assert_eq!(*pps, 500, "custom pps must be preserved, not defaulted");
                assert_eq!(*burst, 500, "custom burst must be preserved, not defaulted");
            }
            other => panic!("expected RateLimit, got {other:?}"),
        }
    }

    #[test]
    fn mark_resumed_rebuilds_by_target_so_cleared_releases_the_source() {
        // Regression test for #119: a restart rehydrates a persisted auto
        // rate-limit via `mark_resumed`. Before the fix, `by_target` stayed
        // empty across the restart, so a later `Cleared` for the victim
        // found nothing to release and the source stayed rate-limited
        // forever. With the fix, `mark_resumed` repopulates `by_target` from
        // the resumed action's `victim`, so `Cleared` emits `ClearRate` for
        // the source, exactly as it would have in the pre-restart session.
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let victim: IpAddr = "203.0.113.7".parse().unwrap();
        let src: IpAddr = "198.51.100.9".parse().unwrap();

        c.mark_resumed(
            &XdpAction::RateLimit {
                src,
                pps: 1000,
                burst: 1000,
                victim: Some(victim),
            },
            XdpOrigin::Auto,
        );
        assert_eq!(
            c.active_entries().len(),
            1,
            "the resumed rate limit must be in the active set"
        );

        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: victim,
            at_ms: 1000,
        });
        assert_eq!(
            acts,
            vec![XdpAction::ClearRate { src }],
            "Cleared must release the resumed source now that by_target was rebuilt"
        );
        assert!(c.active_entries().is_empty());
    }

    #[test]
    fn mark_resumed_without_victim_does_not_populate_by_target() {
        // A resumed manual rate-limit (no victim) must not create a
        // `by_target` entry: nothing should auto-clear it, since it was
        // never tied to a detection in the first place.
        let mut c = XdpController::new(own(), 100, 1000, Vec::new());
        let victim: IpAddr = "203.0.113.7".parse().unwrap();
        let src: IpAddr = "198.51.100.9".parse().unwrap();

        c.mark_resumed(
            &XdpAction::RateLimit {
                src,
                pps: 500,
                burst: 500,
                victim: None,
            },
            XdpOrigin::Manual,
        );

        let acts = c.on_detection(&DetectionEvent::Cleared {
            target: victim,
            at_ms: 1000,
        });
        assert!(
            acts.is_empty(),
            "a resumed manual rate-limit has no victim to be cleared by"
        );
        assert_eq!(
            c.active_entries().len(),
            1,
            "the resumed manual rate-limit must remain active"
        );
    }
}
