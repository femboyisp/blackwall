//! The pure FlowSpec decision engine. No I/O; deterministic given an injected `now`.
//!
//! The FlowSpec analogue of [`crate::controller::RtbhController`]: instead of a single
//! blackhole per target, a target may have multiple active flow rules (one per
//! `(protocol, destination-port)` pair), each carrying its own traffic-rate action.
//! FlowSpec carries no next-hop, so unlike RTBH there is no `has_next_hop` guard.

use crate::controller::{host_prefix, BlackholeOrigin};
use blackwall_bgp::{FlowAction, FlowSpecRule};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Identity of one active FlowSpec rule: the target's host route, the matched
/// IP protocol, and the matched destination port.
pub type FlowKey = (IpNet, u8, u16);

/// State for one active FlowSpec rule.
#[derive(Debug, Clone)]
struct ActiveEntry {
    rule: FlowSpecRule,
    announced_at: u64,
    last_activity: u64,
    origin: BlackholeOrigin,
    clear_requested_at: Option<u64>,
}

/// FlowSpec policy configuration.
///
/// Defines the parameters for the FlowSpec decision engine: eligible prefixes,
/// a hard cap on concurrent rules, and anti-flap hold-down/TTL. FlowSpec carries
/// no next-hop (the traffic-rate action is per-rule), so there is no next-hop field.
#[derive(Debug, Clone)]
pub struct FlowSpecConfig {
    /// Only targets inside these prefixes may have FlowSpec rules installed
    /// (never foreign space).
    pub eligible_prefixes: Vec<IpNet>,
    /// Hard cap on concurrent active rules (summed across all targets).
    pub max_rules: usize,
    /// Minimum time a rule stays before a clear may withdraw it (anti-flap).
    pub hold_down: Duration,
    /// Maximum lifetime of an auto rule (hygiene backstop against a dropped
    /// or missed clear); `None` disables the TTL.
    pub max_ttl: Option<Duration>,
    /// Prefixes that must never have FlowSpec rules installed against them
    /// (own anycast VIPs and similar always-safe destinations), from
    /// `Policy.protected_prefixes`. Empty (the default) protects nothing extra.
    pub protected_prefixes: Vec<IpNet>,
}

/// A decision the [`FlowSpecController`] emits for the sink to execute.
///
/// Either announce a FlowSpec traffic-filter rule for a detected attack flow,
/// or withdraw a previously-announced rule.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowSpecAction {
    /// Announce a FlowSpec rule.
    Announce(FlowSpecRule),
    /// Withdraw a previously-announced FlowSpec rule.
    Withdraw(FlowSpecRule),
}

/// The pure FlowSpec decision engine.
///
/// A stateful controller mapping `(target, rules)` installs to FlowSpec actions.
/// It enforces eligibility, a total-rule capacity cap, and hold-down anti-flap
/// logic — the FlowSpec analogue of [`crate::controller::RtbhController`], adapted
/// from a single blackholed IP to multiple `(protocol, port)` rules per target.
/// Pure-core: deterministic given injected `now` timestamps, no I/O.
#[derive(Debug)]
pub struct FlowSpecController {
    config: FlowSpecConfig,
    active: HashMap<FlowKey, ActiveEntry>,
    /// Count of targets skipped by the protected-prefix guard (see
    /// [`Self::protected_skipped`]).
    protected_skipped: u64,
}

impl FlowSpecController {
    /// Create a controller with no active rules.
    #[must_use]
    pub fn new(config: FlowSpecConfig) -> Self {
        Self {
            config,
            active: HashMap::new(),
            protected_skipped: 0,
        }
    }

    /// Install FlowSpec rules for a detected attack target.
    ///
    /// # Arguments
    ///
    /// * `target` - The attacked IP address; the host route (`/32`/`/128`) is derived
    ///   from it and used as the FlowSpec destination-prefix match for every rule.
    /// * `rules` - `(protocol, destination-port, traffic-rate)` tuples to install.
    /// * `now` - Current time in milliseconds since epoch (used for hold-down/TTL anchoring).
    ///
    /// # Returns
    ///
    /// An `Announce` action per newly-installed rule. A rule already active is
    /// re-asserted (its pending clear, if any, is cancelled and its TTL anchor
    /// refreshed) without emitting a new action. Ineligible targets or a full
    /// capacity cap are ignored.
    pub fn install(
        &mut self,
        target: IpAddr,
        rules: &[(u8, u16, f32)],
        now: u64,
    ) -> Vec<FlowSpecAction> {
        let host = host_prefix(target);
        rules
            .iter()
            .flat_map(|&(protocol, dst_port, rate)| {
                let rule = FlowSpecRule {
                    dst: host,
                    protocol: Some(protocol),
                    dst_port: Some(dst_port),
                    action: FlowAction::TrafficRate(rate),
                };
                self.insert_rule(target, rule, now, BlackholeOrigin::Auto)
            })
            .collect()
    }

    /// Request the clear of every active rule for `target`.
    ///
    /// Applies the same anti-flap logic as [`crate::controller::RtbhController::on_event`]'s
    /// `Cleared` handling, per rule: a `Manual` rule is never auto-cleared; a rule
    /// still within its hold-down has the clear deferred (to a later [`Self::tick`]);
    /// a rule at/after hold-down is withdrawn immediately.
    ///
    /// # Arguments
    ///
    /// * `target` - The IP address whose flows should be cleared.
    /// * `now` - Current time in milliseconds since epoch.
    ///
    /// # Returns
    ///
    /// A `Withdraw` action for every rule of `target` that clears immediately.
    pub fn clear_target(&mut self, target: IpAddr, now: u64) -> Vec<FlowSpecAction> {
        let host = host_prefix(target);
        let hold_ms = u64::try_from(self.config.hold_down.as_millis()).unwrap_or(u64::MAX);
        let keys: Vec<FlowKey> = self
            .active
            .keys()
            .filter(|k| k.0 == host)
            .copied()
            .collect();
        let mut actions = Vec::new();
        for key in keys {
            match self.active.get_mut(&key) {
                // Manual rules are never auto-cleared.
                Some(e) if matches!(e.origin, BlackholeOrigin::Manual) => {}
                Some(e) if now.saturating_sub(e.announced_at) >= hold_ms => {
                    if let Some(e) = self.active.remove(&key) {
                        actions.push(FlowSpecAction::Withdraw(e.rule));
                    }
                }
                Some(e) => {
                    e.clear_requested_at = Some(now);
                }
                None => {}
            }
        }
        actions
    }

    /// Manually install (or upgrade) a FlowSpec rule (for the operator CLI + the lab).
    ///
    /// If a rule with the same `(dst, protocol, dst_port)` is already active as
    /// `Auto`, this upgrades it to `Manual` (and cancels any pending deferred
    /// clear) instead of re-announcing.
    ///
    /// # Arguments
    ///
    /// * `rule` - The FlowSpec rule to install; `rule.dst` should be an eligible
    ///   host route.
    /// * `now` - Current time in milliseconds since epoch.
    ///
    /// # Returns
    ///
    /// An `Announce` action if newly installed, empty vector if upgraded,
    /// ineligible, or at cap.
    pub fn manual_add(&mut self, rule: FlowSpecRule, now: u64) -> Vec<FlowSpecAction> {
        let key = key_of(&rule);
        if let Some(e) = self.active.get_mut(&key) {
            // Already active: upgrade to Manual + cancel any pending clear.
            e.origin = BlackholeOrigin::Manual;
            e.clear_requested_at = None;
            return Vec::new();
        }
        let target = rule.dst.addr();
        self.insert_rule(target, rule, now, BlackholeOrigin::Manual)
    }

    /// Manually withdraw a rule (bypasses hold-down — an operator action is deliberate).
    ///
    /// # Arguments
    ///
    /// * `rule` - Identifies the rule to remove by its `(dst, protocol, dst_port)`.
    ///
    /// # Returns
    ///
    /// A `Withdraw` action if the rule was active, empty vector otherwise.
    pub fn manual_remove(&mut self, rule: FlowSpecRule) -> Vec<FlowSpecAction> {
        let key = key_of(&rule);
        if let Some(e) = self.active.remove(&key) {
            vec![FlowSpecAction::Withdraw(e.rule)]
        } else {
            Vec::new()
        }
    }

    /// Process time-driven withdrawals: deferred clears whose hold-down has now
    /// elapsed, and auto rules past their TTL. Call periodically.
    pub fn tick(&mut self, now: u64) -> Vec<FlowSpecAction> {
        let hold_ms = u64::try_from(self.config.hold_down.as_millis()).unwrap_or(u64::MAX);
        let ttl_ms = self
            .config
            .max_ttl
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let mut expired: Vec<FlowKey> = Vec::new();
        for (key, e) in &self.active {
            let cleared_due = e
                .clear_requested_at
                .is_some_and(|_| now.saturating_sub(e.announced_at) >= hold_ms);
            let ttl_due = matches!(e.origin, BlackholeOrigin::Auto)
                && ttl_ms.is_some_and(|ttl| now.saturating_sub(e.last_activity) >= ttl);
            if cleared_due || ttl_due {
                expired.push(*key);
            }
        }
        expired
            .into_iter()
            .filter_map(|k| {
                self.active
                    .remove(&k)
                    .map(|e| FlowSpecAction::Withdraw(e.rule))
            })
            .collect()
    }

    /// Re-install a persisted FlowSpec rule on a fresh session (rehydration).
    pub fn resume(
        &mut self,
        rule: FlowSpecRule,
        announced_at: u64,
        origin: BlackholeOrigin,
    ) -> Vec<FlowSpecAction> {
        let target = rule.dst.addr();
        self.insert_rule(target, rule, announced_at, origin)
    }

    /// Snapshot the active set (for reconcile mirroring, `list`, and tests).
    #[must_use]
    pub fn active_rules(&self) -> Vec<(FlowKey, u64, BlackholeOrigin)> {
        self.active
            .iter()
            .map(|(k, e)| (*k, e.announced_at, e.origin))
            .collect()
    }

    /// Re-assert every active rule for `target` without re-announcing.
    ///
    /// Used for [`blackwall_flow::FlowMitigationEvent::Update`], which reports that
    /// an attack is still ongoing but (unlike `Open`) carries no rule list to
    /// re-install. Cancels any pending deferred clear and refreshes the TTL
    /// anchor on every active rule of `target`'s host route, mirroring the
    /// re-assertion branch of `Self::insert_rule` — but for rules already known
    /// to the controller, so no BGP re-announce or journal write is needed.
    pub fn refresh_target(&mut self, target: IpAddr, now: u64) {
        let host = host_prefix(target);
        for (key, entry) in &mut self.active {
            if key.0 == host {
                entry.clear_requested_at = None;
                entry.last_activity = now;
            }
        }
    }

    /// Whether `target`'s host route falls inside a configured eligible prefix.
    ///
    /// Pure accessor over [`FlowSpecConfig::eligible_prefixes`]; lets a caller
    /// (e.g. the manager) classify a rejected `manual_add`/`resume` without
    /// duplicating the controller's eligibility logic.
    #[must_use]
    pub fn is_eligible(&self, target: IpAddr) -> bool {
        self.config
            .eligible_prefixes
            .iter()
            .any(|p| p.contains(&target))
    }

    /// Whether `target`'s host route falls inside a configured protected
    /// prefix (own anycast VIP or similar always-safe destination that must
    /// never be mitigated).
    ///
    /// Pure accessor over [`FlowSpecConfig::protected_prefixes`]; mirrors
    /// [`Self::is_eligible`] so a caller (e.g. the manager) can classify a
    /// rejected `manual_add` without duplicating the controller's
    /// self-protection logic.
    #[must_use]
    pub fn is_protected(&self, target: IpAddr) -> bool {
        self.config
            .protected_prefixes
            .iter()
            .any(|p| p.contains(&target))
    }

    /// Number of targets skipped because they fell inside a configured
    /// [`FlowSpecConfig::protected_prefixes`] entry (own anycast VIP or
    /// similar always-safe destination) — the anycast self-protection guard
    /// in [`Self::insert_rule`]. Surfaced for `/metrics`
    /// (`blackwall_mitigations_protected_skipped_total{plane="flowspec"}`).
    #[must_use]
    pub fn protected_skipped(&self) -> u64 {
        self.protected_skipped
    }

    fn insert_rule(
        &mut self,
        target: IpAddr,
        rule: FlowSpecRule,
        announced_at: u64,
        origin: BlackholeOrigin,
    ) -> Vec<FlowSpecAction> {
        // Anycast self-protection (C1): a protected prefix (own VIP) must
        // never have a FlowSpec rule installed against it, even when it also
        // falls inside an eligible prefix — checked BEFORE eligibility, and
        // decisive.
        if self
            .config
            .protected_prefixes
            .iter()
            .any(|p| p.contains(&target))
        {
            tracing::warn!(%target, "FlowSpec: target in a protected prefix; skipping (never mitigate own service)");
            self.protected_skipped = self.protected_skipped.saturating_add(1);
            return Vec::new();
        }
        if !self.is_eligible(target) {
            tracing::warn!(%target, "FlowSpec: target outside eligible prefixes; ignoring");
            return Vec::new();
        }
        let key = key_of(&rule);
        if let Some(e) = self.active.get_mut(&key) {
            // Re-assertion of an already-active rule (e.g. a re-attack during a
            // deferred-clear window): cancel any pending clear and refresh the
            // TTL anchor so `tick` does not withdraw a flow under attack again.
            e.clear_requested_at = None;
            e.last_activity = announced_at;
            return Vec::new();
        }
        if self.active.len() >= self.config.max_rules {
            tracing::warn!(%target, cap = self.config.max_rules, "FlowSpec: at cap; ignoring");
            return Vec::new();
        }
        self.active.insert(
            key,
            ActiveEntry {
                rule: rule.clone(),
                announced_at,
                last_activity: announced_at,
                origin,
                clear_requested_at: None,
            },
        );
        vec![FlowSpecAction::Announce(rule)]
    }

    /// Undo a just-inserted active entry after its BGP announce failed (C2:
    /// commit-after-confirm).
    ///
    /// Removes `key` from the active set and emits nothing — the router
    /// never took the rule, so there is nothing to withdraw. Must only be
    /// called immediately after a [`FlowSpecAction::Announce`] was returned
    /// for `key` (by [`Self::install`], [`Self::manual_add`], or
    /// [`Self::resume`]): [`Self::insert_rule`] emits `Announce` only when it
    /// performs a brand-new insert — a re-assertion, an Auto-to-Manual
    /// upgrade, an at-cap key, or an ineligible/protected target all return
    /// an empty vector instead and never reach this call. So at the point of
    /// a failed announce, `active[key]` is guaranteed to still be exactly the
    /// entry this call is undoing — never a pre-existing `Manual` rule or one
    /// touched by anything else in between. Mirrors
    /// [`crate::controller::RtbhController::rollback`].
    pub fn rollback(&mut self, key: FlowKey) {
        self.active.remove(&key);
    }
}

/// Derive the `FlowKey` a rule is stored/looked-up under.
pub(crate) fn key_of(rule: &FlowSpecRule) -> FlowKey {
    (
        rule.dst,
        rule.protocol.unwrap_or(0),
        rule.dst_port.unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    fn cfg() -> FlowSpecConfig {
        FlowSpecConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            max_rules: 3,
            hold_down: Duration::from_secs(10),
            max_ttl: None,
            protected_prefixes: Vec::new(),
        }
    }

    fn cfg_ttl(ms: u64) -> FlowSpecConfig {
        FlowSpecConfig {
            max_ttl: Some(Duration::from_millis(ms)),
            ..cfg()
        }
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(dst: &str, protocol: u8, dst_port: u16, rate: f32) -> FlowSpecRule {
        FlowSpecRule {
            dst: net(dst),
            protocol: Some(protocol),
            dst_port: Some(dst_port),
            action: FlowAction::TrafficRate(rate),
        }
    }

    #[test]
    fn install_eligible_announces_rule_per_flow() {
        let mut c = FlowSpecController::new(cfg());
        let actions = c.install(ip("203.0.113.7"), &[(17, 53, 1000.0), (6, 80, 500.0)], 1000);
        assert_eq!(actions.len(), 2);
        for a in &actions {
            let FlowSpecAction::Announce(r) = a else {
                panic!("expected Announce")
            };
            assert_eq!(r.dst, net("203.0.113.7/32"));
        }
    }

    #[test]
    fn install_ineligible_is_ignored() {
        let mut c = FlowSpecController::new(cfg());
        assert!(c
            .install(ip("198.51.100.7"), &[(17, 53, 1000.0)], 0)
            .is_empty());
    }

    #[test]
    fn clear_target_withdraws_auto_flow_but_keeps_manual_flow() {
        // A target with BOTH an Auto and a Manual flow: clear_target (past
        // hold-down) withdraws the Auto flow but never the operator's Manual one —
        // each of a target's flows is cleared per its own origin.
        let mut c = FlowSpecController::new(cfg());
        c.install(ip("203.0.113.7"), &[(17, 53, 0.0)], 0); // Auto
        c.manual_add(rule("203.0.113.7/32", 6, 80, 0.0), 0); // Manual, same target
        let actions = c.clear_target(ip("203.0.113.7"), 20_000); // past 10s hold-down
        assert_eq!(actions.len(), 1, "only the Auto flow is withdrawn");
        let FlowSpecAction::Withdraw(r) = &actions[0] else {
            panic!("expected Withdraw")
        };
        assert_eq!((r.protocol, r.dst_port), (Some(17), Some(53)));
        // the Manual flow survives.
        let remaining = c.active_rules();
        assert_eq!(remaining.len(), 1);
        assert_eq!((remaining[0].0 .1, remaining[0].0 .2), (6, 80));
    }

    #[test]
    fn at_cap_is_ignored_across_total_rules() {
        let mut c = FlowSpecController::new(cfg()); // max_rules 3
        let a = c.install(
            ip("203.0.113.1"),
            &[(17, 53, 1.0), (6, 80, 1.0), (6, 443, 1.0)],
            0,
        );
        assert_eq!(a.len(), 3);
        let b = c.install(ip("203.0.113.2"), &[(17, 53, 1.0)], 0);
        assert!(b.is_empty(), "at cap across all targets' rules");
    }

    #[test]
    fn clear_target_defers_then_tick_withdraws_all_flows() {
        let mut c = FlowSpecController::new(cfg()); // 10s hold-down
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0), (6, 80, 1.0)], 0);
        assert!(c.clear_target(ip("203.0.113.7"), 5_000).is_empty());
        assert!(c.tick(9_000).is_empty());
        let actions = c.tick(10_000);
        assert_eq!(actions.len(), 2, "tick withdraws all of the target's flows");
        assert!(c.active_rules().is_empty());
    }

    #[test]
    fn clear_target_at_or_after_hold_down_withdraws_immediately() {
        let mut c = FlowSpecController::new(cfg());
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0);
        let actions = c.clear_target(ip("203.0.113.7"), 10_000);
        assert_eq!(actions.len(), 1);
        assert!(c.active_rules().is_empty());
    }

    #[test]
    fn clear_target_does_not_affect_other_targets() {
        let mut c = FlowSpecController::new(cfg());
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0);
        c.install(ip("203.0.113.8"), &[(17, 53, 1.0)], 0);
        let actions = c.clear_target(ip("203.0.113.7"), 10_000);
        assert_eq!(actions.len(), 1);
        assert_eq!(c.active_rules().len(), 1);
    }

    #[test]
    fn clear_target_with_no_active_flows_is_empty() {
        let mut c = FlowSpecController::new(cfg());
        assert!(c.clear_target(ip("203.0.113.7"), 0).is_empty());
    }

    #[test]
    fn ttl_withdraws_a_never_cleared_auto_rule() {
        let mut c = FlowSpecController::new(cfg_ttl(30_000)); // 30s TTL
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0);
        assert!(c.tick(29_000).is_empty());
        assert_eq!(c.tick(30_000).len(), 1);
    }

    #[test]
    fn manual_survives_clear_target_and_ttl() {
        let mut c = FlowSpecController::new(cfg_ttl(30_000));
        c.manual_add(rule("203.0.113.7/32", 17, 53, 1.0), 0);
        assert!(
            c.clear_target(ip("203.0.113.7"), 100_000).is_empty(),
            "auto-clear must not withdraw a manual rule"
        );
        assert!(c.tick(200_000).is_empty(), "and tick must not either");
        assert_eq!(c.active_rules().len(), 1);
    }

    #[test]
    fn reinstall_during_deferred_clear_cancels_withdraw() {
        let mut c = FlowSpecController::new(cfg()); // 10s hold-down
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0);
        assert!(c.clear_target(ip("203.0.113.7"), 5_000).is_empty());
        // Re-assertion (idempotent — no new announce) must re-arm the entry.
        assert!(c
            .install(ip("203.0.113.7"), &[(17, 53, 1.0)], 6_000)
            .is_empty());
        assert!(
            c.tick(10_000).is_empty(),
            "re-assertion cancelled the deferred withdraw"
        );
        assert_eq!(c.active_rules().len(), 1);
    }

    #[test]
    fn active_rules_snapshot() {
        let mut c = FlowSpecController::new(cfg());
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 1234);
        let snap = c.active_rules();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, (net("203.0.113.7/32"), 17, 53));
        assert_eq!(snap[0].1, 1234);
        assert_eq!(snap[0].2, BlackholeOrigin::Auto);
    }

    #[test]
    fn resume_reannounces_and_counts_against_cap() {
        let mut c = FlowSpecController::new(cfg()); // max_rules 3
        let r = rule("203.0.113.5/32", 17, 53, 1.0);
        let actions = c.resume(r.clone(), 12_345, BlackholeOrigin::Manual);
        assert_eq!(actions, vec![FlowSpecAction::Announce(r)]);
        let snap = c.active_rules();
        assert_eq!(snap[0].1, 12_345);
        assert_eq!(snap[0].2, BlackholeOrigin::Manual);
        // Counts against the cap: 1 (resumed) + 2 more = 3 (cap); a 4th is rejected.
        assert_eq!(
            c.install(ip("203.0.113.6"), &[(6, 80, 1.0), (6, 443, 1.0)], 0)
                .len(),
            2
        );
        assert!(
            c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0).is_empty(),
            "at cap"
        );
    }

    #[test]
    fn manual_add_upgrades_auto_to_manual() {
        let mut c = FlowSpecController::new(cfg());
        assert_eq!(c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0).len(), 1); // Auto
        assert!(
            c.manual_add(rule("203.0.113.7/32", 17, 53, 1.0), 1_000)
                .is_empty(),
            "already active -> no new announce"
        );
        // Now an auto-clear can't remove it.
        assert!(c.clear_target(ip("203.0.113.7"), 100_000).is_empty());
        assert!(c.tick(200_000).is_empty());
        let snap = c.active_rules();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].2, BlackholeOrigin::Manual);
    }

    #[test]
    fn manual_remove_bypasses_hold_down() {
        let mut c = FlowSpecController::new(cfg());
        let r = rule("203.0.113.7/32", 17, 53, 1.0);
        c.manual_add(r.clone(), 0);
        assert_eq!(
            c.manual_remove(r.clone()),
            vec![FlowSpecAction::Withdraw(r)]
        );
        assert!(c.active_rules().is_empty());
    }

    #[test]
    fn manual_remove_of_absent_rule_is_empty() {
        let mut c = FlowSpecController::new(cfg());
        assert!(c
            .manual_remove(rule("203.0.113.7/32", 17, 53, 1.0))
            .is_empty());
    }

    #[test]
    fn ipv6_target_uses_128() {
        let mut cfg6 = cfg();
        cfg6.eligible_prefixes = vec![net("2001:db8::/32")];
        let mut c = FlowSpecController::new(cfg6);
        let actions = c.install(ip("2001:db8::7"), &[(17, 53, 1.0)], 0);
        let FlowSpecAction::Announce(r) = &actions[0] else {
            panic!("expected Announce")
        };
        assert_eq!(r.dst, net("2001:db8::7/128"));
    }

    #[test]
    fn refresh_target_cancels_pending_clear_and_survives_tick() {
        let mut c = FlowSpecController::new(cfg()); // 10s hold-down
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0);
        assert!(c.clear_target(ip("203.0.113.7"), 5_000).is_empty());
        c.refresh_target(ip("203.0.113.7"), 6_000);
        assert!(
            c.tick(10_000).is_empty(),
            "refresh_target cancelled the deferred withdraw"
        );
        assert_eq!(c.active_rules().len(), 1);
    }

    #[test]
    fn refresh_target_does_not_affect_other_targets() {
        let mut c = FlowSpecController::new(cfg());
        c.install(ip("203.0.113.7"), &[(17, 53, 1.0)], 0);
        c.install(ip("203.0.113.8"), &[(17, 53, 1.0)], 0);
        assert!(c.clear_target(ip("203.0.113.7"), 5_000).is_empty());
        assert!(c.clear_target(ip("203.0.113.8"), 5_000).is_empty());
        c.refresh_target(ip("203.0.113.7"), 6_000);
        // only .7 was refreshed; .8's deferred clear still fires at hold-down.
        let actions = c.tick(10_000);
        assert_eq!(actions.len(), 1);
        assert_eq!(c.active_rules().len(), 1);
    }

    #[test]
    fn is_eligible_checks_configured_prefixes() {
        let c = FlowSpecController::new(cfg());
        assert!(c.is_eligible(ip("203.0.113.7")));
        assert!(!c.is_eligible(ip("198.51.100.7")));
    }

    #[test]
    fn protected_target_is_skipped_even_when_eligible() {
        // 203.0.113.53 is inside the eligible /24 but is carved out as a
        // protected VIP: it must never get a FlowSpec rule installed.
        let mut c = FlowSpecController::new(FlowSpecConfig {
            protected_prefixes: vec![net("203.0.113.53/32")],
            ..cfg()
        });
        let actions = c.install(ip("203.0.113.53"), &[(17, 53, 1000.0)], 1_000);
        assert!(actions.is_empty(), "protected VIP must not get a rule");
        assert!(c.active_rules().is_empty());
        assert_eq!(c.protected_skipped(), 1);
    }

    #[test]
    fn unprotected_eligible_target_still_mitigates() {
        let mut c = FlowSpecController::new(FlowSpecConfig {
            protected_prefixes: vec![net("203.0.113.53/32")],
            ..cfg()
        });
        let actions = c.install(ip("203.0.113.7"), &[(17, 53, 1000.0)], 1_000);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions.as_slice(), [FlowSpecAction::Announce(_)]));
        assert_eq!(c.protected_skipped(), 0);
    }
}
