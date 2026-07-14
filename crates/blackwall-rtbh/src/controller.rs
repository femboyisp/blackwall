//! The pure RTBH decision engine. No I/O; deterministic given an injected `now`.

use blackwall_bgp::{Origin, Route};
use blackwall_flow::DetectionEvent;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Why a blackhole is active — governs whether an auto-clear may withdraw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackholeOrigin {
    /// Installed automatically by the detector.
    Auto,
    /// Installed (or upgraded) by an operator; never auto-cleared.
    Manual,
}

/// State for one active blackhole.
#[derive(Debug, Clone, Copy)]
struct ActiveEntry {
    announced_at: u64,
    last_activity: u64,
    origin: BlackholeOrigin,
    clear_requested_at: Option<u64>,
}

/// RTBH policy configuration.
///
/// Defines the parameters for the blackhole decision engine, including eligible prefixes,
/// BGP communities, next-hops by address family, capacity limits, and anti-flap hold-down.
#[derive(Debug, Clone)]
pub struct RtbhConfig {
    /// Only targets inside these prefixes may be blackholed (never foreign space).
    pub eligible_prefixes: Vec<IpNet>,
    /// Communities attached to every blackhole route (default `[(65535, 666)]`).
    pub blackhole_communities: Vec<(u16, u16)>,
    /// NEXT_HOP for IPv4 blackholes; `None` = don't blackhole IPv4.
    pub next_hop_v4: Option<Ipv4Addr>,
    /// NEXT_HOP for IPv6 blackholes; `None` = don't blackhole IPv6.
    pub next_hop_v6: Option<Ipv6Addr>,
    /// Hard cap on concurrent blackholes.
    pub max_blackholes: usize,
    /// Minimum time a blackhole stays before a `Cleared` may withdraw it (anti-flap).
    pub hold_down: Duration,
    /// Maximum lifetime of an auto blackhole (hygiene backstop against a dropped
    /// or missed `Cleared`); `None` disables the TTL.
    pub max_ttl: Option<Duration>,
    /// Prefixes that must never be blackholed (own anycast VIPs and similar
    /// always-safe destinations), from `Policy.protected_prefixes`. Empty
    /// (the default) protects nothing extra.
    pub protected_prefixes: Vec<IpNet>,
}

/// A decision the [`RtbhController`] emits for the sink to execute.
///
/// This enum represents the two outcomes of the RTBH decision engine: either announce
/// a blackhole route for a detected attack target, or withdraw a previously-announced route.
#[derive(Debug, Clone, PartialEq)]
pub enum RtbhAction {
    /// Announce a blackhole host route.
    Announce(Route),
    /// Withdraw a previously-announced blackhole prefix.
    Withdraw(IpNet),
}

/// The pure RTBH decision engine.
///
/// A stateful controller that maps detection events from [`DetectionEvent`] to BGP
/// blackhole actions ([`RtbhAction`]). It enforces eligibility, capacity, and hold-down
/// anti-flap logic. Pure-core: deterministic given injected `now` timestamps, no I/O.
#[derive(Debug)]
pub struct RtbhController {
    config: RtbhConfig,
    active: HashMap<IpAddr, ActiveEntry>,
}

impl RtbhController {
    /// Create a controller with no active blackholes.
    #[must_use]
    pub fn new(config: RtbhConfig) -> Self {
        Self {
            config,
            active: HashMap::new(),
        }
    }

    /// Map one detection event to blackhole actions.
    ///
    /// # Arguments
    ///
    /// * `event` - A detection event from the flow detector.
    /// * `now` - Current time in milliseconds since epoch (used for hold-down checking).
    ///
    /// # Returns
    ///
    /// A vector of actions (typically 0 or 1) for the sink to execute.
    /// - `Opened` events may produce an `Announce` action (if eligible, under cap, not already active).
    /// - `Updated` events produce no action but refresh the TTL activity anchor.
    /// - `Cleared` events may produce an immediate `Withdraw` (hold-down already elapsed),
    ///   or defer the withdraw to a later [`Self::tick`] (hold-down not yet elapsed).
    ///   A `Cleared` for a `Manual` blackhole is ignored entirely.
    pub fn on_event(&mut self, event: &DetectionEvent, now: u64) -> Vec<RtbhAction> {
        match event {
            DetectionEvent::Opened(d) => self.blackhole(d.target, now, BlackholeOrigin::Auto),
            DetectionEvent::Updated(d) => {
                if let Some(e) = self.active.get_mut(&d.target) {
                    // Continued traffic: refresh the TTL anchor and cancel any
                    // pending deferred clear — the attack is not actually over.
                    e.last_activity = now;
                    e.clear_requested_at = None;
                }
                Vec::new()
            }
            DetectionEvent::Cleared { target, .. } => self.request_clear(*target, now),
        }
    }

    /// Manually blackhole a target (for the operator CLI + the lab).
    ///
    /// If the target is already active as an `Auto` blackhole, this upgrades it to
    /// `Manual` (and cancels any pending deferred clear) instead of re-announcing.
    ///
    /// # Arguments
    ///
    /// * `target` - The IP address to blackhole (should be inside an eligible prefix).
    /// * `now` - Current time in milliseconds since epoch.
    ///
    /// # Returns
    ///
    /// An `Announce` action if newly installed, empty vector if upgraded, ineligible, or at cap.
    pub fn manual_add(&mut self, target: IpAddr, now: u64) -> Vec<RtbhAction> {
        if let Some(e) = self.active.get_mut(&target) {
            // Already active: upgrade to Manual + cancel any pending clear.
            e.origin = BlackholeOrigin::Manual;
            e.clear_requested_at = None;
            return Vec::new();
        }
        self.blackhole(target, now, BlackholeOrigin::Manual)
    }

    /// Manually withdraw a target (bypasses hold-down — an operator action is deliberate).
    ///
    /// # Arguments
    ///
    /// * `target` - The IP address to unblackhole.
    ///
    /// # Returns
    ///
    /// A `Withdraw` action if the target was active, empty vector otherwise.
    pub fn manual_remove(&mut self, target: IpAddr) -> Vec<RtbhAction> {
        if self.active.remove(&target).is_some() {
            vec![RtbhAction::Withdraw(host_prefix(target))]
        } else {
            Vec::new()
        }
    }

    /// Process time-driven withdrawals: deferred clears whose hold-down has now
    /// elapsed, and auto blackholes past their TTL. Call periodically.
    pub fn tick(&mut self, now: u64) -> Vec<RtbhAction> {
        let hold_ms = u64::try_from(self.config.hold_down.as_millis()).unwrap_or(u64::MAX);
        let ttl_ms = self
            .config
            .max_ttl
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let mut expired: Vec<IpAddr> = Vec::new();
        for (target, e) in &self.active {
            let cleared_due = e
                .clear_requested_at
                .is_some_and(|_| now.saturating_sub(e.announced_at) >= hold_ms);
            let ttl_due = matches!(e.origin, BlackholeOrigin::Auto)
                && ttl_ms.is_some_and(|ttl| now.saturating_sub(e.last_activity) >= ttl);
            if cleared_due || ttl_due {
                expired.push(*target);
            }
        }
        expired
            .into_iter()
            .map(|t| {
                self.active.remove(&t);
                RtbhAction::Withdraw(host_prefix(t))
            })
            .collect()
    }

    /// Re-install a persisted blackhole on a fresh session (rehydration).
    pub fn resume(
        &mut self,
        target: IpAddr,
        announced_at: u64,
        origin: BlackholeOrigin,
    ) -> Vec<RtbhAction> {
        self.insert_blackhole(target, announced_at, origin)
    }

    /// Snapshot the active set (for reconcile mirroring, `list`, and tests).
    #[must_use]
    pub fn active_blackholes(&self) -> Vec<(IpAddr, u64, BlackholeOrigin)> {
        self.active
            .iter()
            .map(|(t, e)| (*t, e.announced_at, e.origin))
            .collect()
    }

    /// Whether `target` falls inside a configured eligible prefix.
    ///
    /// Pure accessor over [`RtbhConfig::eligible_prefixes`]; lets a caller
    /// (e.g. the manager) classify a rejected `manual_add`/`resume` without
    /// duplicating the controller's eligibility logic.
    #[must_use]
    pub fn is_eligible(&self, target: IpAddr) -> bool {
        self.config
            .eligible_prefixes
            .iter()
            .any(|p| p.contains(&target))
    }

    /// Whether a next-hop is configured for `target`'s address family.
    ///
    /// Pure accessor over [`RtbhConfig::next_hop_v4`] / `next_hop_v6`; lets a
    /// caller classify a rejected `manual_add`/`resume` without duplicating
    /// the controller's routing logic.
    #[must_use]
    pub fn has_next_hop(&self, target: IpAddr) -> bool {
        match target {
            IpAddr::V4(_) => self.config.next_hop_v4.is_some(),
            IpAddr::V6(_) => self.config.next_hop_v6.is_some(),
        }
    }

    fn request_clear(&mut self, target: IpAddr, now: u64) -> Vec<RtbhAction> {
        let hold_ms = u64::try_from(self.config.hold_down.as_millis()).unwrap_or(u64::MAX);
        match self.active.get_mut(&target) {
            // Manual blackholes are never auto-cleared.
            Some(e) if matches!(e.origin, BlackholeOrigin::Manual) => Vec::new(),
            Some(e) if now.saturating_sub(e.announced_at) >= hold_ms => {
                self.active.remove(&target);
                vec![RtbhAction::Withdraw(host_prefix(target))]
            }
            Some(e) => {
                e.clear_requested_at = Some(now);
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    fn blackhole(&mut self, target: IpAddr, now: u64, origin: BlackholeOrigin) -> Vec<RtbhAction> {
        self.insert_blackhole(target, now, origin)
    }

    fn insert_blackhole(
        &mut self,
        target: IpAddr,
        announced_at: u64,
        origin: BlackholeOrigin,
    ) -> Vec<RtbhAction> {
        if !self
            .config
            .eligible_prefixes
            .iter()
            .any(|p| p.contains(&target))
        {
            tracing::warn!(%target, "RTBH: target outside eligible prefixes; ignoring");
            return Vec::new();
        }
        if let Some(e) = self.active.get_mut(&target) {
            // Re-assertion of an already-active target (e.g. a re-attack `Opened`
            // during a deferred-clear window): cancel any pending clear and refresh
            // the TTL anchor so `tick` does not withdraw a target under attack again.
            e.clear_requested_at = None;
            e.last_activity = announced_at;
            return Vec::new();
        }
        if self.active.len() >= self.config.max_blackholes {
            tracing::warn!(%target, cap = self.config.max_blackholes, "RTBH: at cap; ignoring");
            return Vec::new();
        }
        let Some(route) = self.host_route(target) else {
            tracing::warn!(%target, "RTBH: no next-hop for target family; ignoring");
            return Vec::new();
        };
        self.active.insert(
            target,
            ActiveEntry {
                announced_at,
                last_activity: announced_at,
                origin,
                clear_requested_at: None,
            },
        );
        vec![RtbhAction::Announce(route)]
    }

    fn host_route(&self, target: IpAddr) -> Option<Route> {
        let next_hop = match target {
            IpAddr::V4(_) => self.config.next_hop_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.config.next_hop_v6.map(IpAddr::V6),
        }?;
        Some(Route {
            prefix: host_prefix(target),
            next_hop,
            origin: Origin::Igp,
            communities: self.config.blackhole_communities.clone(),
            large_communities: Vec::new(),
        })
    }
}

/// Construct a host prefix for a target address.
///
/// Returns `/32` for IPv4 or `/128` for IPv6.
pub(crate) fn host_prefix(target: IpAddr) -> IpNet {
    match target {
        IpAddr::V4(a) => IpNet::V4(ipnet::Ipv4Net::new(a, 32).expect("v4 /32")),
        IpAddr::V6(a) => IpNet::V6(ipnet::Ipv6Net::new(a, 128).expect("v6 /128")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_flow::{AttackKind, Detection, DetectionEvent, Severity};
    use std::net::IpAddr;
    use std::time::Duration;

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

    fn cfg_ttl(ms: u64) -> RtbhConfig {
        RtbhConfig {
            max_ttl: Some(Duration::from_millis(ms)),
            ..cfg()
        }
    }
    fn det(ip: &str) -> Detection {
        Detection {
            target: ip.parse().unwrap(),
            kind: AttackKind::Volumetric,
            observed_pps: 200_000.0,
            observed_bps: 2e9,
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
    fn net(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn opened_eligible_announces_host_route_with_community() {
        let mut c = RtbhController::new(cfg());
        let actions = c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 1000);
        assert_eq!(actions.len(), 1);
        let RtbhAction::Announce(r) = &actions[0] else {
            panic!("expected Announce")
        };
        assert_eq!(r.prefix, net("203.0.113.7/32"));
        assert_eq!(r.next_hop, ip("10.0.0.1"));
        assert!(r.communities.contains(&(65535, 666)));
    }

    #[test]
    fn opened_ineligible_is_ignored() {
        let mut c = RtbhController::new(cfg());
        assert!(c
            .on_event(&DetectionEvent::Opened(det("198.51.100.7")), 1000)
            .is_empty());
    }

    #[test]
    fn duplicate_opened_is_idempotent() {
        let mut c = RtbhController::new(cfg());
        assert_eq!(
            c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 1000)
                .len(),
            1
        );
        assert!(c
            .on_event(&DetectionEvent::Opened(det("203.0.113.7")), 2000)
            .is_empty());
    }

    #[test]
    fn at_cap_is_ignored() {
        let mut c = RtbhController::new(cfg()); // max 2
        assert_eq!(c.manual_add(ip("203.0.113.1"), 0).len(), 1);
        assert_eq!(c.manual_add(ip("203.0.113.2"), 0).len(), 1);
        assert!(c.manual_add(ip("203.0.113.3"), 0).is_empty());
    }

    #[test]
    fn cleared_after_hold_down_withdraws() {
        let mut c = RtbhController::new(cfg());
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        let actions = c.on_event(
            &DetectionEvent::Cleared {
                target: ip("203.0.113.7"),
                at_ms: 10_000,
            },
            10_000,
        );
        assert_eq!(actions, vec![RtbhAction::Withdraw(net("203.0.113.7/32"))]);
    }

    #[test]
    fn cleared_before_hold_down_keeps_blackhole() {
        let mut c = RtbhController::new(cfg());
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        assert!(c
            .on_event(
                &DetectionEvent::Cleared {
                    target: ip("203.0.113.7"),
                    at_ms: 5000
                },
                5000
            )
            .is_empty());
    }

    #[test]
    fn updated_is_noop() {
        let mut c = RtbhController::new(cfg());
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        assert!(c
            .on_event(&DetectionEvent::Updated(det("203.0.113.7")), 1000)
            .is_empty());
    }

    #[test]
    fn manual_remove_bypasses_hold_down() {
        let mut c = RtbhController::new(cfg());
        c.manual_add(ip("203.0.113.7"), 0);
        assert_eq!(
            c.manual_remove(ip("203.0.113.7")),
            vec![RtbhAction::Withdraw(net("203.0.113.7/32"))]
        );
    }

    #[test]
    fn no_next_hop_for_family_is_ignored() {
        let mut c = RtbhController::new(cfg()); // next_hop_v6 = None
        let mut c6cfg = cfg();
        c6cfg.eligible_prefixes = vec![net("2001:db8::/32")];
        let mut c6 = RtbhController::new(c6cfg);
        // v6 target, no v6 next-hop -> ignored
        assert!(c6.manual_add(ip("2001:db8::7"), 0).is_empty());
        let _ = &mut c;
    }

    #[test]
    fn ipv6_target_uses_128() {
        let mut cfg6 = cfg();
        cfg6.eligible_prefixes = vec![net("2001:db8::/32")];
        cfg6.next_hop_v6 = Some("2001:db8::1".parse().unwrap());
        let mut c = RtbhController::new(cfg6);
        let actions = c.manual_add(ip("2001:db8::7"), 0);
        let RtbhAction::Announce(r) = &actions[0] else {
            panic!()
        };
        assert_eq!(r.prefix, net("2001:db8::7/128"));
    }

    #[test]
    fn cleared_before_hold_down_is_deferred_then_withdrawn_on_tick() {
        let mut c = RtbhController::new(cfg()); // 10s hold-down
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        // Cleared arrives at 5s — before hold-down. Must NOT drop it forever.
        assert!(c
            .on_event(
                &DetectionEvent::Cleared {
                    target: ip("203.0.113.7"),
                    at_ms: 5_000
                },
                5_000
            )
            .is_empty());
        // A tick before hold-down: still held.
        assert!(c.tick(9_000).is_empty());
        // A tick at/after hold-down: the deferred withdraw fires.
        assert_eq!(
            c.tick(10_000),
            vec![RtbhAction::Withdraw(net("203.0.113.7/32"))]
        );
        assert!(c.active_blackholes().is_empty());
    }

    #[test]
    fn ttl_withdraws_a_never_cleared_blackhole() {
        let mut c = RtbhController::new(cfg_ttl(30_000)); // 30s TTL
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        assert!(c.tick(29_000).is_empty());
        assert_eq!(
            c.tick(30_000),
            vec![RtbhAction::Withdraw(net("203.0.113.7/32"))]
        );
    }

    #[test]
    fn updated_refreshes_ttl_anchor() {
        let mut c = RtbhController::new(cfg_ttl(30_000));
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        c.on_event(&DetectionEvent::Updated(det("203.0.113.7")), 20_000); // refresh
        assert!(
            c.tick(45_000).is_empty(),
            "TTL measured from last activity (20s)"
        );
        assert_eq!(c.tick(50_000).len(), 1, "expires 30s after the refresh");
    }

    #[test]
    fn reattack_opened_during_deferred_clear_cancels_withdraw() {
        // A Cleared before hold-down defers the withdraw; a re-attack Opened before
        // the tick fires must cancel it, or tick would withdraw a target under attack.
        let mut c = RtbhController::new(cfg()); // 10s hold-down
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        assert!(c
            .on_event(
                &DetectionEvent::Cleared {
                    target: ip("203.0.113.7"),
                    at_ms: 5_000
                },
                5_000
            )
            .is_empty());
        // Re-attack at 6s (idempotent — no new announce) must re-arm the entry.
        assert!(c
            .on_event(&DetectionEvent::Opened(det("203.0.113.7")), 6_000)
            .is_empty());
        assert!(
            c.tick(10_000).is_empty(),
            "re-attack cancelled the deferred withdraw"
        );
        assert_eq!(c.active_blackholes().len(), 1);
    }

    #[test]
    fn updated_during_deferred_clear_cancels_withdraw() {
        // Continued traffic (Updated) after an early Cleared also cancels the defer.
        let mut c = RtbhController::new(cfg());
        c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0);
        assert!(c
            .on_event(
                &DetectionEvent::Cleared {
                    target: ip("203.0.113.7"),
                    at_ms: 5_000
                },
                5_000
            )
            .is_empty());
        c.on_event(&DetectionEvent::Updated(det("203.0.113.7")), 6_000);
        assert!(c.tick(10_000).is_empty());
        assert_eq!(c.active_blackholes().len(), 1);
    }

    #[test]
    fn manual_survives_auto_clear() {
        let mut c = RtbhController::new(cfg());
        c.manual_add(ip("203.0.113.7"), 0); // Manual
        assert!(
            c.on_event(
                &DetectionEvent::Cleared {
                    target: ip("203.0.113.7"),
                    at_ms: 100_000
                },
                100_000
            )
            .is_empty(),
            "auto-clear must not withdraw a manual blackhole"
        );
        assert!(c.tick(200_000).is_empty(), "and tick must not either");
        assert_eq!(c.active_blackholes().len(), 1);
    }

    #[test]
    fn manual_add_upgrades_auto_to_manual() {
        let mut c = RtbhController::new(cfg());
        assert_eq!(
            c.on_event(&DetectionEvent::Opened(det("203.0.113.7")), 0)
                .len(),
            1
        ); // Auto
        assert!(
            c.manual_add(ip("203.0.113.7"), 1_000).is_empty(),
            "already active → no new announce"
        );
        // Now an auto-clear can't remove it.
        c.on_event(
            &DetectionEvent::Cleared {
                target: ip("203.0.113.7"),
                at_ms: 100_000,
            },
            100_000,
        );
        assert!(c.tick(200_000).is_empty());
        let snap = c.active_blackholes();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].2, BlackholeOrigin::Manual);
    }

    #[test]
    fn resume_reannounces_and_counts_against_cap() {
        let mut c = RtbhController::new(cfg()); // max 2
        let a = c.resume(ip("203.0.113.5"), 12_345, BlackholeOrigin::Manual);
        assert_eq!(a.len(), 1, "resume re-announces");
        let snap = c.active_blackholes();
        assert_eq!(
            snap[0],
            (ip("203.0.113.5"), 12_345, BlackholeOrigin::Manual)
        );
        // counts against the cap
        assert_eq!(c.manual_add(ip("203.0.113.6"), 0).len(), 1);
        assert!(c.manual_add(ip("203.0.113.7"), 0).is_empty(), "at cap");
    }

    #[test]
    fn is_eligible_checks_configured_prefixes() {
        let c = RtbhController::new(cfg());
        assert!(c.is_eligible(ip("203.0.113.7")));
        assert!(!c.is_eligible(ip("198.51.100.7")));
    }

    #[test]
    fn has_next_hop_checks_family() {
        let c = RtbhController::new(cfg()); // v4 next-hop set, v6 not
        assert!(c.has_next_hop(ip("203.0.113.7")));
        assert!(!c.has_next_hop(ip("2001:db8::7")));
    }
}
