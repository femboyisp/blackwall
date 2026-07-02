//! The pure RTBH decision engine. No I/O; deterministic given an injected `now`.

use blackwall_bgp::{Origin, Route};
use blackwall_flow::DetectionEvent;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

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
    active: HashMap<IpAddr, u64>, // target -> announced-at (ms since epoch)
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
    /// - `Updated` events produce no action (hold the blackhole as-is).
    /// - `Cleared` events may produce a `Withdraw` action (only after hold-down has elapsed).
    pub fn on_event(&mut self, event: &DetectionEvent, now: u64) -> Vec<RtbhAction> {
        match event {
            DetectionEvent::Opened(d) => self.blackhole(d.target, now),
            DetectionEvent::Updated(_) => Vec::new(),
            DetectionEvent::Cleared { target, .. } => self.unblackhole(*target, now),
        }
    }

    /// Manually blackhole a target (for the operator CLI + the lab).
    ///
    /// # Arguments
    ///
    /// * `target` - The IP address to blackhole (should be inside an eligible prefix).
    /// * `now` - Current time in milliseconds since epoch.
    ///
    /// # Returns
    ///
    /// An `Announce` action if successful, empty vector if ineligible or at cap.
    pub fn manual_add(&mut self, target: IpAddr, now: u64) -> Vec<RtbhAction> {
        self.blackhole(target, now)
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

    fn blackhole(&mut self, target: IpAddr, now: u64) -> Vec<RtbhAction> {
        if !self
            .config
            .eligible_prefixes
            .iter()
            .any(|p| p.contains(&target))
        {
            tracing::warn!(%target, "RTBH: target outside eligible prefixes; ignoring");
            return Vec::new();
        }
        if self.active.contains_key(&target) {
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
        self.active.insert(target, now);
        vec![RtbhAction::Announce(route)]
    }

    fn unblackhole(&mut self, target: IpAddr, now: u64) -> Vec<RtbhAction> {
        let hold_ms = u64::try_from(self.config.hold_down.as_millis()).unwrap_or(u64::MAX);
        match self.active.get(&target) {
            Some(&at) if now.saturating_sub(at) >= hold_ms => {
                self.active.remove(&target);
                vec![RtbhAction::Withdraw(host_prefix(target))]
            }
            _ => Vec::new(),
        }
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
fn host_prefix(target: IpAddr) -> IpNet {
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
}
