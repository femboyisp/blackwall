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
    /// All currently rate-limited sources, with the origin that installed them.
    rate_limited: HashMap<IpAddr, XdpOrigin>,
    /// All currently blocked networks, with the origin that installed them.
    blocked_nets: HashMap<IpNet, XdpOrigin>,
    /// Victim target -> the (auto) sources currently rate-limited on its
    /// behalf, so a `Cleared` for that target knows which sources to release.
    by_target: HashMap<IpAddr, HashSet<IpAddr>>,
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
    #[must_use]
    pub fn new(prefixes: Vec<IpNet>, max_entries: usize, default_rate_pps: u64) -> Self {
        Self {
            prefixes,
            max_entries,
            default_rate_pps,
            rate_limited: HashMap::new(),
            blocked_nets: HashMap::new(),
            by_target: HashMap::new(),
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
        if self.is_own_prefix(net) {
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
        match self.rate_limited.entry(addr) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(XdpOrigin::Manual);
                return Ok(XdpAction::RateLimit {
                    src: addr,
                    pps,
                    burst,
                });
            }
            std::collections::hash_map::Entry::Vacant(_) if at_cap => {
                return Err(format!(
                    "at capacity ({} entries); cannot rate-limit {addr}",
                    self.max_entries
                ));
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(XdpOrigin::Manual);
            }
        }
        Ok(XdpAction::RateLimit {
            src: addr,
            pps,
            burst,
        })
    }

    /// Whether `net` overlaps one of the configured own prefixes.
    ///
    /// Pure accessor; lets a caller (e.g. the manager) classify a rejected
    /// `manual_block` without duplicating the controller's eligibility logic.
    #[must_use]
    pub fn is_own_prefix(&self, net: IpNet) -> bool {
        self.prefixes.iter().any(|p| p.contains(&net))
    }

    /// Whether the controller is at its combined active-entry cap.
    #[must_use]
    pub fn at_capacity(&self) -> bool {
        self.total_active() >= self.max_entries
    }

    /// Snapshot the active set (for reconcile mirroring and restart rehydration).
    #[must_use]
    pub fn active_entries(&self) -> Vec<(XdpAction, XdpOrigin)> {
        let mut entries: Vec<(XdpAction, XdpOrigin)> = self
            .rate_limited
            .iter()
            .map(|(src, origin)| {
                (
                    XdpAction::RateLimit {
                        src: *src,
                        pps: self.default_rate_pps,
                        burst: self.default_rate_pps,
                    },
                    *origin,
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
    pub fn mark_resumed(&mut self, action: &XdpAction, origin: XdpOrigin) {
        match *action {
            XdpAction::RateLimit { src, .. } => {
                self.rate_limited.insert(src, origin);
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
            self.rate_limited.insert(*src, XdpOrigin::Auto);
            self.by_target.entry(d.target).or_default().insert(*src);
            actions.push(XdpAction::RateLimit {
                src: *src,
                pps: self.default_rate_pps,
                burst: self.default_rate_pps,
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
            match self.rate_limited.get(&src) {
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
            severity: Severity::High,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    #[test]
    fn opened_on_own_victim_rate_limits_each_source() {
        let mut c = XdpController::new(own(), 100, 1000);
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
        let mut c = XdpController::new(own(), 100, 1000);
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "8.8.8.8",
            vec!["198.51.100.9"],
        )));
        assert!(acts.is_empty());
    }

    #[test]
    fn manual_block_of_own_prefix_is_rejected() {
        let mut c = XdpController::new(own(), 100, 1000);
        assert!(c.manual_block("203.0.113.5/32".parse().unwrap()).is_err());
    }

    #[test]
    fn cap_defers_beyond_max_entries() {
        let mut c = XdpController::new(own(), 1, 1000);
        let acts = c.on_detection(&DetectionEvent::Opened(det(
            "203.0.113.7",
            vec!["198.51.100.9", "198.51.100.10"],
        )));
        assert_eq!(acts.len(), 1); // second source over the cap is dropped
    }

    #[test]
    fn cleared_emits_clear_rate_for_each_recorded_source() {
        let mut c = XdpController::new(own(), 100, 1000);
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
        let mut c = XdpController::new(own(), 100, 1000);
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
        let mut c = XdpController::new(own(), 1, 1000);
        c.manual_block("198.51.100.0/24".parse().unwrap()).unwrap();
        assert!(c.manual_block("198.51.101.0/24".parse().unwrap()).is_err());
    }

    #[test]
    fn manual_unblock_is_idempotent() {
        let mut c = XdpController::new(own(), 100, 1000);
        let net = "198.51.100.0/24".parse().unwrap();
        c.manual_block(net).unwrap();
        assert!(c.manual_unblock(net).is_ok());
        assert!(c.manual_unblock(net).is_ok());
        assert!(c.active_entries().is_empty());
    }
}
