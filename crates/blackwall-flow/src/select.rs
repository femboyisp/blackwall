//! Pure concentration-based mitigation selection: a flow-concentrated attack
//! becomes FlowSpec drop rules; a diffuse attack falls back to RTBH.

use crate::detector::Detection;
use std::net::IpAddr;

/// A neutral flow-scoped rule (no BGP types — keeps `blackwall-flow` BGP-free).
#[derive(Debug, Clone, PartialEq)]
pub struct FlowRule {
    /// The victim address (a host route is derived downstream).
    pub dst: IpAddr,
    /// IP protocol (e.g. 17 = UDP).
    pub proto: u8,
    /// Destination port.
    pub dst_port: u16,
    /// Traffic-rate action in bytes/sec; `0.0` = drop.
    pub rate: f32,
}

/// The chosen mitigation for a detection.
#[derive(Debug, Clone, PartialEq)]
pub enum Mitigation {
    /// Drop the listed flows (leaving the victim's other services up).
    FlowSpec(Vec<FlowRule>),
    /// Blackhole the whole victim IP (diffuse attack; FlowSpec can't scope it).
    Rtbh,
}

/// Tunables for [`select`].
#[derive(Debug, Clone)]
pub struct SelectionConfig {
    /// Cumulative top-port weight fraction that counts as "concentrated".
    pub concentration: f64,
    /// Max distinct flows a FlowSpec mitigation may emit.
    pub max_flows: usize,
    /// Traffic-rate for emitted rules (bytes/sec; `0.0` = drop).
    pub rate: f32,
}

/// Choose FlowSpec (flow-scoped drop) vs RTBH (whole-IP) for a detection.
///
/// FlowSpec is chosen only when a small set (≤ `max_flows`) of the top
/// destination ports carries at least `concentration` of the flow — i.e. when
/// dropping those flows actually stops the attack without taking the victim
/// fully offline. Otherwise (diffuse, no ports, or no protocol) falls back to RTBH.
#[must_use]
pub fn select(d: &Detection, cfg: &SelectionConfig) -> Mitigation {
    if d.proto == 0 || d.top_ports.is_empty() {
        return Mitigation::Rtbh;
    }
    let mut ports = d.top_ports.clone();
    ports.sort_by(|a, b| b.1.total_cmp(&a.1)); // weight desc
    let mut cumulative = 0.0_f64;
    let mut chosen: Vec<u16> = Vec::new();
    for (port, weight) in ports {
        if chosen.len() >= cfg.max_flows {
            break;
        }
        chosen.push(port);
        cumulative += weight;
        if cumulative >= cfg.concentration {
            return Mitigation::FlowSpec(
                chosen
                    .into_iter()
                    .map(|p| FlowRule {
                        dst: d.target,
                        proto: d.proto,
                        dst_port: p,
                        rate: cfg.rate,
                    })
                    .collect(),
            );
        }
    }
    Mitigation::Rtbh
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{AttackKind, Detection, Severity};

    fn det(proto: u8, ports: Vec<(u16, f64)>) -> Detection {
        Detection {
            target: "203.0.113.7".parse().unwrap(),
            kind: AttackKind::Volumetric,
            observed_pps: 1.0,
            observed_bps: 1.0,
            proto,
            top_sources: vec![],
            top_ports: ports,
            severity: Severity::High,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }
    fn cfg() -> SelectionConfig {
        SelectionConfig {
            concentration: 0.8,
            max_flows: 4,
            rate: 0.0,
        }
    }

    #[test]
    fn concentrated_single_port_selects_flowspec() {
        let m = select(&det(17, vec![(53, 0.95)]), &cfg());
        assert_eq!(
            m,
            Mitigation::FlowSpec(vec![FlowRule {
                dst: "203.0.113.7".parse().unwrap(),
                proto: 17,
                dst_port: 53,
                rate: 0.0
            }])
        );
    }

    #[test]
    fn concentrated_multi_port_under_cap_selects_flowspec() {
        // two ports together cross 0.8; both become rules.
        let m = select(&det(6, vec![(80, 0.5), (443, 0.4), (22, 0.1)]), &cfg());
        let Mitigation::FlowSpec(rules) = m else {
            panic!("expected FlowSpec")
        };
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].dst_port, 80);
        assert_eq!(rules[1].dst_port, 443);
    }

    #[test]
    fn diffuse_falls_back_to_rtbh() {
        // Genuinely diffuse: the top 4 ports (max_flows) sum to only 0.4, well
        // short of 0.8 — no small flow set can stop the attack, so RTBH.
        let m = select(
            &det(
                17,
                vec![
                    (1, 0.1),
                    (2, 0.1),
                    (3, 0.1),
                    (4, 0.1),
                    (5, 0.1),
                    (6, 0.1),
                    (7, 0.1),
                    (8, 0.1),
                ],
            ),
            &cfg(),
        );
        assert_eq!(m, Mitigation::Rtbh);
    }

    #[test]
    fn single_port_100pct_with_max_flows_1_selects_flowspec() {
        // Textbook FlowSpec case: 100% on one port, tightest budget (max_flows=1)
        // — must be a surgical flow rule, NOT a whole-IP blackhole.
        let c = SelectionConfig {
            concentration: 0.8,
            max_flows: 1,
            rate: 0.0,
        };
        let m = select(&det(17, vec![(53, 1.0)]), &c);
        let Mitigation::FlowSpec(rules) = m else {
            panic!("expected FlowSpec, got {m:?}")
        };
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst_port, 53);
    }

    #[test]
    fn ranks_ports_by_weight_before_selecting() {
        // Unsorted input: the dominant port (443, 0.9) is listed last; it must
        // still be the chosen flow.
        let m = select(&det(6, vec![(22, 0.05), (80, 0.05), (443, 0.9)]), &cfg());
        let Mitigation::FlowSpec(rules) = m else {
            panic!("expected FlowSpec")
        };
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst_port, 443);
    }

    #[test]
    fn empty_ports_or_no_proto_is_rtbh() {
        assert_eq!(select(&det(17, vec![]), &cfg()), Mitigation::Rtbh);
        assert_eq!(select(&det(0, vec![(53, 0.99)]), &cfg()), Mitigation::Rtbh);
    }

    #[test]
    fn respects_max_flows_cap() {
        // 5 ports each 0.19 reach 0.8 only at the 5th, but max_flows=4 -> diffuse.
        let c = SelectionConfig {
            concentration: 0.8,
            max_flows: 4,
            rate: 0.0,
        };
        let m = select(
            &det(
                17,
                vec![(1, 0.19), (2, 0.19), (3, 0.19), (4, 0.19), (5, 0.19)],
            ),
            &c,
        );
        assert_eq!(m, Mitigation::Rtbh);
    }
}
