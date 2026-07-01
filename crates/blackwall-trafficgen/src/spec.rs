//! Generation spec (`full-set`) and the receive-side gate thresholds.

use crate::error::{Result, TrafficGenError};
use crate::pattern::{MalformedKind, Pattern, ReflProto};
use crate::report::{ConnectReport, RecvReport};

/// One pattern at one rate.
#[derive(Debug, Clone)]
pub struct PatternSpec {
    /// The pattern to generate.
    pub pattern: Pattern,
    /// Target packets per second.
    pub pps: u64,
}

/// A full generation spec: several patterns sent concurrently.
#[derive(Debug, Clone)]
pub struct GenSpec {
    /// The patterns + rates.
    pub patterns: Vec<PatternSpec>,
}

/// Parse a named spec. Only `"full-set"` is defined in increment 1.
///
/// # Errors
/// [`TrafficGenError::Spec`] for any other name.
pub fn parse_spec(name: &str) -> Result<GenSpec> {
    match name {
        "full-set" => Ok(GenSpec {
            patterns: vec![
                PatternSpec {
                    pattern: Pattern::UdpFlood,
                    pps: 50_000,
                },
                PatternSpec {
                    pattern: Pattern::SynFlood { spoof_src: true },
                    pps: 20_000,
                },
                PatternSpec {
                    pattern: Pattern::Reflection(ReflProto::Dns),
                    pps: 5_000,
                },
                PatternSpec {
                    pattern: Pattern::Malformed(MalformedKind::BadIpChecksum),
                    pps: 1_000,
                },
                PatternSpec {
                    pattern: Pattern::Benign,
                    pps: 1_000,
                },
            ],
        }),
        other => Err(TrafficGenError::Spec(format!("unknown spec `{other}`"))),
    }
}

/// Result of evaluating the receive-side gate.
#[derive(Debug)]
pub struct VerifyOutcome {
    /// Whether all thresholds passed.
    pub passed: bool,
    /// One line per failed (or noted) threshold.
    pub reasons: Vec<String>,
}

/// The `connect-flood` gate predicate: the engine is **alive** (served > 0) AND
/// the flood was **bounded** (some excess rejected — dropped at the cap, or failed
/// at the backlog). Requiring only `dropped > 0` would be flaky since under heavy
/// load the excess can shift to backlog-`failed`; the robust property is
/// "alive AND bounded".
#[must_use]
pub fn connect_flood_ok(r: &ConnectReport) -> bool {
    r.served > 0 && (r.dropped + r.failed) > 0
}

/// Apply the increment-1 gate thresholds (spec §5.3) to a receive report.
#[must_use]
pub fn verify(report: &RecvReport, spec: &GenSpec) -> VerifyOutcome {
    let mut reasons = Vec::new();
    let pkts = |k: &str| report.per_flow.get(k).map_or(0, |c| c.packets);
    let total_pps: u64 = spec.patterns.iter().map(|p| p.pps).sum();

    // (1) benign survives: it must hold at least 95% of its proportional share of
    // delivered traffic. All patterns are sent over the same window, so absent a
    // mitigation the received counts are proportional to their pps; the benign
    // flow's share is `benign_pps / total_pps`. This is duration-free — it does
    // not depend on the sink's capture window matching the send window — and stays
    // meaningful once a mitigation drops the floods (benign's share then rises).
    // Cross-multiplied to integers: got * total_pps * 100 >= 95 * total * benign_pps.
    if let Some(b) = spec
        .patterns
        .iter()
        .find(|p| matches!(p.pattern, Pattern::Benign))
    {
        let got = pkts("benign");
        let total = report.total.packets;
        let lhs = got.saturating_mul(total_pps).saturating_mul(100);
        let rhs = total.saturating_mul(b.pps).saturating_mul(95);
        if lhs < rhs {
            reasons.push(format!(
                "benign starved: {got}/{total} below 95% of the {}/{total_pps} pps share",
                b.pps
            ));
        }
    }

    // (2) attack + malformed classes actually arrived.
    if pkts("udp-flood") == 0 {
        reasons.push("no udp-flood packets classified".to_owned());
    }
    if pkts("malformed") == 0 {
        reasons.push("no malformed packets classified".to_owned());
    }

    // (3) the two measurement views corroborate (within 15%).
    let sink = report.total.packets;
    let kern = report.kernel_rx_packets;
    let hi = sink.max(kern);
    let lo = sink.min(kern);
    if hi.saturating_sub(lo).saturating_mul(100) > hi.max(1).saturating_mul(15) {
        reasons.push(format!("sink/kernel mismatch: sink={sink} kernel={kern}"));
    }

    // (4) no systematic misclassification: the `unknown` bucket must stay under
    // 1% of all captured frames. A real netns sink also captures the victim's
    // own incidental outbound traffic (kernel RSTs to the SYN flood, ICMP, IPv6
    // ND), which is legitimately unclassifiable noise — a strict `== 0` would be
    // flaky. A whole misclassified attack flow, by contrast, is far above 1%.
    let unknown = pkts("unknown");
    if unknown.saturating_mul(100) > report.total.packets {
        reasons.push(format!(
            "{unknown} unknown packets exceed 1% of {} total",
            report.total.packets
        ));
    }

    VerifyOutcome {
        passed: reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::FlowCounts;
    use std::collections::BTreeMap;

    #[test]
    fn parse_full_set_has_five_patterns() {
        let spec = parse_spec("full-set").unwrap();
        assert_eq!(spec.patterns.len(), 5);
    }

    #[test]
    fn parse_rejects_unknown_spec() {
        assert!(parse_spec("nonsense").is_err());
    }

    fn good_report() -> RecvReport {
        let mut per_flow = BTreeMap::new();
        per_flow.insert(
            "benign".to_owned(),
            FlowCounts {
                packets: 8000,
                bytes: 128000,
            },
        );
        per_flow.insert(
            "udp-flood".to_owned(),
            FlowCounts {
                packets: 400000,
                bytes: 6_400_000,
            },
        );
        per_flow.insert(
            "malformed".to_owned(),
            FlowCounts {
                packets: 8000,
                bytes: 100_000,
            },
        );
        let total = FlowCounts {
            packets: 416000,
            bytes: 0,
        };
        RecvReport {
            elapsed_ms: 8000,
            total,
            kernel_rx_packets: 416000,
            per_flow,
        }
    }

    #[test]
    fn verify_passes_on_good_report() {
        let spec = parse_spec("full-set").unwrap();
        let out = verify(&good_report(), &spec);
        assert!(out.passed, "reasons: {:?}", out.reasons);
    }

    #[test]
    fn verify_fails_when_benign_starved() {
        let spec = parse_spec("full-set").unwrap();
        let mut r = good_report();
        r.per_flow.get_mut("benign").unwrap().packets = 10; // way below 95%
        assert!(!verify(&r, &spec).passed);
    }

    #[test]
    fn verify_fails_on_systematic_unknown_traffic() {
        // A whole misclassified flow (well over 1% of the ~416k total) fails.
        let spec = parse_spec("full-set").unwrap();
        let mut r = good_report();
        r.per_flow.insert(
            "unknown".to_owned(),
            FlowCounts {
                packets: 50_000,
                bytes: 800_000,
            },
        );
        assert!(!verify(&r, &spec).passed);
    }

    #[test]
    fn verify_tolerates_incidental_unknown_noise() {
        // A handful of unclassifiable frames (kernel RSTs/ICMP/ND captured by the
        // sink) stay under 1% of the total and must not fail the gate.
        let spec = parse_spec("full-set").unwrap();
        let mut r = good_report();
        r.per_flow.insert(
            "unknown".to_owned(),
            FlowCounts {
                packets: 15,
                bytes: 1200,
            },
        );
        assert!(
            verify(&r, &spec).passed,
            "reasons: {:?}",
            verify(&r, &spec).reasons
        );
    }

    #[test]
    fn connect_flood_ok_needs_served_and_bounded() {
        use crate::report::ConnectReport;
        // alive AND bounded (some dropped) -> ok
        assert!(connect_flood_ok(&ConnectReport {
            attempted: 900,
            served: 256,
            dropped: 600,
            failed: 0,
        }));
        // alive AND bounded (some failed at the backlog) -> ok
        assert!(connect_flood_ok(&ConnectReport {
            attempted: 900,
            served: 256,
            dropped: 0,
            failed: 600,
        }));
        // everything served, nothing bounded -> not ok (cap never engaged)
        assert!(!connect_flood_ok(&ConnectReport {
            attempted: 256,
            served: 256,
            dropped: 0,
            failed: 0,
        }));
        // engine dead (nothing served) -> not ok
        assert!(!connect_flood_ok(&ConnectReport {
            attempted: 900,
            served: 0,
            dropped: 900,
            failed: 0,
        }));
    }
}
