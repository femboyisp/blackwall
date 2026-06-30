//! Generation spec (`full-set`) and the receive-side gate thresholds.

use crate::error::{Result, TrafficGenError};
use crate::pattern::{MalformedKind, Pattern, ReflProto};
use crate::report::RecvReport;

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

/// Apply the increment-1 gate thresholds (spec §5.3) to a receive report.
#[must_use]
pub fn verify(report: &RecvReport, spec: &GenSpec) -> VerifyOutcome {
    let mut reasons = Vec::new();
    let pkts = |k: &str| report.per_flow.get(k).map_or(0, |c| c.packets);
    let elapsed_s = (report.elapsed_ms / 1000).max(1);

    // (1) benign survives ≥ 95% of expected.
    if let Some(b) = spec
        .patterns
        .iter()
        .find(|p| matches!(p.pattern, Pattern::Benign))
    {
        let expected = b.pps.saturating_mul(elapsed_s);
        let got = pkts("benign");
        if got.saturating_mul(100) < expected.saturating_mul(95) {
            reasons.push(format!("benign starved: {got} < 95% of {expected}"));
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

    // (4) no misclassified traffic.
    if pkts("unknown") != 0 {
        reasons.push(format!("{} unknown packets", pkts("unknown")));
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
    fn verify_fails_on_unknown_traffic() {
        let spec = parse_spec("full-set").unwrap();
        let mut r = good_report();
        r.per_flow.insert(
            "unknown".to_owned(),
            FlowCounts {
                packets: 5,
                bytes: 80,
            },
        );
        assert!(!verify(&r, &spec).passed);
    }
}
