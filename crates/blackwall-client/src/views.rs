//! Typed views over a raw [`crate::MetricsSnapshot`]: the panels' actual
//! inputs, plus rate computation across two snapshots.
//!
//! **Deviation from the original plan:** the plan's `BgpState` decode assumed
//! a 6-value BGP FSM (`Idle..=Established`, 1..=6) with a `peer` label on
//! `blackwall_bgp_session_state`. The live exporter
//! (`bin/blackwalld/src/metrics.rs`, `blackwall_bgp::SessionState`) only ever
//! emits an **unlabeled** gauge with three possible values: `0` = idle, `1` =
//! connecting, `2` = established (Blackwall runs exactly one upstream BGP
//! session for RTBH, not a multi-peer table). This module decodes against
//! that reality — `0/1/2` map to `Idle/Connect/Established`, anything else to
//! `Unknown` — and keeps the fuller FSM variants (`Active`, `OpenSent`,
//! `OpenConfirm`) defined but currently unreachable, so a future
//! labeled/finer-grained exporter needs no enum change. `bgp_peers` reads
//! whatever `peer` label is present per sample and falls back to `"upstream"`
//! when absent (today: always absent), so the peerings panel renders one row
//! for the single session rather than an empty table.

use crate::MetricsSnapshot;

/// Decoded BGP session state. See the module-level note: only
/// `Idle`/`Connect`/`Established`/`Unknown` are reachable against the
/// current exporter; the rest are defined for forward compatibility with a
/// future finer-grained FSM export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpState {
    /// FSM value `0`.
    Idle,
    /// FSM value `1` (the exporter's "connecting").
    Connect,
    /// Not currently emitted by the exporter.
    Active,
    /// Not currently emitted by the exporter.
    OpenSent,
    /// Not currently emitted by the exporter.
    OpenConfirm,
    /// FSM value `2`.
    Established,
    /// Any value outside the known range.
    Unknown,
}

impl BgpState {
    /// Decode the exporter's numeric `blackwall_bgp_session_state` value.
    fn from_value(v: f64) -> Self {
        // Compare against the same set of integral values the exporter can
        // actually produce (0/1/2 today) plus the plan's originally intended
        // finer FSM (3..=6), so a future export change is a no-op here.
        if (v - 0.0).abs() < f64::EPSILON {
            BgpState::Idle
        } else if (v - 1.0).abs() < f64::EPSILON {
            BgpState::Connect
        } else if (v - 2.0).abs() < f64::EPSILON {
            BgpState::Established
        } else if (v - 3.0).abs() < f64::EPSILON {
            BgpState::Active
        } else if (v - 4.0).abs() < f64::EPSILON {
            BgpState::OpenSent
        } else if (v - 5.0).abs() < f64::EPSILON {
            BgpState::OpenConfirm
        } else {
            BgpState::Unknown
        }
    }
}

/// A single BGP session as shown by the peerings panel.
#[derive(Debug, Clone, PartialEq)]
pub struct BgpPeer {
    /// The `peer` label value, or `"upstream"` when the exporter emits an
    /// unlabeled sample (today: always).
    pub peer: String,
    /// Decoded session state.
    pub state: BgpState,
    /// Cumulative reconnect count (`blackwall_bgp_reconnects_total`), summed
    /// when multiple samples share this session (there is normally exactly
    /// one).
    pub reconnects: u64,
}

/// Build the peerings panel's rows from `blackwall_bgp_session_state` (and
/// `blackwall_bgp_reconnects_total` for the matching peer label, when
/// present). Returns one entry per distinct `peer` label observed, or one
/// `"upstream"` entry when the exporter omits the label entirely.
#[must_use]
pub fn bgp_peers(s: &MetricsSnapshot) -> Vec<BgpPeer> {
    let reconnects_by_peer: std::collections::HashMap<String, u64> = s
        .samples("blackwall_bgp_reconnects_total")
        .iter()
        .map(|sample| {
            let peer = sample
                .labels
                .get("peer")
                .cloned()
                .unwrap_or_else(|| "upstream".to_string());
            (peer, sample.value.max(0.0) as u64)
        })
        .collect();

    s.samples("blackwall_bgp_session_state")
        .iter()
        .map(|sample| {
            let peer = sample
                .labels
                .get("peer")
                .cloned()
                .unwrap_or_else(|| "upstream".to_string());
            let reconnects = reconnects_by_peer.get(&peer).copied().unwrap_or(0);
            BgpPeer {
                peer,
                state: BgpState::from_value(sample.value),
                reconnects,
            }
        })
        .collect()
}

/// Throughput derived from two `blackwall_flow_sampled_{bytes,packets}_total`
/// snapshots (Task 1's dashboard-only counters).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Throughput {
    /// Bits per second over the interval.
    pub bps: f64,
    /// Packets per second over the interval.
    pub pps: f64,
}

/// Compute throughput as the delta of the sampled-bytes/packets counters
/// between `prev` and `cur`, divided by `dt_secs`. A negative delta (counter
/// reset, e.g. process restart) clamps to `0.0` rather than going negative.
#[must_use]
pub fn throughput(prev: &MetricsSnapshot, cur: &MetricsSnapshot, dt_secs: f64) -> Throughput {
    let prev_bytes = prev
        .gauge("blackwall_flow_sampled_bytes_total")
        .unwrap_or(0.0);
    let cur_bytes = cur
        .gauge("blackwall_flow_sampled_bytes_total")
        .unwrap_or(0.0);
    let prev_packets = prev
        .gauge("blackwall_flow_sampled_packets_total")
        .unwrap_or(0.0);
    let cur_packets = cur
        .gauge("blackwall_flow_sampled_packets_total")
        .unwrap_or(0.0);

    let delta_bytes = (cur_bytes - prev_bytes).max(0.0);
    let delta_packets = (cur_packets - prev_packets).max(0.0);

    if dt_secs <= 0.0 {
        return Throughput { bps: 0.0, pps: 0.0 };
    }

    Throughput {
        bps: delta_bytes * 8.0 / dt_secs,
        pps: delta_packets / dt_secs,
    }
}

/// Whether mitigations are actually being applied (`blackwall_armed`): `1`
/// live, `0` under shadow mode or after a disarm. Absent (e.g. the flow
/// daemon isn't a mitigation daemon) reads as `false`.
#[must_use]
pub fn armed(s: &MetricsSnapshot) -> bool {
    s.gauge("blackwall_armed").is_some_and(|v| v > 0.0)
}

/// Deception honeypot sessions currently in flight
/// (`blackwall_deception_sessions_active`). Absent reads as `0`.
#[must_use]
pub fn deception_sessions(s: &MetricsSnapshot) -> u64 {
    s.gauge("blackwall_deception_sessions_active")
        .map(|v| v.max(0.0) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_prometheus;

    #[test]
    fn decodes_bgp_state_against_the_live_exporters_unlabeled_0_1_2_gauge() {
        // The real exporter emits exactly this shape: no `peer` label, value
        // in {0,1,2}. See the module doc for why this replaces the plan's
        // original labeled/1..=6 test.
        let idle = parse_prometheus("blackwall_bgp_session_state 0\n");
        let connecting = parse_prometheus("blackwall_bgp_session_state 1\n");
        let established = parse_prometheus("blackwall_bgp_session_state 2\n");

        assert_eq!(bgp_peers(&idle)[0].state, BgpState::Idle);
        assert_eq!(bgp_peers(&connecting)[0].state, BgpState::Connect);
        assert_eq!(bgp_peers(&established)[0].state, BgpState::Established);
        assert_eq!(bgp_peers(&established)[0].peer, "upstream");
    }

    #[test]
    fn decodes_labeled_multi_peer_samples_for_forward_compatibility() {
        let s = parse_prometheus(
            "blackwall_bgp_session_state{peer=\"a\"} 2\nblackwall_bgp_session_state{peer=\"b\"} 3\n",
        );
        let peers = bgp_peers(&s);
        assert_eq!(peers.len(), 2);
        assert!(peers
            .iter()
            .any(|p| p.peer == "a" && p.state == BgpState::Established));
        assert!(peers
            .iter()
            .any(|p| p.peer == "b" && p.state == BgpState::Active));
    }

    #[test]
    fn unknown_fsm_value_decodes_to_unknown() {
        let s = parse_prometheus("blackwall_bgp_session_state 99\n");
        assert_eq!(bgp_peers(&s)[0].state, BgpState::Unknown);
    }

    #[test]
    fn bgp_peers_is_empty_when_the_family_is_absent() {
        let s = parse_prometheus("");
        assert!(bgp_peers(&s).is_empty());
    }

    #[test]
    fn reconnects_are_matched_by_peer_label() {
        let s =
            parse_prometheus("blackwall_bgp_session_state 2\nblackwall_bgp_reconnects_total 4\n");
        assert_eq!(bgp_peers(&s)[0].reconnects, 4);
    }

    #[test]
    fn throughput_is_delta_over_time_and_bits() {
        let a = parse_prometheus(
            "blackwall_flow_sampled_bytes_total 1000\nblackwall_flow_sampled_packets_total 10\n",
        );
        let b = parse_prometheus(
            "blackwall_flow_sampled_bytes_total 2000\nblackwall_flow_sampled_packets_total 20\n",
        );
        let t = throughput(&a, &b, 2.0);
        assert_eq!(t.bps, 4000.0); // (2000-1000)*8 / 2
        assert_eq!(t.pps, 5.0); // (20-10)/2
    }

    #[test]
    fn throughput_clamps_counter_reset() {
        let a = parse_prometheus(
            "blackwall_flow_sampled_bytes_total 5000\nblackwall_flow_sampled_packets_total 50\n",
        );
        let b = parse_prometheus(
            "blackwall_flow_sampled_bytes_total 10\nblackwall_flow_sampled_packets_total 1\n",
        );
        let t = throughput(&a, &b, 1.0);
        assert_eq!(t.bps, 0.0);
        assert_eq!(t.pps, 0.0);
    }

    #[test]
    fn throughput_with_zero_dt_is_zero_not_infinite() {
        let a = parse_prometheus("blackwall_flow_sampled_bytes_total 0\n");
        let b = parse_prometheus("blackwall_flow_sampled_bytes_total 1000\n");
        let t = throughput(&a, &b, 0.0);
        assert_eq!(t.bps, 0.0);
        assert_eq!(t.pps, 0.0);
    }

    #[test]
    fn armed_reads_the_gauge() {
        assert!(armed(&parse_prometheus("blackwall_armed 1\n")));
        assert!(!armed(&parse_prometheus("blackwall_armed 0\n")));
        assert!(!armed(&parse_prometheus("")));
    }

    #[test]
    fn deception_sessions_reads_the_gauge() {
        assert_eq!(
            deception_sessions(&parse_prometheus("blackwall_deception_sessions_active 7\n")),
            7
        );
        assert_eq!(deception_sessions(&parse_prometheus("")), 0);
    }
}
