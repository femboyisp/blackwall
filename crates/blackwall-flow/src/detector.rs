//! Threshold-based DDoS detector with attack lifecycle management.
//!
//! [`ThresholdDetector`] consumes [`FlowObservation`]s and emits
//! [`DetectionEvent`]s when traffic to a protected destination crosses
//! configured packet-per-second or bit-per-second thresholds.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::FlowObservation;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Category of attack detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackKind {
    /// High-volume flood (packets or bits).
    Volumetric,
}

/// Severity bucket derived from how far the observed rate exceeds the threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Rate is between 1× and 2× the threshold.
    Warning,
    /// Rate is between 2× and 10× the threshold.
    High,
    /// Rate is at or above 10× the threshold.
    Critical,
}

/// One POP's contribution to a detection within the window.
#[derive(Debug, Clone, PartialEq)]
pub struct PopContribution {
    /// POP name (or `"unknown"`).
    pub pop: String,
    /// Estimated packets/s this POP contributed.
    pub est_pps: f64,
    /// Estimated bits/s this POP contributed.
    pub est_bps: f64,
}

/// A snapshot of an active attack against a single destination.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    /// The destination address under attack.
    pub target: IpAddr,
    /// The category of attack.
    pub kind: AttackKind,
    /// Estimated packets per second arriving at `target`.
    pub observed_pps: f64,
    /// Estimated bits per second arriving at `target`.
    pub observed_bps: f64,
    /// Dominant IP protocol number (the protocol seen in the most samples).
    pub proto: u8,
    /// Top-3 source addresses by estimated PPS, descending.
    pub top_sources: Vec<(IpAddr, f64)>,
    /// Top-3 destination ports by estimated PPS, descending.
    pub top_ports: Vec<(u16, f64)>,
    /// Per-POP contribution to this detection, by contributed PPS descending.
    pub pops: Vec<PopContribution>,
    /// Top attacker source blocks (/24 v4, /48 v6) by estimated PPS, descending.
    pub top_source_blocks: Vec<(ipnet::IpNet, f64)>,
    /// Severity derived from `max(pps/threshold, bps/threshold)`.
    pub severity: Severity,
    /// Timestamp (ms since epoch) when this detection was first opened.
    pub first_seen_ms: u64,
    /// Timestamp (ms since epoch) of the last tick that saw traffic over threshold.
    pub last_seen_ms: u64,
}

/// An event produced by [`Detector::tick`].
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionEvent {
    /// A new attack has been detected.
    Opened(Detection),
    /// An existing attack is still ongoing.
    Updated(Detection),
    /// An attack has ended (held below threshold for the hold-down period).
    Cleared {
        /// The destination that is no longer under attack.
        target: IpAddr,
        /// Timestamp (ms since epoch) when the detection was cleared.
        at_ms: u64,
    },
}

/// Interface for flow-based detectors.
pub trait Detector {
    /// Record one sampled packet observation at time `now_ms`.
    fn observe(&mut self, obs: &FlowObservation, now_ms: u64);

    /// Advance time to `now_ms`, evict stale samples, and return any new events.
    fn tick(&mut self, now_ms: u64) -> Vec<DetectionEvent>;

    /// Per-agent telemetry for the metrics endpoint; default empty for
    /// detectors without a notion of registered agents.
    fn agent_stats(&self) -> Vec<AgentStat> {
        Vec::new()
    }

    /// Count of observations attributed to an agent absent from the POP
    /// registry; default zero for detectors without a notion of registered
    /// agents.
    fn unknown_agent_observations(&self) -> u64 {
        0
    }
}

/// Per-POP telemetry snapshot for the metrics endpoint: one entry per agent
/// known to the [`AgentRegistry`](crate::agents::AgentRegistry), refreshed
/// once per collector tick.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentStat {
    /// POP name for this agent, as configured in the registry.
    pub pop: String,
    /// Timestamp (ms since epoch) this agent was last observed.
    pub last_seen_ms: u64,
    /// Count of samples from this agent whose reported sampling rate was
    /// clamped because it deviated far from the agent's expected rate.
    pub mismatches: u64,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A single recorded sample from one [`FlowObservation`].
struct Sample {
    ts_ms: u64,
    src: IpAddr,
    dst_port: u16,
    proto: u8,
    est_packets: u64,
    est_bytes: u64,
    agent: IpAddr,
}

/// Per-destination state tracked by [`ThresholdDetector`].
struct DstState {
    samples: Vec<Sample>,
    /// Whether a detection is currently open for this destination.
    open: bool,
    /// The timestamp when the detection was first opened.
    first_seen_ms: u64,
    /// The last timestamp at which the destination was over threshold.
    last_over_ms: u64,
}

// ---------------------------------------------------------------------------
// ThresholdDetector
// ---------------------------------------------------------------------------

/// A stateful detector that emits events when per-destination traffic rates
/// cross configurable PPS or BPS thresholds.
pub struct ThresholdDetector {
    prefixes: Vec<IpNet>,
    pps_threshold: f64,
    bps_threshold: f64,
    window_ms: u64,
    hold_down_ms: u64,
    state: HashMap<IpAddr, DstState>,
    agents: crate::agents::AgentRegistry,
    agent_last_seen: HashMap<IpAddr, u64>,
    sampling_mismatches: HashMap<IpAddr, u64>,
    unknown_agent_observations: u64,
}

impl ThresholdDetector {
    /// Create a new detector.
    ///
    /// # Parameters
    ///
    /// - `prefixes` — only destinations within these prefixes are monitored.
    /// - `pps_threshold` — packets per second above which an attack is declared.
    /// - `bps_threshold` — bits per second above which an attack is declared.
    /// - `window_ms` — sliding window size in milliseconds for rate computation.
    /// - `hold_down_ms` — milliseconds below threshold before a detection is cleared.
    /// - `agents` — registry of known sFlow agents and their expected sampling
    ///   rates, used for liveness tracking and the sampling-sanity clamp.
    pub fn new(
        prefixes: Vec<IpNet>,
        pps_threshold: f64,
        bps_threshold: f64,
        window_ms: u64,
        hold_down_ms: u64,
        agents: crate::agents::AgentRegistry,
    ) -> Self {
        Self {
            prefixes,
            pps_threshold,
            bps_threshold,
            window_ms,
            hold_down_ms,
            state: HashMap::new(),
            agents,
            agent_last_seen: HashMap::new(),
            sampling_mismatches: HashMap::new(),
            unknown_agent_observations: 0,
        }
    }

    /// Last-seen timestamp (ms) per agent, for liveness monitoring.
    pub fn agent_last_seen(&self) -> &HashMap<IpAddr, u64> {
        &self.agent_last_seen
    }

    /// Count of samples per agent whose reported sampling rate was clamped
    /// because it deviated far from the agent's configured expected rate.
    pub fn sampling_mismatches(&self) -> &HashMap<IpAddr, u64> {
        &self.sampling_mismatches
    }
}

impl Detector for ThresholdDetector {
    fn observe(&mut self, obs: &FlowObservation, now_ms: u64) {
        // Liveness + sampling sanity are tracked ONLY for agents known to the
        // registry. The sFlow agent address is attacker-controlled, unauthenticated
        // application-layer data; keying the liveness/mismatch maps on arbitrary
        // (possibly spoofed) addresses would let a UDP sender grow them without
        // bound (memory DoS). Restricting to configured POPs bounds both maps to
        // the number of known agents, and an unknown agent's "liveness" is
        // meaningless anyway. Unknown agents are trusted as-is for the volume math.
        let effective_rate = match self.agents.expected_sampling(obs.agent) {
            Some(expected) => {
                self.agent_last_seen.insert(obs.agent, now_ms);

                // Clamp an agent whose reported rate deviates far from its
                // configured expected rate (guards the volume math + collector
                // against a misconfigured POP), and count the mismatch.
                let lo = expected / 4;
                let hi = expected.saturating_mul(4);
                if obs.sampling_rate < lo || obs.sampling_rate > hi {
                    *self.sampling_mismatches.entry(obs.agent).or_insert(0) += 1;
                    expected
                } else {
                    obs.sampling_rate
                }
            }
            None => {
                self.unknown_agent_observations = self.unknown_agent_observations.saturating_add(1);
                obs.sampling_rate
            }
        };

        if !self.prefixes.iter().any(|p| p.contains(&obs.dst)) {
            return;
        }

        let est_packets = u64::from(effective_rate);
        let est_bytes = u64::from(effective_rate) * u64::from(obs.frame_len);

        let entry = self.state.entry(obs.dst).or_insert_with(|| DstState {
            samples: Vec::new(),
            open: false,
            first_seen_ms: 0,
            last_over_ms: 0,
        });

        entry.samples.push(Sample {
            ts_ms: now_ms,
            src: obs.src,
            dst_port: obs.dst_port,
            proto: obs.proto,
            est_packets,
            est_bytes,
            agent: obs.agent,
        });
    }

    fn tick(&mut self, now_ms: u64) -> Vec<DetectionEvent> {
        let window_ms = self.window_ms;
        let pps_threshold = self.pps_threshold;
        let bps_threshold = self.bps_threshold;
        let hold_down_ms = self.hold_down_ms;

        #[expect(
            clippy::cast_precision_loss,
            reason = "window_ms to f64 divisor; ms-scale precision loss acceptable"
        )]
        let window_secs = window_ms.max(1) as f64 / 1000.0;

        let mut events = Vec::new();
        let mut to_remove = Vec::new();

        for (dst, state) in &mut self.state {
            // Evict samples outside the window.
            state.samples.retain(|s| s.ts_ms + window_ms > now_ms);

            if state.samples.is_empty() {
                // No samples; check if we need to clear an open detection.
                if state.open && now_ms.saturating_sub(state.last_over_ms) >= hold_down_ms {
                    events.push(DetectionEvent::Cleared {
                        target: *dst,
                        at_ms: now_ms,
                    });
                    to_remove.push(*dst);
                }
                continue;
            }

            // Aggregate totals.
            // Use u128 with saturating addition: est_bytes per sample can be up to
            // u32::MAX * u32::MAX ≈ u64::MAX, so summing many samples overflows u64.
            // Widening to u128 (saturating) prevents overflow/panic on attacker-influenced input.
            let total_packets: u128 = state.samples.iter().fold(0u128, |acc, s| {
                acc.saturating_add(u128::from(s.est_packets))
            });
            let total_bytes: u128 = state
                .samples
                .iter()
                .fold(0u128, |acc, s| acc.saturating_add(u128::from(s.est_bytes)));

            #[expect(
                clippy::cast_precision_loss,
                reason = "u128 packet/byte sums to f64; precision loss acceptable for rate estimates"
            )]
            let pps = total_packets as f64 / window_secs;
            #[expect(
                clippy::cast_precision_loss,
                reason = "u128 byte sums to f64; precision loss acceptable for rate estimates"
            )]
            let bps = (total_bytes as f64) * 8.0 / window_secs;

            let over_threshold = pps > pps_threshold || bps > bps_threshold;

            if over_threshold {
                state.last_over_ms = now_ms;

                if state.open {
                    let detection = build_detection(DetectionParams {
                        target: *dst,
                        pps,
                        bps,
                        pps_threshold,
                        bps_threshold,
                        samples: &state.samples,
                        window_secs,
                        first_seen_ms: state.first_seen_ms,
                        last_seen_ms: now_ms,
                        agents: &self.agents,
                    });
                    events.push(DetectionEvent::Updated(detection));
                } else {
                    state.open = true;
                    state.first_seen_ms = now_ms;
                    let detection = build_detection(DetectionParams {
                        target: *dst,
                        pps,
                        bps,
                        pps_threshold,
                        bps_threshold,
                        samples: &state.samples,
                        window_secs,
                        first_seen_ms: now_ms,
                        last_seen_ms: now_ms,
                        agents: &self.agents,
                    });
                    events.push(DetectionEvent::Opened(detection));
                }
            } else if state.open {
                // Under threshold — check hold-down.
                if now_ms.saturating_sub(state.last_over_ms) >= hold_down_ms {
                    events.push(DetectionEvent::Cleared {
                        target: *dst,
                        at_ms: now_ms,
                    });
                    to_remove.push(*dst);
                }
            }
        }

        for dst in to_remove {
            self.state.remove(&dst);
        }

        events
    }

    fn agent_stats(&self) -> Vec<AgentStat> {
        self.agent_last_seen
            .iter()
            .map(|(&addr, &last_seen_ms)| AgentStat {
                pop: self.agents.name(addr).to_owned(),
                last_seen_ms,
                mismatches: self.sampling_mismatches.get(&addr).copied().unwrap_or(0),
            })
            .collect()
    }

    fn unknown_agent_observations(&self) -> u64 {
        self.unknown_agent_observations
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Parameters for building a [`Detection`].
struct DetectionParams<'a> {
    target: IpAddr,
    pps: f64,
    bps: f64,
    pps_threshold: f64,
    bps_threshold: f64,
    samples: &'a [Sample],
    window_secs: f64,
    first_seen_ms: u64,
    last_seen_ms: u64,
    agents: &'a crate::agents::AgentRegistry,
}

/// Build a [`Detection`] from the current window of samples.
fn build_detection(p: DetectionParams<'_>) -> Detection {
    // Dominant protocol: the one with the most estimated packets.
    // Use u128 with saturating addition to avoid overflow with attacker-influenced values.
    let mut proto_counts: HashMap<u8, u128> = HashMap::new();
    for s in p.samples {
        let entry = proto_counts.entry(s.proto).or_insert(0u128);
        *entry = entry.saturating_add(u128::from(s.est_packets));
    }
    let proto = proto_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(proto, _)| proto)
        .unwrap_or(0);

    // Top-3 sources by summed est_packets.
    // Use u128 with saturating addition to match the widened window totals and avoid overflow.
    let mut src_map: HashMap<IpAddr, u128> = HashMap::new();
    for s in p.samples {
        let entry = src_map.entry(s.src).or_insert(0u128);
        *entry = entry.saturating_add(u128::from(s.est_packets));
    }
    let mut src_vec: Vec<(IpAddr, u128)> = src_map.into_iter().collect();
    src_vec.sort_by_key(|e| std::cmp::Reverse(e.1));
    let top_sources: Vec<(IpAddr, f64)> = src_vec
        .into_iter()
        .take(3)
        .map(|(addr, pkts)| {
            #[expect(
                clippy::cast_precision_loss,
                reason = "u128 packet sum to f64 for pps display; precision loss acceptable"
            )]
            let src_pps = pkts as f64 / p.window_secs;
            (addr, src_pps)
        })
        .collect();

    // Top-3 ports by summed est_packets.
    // Use u128 with saturating addition to match the widened window totals and avoid overflow.
    let mut port_map: HashMap<u16, u128> = HashMap::new();
    for s in p.samples {
        let entry = port_map.entry(s.dst_port).or_insert(0u128);
        *entry = entry.saturating_add(u128::from(s.est_packets));
    }
    let mut port_vec: Vec<(u16, u128)> = port_map.into_iter().collect();
    port_vec.sort_by_key(|e| std::cmp::Reverse(e.1));
    let top_ports: Vec<(u16, f64)> = port_vec
        .into_iter()
        .take(3)
        .map(|(port, pkts)| {
            #[expect(
                clippy::cast_precision_loss,
                reason = "u128 packet sum to f64 for pps display; precision loss acceptable"
            )]
            let port_pps = pkts as f64 / p.window_secs;
            (port, port_pps)
        })
        .collect();

    // Per-POP contribution: sum est per agent, name via the registry.
    let mut pop_pkts: HashMap<IpAddr, (u128, u128)> = HashMap::new();
    for s in p.samples {
        let e = pop_pkts.entry(s.agent).or_insert((0, 0));
        e.0 = e.0.saturating_add(u128::from(s.est_packets));
        e.1 = e.1.saturating_add(u128::from(s.est_bytes));
    }
    let mut pops: Vec<PopContribution> = pop_pkts
        .into_iter()
        .map(|(agent, (pkts, bytes))| {
            #[expect(clippy::cast_precision_loss, reason = "u128 sums to f64 rate estimate")]
            let est_pps = pkts as f64 / p.window_secs;
            #[expect(clippy::cast_precision_loss, reason = "u128 sums to f64 rate estimate")]
            let est_bps = (bytes as f64) * 8.0 / p.window_secs;
            PopContribution {
                pop: p.agents.name(agent).to_owned(),
                est_pps,
                est_bps,
            }
        })
        .collect();
    pops.sort_by(|a, b| {
        b.est_pps
            .partial_cmp(&a.est_pps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Source-block rollup: /24 for v4, /48 for v6.
    let mut block_pkts: HashMap<ipnet::IpNet, u128> = HashMap::new();
    for s in p.samples {
        let block = source_block(s.src);
        let entry = block_pkts.entry(block).or_insert(0u128);
        *entry = entry.saturating_add(u128::from(s.est_packets));
    }
    let mut top_source_blocks: Vec<(ipnet::IpNet, f64)> = block_pkts
        .into_iter()
        .map(|(net, pkts)| {
            #[expect(clippy::cast_precision_loss, reason = "u128 sum to f64 rate estimate")]
            let pps = pkts as f64 / p.window_secs;
            (net, pps)
        })
        .collect();
    top_source_blocks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    top_source_blocks.truncate(5);

    // Severity.
    let r = f64::max(p.pps / p.pps_threshold, p.bps / p.bps_threshold);
    let severity = if r >= 10.0 {
        Severity::Critical
    } else if r >= 2.0 {
        Severity::High
    } else {
        Severity::Warning
    };

    Detection {
        target: p.target,
        kind: AttackKind::Volumetric,
        observed_pps: p.pps,
        observed_bps: p.bps,
        proto,
        top_sources,
        top_ports,
        pops,
        top_source_blocks,
        severity,
        first_seen_ms: p.first_seen_ms,
        last_seen_ms: p.last_seen_ms,
    }
}

/// The attacker source block for attribution: /24 for IPv4, /48 for IPv6.
fn source_block(src: IpAddr) -> ipnet::IpNet {
    match src {
        IpAddr::V4(v4) => ipnet::Ipv4Net::new(v4, 24)
            .map(|n| ipnet::IpNet::V4(n.trunc()))
            .unwrap_or_else(|_| ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap())),
        IpAddr::V6(v6) => ipnet::Ipv6Net::new(v6, 48)
            .map(|n| ipnet::IpNet::V6(n.trunc()))
            .unwrap_or_else(|_| ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::AgentRegistry;
    use blackwall_core::PopEntry;
    use std::net::{IpAddr, Ipv4Addr};

    fn obs(dst: [u8; 4], src: [u8; 4], rate: u32, len: u32) -> FlowObservation {
        FlowObservation {
            src: IpAddr::V4(Ipv4Addr::from(src)),
            dst: IpAddr::V4(Ipv4Addr::from(dst)),
            proto: 17,
            src_port: 9,
            dst_port: 53,
            frame_len: len,
            sampling_rate: rate,
            tcp_flags: 0,
            agent: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        }
    }

    /// Build a `FlowObservation` destined to a host in `203.0.113.0/24`, for the
    /// monotonic-clock windowing regression test below. `ms` is accepted (and
    /// named into the call site) purely for readability, pairing with the
    /// `now_ms` argument passed separately to `observe`/`tick` — `FlowObservation`
    /// itself carries no timestamp field.
    fn obs_at(_ms: u64) -> FlowObservation {
        obs([203, 0, 113, 7], [198, 51, 100, 9], 1, 100)
    }

    fn agent_ip(o: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 222, 0, o))
    }

    /// Test helper for agent-aware observations (distinct from `obs` above,
    /// which predates agent-awareness and is kept for the existing tests).
    fn agent_obs(
        agent: std::net::IpAddr,
        src: &str,
        dst: &str,
        rate: u32,
        frame: u32,
    ) -> FlowObservation {
        FlowObservation {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            proto: 17,
            src_port: 1234,
            dst_port: 53,
            frame_len: frame,
            sampling_rate: rate,
            tcp_flags: 0,
            agent,
        }
    }

    fn detector() -> ThresholdDetector {
        // prefix 203.0.113.0/24; pps threshold 100k; bps very high; window 1s; hold-down 2s
        ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            100_000.0,
            1e15,
            1000,
            2000,
            AgentRegistry::default(),
        )
    }

    #[test]
    fn opens_when_pps_over_threshold_within_prefix() {
        let mut d = detector();
        // 200 samples * rate 1024 = 204800 est packets in a 1s window -> 204800 pps > 100k
        for _ in 0..200 {
            d.observe(&obs([203, 0, 113, 7], [198, 51, 100, 9], 1024, 100), 0);
        }
        let events = d.tick(0);
        assert_eq!(events.len(), 1);
        match &events[0] {
            DetectionEvent::Opened(det) => {
                assert_eq!(det.target, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
                assert!(det.observed_pps > 100_000.0);
                assert_eq!(
                    det.top_sources[0].0,
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
                );
            }
            other => panic!("expected Opened, got {other:?}"),
        }
    }

    #[test]
    fn ignores_destination_outside_prefixes() {
        let mut d = detector();
        for _ in 0..500 {
            d.observe(&obs([8, 8, 8, 8], [198, 51, 100, 9], 4096, 100), 0); // not in 203.0.113.0/24
        }
        assert!(d.tick(0).is_empty());
    }

    #[test]
    fn clears_after_hold_down() {
        let mut d = detector();
        for _ in 0..200 {
            d.observe(&obs([203, 0, 113, 7], [198, 51, 100, 9], 1024, 100), 0);
        }
        assert!(matches!(d.tick(0)[0], DetectionEvent::Opened(_)));
        // no new traffic; window empties. tick within hold-down -> nothing yet.
        assert!(d.tick(1500).is_empty());
        // past hold-down (last_over=0, now=2000 >= 2000) -> Cleared
        let ev = d.tick(2000);
        assert!(matches!(ev.as_slice(), [DetectionEvent::Cleared { .. }]));
    }

    #[test]
    fn emits_updated_on_subsequent_ticks_over_threshold() {
        let mut d = detector();
        for _ in 0..200 {
            d.observe(&obs([203, 0, 113, 1], [10, 0, 0, 1], 1024, 100), 0);
        }
        assert!(matches!(d.tick(0)[0], DetectionEvent::Opened(_)));

        // Add more traffic still in the window at t=100ms.
        for _ in 0..200 {
            d.observe(&obs([203, 0, 113, 1], [10, 0, 0, 1], 1024, 100), 100);
        }
        let ev = d.tick(100);
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], DetectionEvent::Updated(_)));
    }

    #[test]
    fn severity_warning_just_over_threshold() {
        let mut d = detector();
        // 110 samples * 1024 = 112640 pps; ratio ≈ 1.13 → Warning
        for _ in 0..110 {
            d.observe(&obs([203, 0, 113, 2], [10, 0, 0, 2], 1024, 100), 0);
        }
        let ev = d.tick(0);
        if let DetectionEvent::Opened(det) = &ev[0] {
            assert_eq!(det.severity, Severity::Warning);
        } else {
            panic!("expected Opened");
        }
    }

    #[test]
    fn severity_high_at_2x_threshold() {
        let mut d = detector();
        // 200 samples * 1024 = 204800 pps; ratio ≈ 2.05 → High
        for _ in 0..200 {
            d.observe(&obs([203, 0, 113, 3], [10, 0, 0, 3], 1024, 100), 0);
        }
        let ev = d.tick(0);
        if let DetectionEvent::Opened(det) = &ev[0] {
            assert_eq!(det.severity, Severity::High);
        } else {
            panic!("expected Opened");
        }
    }

    #[test]
    fn severity_critical_at_10x_threshold() {
        let mut d = detector();
        // 1000 samples * 1024 = 1024000 pps; ratio ≈ 10.24 → Critical
        for _ in 0..1000 {
            d.observe(&obs([203, 0, 113, 4], [10, 0, 0, 4], 1024, 100), 0);
        }
        let ev = d.tick(0);
        if let DetectionEvent::Opened(det) = &ev[0] {
            assert_eq!(det.severity, Severity::Critical);
        } else {
            panic!("expected Opened");
        }
    }

    #[test]
    fn window_eviction_removes_old_samples() {
        let mut d = detector();
        // Observe at t=0, window is 1000ms.
        for _ in 0..200 {
            d.observe(&obs([203, 0, 113, 5], [10, 0, 0, 5], 1024, 100), 0);
        }
        assert!(matches!(d.tick(0)[0], DetectionEvent::Opened(_)));

        // At t=1001 the samples at t=0 are outside the window (0 + 1000 > 1001 is false).
        // No new traffic added. Hold-down is 2s; last_over=0; 1001 < 2000 → no clear yet.
        assert!(d.tick(1001).is_empty());

        // At t=2000 hold-down expires → Cleared.
        let ev = d.tick(2000);
        assert!(matches!(ev.as_slice(), [DetectionEvent::Cleared { .. }]));
    }

    #[test]
    fn top_sources_limited_to_three() {
        let mut d = detector();
        // 4 different sources, 50 samples each * 1024 = 51200 pps each; total 204800 pps.
        for i in 0u8..4 {
            for _ in 0..50 {
                d.observe(&obs([203, 0, 113, 6], [10, 0, 0, i + 1], 1024, 100), 0);
            }
        }
        let ev = d.tick(0);
        if let DetectionEvent::Opened(det) = &ev[0] {
            assert!(det.top_sources.len() <= 3);
        } else {
            panic!("expected Opened");
        }
    }

    #[test]
    fn window_zero_does_not_produce_inf_rates() {
        // window_ms = 0 must be clamped to 1 ms, not produce inf rates.
        let mut d = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1e15, // impossibly high pps threshold
            1e15, // impossibly high bps threshold
            0,    // zero window — the fix clamps this to 1ms
            2000,
            AgentRegistry::default(),
        );
        // A modest number of samples that should not cross 1e15 threshold.
        for _ in 0..10 {
            d.observe(&obs([203, 0, 113, 9], [10, 0, 0, 1], 1, 100), 0);
        }
        let events = d.tick(0);
        // No detection should be opened (rates must be finite and below threshold).
        assert!(
            events.is_empty(),
            "expected no detection with zero window_ms; got {events:?}"
        );
    }

    #[test]
    fn bps_threshold_triggers_detection() {
        // Set very high pps threshold but low bps threshold.
        let mut d = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1e12,   // pps impossibly high
            1000.0, // bps very low
            1000,
            2000,
            AgentRegistry::default(),
        );
        // 1 sample * rate=1 * frame_len=200 → est_bytes=200 → bps = 200*8/1 = 1600 > 1000
        d.observe(&obs([203, 0, 113, 8], [10, 0, 0, 1], 1, 200), 0);
        let ev = d.tick(0);
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], DetectionEvent::Opened(_)));
    }

    #[test]
    fn wide_sums_do_not_overflow() {
        // Each sample: est_packets = u32::MAX ≈ 4.3e9, est_bytes = u32::MAX * u32::MAX ≈ 1.8e19.
        // 64 such samples would overflow u64 for both est_packets and est_bytes.
        // With u128 saturating sums this must NOT panic and must produce a finite, very large rate.
        let mut d = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0, // very low pps threshold so a detection opens
            1.0, // very low bps threshold
            1000,
            2000,
            AgentRegistry::default(),
        );
        let max_rate = u32::MAX;
        let max_len = u32::MAX;
        for _ in 0..64 {
            d.observe(&obs([203, 0, 113, 10], [10, 0, 0, 1], max_rate, max_len), 0);
        }
        // Must not panic (in debug builds u64 overflow would panic).
        let ev = d.tick(0);
        // A detection must have been opened (rates are astronomically above threshold).
        assert_eq!(ev.len(), 1, "expected exactly one Opened event; got {ev:?}");
        match &ev[0] {
            DetectionEvent::Opened(det) => {
                assert!(
                    det.observed_bps.is_finite(),
                    "observed_bps must be finite, got {}",
                    det.observed_bps
                );
                assert!(
                    det.observed_pps.is_finite(),
                    "observed_pps must be finite, got {}",
                    det.observed_pps
                );
                assert!(det.observed_bps > 1.0, "expected very large bps");
            }
            other => panic!("expected Opened, got {other:?}"),
        }
    }

    #[test]
    fn clamps_rogue_agent_sampling_to_expected() {
        // A rogue agent reporting 1-in-1 (expected 1-in-1000) must be clamped to
        // 1000, so its observed volume equals what a correctly-configured agent
        // reporting 1-in-1000 would produce — NOT the ~1000x-inflated rogue value.
        // Assert equality against a control detector fed the honest rate.
        let window_ms = 1_000; // 1s window so bps math is a clean divisor.
        let mk = || {
            ThresholdDetector::new(
                vec!["203.0.113.0/24".parse().unwrap()],
                1.0,
                1.0,
                window_ms,
                30_000,
                AgentRegistry::from_entries(&[PopEntry {
                    name: "ord".into(),
                    agent: agent_ip(8),
                    sampling: 1000,
                }]),
            )
        };
        // Rogue: claims sampling_rate=1; honest control: claims 1000.
        let mut rogue = mk();
        rogue.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1, 100),
            500,
        );
        let rogue_d = rogue
            .tick(1_000)
            .into_iter()
            .find_map(|e| match e {
                DetectionEvent::Opened(d) => Some(d),
                _ => None,
            })
            .expect("rogue opened");

        let mut honest = mk();
        honest.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1000, 100),
            500,
        );
        let honest_d = honest
            .tick(1_000)
            .into_iter()
            .find_map(|e| match e {
                DetectionEvent::Opened(d) => Some(d),
                _ => None,
            })
            .expect("honest opened");

        // Clamp makes the rogue volume identical to the honest-rate volume.
        assert_eq!(rogue_d.observed_bps, honest_d.observed_bps);
        assert_eq!(rogue_d.observed_pps, honest_d.observed_pps);
    }

    #[test]
    fn tracks_agent_last_seen() {
        let reg = AgentRegistry::from_entries(&[PopEntry {
            name: "ord".into(),
            agent: agent_ip(8),
            sampling: 1000,
        }]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );
        det.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1000, 100),
            5_000,
        );
        assert_eq!(det.agent_last_seen().get(&agent_ip(8)), Some(&5_000));
    }

    #[test]
    fn unknown_agent_not_tracked() {
        // Only agent_ip(8) is registered. An observation from an unregistered
        // (possibly spoofed) agent must NOT grow the liveness or mismatch maps —
        // otherwise an unauthenticated UDP sender could exhaust memory.
        let reg = AgentRegistry::from_entries(&[PopEntry {
            name: "ord".into(),
            agent: agent_ip(8),
            sampling: 1000,
        }]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );

        // Unknown agent with a wildly-off rate: still untracked and trusted as-is.
        det.observe(
            &agent_obs(agent_ip(200), "198.51.100.5", "203.0.113.9", 1, 100),
            5_000,
        );

        assert_eq!(det.agent_last_seen().get(&agent_ip(200)), None);
        assert!(det.agent_last_seen().is_empty());
        assert_eq!(det.sampling_mismatches().get(&agent_ip(200)), None);
        assert!(det.sampling_mismatches().is_empty());
    }

    #[test]
    fn counts_sampling_mismatch() {
        let reg = AgentRegistry::from_entries(&[
            PopEntry {
                name: "ord".into(),
                agent: agent_ip(8),
                sampling: 1000,
            },
            PopEntry {
                name: "iad".into(),
                agent: agent_ip(9),
                sampling: 1000,
            },
        ]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );

        // Rogue agent: reports rate=1, wildly outside [250, 4000] band for expected 1000.
        det.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1, 100),
            1_000,
        );
        // Honest agent: reports the expected rate.
        det.observe(
            &agent_obs(agent_ip(9), "198.51.100.6", "203.0.113.9", 1000, 100),
            1_000,
        );

        assert_eq!(det.sampling_mismatches().get(&agent_ip(8)), Some(&1));
        assert_eq!(det.sampling_mismatches().get(&agent_ip(9)), None);
    }

    #[test]
    fn agent_stats_reports_known_agent_last_seen_and_mismatches() {
        let reg = AgentRegistry::from_entries(&[PopEntry {
            name: "ord".into(),
            agent: agent_ip(8),
            sampling: 1000,
        }]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );
        // Rogue rate (1) vs expected 1000 -> clamped, one mismatch recorded.
        det.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1, 100),
            5_000,
        );

        let stats = det.agent_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].pop, "ord");
        assert_eq!(stats[0].last_seen_ms, 5_000);
        assert_eq!(stats[0].mismatches, 1);
    }

    #[test]
    fn agent_stats_excludes_unknown_agents() {
        let reg = AgentRegistry::from_entries(&[PopEntry {
            name: "ord".into(),
            agent: agent_ip(8),
            sampling: 1000,
        }]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );
        det.observe(
            &agent_obs(agent_ip(200), "198.51.100.5", "203.0.113.9", 1, 100),
            5_000,
        );
        assert!(det.agent_stats().is_empty());
    }

    #[test]
    fn unknown_agent_observations_counts_only_unregistered_agents() {
        let reg = AgentRegistry::from_entries(&[PopEntry {
            name: "ord".into(),
            agent: agent_ip(8),
            sampling: 1000,
        }]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );
        assert_eq!(det.unknown_agent_observations(), 0);

        // Known agent: does not count.
        det.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1000, 100),
            1_000,
        );
        assert_eq!(det.unknown_agent_observations(), 0);

        // Unknown agent: counts, twice.
        det.observe(
            &agent_obs(agent_ip(200), "198.51.100.6", "203.0.113.9", 1, 100),
            1_000,
        );
        det.observe(
            &agent_obs(agent_ip(201), "198.51.100.7", "203.0.113.9", 1, 100),
            1_000,
        );
        assert_eq!(det.unknown_agent_observations(), 2);
    }

    #[test]
    fn detection_tags_contributing_pops_and_source_blocks() {
        let reg = AgentRegistry::from_entries(&[
            blackwall_core::PopEntry {
                name: "ord".into(),
                agent: agent_ip(8),
                sampling: 1,
            },
            blackwall_core::PopEntry {
                name: "fra".into(),
                agent: agent_ip(9),
                sampling: 1,
            },
        ]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0,
            1.0,
            10_000,
            30_000,
            reg,
        );
        // Two POPs each see traffic to the same victim from the same /24.
        det.observe(
            &agent_obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1, 100),
            1_000,
        );
        det.observe(
            &agent_obs(agent_ip(9), "198.51.100.6", "203.0.113.9", 1, 100),
            1_000,
        );
        let ev = det.tick(1_000);
        let d = ev
            .iter()
            .find_map(|e| match e {
                DetectionEvent::Opened(d) => Some(d),
                _ => None,
            })
            .expect("opened");
        let names: Vec<&str> = d.pops.iter().map(|p| p.pop.as_str()).collect();
        assert!(names.contains(&"ord") && names.contains(&"fra"));
        // Both sources are in 198.51.100.0/24 → one rolled-up block.
        assert_eq!(
            d.top_source_blocks[0].0,
            "198.51.100.0/24".parse::<ipnet::IpNet>().unwrap()
        );
    }

    #[test]
    fn detection_windowing_is_monotonic_not_wall_clock() {
        // Two ticks 5s apart on a MONOTONIC scale must evict correctly even if the
        // caller's wall clock jumped backward between them. The detector only sees the
        // ms values it is handed; this documents that the collector must hand it a
        // monotonic source (regression guard for the collector wiring).
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            100.0,
            1_000_000_000.0,
            10_000,
            30_000,
            crate::agents::AgentRegistry::from_entries(&[]),
        );
        // sample at t=1000 (monotonic), window 10s
        det.observe(&obs_at(1_000), 1_000); // helper builds a FlowObservation for 203.0.113.7
                                            // a wall-clock backstep would make a naive now() < 1000; monotonic keeps rising:
        let events = det.tick(2_000); // still within window; no spurious clear
        assert!(events
            .iter()
            .all(|e| !matches!(e, DetectionEvent::Cleared { .. })));
    }
}
