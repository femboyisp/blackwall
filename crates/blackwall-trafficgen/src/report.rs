//! Aggregated send/receive reports + their JSON form (the lab gate reads these).

use crate::error::{Result, TrafficGenError};
use crate::flow::FlowClass;
use crate::pattern::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Packet + byte counts for one flow (or a total).
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct FlowCounts {
    /// Number of frames.
    pub packets: u64,
    /// Number of bytes.
    pub bytes: u64,
}

/// What `send` produced.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendReport {
    /// The configured pps target.
    pub target_pps: u64,
    /// Elapsed send time in milliseconds.
    pub elapsed_ms: u64,
    /// Total frames/bytes sent.
    pub sent: FlowCounts,
    /// Per-pattern breakdown, keyed by [`flow_key`].
    pub per_pattern: BTreeMap<String, FlowCounts>,
}

/// What `recv` measured.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecvReport {
    /// Elapsed receive time in milliseconds.
    pub elapsed_ms: u64,
    /// Total frames/bytes captured by the sink.
    pub total: FlowCounts,
    /// Independent kernel counter (`/proc/net/dev` rx_packets delta).
    pub kernel_rx_packets: u64,
    /// Per-flow breakdown, keyed by [`flow_key`].
    pub per_flow: BTreeMap<String, FlowCounts>,
}

/// What a `connect-flood` run observed. `served` = a banner was read; `dropped`
/// = the TCP connect succeeded but the engine closed with no banner (drop-at-cap);
/// `failed` = the TCP connect itself errored (refused/reset/backlog).
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct ConnectReport {
    /// Total connection attempts started.
    pub attempted: u64,
    /// Connections that received a banner (the engine served them).
    pub served: u64,
    /// Connections accepted then closed without a banner (the engine's drop-at-cap).
    pub dropped: u64,
    /// Connection attempts that errored before any data (refused/reset/backlog).
    pub failed: u64,
}

/// Map a [`Pattern`] to the same stable key its received frames classify to.
#[must_use]
pub fn flow_key_for_pattern(p: &Pattern) -> &'static str {
    match p {
        Pattern::UdpFlood => "udp-flood",
        Pattern::SynFlood { .. } => "syn-flood",
        Pattern::Reflection(_) => "reflection",
        Pattern::Malformed(_) => "malformed",
        Pattern::Benign => "benign",
    }
}

/// Stable string key for a flow class (used in both reports' maps).
#[must_use]
pub fn flow_key(c: FlowClass) -> &'static str {
    match c {
        FlowClass::UdpFlood => "udp-flood",
        FlowClass::SynFlood => "syn-flood",
        FlowClass::Reflection => "reflection",
        FlowClass::Benign => "benign",
        FlowClass::Malformed => "malformed",
        FlowClass::Unknown => "unknown",
    }
}

impl SendReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// [`TrafficGenError::Report`] on serialization failure.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| TrafficGenError::Report(e.to_string()))
    }
}

impl RecvReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// [`TrafficGenError::Report`] on serialization failure.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| TrafficGenError::Report(e.to_string()))
    }

    /// Parse from JSON.
    ///
    /// # Errors
    /// [`TrafficGenError::Report`] on parse failure.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| TrafficGenError::Report(e.to_string()))
    }
}

impl ConnectReport {
    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// [`TrafficGenError::Report`] on serialization failure.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| TrafficGenError::Report(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowClass;

    #[test]
    fn flow_keys_are_stable() {
        assert_eq!(flow_key(FlowClass::UdpFlood), "udp-flood");
        assert_eq!(flow_key(FlowClass::Malformed), "malformed");
        assert_eq!(flow_key(FlowClass::Unknown), "unknown");
    }

    #[test]
    fn recv_report_round_trips_json() {
        let mut per_flow = std::collections::BTreeMap::new();
        per_flow.insert(
            "benign".to_owned(),
            FlowCounts {
                packets: 100,
                bytes: 1600,
            },
        );
        let r = RecvReport {
            elapsed_ms: 8000,
            total: FlowCounts {
                packets: 100,
                bytes: 1600,
            },
            kernel_rx_packets: 100,
            per_flow,
        };
        let json = r.to_json().unwrap();
        let back = RecvReport::from_json(&json).unwrap();
        assert_eq!(back.total.packets, 100);
        assert_eq!(back.per_flow["benign"].bytes, 1600);
    }

    #[test]
    fn flow_key_for_pattern_matches_flow_key() {
        use crate::pattern::{MalformedKind, Pattern, ReflProto};
        // Every sendable pattern maps to the same key its received frames classify
        // to (so the send and recv reports use a shared vocabulary).
        assert_eq!(flow_key_for_pattern(&Pattern::UdpFlood), "udp-flood");
        assert_eq!(
            flow_key_for_pattern(&Pattern::SynFlood { spoof_src: true }),
            "syn-flood"
        );
        assert_eq!(
            flow_key_for_pattern(&Pattern::Reflection(ReflProto::Ntp)),
            "reflection"
        );
        assert_eq!(
            flow_key_for_pattern(&Pattern::Malformed(MalformedKind::TruncatedL4)),
            "malformed"
        );
        assert_eq!(flow_key_for_pattern(&Pattern::Benign), "benign");
    }

    #[test]
    fn send_report_serializes_to_json() {
        let mut per_pattern = BTreeMap::new();
        per_pattern.insert(
            "udp-flood".to_owned(),
            FlowCounts {
                packets: 250,
                bytes: 4000,
            },
        );
        let r = SendReport {
            target_pps: 77_000,
            elapsed_ms: 5000,
            sent: FlowCounts {
                packets: 250,
                bytes: 4000,
            },
            per_pattern,
        };
        let json = r.to_json().unwrap();
        assert!(json.contains("\"target_pps\""));
        assert!(json.contains("udp-flood"));
    }

    #[test]
    fn connect_report_serializes_to_json() {
        let r = ConnectReport {
            attempted: 900,
            served: 256,
            dropped: 600,
            failed: 44,
        };
        let json = r.to_json().unwrap();
        assert!(json.contains("\"served\""));
        assert!(json.contains("256"));
    }
}
