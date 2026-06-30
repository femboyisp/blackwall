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
}
