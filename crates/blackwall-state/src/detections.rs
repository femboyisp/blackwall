//! Row types for flow-based attack detection persistence.

use std::net::IpAddr;

/// One currently-active (not yet cleared) detection row.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionRow {
    /// The attacked target address.
    pub target: IpAddr,
    /// Most recently observed packets/sec.
    pub observed_pps: f64,
    /// Most recently observed bits/sec.
    pub observed_bps: f64,
    /// `"warning"`, `"high"`, or `"critical"`.
    pub severity: String,
    /// Wall-clock milliseconds the detection was first opened.
    pub first_seen_ms: u64,
    /// Wall-clock milliseconds of the most recent observation.
    pub last_seen_ms: u64,
}
