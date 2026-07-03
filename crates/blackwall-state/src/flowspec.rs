//! Row types for FlowSpec auto-mitigation persistence: the announced-mirror
//! table and the append-only operator request queue.

use std::net::IpAddr;

/// One row of the `flowspec_rules` announced mirror.
///
/// Derives `PartialEq` but not `Eq` because `rate: f32` is not `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpecRuleRow {
    /// Victim host address (a `/32` or `/128` route is derived downstream).
    pub dst: IpAddr,
    /// IP protocol number (e.g. 17 = UDP).
    pub proto: u8,
    /// Destination port.
    pub dst_port: u16,
    /// Traffic-rate action in bytes/sec; `0.0` = drop.
    pub rate: f32,
    /// `"auto"` or `"manual"`.
    pub origin: String,
    /// Announce time in epoch milliseconds.
    pub announced_at_ms: u64,
    /// Withdraw time in epoch milliseconds, if withdrawn.
    pub withdrawn_at_ms: Option<u64>,
}

/// One row of the `flowspec_requests` append-only operator intent queue.
///
/// Derives `PartialEq` but not `Eq` because `rate: f32` is not `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpecRequestRow {
    /// Row id (used to scope supersession).
    pub id: i64,
    /// Victim host address.
    pub dst: IpAddr,
    /// IP protocol number.
    pub proto: u8,
    /// Destination port.
    pub dst_port: u16,
    /// Traffic-rate action in bytes/sec; `0.0` = drop.
    pub rate: f32,
    /// `"add"` or `"remove"`.
    pub action: String,
    /// Operator identity that queued the request.
    pub created_by: String,
    /// `"pending"` | `"applied"` | `"rejected"`.
    pub status: String,
    /// Optional free-text note (e.g. rejection reason).
    pub note: Option<String>,
}
