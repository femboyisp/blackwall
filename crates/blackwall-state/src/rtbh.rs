//! Row types for RTBH (remotely-triggered blackhole) persistence:
//! the announced-mirror table and the append-only operator request queue.

use std::net::IpAddr;

/// One row of the `rtbh_blackholes` announced mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtbhBlackholeRow {
    /// The blackholed target address.
    pub target: IpAddr,
    /// `"auto"` or `"manual"`.
    pub origin: String,
    /// Wall-clock milliseconds the blackhole was announced.
    pub announced_at_ms: u64,
    /// Wall-clock milliseconds the blackhole was withdrawn, if it has been.
    pub withdrawn_at_ms: Option<u64>,
}

/// One row of the `rtbh_requests` append-only operator intent queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtbhRequestRow {
    /// Monotonically increasing request id.
    pub id: i64,
    /// The target address the request applies to.
    pub target: IpAddr,
    /// `"add"` or `"remove"`.
    pub action: String,
    /// Attribution for the request (`$USER@host` or `--operator`).
    pub created_by: String,
    /// `"pending"`, `"applied"`, or `"rejected"`.
    pub status: String,
    /// Optional note (e.g. a rejection reason).
    pub note: Option<String>,
}
