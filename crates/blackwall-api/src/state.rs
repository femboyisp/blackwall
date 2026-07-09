//! The `AppState` seam: what handlers need from the daemon, and the plain
//! data views they return. Phase 1 is read-only; Phase 2 adds mutation methods.

use crate::error::ApiResult;
use async_trait::async_trait;
use std::net::IpAddr;

/// A tenant and the addresses it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantView {
    /// Unique tenant name.
    pub name: String,
    /// Addresses assigned to the tenant.
    pub owned: Vec<IpAddr>,
}

/// A real service exposed by a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    /// Owning tenant name.
    pub tenant: String,
    /// Frontend address.
    pub address: IpAddr,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Frontend port.
    pub port: u16,
    /// Rendered target (e.g. `"host"` or `"nat:203.0.113.9:8080"`).
    pub target: String,
}

/// One tenant↔address assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAssignmentView {
    /// Owning tenant name.
    pub tenant: String,
    /// Assigned address.
    pub address: IpAddr,
}

/// An RTBH blackhole (announced mirror).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtbhView {
    /// Null-routed target.
    pub target: IpAddr,
    /// Who requested it.
    pub origin: String,
    /// Announce time (ms since epoch).
    pub announced_at_ms: u64,
    /// Withdraw time, if withdrawn.
    pub withdrawn_at_ms: Option<u64>,
}

/// A FlowSpec rule (announced mirror).
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpecView {
    /// Victim destination.
    pub dst: IpAddr,
    /// IP protocol number.
    pub proto: u8,
    /// Destination port.
    pub dst_port: u16,
    /// Rate-limit (bytes/s; 0 = drop).
    pub rate: f32,
    /// Who requested it.
    pub origin: String,
    /// Announce time (ms).
    pub announced_at_ms: u64,
    /// Withdraw time, if withdrawn.
    pub withdrawn_at_ms: Option<u64>,
}

/// An active XDP block / rate-limit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpView {
    /// `"block"` or `"rate_limit"`.
    pub kind: String,
    /// Source or victim target.
    pub target: IpAddr,
    /// LPM prefix length, if a prefix.
    pub prefixlen: Option<u8>,
    /// Rate limit (pps), if a rate-limit entry.
    pub rate_pps: Option<u64>,
    /// Token-bucket burst, if a rate-limit entry.
    pub burst: Option<u64>,
    /// Who requested it.
    pub origin: String,
    /// Victim address, if source-keyed to a victim.
    pub victim: Option<IpAddr>,
}

/// An active volumetric detection.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionView {
    /// Detected target.
    pub target: IpAddr,
    /// Observed packets/s.
    pub observed_pps: f64,
    /// Observed bits/s.
    pub observed_bps: f64,
    /// Severity label.
    pub severity: String,
    /// First-seen time (ms).
    pub first_seen_ms: u64,
    /// Last-seen time (ms).
    pub last_seen_ms: u64,
}

/// A recorded deception session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    /// Local (honeypot) address.
    pub local_addr: IpAddr,
    /// Local port.
    pub local_port: u16,
    /// Peer (attacker) address.
    pub peer_addr: IpAddr,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Emulator that handled it.
    pub emulator: String,
    /// Bytes received.
    pub bytes_in: i64,
    /// Bytes sent.
    pub bytes_out: i64,
    /// Captured detail (request line / attempted creds).
    pub note: Option<String>,
}

/// One audit-log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditView {
    /// Event time (ms).
    pub at_ms: u64,
    /// Who acted (e.g. `"api:admin"`).
    pub actor: String,
    /// What happened (e.g. `"service.create"`).
    pub action: String,
    /// Structured detail.
    pub detail: serde_json::Value,
}

/// Everything the read-only handlers need from the daemon. The concrete impl
/// lives in `blackwalld`; tests use an in-memory fake.
#[async_trait]
pub trait AppState: Send + Sync + 'static {
    /// All tenants.
    async fn tenants(&self) -> ApiResult<Vec<TenantView>>;
    /// All exposed services.
    async fn services(&self) -> ApiResult<Vec<ServiceView>>;
    /// All tenant↔address assignments.
    async fn ip_assignments(&self) -> ApiResult<Vec<IpAssignmentView>>;
    /// Active RTBH blackholes.
    async fn rtbh(&self) -> ApiResult<Vec<RtbhView>>;
    /// Active FlowSpec rules.
    async fn flowspec(&self) -> ApiResult<Vec<FlowSpecView>>;
    /// Active XDP entries.
    async fn xdp(&self) -> ApiResult<Vec<XdpView>>;
    /// Active detections.
    async fn detections(&self) -> ApiResult<Vec<DetectionView>>;
    /// Most-recent sessions, newest first, capped at `limit`.
    async fn sessions(&self, limit: i64) -> ApiResult<Vec<SessionView>>;
    /// Most-recent audit entries, newest first, capped at `limit`.
    async fn audit(&self, limit: i64) -> ApiResult<Vec<AuditView>>;
}
