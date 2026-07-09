//! HTTP response bodies. Separate from the internal `*View` types so the wire
//! contract is decoupled from the daemon's data model.

use crate::state::{
    AuditView, DetectionView, FlowSpecView, IpAssignmentView, RtbhView, ServiceView, SessionView,
    TenantView, XdpView,
};
use serde::Serialize;
use std::net::IpAddr;
use utoipa::ToSchema;

/// A tenant and its owned addresses.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantDto {
    /// Unique tenant name.
    pub name: String,
    /// Addresses assigned to the tenant.
    #[schema(value_type = Vec<String>)]
    pub owned: Vec<IpAddr>,
}

impl From<TenantView> for TenantDto {
    fn from(v: TenantView) -> Self {
        Self {
            name: v.name,
            owned: v.owned,
        }
    }
}

/// A real service exposed by a tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceDto {
    /// Owning tenant.
    pub tenant: String,
    /// Frontend address.
    #[schema(value_type = String)]
    pub address: IpAddr,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Frontend port.
    pub port: u16,
    /// Rendered target.
    pub target: String,
}

impl From<ServiceView> for ServiceDto {
    fn from(v: ServiceView) -> Self {
        Self {
            tenant: v.tenant,
            address: v.address,
            proto: v.proto,
            port: v.port,
            target: v.target,
        }
    }
}

/// One tenant↔address assignment.
#[derive(Debug, Serialize, ToSchema)]
pub struct IpAssignmentDto {
    /// Owning tenant name.
    pub tenant: String,
    /// Assigned address.
    #[schema(value_type = String)]
    pub address: IpAddr,
}

impl From<IpAssignmentView> for IpAssignmentDto {
    fn from(v: IpAssignmentView) -> Self {
        Self {
            tenant: v.tenant,
            address: v.address,
        }
    }
}

/// An RTBH blackhole (announced mirror).
#[derive(Debug, Serialize, ToSchema)]
pub struct RtbhDto {
    /// Null-routed target.
    #[schema(value_type = String)]
    pub target: IpAddr,
    /// Who requested it.
    pub origin: String,
    /// Announce time (ms since epoch).
    pub announced_at_ms: u64,
    /// Withdraw time, if withdrawn.
    pub withdrawn_at_ms: Option<u64>,
}

impl From<RtbhView> for RtbhDto {
    fn from(v: RtbhView) -> Self {
        Self {
            target: v.target,
            origin: v.origin,
            announced_at_ms: v.announced_at_ms,
            withdrawn_at_ms: v.withdrawn_at_ms,
        }
    }
}

/// A FlowSpec rule (announced mirror).
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowSpecDto {
    /// Victim destination.
    #[schema(value_type = String)]
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

impl From<FlowSpecView> for FlowSpecDto {
    fn from(v: FlowSpecView) -> Self {
        Self {
            dst: v.dst,
            proto: v.proto,
            dst_port: v.dst_port,
            rate: v.rate,
            origin: v.origin,
            announced_at_ms: v.announced_at_ms,
            withdrawn_at_ms: v.withdrawn_at_ms,
        }
    }
}

/// An active XDP block / rate-limit entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct XdpDto {
    /// `"block"` or `"rate_limit"`.
    pub kind: String,
    /// Source or victim target.
    #[schema(value_type = String)]
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
    #[schema(value_type = Option<String>)]
    pub victim: Option<IpAddr>,
}

impl From<XdpView> for XdpDto {
    fn from(v: XdpView) -> Self {
        Self {
            kind: v.kind,
            target: v.target,
            prefixlen: v.prefixlen,
            rate_pps: v.rate_pps,
            burst: v.burst,
            origin: v.origin,
            victim: v.victim,
        }
    }
}

/// An active volumetric detection.
#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionDto {
    /// Detected target.
    #[schema(value_type = String)]
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

impl From<DetectionView> for DetectionDto {
    fn from(v: DetectionView) -> Self {
        Self {
            target: v.target,
            observed_pps: v.observed_pps,
            observed_bps: v.observed_bps,
            severity: v.severity,
            first_seen_ms: v.first_seen_ms,
            last_seen_ms: v.last_seen_ms,
        }
    }
}

/// A recorded deception session.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionDto {
    /// Local (honeypot) address.
    #[schema(value_type = String)]
    pub local_addr: IpAddr,
    /// Local port.
    pub local_port: u16,
    /// Peer (attacker) address.
    #[schema(value_type = String)]
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

impl From<SessionView> for SessionDto {
    fn from(v: SessionView) -> Self {
        Self {
            local_addr: v.local_addr,
            local_port: v.local_port,
            peer_addr: v.peer_addr,
            proto: v.proto,
            emulator: v.emulator,
            bytes_in: v.bytes_in,
            bytes_out: v.bytes_out,
            note: v.note,
        }
    }
}

/// One audit-log entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditDto {
    /// Event time (ms).
    pub at_ms: u64,
    /// Who acted (e.g. `"api:admin"`).
    pub actor: String,
    /// What happened (e.g. `"service.create"`).
    pub action: String,
    /// Structured detail.
    pub detail: serde_json::Value,
}

impl From<AuditView> for AuditDto {
    fn from(v: AuditView) -> Self {
        Self {
            at_ms: v.at_ms,
            actor: v.actor,
            action: v.action,
            detail: v.detail,
        }
    }
}
