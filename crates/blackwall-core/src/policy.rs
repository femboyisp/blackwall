//! The desired-state policy model: tenants, the addresses they own, and the
//! ports they expose as real services. Everything not listed is deception.

use crate::{L4Proto, PortState, ServiceTarget};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// One "expose this port as a real service" rule within a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowRule {
    /// Transport protocol.
    pub proto: L4Proto,
    /// Port number.
    pub port: u16,
    /// Where matching traffic is forwarded.
    pub target: ServiceTarget,
    /// Optional per-address scope. `None` opens the port on **all** of the
    /// tenant's owned addresses (config-file `allow` semantics). `Some(addr)`
    /// opens it only on `addr` — used by discovery so a service observed on one
    /// address does not open that port on the tenant's other addresses.
    pub scope: Option<IpAddr>,
}

/// A customer who owns one or more addresses and may expose ports on them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant name.
    pub name: String,
    /// Addresses assigned to this tenant. Allow rules apply to all of them.
    pub owned: Vec<IpAddr>,
    /// Ports this tenant exposes as real services.
    pub allows: Vec<AllowRule>,
}

/// The complete desired firewall policy parsed from config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// The uplink interface Blackwall manages (e.g. `eth0`).
    pub interface: String,
    /// The IPv4/IPv6 prefixes Blackwall is authoritative for.
    pub prefixes: Vec<IpNet>,
    /// The state applied to any port not matched by an allow rule.
    pub default_state: PortState,
    /// Tenants and their exposed services.
    pub tenants: Vec<Tenant>,
    /// Traffic-shaping rules (empty if the config defines none).
    pub shaping: Vec<crate::ShapeRule>,
    /// Banner fast-flux config (rotate the deception persona over time); `None` disables it.
    pub banner_flux: Option<crate::BannerFluxConfig>,
    /// DNS fast-flux config (rotate a name's records over time); `None` disables it.
    pub dns_flux: Option<crate::DnsFluxConfig>,
    /// RTBH control-plane config (`rtbh` directive); `None` disables RTBH.
    pub rtbh: Option<crate::RtbhPolicy>,
    /// FlowSpec auto-mitigation policy; `None` disables FlowSpec (RTBH-only).
    pub flowspec: Option<crate::FlowSpecPolicy>,
    /// Address the Prometheus metrics endpoint listens on (`metrics listen=`); `None` disables it.
    pub metrics_listen: Option<std::net::SocketAddr>,
    /// Deception-engine wiring (concurrency, timeout, TPROXY port, NFQUEUE number).
    /// Defaults if no `engine` directive is present.
    pub engine: crate::EngineConfig,
    /// nftables flowtable fast path for real-service traffic (`flowtable` directive);
    /// `None` keeps all real traffic on the nft slow path.
    pub flowtable: Option<crate::FlowTableConfig>,
    /// XDP fast-path config (`xdp` directive); `None` disables it.
    pub xdp: Option<crate::XdpConfig>,
}
