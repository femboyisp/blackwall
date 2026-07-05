//! Shared domain types and the policy model for Blackwall.

mod dns;
mod engine;
mod flowspec;
mod flux;
mod md5secret;
mod policy;
mod port;
mod proto;
mod resolve;
mod rtbh;
mod shape;
mod target;

pub use dns::DnsFluxConfig;
pub use engine::{
    EngineConfig, DEFAULT_MAX_CONCURRENT, DEFAULT_NFQUEUE_NUM, DEFAULT_SESSION_TIMEOUT_SECS,
    DEFAULT_TPROXY_PORT,
};
pub use flowspec::FlowSpecPolicy;
pub use flux::BannerFluxConfig;
pub use md5secret::Md5Secret;
pub use policy::{AllowRule, Policy, Tenant};
pub use port::PortState;
pub use proto::L4Proto;
pub use resolve::{PolicyError, ResolvedService};
pub use rtbh::RtbhPolicy;
pub use shape::{ShapeBandwidth, ShapeRule};
pub use target::ServiceTarget;
