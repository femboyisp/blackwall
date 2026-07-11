//! Shared domain types and the policy model for Blackwall.

mod api;
mod dns;
mod engine;
mod flowspec;
mod flowtable;
mod flux;
mod hsflowd;
mod md5secret;
mod policy;
mod pop;
mod port;
mod proto;
mod resolve;
mod rtbh;
mod shape;
mod target;
mod xdp;

pub use api::ApiConfig;
pub use dns::DnsFluxConfig;
pub use engine::{
    EngineConfig, DEFAULT_MAX_CONCURRENT, DEFAULT_NFQUEUE_NUM, DEFAULT_SESSION_TIMEOUT_SECS,
    DEFAULT_TPROXY_PORT,
};
pub use flowspec::FlowSpecPolicy;
pub use flowtable::FlowTableConfig;
pub use flux::BannerFluxConfig;
pub use hsflowd::render_hsflowd_conf;
pub use md5secret::Md5Secret;
pub use policy::{AllowRule, Policy, Tenant};
pub use pop::PopEntry;
pub use port::PortState;
pub use proto::L4Proto;
pub use resolve::{PolicyError, ResolvedService};
pub use rtbh::RtbhPolicy;
pub use shape::{ShapeBandwidth, ShapeRule};
pub use target::ServiceTarget;
pub use xdp::{XdpConfig, XdpMode};
