//! Deception traffic transports.

mod metrics;
mod nfqueue;
mod packet;
mod tproxy;

pub use metrics::StatelessMetrics;
pub use nfqueue::{run as run_nfqueue, BannerLookup};
// Pure, byte-exact stateless TCP SYN-cookie packet builders (Component 2 of
// the stateless SYN-cookie tier design), plus the request parser the NFQUEUE
// TCP dispatcher (Component 2b) uses to route SYN/ACK segments. Re-exported
// here so the builders are part of the crate's public surface (and
// coverage-visible), mirroring how `cookie.rs`'s pure functions are exported
// at the crate root.
pub use packet::{
    parse_tcp_request, tcp_banner_fin, tcp_syn_ack, TcpRequestInfo, DEFAULT_CLIENT_MSS,
};
pub use tproxy::{serve, SessionRecord, TproxyListener};
