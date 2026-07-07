//! Deception traffic transports.

mod metrics;
mod nfqueue;
mod packet;
mod tproxy;
mod traits;

pub use metrics::StatelessMetrics;
pub use nfqueue::{run as run_nfqueue, BannerLookup, NfqueueTransport};
// Pure, byte-exact stateless TCP SYN-cookie packet builders (Component 2 of
// the stateless SYN-cookie tier design), plus the request parser the NFQUEUE
// TCP dispatcher (Component 2b) uses to route SYN/ACK segments. Re-exported
// here so the builders are part of the crate's public surface (and
// coverage-visible), mirroring how `cookie.rs`'s pure functions are exported
// at the crate root.
pub use packet::{
    parse_tcp_request, tcp_banner_fin, tcp_syn_ack, TcpRequestInfo, DEFAULT_CLIENT_MSS,
};
// UDP request parser + reflection-safe responder, plus the AF_XDP L2-frame
// wrapper (`udp_l2_response`, sub-project B3.2) the flow daemon's AF_XDP UDP
// responder loop uses to turn a redirected Ethernet frame into a reply frame.
pub use packet::{parse_udp_request, udp_l2_response, udp_response, UdpRequestInfo};
pub use tproxy::{serve, SessionRecord, TproxyListener, TproxyTransport};
pub use traits::DeceptionTransport;
