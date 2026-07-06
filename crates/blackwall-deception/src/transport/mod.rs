//! Deception traffic transports.

mod nfqueue;
mod packet;
mod tproxy;

pub use nfqueue::run as run_nfqueue;
// Pure, byte-exact stateless TCP SYN-cookie packet builders (Component 2 of
// the stateless SYN-cookie tier design). NFQUEUE dispatch that calls these is
// a separate follow-on increment; re-exported here so the builders are part
// of the crate's public surface (and coverage-visible) ahead of that wiring,
// mirroring how `cookie.rs`'s pure functions are exported at the crate root
// before anything calls them.
pub use packet::{tcp_banner_fin, tcp_syn_ack};
pub use tproxy::{serve, SessionRecord, TproxyListener};
