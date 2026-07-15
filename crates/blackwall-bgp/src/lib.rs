//! A minimal, injection-only native BGP speaker for Blackwall.

mod error;
mod flowspec;
mod message;
mod render;
mod route;
mod session_net;
mod update;

pub use error::BgpError;
pub use flowspec::{build_flowspec_announce, build_flowspec_withdraw, FlowAction, FlowSpecRule};
pub use message::{
    decode_message, decode_notification, decode_open, encode_header, encode_keepalive,
    encode_notification, encode_open, parse_header, BgpMessage, MsgType, NotificationMsg, OpenMsg,
    HEADER_LEN, MARKER,
};
pub use render::{render_bird_ibgp, BirdGenError};
pub use route::{Origin, Route};
pub use session_net::{
    spawn, BgpHandle, BgpSendError, PeerConfig, PeerConfigError, SessionCommand, SessionState,
    UnnegotiatedSkipCounts,
};
pub use update::{build_announce, build_withdraw};
