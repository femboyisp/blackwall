//! A minimal, injection-only native BGP speaker for Blackwall.

mod error;
mod message;
mod route;

pub use error::BgpError;
pub use message::{
    decode_open, encode_header, encode_open, parse_header, MsgType, OpenMsg, HEADER_LEN, MARKER,
};
pub use route::{Origin, Route};
