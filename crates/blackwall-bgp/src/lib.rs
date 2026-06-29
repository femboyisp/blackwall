//! A minimal, injection-only native BGP speaker for Blackwall.

mod error;
mod message;
mod route;

pub use error::BgpError;
pub use message::{encode_header, parse_header, HEADER_LEN, MARKER};
pub use route::{Origin, Route};
