//! Blackwall traffic generator: craft + send DDoS attack and benign traffic
//! over `AF_PACKET` in a lab namespace, and measure per-flow delivery.
//!
//! Pure modules ([`pattern`], [`flow`], [`rate`], [`report`], [`spec`]) are
//! byte-exact unit-tested; the thin `io` layer and the `trafficgen` binary do
//! the actual sockets and are validated end-to-end by the lab scenario.

pub mod error;
pub mod flow;
pub mod io;
pub mod pattern;
pub mod rate;
pub mod report;
pub mod spec;

pub use error::{Result, TrafficGenError};
