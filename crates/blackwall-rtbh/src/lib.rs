//! Remotely-triggered blackhole (RTBH): turn a detected attack into a BGP
//! blackhole announcement. A pure [`RtbhController`] decides; a thin sink
//! (added next) executes via the BGP speaker.

pub mod controller;
pub mod sink;

pub use controller::{RtbhAction, RtbhConfig, RtbhController};
pub use sink::RtbhSink;
