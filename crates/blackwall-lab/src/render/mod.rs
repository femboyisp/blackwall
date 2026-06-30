//! Byte-exact renderers that turn topology data into daemon configs.

pub mod bird;
pub mod wireguard;

pub use bird::render_bird;
pub use wireguard::{render_wireguard, WgPeer};
