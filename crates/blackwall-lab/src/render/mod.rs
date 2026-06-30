//! Byte-exact renderers that turn topology data into daemon configs.

pub mod bird;
pub mod knot;
pub mod wireguard;

pub use bird::render_bird;
pub use knot::{render_knot_conf, render_zone};
pub use wireguard::{render_wireguard, WgPeer};
