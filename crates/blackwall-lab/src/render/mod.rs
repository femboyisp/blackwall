//! Byte-exact renderers that turn topology data into daemon configs.

pub mod bird;

pub use bird::render_bird;
