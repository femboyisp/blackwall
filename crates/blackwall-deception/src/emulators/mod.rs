//! Built-in service emulators.

mod generic;
mod http;

pub use generic::GenericBannerEmulator;
pub use http::HttpEmulator;
