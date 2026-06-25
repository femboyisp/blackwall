//! Built-in service emulators.

mod generic;
mod http;
mod ssh;

pub use generic::GenericBannerEmulator;
pub use http::HttpEmulator;
pub use ssh::SshEmulator;
