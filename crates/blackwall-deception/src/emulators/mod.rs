//! Built-in service emulators.

mod generic;
mod http;
mod redis;
mod smtp;
mod ssh;

pub use generic::GenericBannerEmulator;
pub use http::HttpEmulator;
pub use redis::RedisEmulator;
pub use smtp::SmtpEmulator;
pub use ssh::SshEmulator;
