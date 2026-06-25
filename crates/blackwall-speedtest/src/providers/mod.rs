//! Built-in speedtest providers.

mod client_net;
mod cloudflare_net;
mod cloudflare_parse;
mod fast_net;
mod fast_parse;
mod librespeed_net;
mod librespeed_parse;
mod ookla_net;
mod ookla_parse;

pub(crate) use client_net::build_client;
pub use cloudflare_net::CloudflareProvider;
pub use fast_net::FastProvider;
pub use librespeed_net::LibreSpeedProvider;
/// Parse a LibreSpeed `servers.json` to discover a server URL to pass to
/// [`LibreSpeedProvider::new`]. Exposed for callers that select a server.
pub use librespeed_parse::{parse_server_list, LibreServer};
pub use ookla_net::OoklaProvider;
