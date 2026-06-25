//! Built-in speedtest providers.

mod cloudflare_net;
mod cloudflare_parse;
mod librespeed_net;
mod librespeed_parse;

pub use cloudflare_net::CloudflareProvider;
pub use librespeed_net::LibreSpeedProvider;
/// Parse a LibreSpeed `servers.json` to discover a server URL to pass to
/// [`LibreSpeedProvider::new`]. Exposed for callers that select a server.
pub use librespeed_parse::{parse_server_list, LibreServer};
