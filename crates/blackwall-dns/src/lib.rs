//! DNS fast-flux for Blackwall: deterministic rotation of A/AAAA records via
//! TSIG-authenticated RFC-2136 dynamic updates.

mod error;
mod flux;
mod send_net;
mod tsig;
mod update;

pub use error::DnsError;
pub use flux::{flux_pool, flux_window, next_boundary_delay};
pub use send_net::{read_tsig_key, send_update};
pub use tsig::{parse_tsig_key, TsigAlgorithm, TsigKey};
pub use update::{build_update, RecordKind, UpdatePlan};
