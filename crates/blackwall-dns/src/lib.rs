//! DNS fast-flux for Blackwall: deterministic rotation of A/AAAA records via
//! TSIG-authenticated RFC-2136 dynamic updates.

mod error;
mod flux;
mod tsig;
mod update;

pub use error::DnsError;
pub use flux::{flux_pool, flux_window, next_boundary_delay};
pub use tsig::{parse_tsig_key, TsigAlgorithm, TsigKey};
pub use update::{build_update, RecordKind, UpdatePlan};
