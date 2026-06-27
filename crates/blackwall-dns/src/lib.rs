//! DNS fast-flux for Blackwall: deterministic rotation of A/AAAA records via
//! TSIG-authenticated RFC-2136 dynamic updates.

mod error;
mod flux;

pub use error::DnsError;
pub use flux::{flux_pool, flux_window, next_boundary_delay};
