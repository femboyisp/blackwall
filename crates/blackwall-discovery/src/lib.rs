//! Service discovery for Blackwall: find what the host and Incus instances
//! expose, and reconcile it into the effective firewall policy.

mod error;
mod reconcile;

pub use error::DiscoveryError;
pub use reconcile::{reconcile, DiscoveredService, DiscoverySource};
