//! Service-row persistence.

use blackwall_core::{L4Proto, ServiceTarget};
use std::net::IpAddr;

/// A service row read back from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredService {
    /// Exposed address.
    pub address: IpAddr,
    /// Transport protocol.
    pub proto: L4Proto,
    /// Port number.
    pub port: u16,
    /// Forwarding target.
    pub target: ServiceTarget,
    /// Owning tenant name.
    pub tenant: String,
}
