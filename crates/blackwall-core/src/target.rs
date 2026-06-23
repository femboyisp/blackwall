//! Where a real (open) service forwards to.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// The backend an open port forwards to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceTarget {
    /// A service running on the Blackwall host itself.
    Host,
    /// An Incus instance, addressed by name (resolved to an address later).
    Incus(String),
    /// A fixed DNAT target address:port.
    Nat(SocketAddr),
}
