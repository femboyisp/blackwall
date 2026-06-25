//! Deception-session audit rows.

use std::net::IpAddr;

/// One captured deception session, ready to persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// Original destination address the client tried to reach.
    pub local_addr: IpAddr,
    /// Original destination port.
    pub local_port: u16,
    /// Client address.
    pub peer_addr: IpAddr,
    /// Transport protocol (`tcp`/`udp`/`icmp`).
    pub proto: String,
    /// Which emulator handled it.
    pub emulator: String,
    /// Bytes received from the client.
    pub bytes_in: i64,
    /// Bytes sent to the client.
    pub bytes_out: i64,
    /// Optional captured detail.
    pub note: Option<String>,
}
