//! POP-map entries (`pop` directive): map an sFlow agent address to a human POP
//! name and its expected sampling rate.

use std::net::IpAddr;

/// One POP: its sFlow agent address, display name, and configured 1-in-N
/// sampling rate (used to name detections' contributing POPs and to sanity-check
/// the rate each agent reports).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PopEntry {
    /// Human POP name, e.g. `"ord"`.
    pub name: String,
    /// The sFlow agent address the POP's hsflowd stamps on its datagrams.
    pub agent: IpAddr,
    /// Configured 1-in-N sampling rate for this POP.
    pub sampling: u32,
}
