//! The deception/forwarding state of a single port.

use serde::{Deserialize, Serialize};

/// What Blackwall does with traffic to a given `(IP, proto, port)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    /// Silently drop (e.g. management ports).
    Closed,
    /// Answer with the deception engine so the port looks open.
    Deception,
    /// Forward to a real backend service.
    Open,
}
