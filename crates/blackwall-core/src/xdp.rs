//! XDP data-plane configuration (`xdp` directive).

use serde::{Deserialize, Serialize};

/// XDP attach mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum XdpMode {
    /// Try native/driver mode, fall back to generic (skb) with a warning.
    #[default]
    Auto,
    /// Require native/driver mode (fail if the NIC driver lacks XDP).
    Native,
    /// Force generic (skb) mode.
    Generic,
}

/// Configuration for the on-box XDP fast path (`xdp` directive); `None` on
/// [`crate::Policy`] means XDP is disabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpConfig {
    /// Interface to attach to; `None` uses the policy's managed `interface`.
    pub interface: Option<String>,
    /// Attach mode.
    pub mode: XdpMode,
    /// Default per-source rate limit (pps) applied by the auto-sink to each
    /// identified attacker source; `None` means the sink drops nothing
    /// automatically and only operator CLI actions populate the maps.
    pub default_rate_limit_pps: Option<u64>,
}
