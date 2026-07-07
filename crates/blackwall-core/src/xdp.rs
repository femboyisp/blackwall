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
    /// Deception TCP ports the in-kernel SYN-cookie fast path answers on
    /// behalf of the box's owned prefixes (`cookie-ports=` directive). Empty
    /// (the default) leaves the fast path inert: the flow daemon never loads
    /// the cookie secret/protected prefixes/ports into the XDP maps, and the
    /// eBPF SYN handler falls through to `XDP_PASS` for every port (B2.3a/b
    /// fail-closed behavior).
    pub cookie_ports: Vec<u16>,
    /// Deception UDP ports whose IPv4 datagrams the in-kernel redirect fast
    /// path diverts to a userspace `AF_XDP` socket, where the flow daemon
    /// answers them at line rate with the reflection-safe `udp_response`
    /// builder (`afxdp-udp-ports=` directive, sub-project B3.2). Empty (the
    /// default) leaves the AF_XDP UDP responder disabled: the flow daemon never
    /// installs the `REDIRECT_PORT` set nor binds an `AF_XDP` socket, and the
    /// eBPF redirect handler passes every UDP datagram through to the kernel
    /// stack (B3.1 fail-closed behavior).
    pub afxdp_udp_ports: Vec<u16>,
}
