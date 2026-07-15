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

/// Conservative default for [`XdpConfig::syn_cookie_tx_cap`] (packets per
/// second), used when the `syn-cookie-tx-cap=` directive key is absent.
///
/// **Never `0`** (`0` means "unlimited" to the in-kernel `TX_BUDGET` bucket —
/// see `blackwall_xdp_common::TxBucket`'s doc comment): an operator who
/// enables `cookie-ports` without also specifying this knob must still get a
/// bounded SYN-ACK reflector rather than an unbounded gain-1 amplifier.
pub const DEFAULT_SYN_COOKIE_TX_CAP_PPS: u32 = 1000;

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
    /// Banner bytes the AF_XDP UDP responder reflects to `afxdp_udp_ports`
    /// (`afxdp-udp-banner=` directive), decoded from the config string with
    /// `\n`/`\r`/`\t`/`\s`/`\\` escapes plus `\xNN` for an arbitrary byte
    /// (config is whitespace-tokenized, so a space must be written `\s` — e.g.
    /// `220\sready\r\n`; a binary DNS/NTP-style response uses `\xNN`, e.g.
    /// `\x00\x1c\x81\x80…`). Raw bytes, so it need not be valid UTF-8. `None`
    /// (the default) uses the built-in placeholder. The reflection-safe builder
    /// still truncates the banner to at most the request's payload length, so
    /// this can never amplify.
    pub afxdp_udp_banner: Option<Vec<u8>>,
    /// Global cap (packets per second) on the in-kernel SYN-cookie `XDP_TX`
    /// mint rate (`syn-cookie-tx-cap=` directive, sub-project X3), written into
    /// the eBPF `TX_BUDGET` bucket via
    /// `blackwall_xdp::XdpDataplane::set_syn_cookie_tx_cap`. Bounds the
    /// *aggregate* SYN-ACK reflection rate regardless of how many distinct
    /// (possibly spoofed) source addresses a flood spreads across — the
    /// per-source `RATE` limiter alone never engages against a flood that never
    /// reuses a source. Defaults to [`DEFAULT_SYN_COOKIE_TX_CAP_PPS`]
    /// (never `0`/unlimited) so enabling `cookie-ports` without this knob still
    /// yields a bounded reflector.
    pub syn_cookie_tx_cap: u32,
}
