//! Deception-engine wiring knobs: resource limits and the kernel hand-off
//! points (TPROXY port and NFQUEUE number) shared between the nft data plane
//! and the running engine.

use serde::{Deserialize, Serialize};

/// Default maximum concurrent deception sessions.
pub const DEFAULT_MAX_CONCURRENT: usize = 1024;
/// Default hard ceiling on a single deception session, in seconds.
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 60;
/// Default TCP port the deception engine's TPROXY listener binds to.
pub const DEFAULT_TPROXY_PORT: u16 = 61000;
/// Default NFQUEUE number for deception ICMP/UDP packets.
pub const DEFAULT_NFQUEUE_NUM: u16 = 0;

/// Deception-engine configuration.
///
/// The TPROXY port and NFQUEUE number are a single source of truth: the nft
/// renderer emits rules pointing at them and the engine binds/opens the same
/// values, so they can never drift. Every field defaults to a working value,
/// so an `engine` directive is optional and may set only the knobs it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Maximum number of deception sessions handled concurrently. Connections
    /// arriving while at the cap are dropped rather than queued.
    pub max_concurrent: usize,
    /// Hard ceiling on a single session's duration, in seconds.
    pub session_timeout_secs: u64,
    /// TCP port the deception engine's TPROXY listener binds to; the nft
    /// deception-TCP rule redirects here.
    pub tproxy_port: u16,
    /// NFQUEUE number the deception engine reads ICMP/UDP packets from; the nft
    /// deception ICMP/UDP rule queues here.
    pub nfqueue_num: u16,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            session_timeout_secs: DEFAULT_SESSION_TIMEOUT_SECS,
            tproxy_port: DEFAULT_TPROXY_PORT,
            nfqueue_num: DEFAULT_NFQUEUE_NUM,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_historical_hardcoded_values() {
        let e = EngineConfig::default();
        assert_eq!(e.max_concurrent, 1024);
        assert_eq!(e.session_timeout_secs, 60);
        assert_eq!(e.tproxy_port, 61000);
        assert_eq!(e.nfqueue_num, 0);
    }
}
