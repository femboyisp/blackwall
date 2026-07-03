//! FlowSpec auto-mitigation policy (selection + controller tunables). Reuses
//! the `rtbh` block's BGP peer and `Policy.prefixes` for eligibility.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Policy for FlowSpec auto-mitigation. Reuses the `rtbh` block's BGP peer
/// (single shared iBGP session) and `Policy.prefixes` for eligibility, so it
/// carries only the selection + controller tunables.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowSpecPolicy {
    /// Cumulative top-port weight fraction that counts as "concentrated".
    pub concentration: f64,
    /// Max distinct flows a single FlowSpec mitigation may emit.
    pub max_flows: usize,
    /// Traffic-rate action for emitted rules (bytes/sec; `0.0` = drop).
    pub rate: f32,
    /// Hard cap on concurrently-active FlowSpec rules (summed across targets).
    pub max_rules: usize,
    /// Deferred-withdraw hold-down.
    pub hold_down: Duration,
    /// Optional absolute TTL from last activity.
    pub max_ttl: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flowspec_policy_roundtrips_serde() {
        let p = FlowSpecPolicy {
            concentration: 0.8,
            max_flows: 4,
            rate: 0.0,
            max_rules: 256,
            hold_down: std::time::Duration::from_secs(60),
            max_ttl: Some(std::time::Duration::from_secs(7200)),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: FlowSpecPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
