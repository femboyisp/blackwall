//! Traffic-shaping rules parsed from the config DSL.

use serde::{Deserialize, Serialize};

/// How a direction's CAKE bandwidth is determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShapeBandwidth {
    /// Set from the latest speedtest measurement.
    Auto,
    /// A fixed bandwidth in megabits per second.
    Fixed(u32),
}

/// A shaping rule for one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeRule {
    /// The interface to shape (e.g. `eth0`).
    pub iface: String,
    /// Download (ingress) bandwidth source.
    pub download: ShapeBandwidth,
    /// Upload (egress) bandwidth source.
    pub upload: ShapeBandwidth,
    /// Optional CAKE `rtt` hint in milliseconds.
    pub rtt_ms: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_rule_round_trips_through_json() {
        let r = ShapeRule {
            iface: "eth0".to_owned(),
            download: ShapeBandwidth::Auto,
            upload: ShapeBandwidth::Fixed(50),
            rtt_ms: Some(50),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(r, serde_json::from_str(&json).unwrap());
    }
}
