//! A route to inject and its BGP attributes.

use ipnet::IpNet;
use std::net::IpAddr;

/// BGP ORIGIN attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Interior (IGP).
    Igp,
    /// Exterior (EGP).
    Egp,
    /// Incomplete.
    Incomplete,
}

impl Origin {
    /// The on-wire ORIGIN byte.
    pub fn wire(self) -> u8 {
        match self {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }
}

/// A route to announce or withdraw, with its path attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The prefix (host route for RTBH, e.g. a `/32`).
    pub prefix: IpNet,
    /// NEXT_HOP for the route.
    pub next_hop: IpAddr,
    /// ORIGIN attribute.
    pub origin: Origin,
    /// Standard communities (`(asn16, value16)`), e.g. `(65535, 666)` = BLACKHOLE.
    pub communities: Vec<(u16, u16)>,
    /// Large communities (`(global, local1, local2)`).
    pub large_communities: Vec<(u32, u32, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_wire_values() {
        assert_eq!(Origin::Igp.wire(), 0);
        assert_eq!(Origin::Egp.wire(), 1);
        assert_eq!(Origin::Incomplete.wire(), 2);
    }
}
