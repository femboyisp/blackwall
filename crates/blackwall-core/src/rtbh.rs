//! RTBH (remotely-triggered blackhole) policy: the BGP peering + blackhole
//! parameters an operator configures. Eligibility reuses `Policy.prefixes`.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// RTBH control-plane configuration parsed from the `rtbh` config directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtbhPolicy {
    /// Local (and, for iBGP, peer) Autonomous System number.
    pub local_asn: u32,
    /// Peer ASN. Must equal `local_asn` (iBGP-injection only).
    pub peer_asn: u32,
    /// BGP peer TCP address (usually port 179).
    pub peer_addr: SocketAddr,
    /// Router-ID advertised in the OPEN.
    pub router_id: Ipv4Addr,
    /// Communities on every blackhole route (default `[(65535, 666)]`, RFC 7999).
    pub blackhole_communities: Vec<(u16, u16)>,
    /// NEXT_HOP for IPv4 blackholes; `None` disables IPv4 blackholing.
    pub next_hop_v4: Option<Ipv4Addr>,
    /// NEXT_HOP for IPv6 blackholes; `None` disables IPv6 blackholing.
    pub next_hop_v6: Option<Ipv6Addr>,
    /// Hard cap on concurrent blackholes.
    pub max_blackholes: usize,
    /// Minimum time a blackhole is held before a `Cleared` may withdraw it.
    pub hold_down: Duration,
    /// Auto-blackhole lifetime backstop; `None` disables the TTL.
    pub max_ttl: Option<Duration>,
    /// Optional TCP-MD5 (RFC 2385) shared secret for the BGP session; `None`
    /// leaves the session unauthenticated.
    pub md5: Option<crate::Md5Secret>,
    /// Optional GTSM (RFC 5082) TTL-security hop count for the BGP session.
    /// `Some(n)` requires received packets to have TTL ≥ `256 - n` (so `1` =
    /// directly connected peer, TTL 255) and sends with TTL 255; `None`
    /// disables the TTL check.
    pub gtsm_hops: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rtbh_policy_roundtrips_serde() {
        let p = RtbhPolicy {
            local_asn: 214_806,
            peer_asn: 214_806,
            peer_addr: "10.0.0.2:179".parse().unwrap(),
            router_id: "10.222.255.1".parse().unwrap(),
            blackhole_communities: vec![(65535, 666)],
            next_hop_v4: Some("10.222.255.99".parse().unwrap()),
            next_hop_v6: None,
            max_blackholes: 256,
            hold_down: std::time::Duration::from_secs(60),
            max_ttl: Some(std::time::Duration::from_secs(7200)),
            md5: Some(crate::Md5Secret::new("pw".into())),
            gtsm_hops: Some(1),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: RtbhPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
