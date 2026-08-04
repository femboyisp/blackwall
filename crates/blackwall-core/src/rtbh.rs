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
    /// Blackwall's own BGP source address — bound by the speaker as the TCP
    /// source and emitted as BIRD's `neighbor`. `None` = OS-chosen source (no
    /// generated BIRD session possible). Its family should match `peer_addr`.
    pub local_addr: Option<std::net::IpAddr>,
    /// Cross-plane cap (C6) on how many NEW mitigations (BGP announces) may
    /// be armed per rolling 60s window, shared between RTBH and FlowSpec
    /// (FlowSpec reuses this block) — a safety ceiling on the *arrival rate*
    /// of mitigations, distinct from `max_blackholes`/`FlowSpecPolicy::max_rules`
    /// which only bound the steady-state active-set size. `None` (the
    /// default; absent `max-new-per-min` key) is unlimited — today's
    /// behavior.
    pub max_new_per_min: Option<u32>,
}

impl RtbhPolicy {
    /// Configured NEXT_HOPs that fall in a documentation / discard placeholder
    /// range and so will never resolve to a real blackhole route — i.e. an
    /// unreplaced config-template value. BIRD leaves a route with such a next-hop
    /// as `unreachable` (not `blackhole`) and refuses to export it, so an armed
    /// daemon would silently announce nothing. Flags RFC 5737
    /// (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849
    /// (`2001:db8::/32`), and RFC 6666 (`100::/64`) — which are exactly the
    /// example values `docs/deployment.md` ships.
    #[must_use]
    pub fn placeholder_next_hops(&self) -> Vec<std::net::IpAddr> {
        let mut out = Vec::new();
        if let Some(v4) = self.next_hop_v4 {
            if is_placeholder_v4(v4) {
                out.push(v4.into());
            }
        }
        if let Some(v6) = self.next_hop_v6 {
            if is_placeholder_v6(v6) {
                out.push(v6.into());
            }
        }
        out
    }

    /// Arm-time verdict on the configured blackhole NEXT_HOPs.
    ///
    /// A documentation/discard-placeholder next-hop used to be a hard
    /// arm-blocking error, because a route with such a next-hop never resolves
    /// and BIRD leaves it `unreachable` instead of exporting a real blackhole.
    /// Since `c49e31b` that is no longer the only path to a real discard:
    /// blackwall's generated BIRD import filter converts an RFC 7999
    /// community-tagged host route directly to `dest = RTD_BLACKHOLE` on
    /// import, so the next-hop need not resolve at all. Whenever a blackhole
    /// community is configured (the default `[(65535, 666)]`), a placeholder
    /// next-hop is therefore acceptable — but blackwalld cannot see the
    /// router's config to confirm the import filter is actually in place, so
    /// that case is a warning, not a hard block. Only with NO community
    /// configured is next-hop resolution the sole mechanism, and a placeholder
    /// definitely broken.
    #[must_use]
    pub fn next_hop_verdict(&self) -> NextHopVerdict {
        let placeholders = self.placeholder_next_hops();
        if placeholders.is_empty() {
            NextHopVerdict::Ok
        } else if self.blackhole_communities.is_empty() {
            NextHopVerdict::PlaceholderNoCommunity(placeholders)
        } else {
            NextHopVerdict::PlaceholderWithCommunity(placeholders)
        }
    }
}

/// Outcome of [`RtbhPolicy::next_hop_verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextHopVerdict {
    /// No placeholder next-hop configured; nothing to flag.
    Ok,
    /// Placeholder next-hop(s), but a blackhole community is configured, so
    /// BIRD's community→`RTD_BLACKHOLE` import filter (`c49e31b`) can produce a
    /// real blackhole without next-hop resolution. Warn, but arm.
    PlaceholderWithCommunity(Vec<std::net::IpAddr>),
    /// Placeholder next-hop(s) and no blackhole community, so there is no path
    /// to a real discard route. Refuse to arm.
    PlaceholderNoCommunity(Vec<std::net::IpAddr>),
}

/// True if `a` is in an RFC 5737 documentation range (never a real next-hop).
fn is_placeholder_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    matches!(
        (o[0], o[1], o[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    )
}

/// True if `a` is in RFC 3849 (`2001:db8::/32`) or RFC 6666 (`100::/64`).
fn is_placeholder_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_next_hops_flags_doc_ranges_only() {
        let base = RtbhPolicy {
            local_asn: 1,
            peer_asn: 1,
            peer_addr: "10.0.0.2:179".parse().unwrap(),
            router_id: "10.0.0.1".parse().unwrap(),
            blackhole_communities: vec![(65535, 666)],
            next_hop_v4: Some("192.0.2.1".parse().unwrap()), // RFC 5737
            next_hop_v6: Some("100::1".parse().unwrap()),    // RFC 6666
            max_blackholes: 8,
            hold_down: std::time::Duration::from_secs(60),
            max_ttl: None,
            md5: None,
            gtsm_hops: None,
            local_addr: None,
            max_new_per_min: None,
        };
        assert_eq!(
            base.placeholder_next_hops().len(),
            2,
            "both are placeholders"
        );

        let real = RtbhPolicy {
            next_hop_v4: Some("10.222.255.99".parse().unwrap()),
            next_hop_v6: Some("2a12:9b00:b00b::99".parse().unwrap()),
            ..base.clone()
        };
        assert!(
            real.placeholder_next_hops().is_empty(),
            "real next-hops must not be flagged"
        );

        // 2001:db8::/32 (RFC 3849) is also caught.
        let doc_v6 = RtbhPolicy {
            next_hop_v4: None,
            next_hop_v6: Some("2001:db8::1".parse().unwrap()),
            ..base
        };
        assert_eq!(doc_v6.placeholder_next_hops().len(), 1);
    }

    #[test]
    fn next_hop_verdict_gates_on_blackhole_community() {
        let placeholder = RtbhPolicy {
            local_asn: 214_806,
            peer_asn: 214_806,
            peer_addr: "10.0.0.2:179".parse().unwrap(),
            router_id: "10.0.0.1".parse().unwrap(),
            blackhole_communities: vec![(65535, 666)],
            next_hop_v4: Some("192.0.2.1".parse().unwrap()), // RFC 5737 placeholder
            next_hop_v6: Some("100::1".parse().unwrap()),    // RFC 6666 placeholder
            max_blackholes: 8,
            hold_down: std::time::Duration::from_secs(60),
            max_ttl: None,
            md5: None,
            gtsm_hops: None,
            local_addr: None,
            max_new_per_min: None,
        };

        // Placeholder next-hops WITH a blackhole community: the community→
        // RTD_BLACKHOLE import filter (c49e31b) makes the next-hop irrelevant,
        // so this is a warn-and-arm, not a block. (Regression for #273.)
        assert_eq!(
            placeholder.next_hop_verdict(),
            NextHopVerdict::PlaceholderWithCommunity(vec![
                "192.0.2.1".parse().unwrap(),
                "100::1".parse().unwrap(),
            ]),
        );

        // Placeholder next-hops with NO community: next-hop resolution is the
        // only path to a real discard, so a placeholder is a hard block.
        let no_community = RtbhPolicy {
            blackhole_communities: vec![],
            ..placeholder.clone()
        };
        assert_eq!(
            no_community.next_hop_verdict(),
            NextHopVerdict::PlaceholderNoCommunity(vec![
                "192.0.2.1".parse().unwrap(),
                "100::1".parse().unwrap(),
            ]),
        );

        // A real next-hop is always Ok, community or not.
        let real = RtbhPolicy {
            next_hop_v4: Some("94.156.238.67".parse().unwrap()),
            next_hop_v6: Some("2a12:9b00:b00b::67".parse().unwrap()),
            ..placeholder.clone()
        };
        assert_eq!(real.next_hop_verdict(), NextHopVerdict::Ok);
        let real_no_comm = RtbhPolicy {
            blackhole_communities: vec![],
            ..real
        };
        assert_eq!(real_no_comm.next_hop_verdict(), NextHopVerdict::Ok);
    }

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
            local_addr: Some("10.222.255.2".parse().unwrap()),
            max_new_per_min: Some(60),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: RtbhPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
