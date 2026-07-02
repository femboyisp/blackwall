//! BGP UPDATE message encoding: NLRI packing + IPv4/IPv6 announce/withdraw.
//!
//! IPv4 routes use the classic NEXT_HOP attribute and trailing NLRI field.
//! IPv6 routes use MP-BGP (RFC 4760): `MP_REACH_NLRI` (type 14) carries the
//! next-hop and NLRI; `MP_UNREACH_NLRI` (type 15) carries the withdrawn NLRI.
//! No v4 NEXT_HOP attribute or trailing v4 NLRI is emitted for v6 routes.

use crate::message::encode_header;
use crate::route::Route;
use ipnet::IpNet;
use std::net::IpAddr;

// ── Path-attribute flag/type constants ──────────────────────────────────────

/// Well-known mandatory flag (Transitive, not Optional).
const FLAG_WELL_KNOWN: u8 = 0x40;
/// Optional transitive flag.
const FLAG_OPT_TRANS: u8 = 0xC0;
/// Optional non-transitive flag (used for MP_REACH/MP_UNREACH_NLRI per RFC 4760).
const FLAG_OPT_NON_TRANS: u8 = 0x80;
/// Extended-Length attribute flag bit (RFC 4271 §4.3): when set, the length
/// field is two octets instead of one.
const FLAG_EXTENDED_LEN: u8 = 0x10;

/// ORIGIN attribute type code.
const ATTR_ORIGIN: u8 = 1;
/// AS_PATH attribute type code.
const ATTR_AS_PATH: u8 = 2;
/// NEXT_HOP attribute type code (IPv4 only).
const ATTR_NEXT_HOP: u8 = 3;
/// COMMUNITIES attribute type code (RFC 1997).
const ATTR_COMMUNITIES: u8 = 8;
/// MP_REACH_NLRI attribute type code (RFC 4760).
const ATTR_MP_REACH_NLRI: u8 = 14;
/// MP_UNREACH_NLRI attribute type code (RFC 4760).
const ATTR_MP_UNREACH_NLRI: u8 = 15;
/// LARGE_COMMUNITIES attribute type code (RFC 8092).
const ATTR_LARGE_COMMUNITIES: u8 = 32;

/// AFI for IPv6 Unicast (RFC 4760).
const AFI_IPV6: u16 = 2;
/// SAFI for Unicast.
const SAFI_UNICAST: u8 = 1;

// ── NLRI encoding ────────────────────────────────────────────────────────────

/// Encode a single NLRI prefix in BGP wire format.
///
/// Format: `u8` prefix-length bits, then `ceil(bits/8)` high-order address
/// octets (4 octets available for IPv4, 16 for IPv6).
///
/// Examples:
/// - `203.0.113.7/32`  → `[32, 203, 0, 113, 7]`
/// - `203.0.113.0/24`  → `[24, 203, 0, 113]`
/// - `0.0.0.0/0`       → `[0]`
pub(crate) fn encode_nlri(prefix: &IpNet) -> Vec<u8> {
    let bits = prefix.prefix_len();
    let nbytes = usize::from(bits.div_ceil(8));
    let mut out = Vec::with_capacity(1 + nbytes);
    out.push(bits);
    // Truncate host bits so a non-host prefix can never emit a malformed NLRI.
    let addr_octets: Vec<u8> = match prefix.trunc().addr() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    out.extend_from_slice(&addr_octets[..nbytes]);
    out
}

// ── Path-attribute helpers ───────────────────────────────────────────────────

/// Append a path attribute to `buf`, choosing the one-byte or two-byte
/// (extended-length, RFC 4271 §4.3) length form based on the value size.
fn push_attr(buf: &mut Vec<u8>, flags: u8, type_code: u8, value: &[u8]) {
    if let Ok(len) = u8::try_from(value.len()) {
        buf.push(flags);
        buf.push(type_code);
        buf.push(len);
    } else {
        let len = u16::try_from(value.len()).expect("attribute value exceeds 65535 bytes");
        buf.push(flags | FLAG_EXTENDED_LEN);
        buf.push(type_code);
        buf.extend_from_slice(&len.to_be_bytes());
    }
    buf.extend_from_slice(value);
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Build a BGP UPDATE message announcing a route.
///
/// Dispatches on `route.prefix`'s address family:
///
/// **IPv4** — classic UPDATE body:
/// 1. `u16` withdrawn-routes length (0 — nothing withdrawn)
/// 2. `u16` total path-attribute length
/// 3. Path attributes in order: ORIGIN, AS_PATH (empty), NEXT_HOP,
///    COMMUNITIES (if any), LARGE_COMMUNITIES (if any)
/// 4. NLRI (the announced prefix)
///
/// **IPv6** — MP-BGP UPDATE body (RFC 4760):
/// 1. `u16` withdrawn-routes length (0)
/// 2. `u16` total path-attribute length
/// 3. Path attributes: ORIGIN, AS_PATH (empty), MP_REACH_NLRI, COMMUNITIES
///    (if any), LARGE_COMMUNITIES (if any)
///    — no v4 NEXT_HOP attribute, no trailing v4 NLRI
///
/// `MP_REACH_NLRI` value layout: `u16` AFI(2) + `u8` SAFI(1) +
/// `u8` nexthop_len(16) + 16 next-hop octets + `u8` reserved(0) + NLRI.
///
/// # Contract
///
/// The caller must supply a `next_hop` whose address family matches `prefix`.
/// An IPv6 prefix with an IPv4 next-hop (or vice-versa) is a logic error;
/// a `debug_assert!` guards this in debug builds.
pub fn build_announce(route: &Route) -> Vec<u8> {
    // Dispatch on address family.
    match (&route.prefix, &route.next_hop) {
        (IpNet::V4(_), IpAddr::V4(nh)) => {
            // ── assemble path attributes ─────────────────────────────────────

            let mut attrs: Vec<u8> = Vec::new();

            // ORIGIN: well-known mandatory, 1 byte value
            push_attr(
                &mut attrs,
                FLAG_WELL_KNOWN,
                ATTR_ORIGIN,
                &[route.origin.wire()],
            );

            // AS_PATH: well-known mandatory, empty (iBGP injection)
            push_attr(&mut attrs, FLAG_WELL_KNOWN, ATTR_AS_PATH, &[]);

            // NEXT_HOP: well-known mandatory, 4 bytes
            push_attr(&mut attrs, FLAG_WELL_KNOWN, ATTR_NEXT_HOP, &nh.octets());

            // COMMUNITIES (optional transitive): 4 bytes per community
            if !route.communities.is_empty() {
                let mut val: Vec<u8> = Vec::with_capacity(4 * route.communities.len());
                for (asn, community) in &route.communities {
                    val.extend_from_slice(&asn.to_be_bytes());
                    val.extend_from_slice(&community.to_be_bytes());
                }
                push_attr(&mut attrs, FLAG_OPT_TRANS, ATTR_COMMUNITIES, &val);
            }

            // LARGE_COMMUNITIES (optional transitive): 12 bytes per community
            if !route.large_communities.is_empty() {
                let mut val: Vec<u8> = Vec::with_capacity(12 * route.large_communities.len());
                for (global, local1, local2) in &route.large_communities {
                    val.extend_from_slice(&global.to_be_bytes());
                    val.extend_from_slice(&local1.to_be_bytes());
                    val.extend_from_slice(&local2.to_be_bytes());
                }
                push_attr(&mut attrs, FLAG_OPT_TRANS, ATTR_LARGE_COMMUNITIES, &val);
            }

            // ── assemble UPDATE body ──────────────────────────────────────────

            let nlri = encode_nlri(&route.prefix);
            let total_attr_len =
                u16::try_from(attrs.len()).expect("path attributes exceed 65535 bytes");

            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn_routes_len = 0
            body.extend_from_slice(&total_attr_len.to_be_bytes()); // total_path_attr_len
            body.extend_from_slice(&attrs);
            body.extend_from_slice(&nlri); // announced NLRI

            encode_header(2, &body)
        }

        // IPv6 MP-BGP announce: next-hop rides inside MP_REACH_NLRI (RFC 4760).
        (IpNet::V6(_), IpAddr::V6(nh)) => {
            // ── build MP_REACH_NLRI value ─────────────────────────────────────
            // value = AFI(2) + SAFI(1) + nhlen(1) + nexthop(16) + reserved(1) + NLRI
            let nlri = encode_nlri(&route.prefix);
            let mut mp_reach_val: Vec<u8> = Vec::new();
            mp_reach_val.extend_from_slice(&AFI_IPV6.to_be_bytes()); // AFI = 2
            mp_reach_val.push(SAFI_UNICAST); // SAFI = 1
            mp_reach_val.push(16u8); // next-hop length: 16 octets
            mp_reach_val.extend_from_slice(&nh.octets()); // 16-byte next-hop
            mp_reach_val.push(0u8); // reserved
            mp_reach_val.extend_from_slice(&nlri); // NLRI (bit-length + packed prefix)

            // ── assemble path attributes ─────────────────────────────────────

            let mut attrs: Vec<u8> = Vec::new();

            // ORIGIN: well-known mandatory, 1 byte value
            push_attr(
                &mut attrs,
                FLAG_WELL_KNOWN,
                ATTR_ORIGIN,
                &[route.origin.wire()],
            );

            // AS_PATH: well-known mandatory, empty (iBGP injection)
            push_attr(&mut attrs, FLAG_WELL_KNOWN, ATTR_AS_PATH, &[]);

            // MP_REACH_NLRI: optional non-transitive (flags 0x80), type 14
            push_attr(
                &mut attrs,
                FLAG_OPT_NON_TRANS,
                ATTR_MP_REACH_NLRI,
                &mp_reach_val,
            );

            // COMMUNITIES (optional transitive): 4 bytes per community
            if !route.communities.is_empty() {
                let mut val: Vec<u8> = Vec::with_capacity(4 * route.communities.len());
                for (asn, community) in &route.communities {
                    val.extend_from_slice(&asn.to_be_bytes());
                    val.extend_from_slice(&community.to_be_bytes());
                }
                push_attr(&mut attrs, FLAG_OPT_TRANS, ATTR_COMMUNITIES, &val);
            }

            // LARGE_COMMUNITIES (optional transitive): 12 bytes per community
            if !route.large_communities.is_empty() {
                let mut val: Vec<u8> = Vec::with_capacity(12 * route.large_communities.len());
                for (global, local1, local2) in &route.large_communities {
                    val.extend_from_slice(&global.to_be_bytes());
                    val.extend_from_slice(&local1.to_be_bytes());
                    val.extend_from_slice(&local2.to_be_bytes());
                }
                push_attr(&mut attrs, FLAG_OPT_TRANS, ATTR_LARGE_COMMUNITIES, &val);
            }

            // ── assemble UPDATE body ──────────────────────────────────────────
            // No v4 withdrawn field, no trailing v4 NLRI — NLRI is inside MP_REACH_NLRI.

            let total_attr_len =
                u16::try_from(attrs.len()).expect("path attributes exceed 65535 bytes");

            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn_routes_len = 0
            body.extend_from_slice(&total_attr_len.to_be_bytes()); // total_path_attr_len
            body.extend_from_slice(&attrs);
            // no trailing NLRI — carried inside MP_REACH_NLRI above

            encode_header(2, &body)
        }

        // Address-family mismatch (e.g. v4 prefix + v6 next-hop).  The caller
        // contract requires matching families; this is a programming error.
        _ => panic!(
            "build_announce: next_hop address family does not match prefix family \
             (prefix={}, next_hop={})",
            route.prefix, route.next_hop
        ),
    }
}

/// Build a BGP UPDATE message withdrawing a prefix.
///
/// Dispatches on `prefix`'s address family:
///
/// **IPv4** — classic UPDATE body:
/// 1. `u16` withdrawn-routes length (the packed NLRI length)
/// 2. The withdrawn NLRI (`u8` bits + high-order address octets)
/// 3. `u16` total path-attribute length (0 — no path attributes)
///
/// **IPv6** — MP-BGP UPDATE body (RFC 4760):
/// 1. `u16` withdrawn-routes length (0 — v4 field unused for v6)
/// 2. `u16` total path-attribute length
/// 3. `MP_UNREACH_NLRI` attribute (optional non-transitive, type 15):
///    value = `u16` AFI(2) + `u8` SAFI(1) + NLRI
pub fn build_withdraw(prefix: &IpNet) -> Vec<u8> {
    match prefix {
        IpNet::V4(_) => {
            let nlri = encode_nlri(prefix);
            let withdrawn_len =
                u16::try_from(nlri.len()).expect("withdrawn NLRI exceeds 65535 bytes");

            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&withdrawn_len.to_be_bytes()); // withdrawn_routes_len
            body.extend_from_slice(&nlri); // the withdrawn prefix
            body.extend_from_slice(&0u16.to_be_bytes()); // total_path_attr_len = 0

            encode_header(2, &body)
        }

        // IPv6 MP-BGP withdraw: NLRI rides inside MP_UNREACH_NLRI (RFC 4760).
        IpNet::V6(_) => {
            // MP_UNREACH_NLRI value = AFI(2) + SAFI(1) + NLRI
            let nlri = encode_nlri(prefix);
            let mut mp_unreach_val: Vec<u8> = Vec::new();
            mp_unreach_val.extend_from_slice(&AFI_IPV6.to_be_bytes()); // AFI = 2
            mp_unreach_val.push(SAFI_UNICAST); // SAFI = 1
            mp_unreach_val.extend_from_slice(&nlri); // NLRI

            let mut attrs: Vec<u8> = Vec::new();
            // MP_UNREACH_NLRI: optional non-transitive (flags 0x80), type 15
            push_attr(
                &mut attrs,
                FLAG_OPT_NON_TRANS,
                ATTR_MP_UNREACH_NLRI,
                &mp_unreach_val,
            );

            let total_attr_len =
                u16::try_from(attrs.len()).expect("path attributes exceed 65535 bytes");

            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn_routes_len = 0 (v6 uses MP_UNREACH)
            body.extend_from_slice(&total_attr_len.to_be_bytes()); // total_path_attr_len
            body.extend_from_slice(&attrs);

            encode_header(2, &body)
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{Origin, Route};
    use std::net::IpAddr;

    #[test]
    fn nlri_packs_v4_host_and_prefix() {
        assert_eq!(
            encode_nlri(&"203.0.113.7/32".parse().unwrap()),
            vec![32, 203, 0, 113, 7]
        );
        assert_eq!(
            encode_nlri(&"203.0.113.0/24".parse().unwrap()),
            vec![24, 203, 0, 113]
        );
        assert_eq!(encode_nlri(&"0.0.0.0/0".parse().unwrap()), vec![0]);
    }

    #[test]
    fn announce_v4_has_attrs_and_nlri() {
        let route = Route {
            prefix: "203.0.113.7/32".parse().unwrap(),
            next_hop: "10.222.255.1".parse::<IpAddr>().unwrap(),
            origin: Origin::Igp,
            communities: vec![(65535, 666)],
            large_communities: vec![],
        };
        let msg = build_announce(&route);
        let (ty, total) = crate::message::parse_header(&msg).unwrap();
        assert_eq!(ty, 2); // UPDATE
        assert_eq!(total, msg.len());
        // withdrawn_len = 0
        assert_eq!(u16::from_be_bytes([msg[19], msg[20]]), 0);
        // the trailing NLRI is the /32
        assert_eq!(&msg[msg.len() - 5..], &[32, 203, 0, 113, 7]);
        // the COMMUNITY 65535:666 appears in the attribute bytes
        let needle = [0xFF, 0xFF, 0x02, 0x9A]; // 65535, 666
        assert!(msg.windows(4).any(|w| w == needle));
        // NEXT_HOP bytes appear
        assert!(msg.windows(4).any(|w| w == [10, 222, 255, 1]));
    }

    #[test]
    fn withdraw_v4_puts_prefix_in_withdrawn_field() {
        let msg = build_withdraw(&"203.0.113.7/32".parse().unwrap());
        let (ty, _) = crate::message::parse_header(&msg).unwrap();
        assert_eq!(ty, 2);
        // withdrawn_len = 5 (the /32 NLRI), then the NLRI, then path_attr_len = 0
        assert_eq!(u16::from_be_bytes([msg[19], msg[20]]), 5);
        assert_eq!(&msg[21..26], &[32, 203, 0, 113, 7]);
        assert_eq!(u16::from_be_bytes([msg[26], msg[27]]), 0); // total path attr len
    }

    #[test]
    fn announce_v6_uses_mp_reach_nlri() {
        let route = Route {
            prefix: "2001:db8::1/128".parse().unwrap(),
            next_hop: "fd00:b00b:ffff::1".parse::<std::net::IpAddr>().unwrap(),
            origin: Origin::Igp,
            communities: vec![(65535, 666)],
            large_communities: vec![],
        };
        let msg = build_announce(&route);
        let (ty, total) = crate::message::parse_header(&msg).unwrap();
        assert_eq!(ty, 2);
        assert_eq!(total, msg.len());
        // MP_REACH_NLRI attribute type (14) appears with the optional flag
        assert!(msg.windows(2).any(|w| w == [0x80, 14]));
        // AFI 2 (ipv6), SAFI 1 present
        assert!(msg.windows(3).any(|w| w == [0x00, 0x02, 0x01]));
        // the /128 NLRI (bits=128 then 16 bytes) — check the bit-length byte 128 occurs
        assert!(msg.contains(&128u8));
        // no IPv4 NEXT_HOP attribute (type 3) for a v6 route
        assert!(!msg.windows(2).any(|w| w == [0x40, 3]));
    }

    #[test]
    fn withdraw_v6_uses_mp_unreach_nlri() {
        let msg = build_withdraw(&"2001:db8::1/128".parse().unwrap());
        let (ty, _) = crate::message::parse_header(&msg).unwrap();
        assert_eq!(ty, 2);
        // withdrawn_len (v4 field) = 0 for a v6 withdraw
        assert_eq!(u16::from_be_bytes([msg[19], msg[20]]), 0);
        // MP_UNREACH_NLRI attribute type 15 present
        assert!(msg.windows(2).any(|w| w == [0x80, 15]));
    }

    #[test]
    fn push_attr_uses_extended_length_past_255_bytes() {
        // 64 standard communities = 256 bytes of value → must NOT panic and must
        // use the two-byte extended-length form (flag bit 0x10 set).
        let communities: Vec<(u16, u16)> = (0..64).map(|i| (65535, i)).collect();
        let route = Route {
            prefix: "203.0.113.7/32".parse().unwrap(),
            next_hop: "10.0.0.1".parse::<IpAddr>().unwrap(),
            origin: Origin::Igp,
            communities,
            large_communities: vec![],
        };
        let msg = build_announce(&route); // previously panicked
        // Find the COMMUNITIES attribute (type 8). Its value is 256 bytes, so the
        // Extended-Length bit (0x10) must be OR'd into the flags and the length is
        // two bytes big-endian.
        // Flags for COMMUNITIES = optional-transitive (0xC0) | extended-length (0x10) = 0xD0.
        let idx = msg
            .windows(2)
            .position(|w| w == [0xD0, 8])
            .expect("extended-length COMMUNITIES attribute present");
        let len = u16::from_be_bytes([msg[idx + 2], msg[idx + 3]]);
        assert_eq!(len, 256, "two-byte extended length == 256");
    }

    #[test]
    fn encode_nlri_truncates_host_bits() {
        // 203.0.113.130/25 → bits=25, nbytes=4; the low 7 bits of the 4th octet
        // must be masked to 0 (203.0.113.128), not carried as 130.
        assert_eq!(
            encode_nlri(&"203.0.113.130/25".parse().unwrap()),
            vec![25, 203, 0, 113, 128]
        );
    }
}
