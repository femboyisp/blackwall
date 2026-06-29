//! BGP UPDATE message encoding: NLRI packing + IPv4 announce/withdraw.
//!
//! IPv6 (MP-BGP) is deferred to Task 5.

use crate::message::encode_header;
use crate::route::Route;
use ipnet::IpNet;
use std::net::IpAddr;

// ── Path-attribute flag/type constants ──────────────────────────────────────

/// Well-known mandatory flag (Transitive, not Optional).
const FLAG_WELL_KNOWN: u8 = 0x40;
/// Optional transitive flag.
const FLAG_OPT_TRANS: u8 = 0xC0;

/// ORIGIN attribute type code.
const ATTR_ORIGIN: u8 = 1;
/// AS_PATH attribute type code.
const ATTR_AS_PATH: u8 = 2;
/// NEXT_HOP attribute type code.
const ATTR_NEXT_HOP: u8 = 3;
/// COMMUNITIES attribute type code (RFC 1997).
const ATTR_COMMUNITIES: u8 = 8;
/// LARGE_COMMUNITIES attribute type code (RFC 8092).
const ATTR_LARGE_COMMUNITIES: u8 = 32;

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
    let addr_octets: Vec<u8> = match prefix.addr() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    out.extend_from_slice(&addr_octets[..nbytes]);
    out
}

// ── Path-attribute helpers ───────────────────────────────────────────────────

/// Append a short (≤255 byte value) path attribute to `buf`.
fn push_attr(buf: &mut Vec<u8>, flags: u8, type_code: u8, value: &[u8]) {
    buf.push(flags);
    buf.push(type_code);
    // Length fits in u8 for all attrs this module encodes (enforced at call sites).
    buf.push(u8::try_from(value.len()).expect("attribute value exceeds 255 bytes"));
    buf.extend_from_slice(value);
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Build a BGP UPDATE message announcing an IPv4 route.
///
/// The UPDATE body contains:
/// 1. `u16` withdrawn-routes length (0 — nothing withdrawn)
/// 2. `u16` total path-attribute length
/// 3. Path attributes in order: ORIGIN, AS_PATH (empty), NEXT_HOP,
///    COMMUNITIES (if any), LARGE_COMMUNITIES (if any)
/// 4. NLRI (the announced prefix)
///
/// # Panics
///
/// Panics with `todo!` if `route.prefix` or `route.next_hop` is IPv6 — IPv6
/// MP-BGP is implemented in Task 5. The panic site is structured as a clear
/// `// IPv6: Task 5` branch so Task 5 can replace it without touching any
/// surrounding code.
pub fn build_announce(route: &Route) -> Vec<u8> {
    // Dispatch on address family.  Task 5 fills the IPv6 branch.
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

        // IPv6: Task 5
        _ => todo!("IPv6 MP-BGP announce — Task 5"),
    }
}

/// Build a BGP UPDATE message withdrawing an IPv4 prefix.
///
/// The UPDATE body contains:
/// 1. `u16` withdrawn-routes length (the packed NLRI length)
/// 2. The withdrawn NLRI (`u8` bits + high-order address octets)
/// 3. `u16` total path-attribute length (0 — no path attributes)
///
/// # Panics
///
/// Panics with `todo!` if `prefix` is IPv6 — IPv6 MP-BGP withdraw is
/// implemented in Task 5.
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

        // IPv6: Task 5
        IpNet::V6(_) => todo!("IPv6 MP-BGP withdraw — Task 5"),
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
}
