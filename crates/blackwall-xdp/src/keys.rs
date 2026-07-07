//! Encode `IpNet`/`IpAddr` into the shared LPM-trie map keys, and the 128-bit
//! SYN-cookie secret into the `COOKIE_KEY` map value.

use blackwall_xdp_common::{lpm_key_v4, lpm_key_v6, CookieKeyValue, LpmKeyV4, LpmKeyV6};
use ipnet::IpNet;
use std::net::IpAddr;

/// A blocklist LPM key for either family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LpmKey {
    /// IPv4 key.
    V4(LpmKeyV4),
    /// IPv6 key.
    V6(LpmKeyV6),
}

/// Encode a network prefix into an LPM key (big-endian octets).
#[must_use]
pub fn lpm_key(net: IpNet) -> LpmKey {
    match net {
        IpNet::V4(n) => LpmKey::V4(lpm_key_v4(n.prefix_len(), n.network().octets())),
        IpNet::V6(n) => LpmKey::V6(lpm_key_v6(n.prefix_len(), n.network().octets())),
    }
}

/// Encode a single host address as a /32 (v4) or /128 (v6) LPM key.
#[must_use]
pub fn host_lpm_key(addr: IpAddr) -> LpmKey {
    match addr {
        IpAddr::V4(a) => LpmKey::V4(lpm_key_v4(32, a.octets())),
        IpAddr::V6(a) => LpmKey::V6(lpm_key_v6(128, a.octets())),
    }
}

/// Encode the raw 128-bit SYN-cookie secret into the [`CookieKeyValue`] the
/// `COOKIE_KEY` map carries: the pre-split SipHash-2-4 `(k0, k1)` little-endian
/// `u64` pair.
///
/// The little-endian split matches `blackwall_deception::CookieKey::to_u64_pair`
/// and the shared cookie core, so a cookie the eBPF program mints under this key
/// is byte-identical to one the userspace tier computes under the same 16 bytes.
#[must_use]
pub fn encode_cookie_key(key: [u8; 16]) -> CookieKeyValue {
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&key[0..8]);
    hi.copy_from_slice(&key[8..16]);
    CookieKeyValue {
        k0: u64::from_le_bytes(lo),
        k1: u64::from_le_bytes(hi),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn v4_net_key() {
        let LpmKey::V4(k) = lpm_key("203.0.113.0/24".parse().unwrap()) else {
            panic!("expected v4");
        };
        assert_eq!(k.prefixlen, 24);
        assert_eq!(k.addr, [203, 0, 113, 0]);
    }

    #[test]
    fn v6_host_key_is_128() {
        let LpmKey::V6(k) = host_lpm_key("2001:db8::1".parse::<IpAddr>().unwrap()) else {
            panic!("expected v6");
        };
        assert_eq!(k.prefixlen, 128);
        assert_eq!(
            k.addr,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[test]
    fn v4_host_key_is_32() {
        let LpmKey::V4(k) = host_lpm_key("198.51.100.9".parse::<IpAddr>().unwrap()) else {
            panic!("expected v4");
        };
        assert_eq!(k.prefixlen, 32);
        assert_eq!(k.addr, [198, 51, 100, 9]);
    }

    #[test]
    fn cookie_key_splits_little_endian() {
        // Bytes 0x00..=0x0f split LE into the same (k0, k1) the cookie crate's
        // golden vector uses (byte 0 is the least-significant byte of k0).
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let v = encode_cookie_key(key);
        assert_eq!(v.k0, 0x0706_0504_0302_0100);
        assert_eq!(v.k1, 0x0f0e_0d0c_0b0a_0908);
    }

    #[test]
    fn cookie_key_zero_and_max_round_trip() {
        assert_eq!(
            encode_cookie_key([0u8; 16]),
            CookieKeyValue { k0: 0, k1: 0 }
        );
        assert_eq!(
            encode_cookie_key([0xff; 16]),
            CookieKeyValue {
                k0: u64::MAX,
                k1: u64::MAX,
            }
        );
    }
}
