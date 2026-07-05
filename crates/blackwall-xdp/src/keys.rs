//! Encode `IpNet`/`IpAddr` into the shared LPM-trie map keys.

use blackwall_xdp_common::{lpm_key_v4, lpm_key_v6, LpmKeyV4, LpmKeyV6};
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
}
