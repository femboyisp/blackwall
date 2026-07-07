//! Shared, `#![no_std]`-safe POD types for the Blackwall XDP data plane, used
//! by both the eBPF program and the userspace loader so the map byte layout
//! has a single definition.
#![no_std]

/// IP-version discriminants used in stats/logging.
pub const V4: u8 = 4;
/// IPv6 discriminant.
pub const V6: u8 = 6;

/// Stat reason codes (index into the per-CPU stats array).
pub const REASON_PASS: u32 = 0;
/// Dropped by the blocklist.
pub const REASON_BLOCKLIST: u32 = 1;
/// Dropped by the per-source rate limiter.
pub const REASON_RATELIMIT: u32 = 2;
/// Answered in-kernel with a SipHash-cookie SYN-ACK bounced out via `XDP_TX`
/// (sub-project B2.2). Counts SYNs absorbed at the driver level ahead of nft.
pub const REASON_SYNCOOKIE: u32 = 3;
/// Redirected to a userspace `AF_XDP` socket via the `XSKS` [`BPF_MAP_TYPE_XSKMAP`]
/// (sub-project B3.1). Counts frames matching the redirect condition that were
/// handed to the zero-copy/copy-mode `AF_XDP` receiver ahead of the kernel stack.
pub const REASON_REDIRECT: u32 = 4;
/// Number of reason codes (stats array length).
pub const REASON_COUNT: u32 = 5;

/// LPM-trie key for the IPv4 source blocklist (`bpf_lpm_trie_key` layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV4 {
    /// Significant prefix length in bits (0..=32).
    pub prefixlen: u32,
    /// Big-endian address bytes.
    pub addr: [u8; 4],
}

/// LPM-trie key for the IPv6 source blocklist.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV6 {
    /// Significant prefix length in bits (0..=128).
    pub prefixlen: u32,
    /// Big-endian address bytes.
    pub addr: [u8; 16],
}

/// Per-source token bucket value for the rate-limit map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateBucket {
    /// Tokens currently available.
    pub tokens: u64,
    /// `bpf_ktime_get_ns()` of the last refill.
    pub last_ns: u64,
    /// Refill rate in packets per second.
    pub rate_pps: u64,
    /// Maximum token capacity (burst).
    pub burst: u64,
}

/// A single per-CPU counter entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    /// Packets counted.
    pub packets: u64,
    /// Bytes counted.
    pub bytes: u64,
}

/// Value of the single-entry `COOKIE_KEY` map: the 128-bit SYN-cookie secret,
/// pre-split into the SipHash-2-4 `(k0, k1)` little-endian `u64` pair the cookie
/// core ([`blackwall_cookie::make_cookie_raw`]) consumes.
///
/// The split is performed once, in userspace ([`crate`]'s consumer
/// `blackwall_xdp::keys::encode_cookie_key`), so the eBPF SYN handler reads
/// `k0`/`k1` directly with no in-kernel byte juggling. Both `u64`s are stored in
/// the map in host-native byte order — userspace and the eBPF program share the
/// machine's endianness, exactly as the `RateBucket` `u64` fields already do.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CookieKeyValue {
    /// Low 64 bits of the key (`u64::from_le_bytes(key[0..8])`).
    pub k0: u64,
    /// High 64 bits of the key (`u64::from_le_bytes(key[8..16])`).
    pub k1: u64,
}

/// Build an IPv4 LPM key.
#[must_use]
pub fn lpm_key_v4(prefixlen: u8, addr: [u8; 4]) -> LpmKeyV4 {
    LpmKeyV4 {
        prefixlen: u32::from(prefixlen),
        addr,
    }
}

/// Build an IPv6 LPM key.
#[must_use]
pub fn lpm_key_v6(prefixlen: u8, addr: [u8; 16]) -> LpmKeyV6 {
    LpmKeyV6 {
        prefixlen: u32::from(prefixlen),
        addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpm_key_v4_layout() {
        let k = lpm_key_v4(24, [203, 0, 113, 0]);
        assert_eq!(k.prefixlen, 24);
        assert_eq!(k.addr, [203, 0, 113, 0]);
        // POD size: u32 prefixlen + 4 bytes addr = 8 bytes.
        assert_eq!(core::mem::size_of::<LpmKeyV4>(), 8);
    }

    #[test]
    fn lpm_key_v6_layout() {
        let k = lpm_key_v6(128, [0; 16]);
        assert_eq!(k.prefixlen, 128);
        assert_eq!(core::mem::size_of::<LpmKeyV6>(), 20);
    }

    #[test]
    fn rate_bucket_and_stat_are_pod() {
        assert_eq!(core::mem::size_of::<RateBucket>(), 32);
        assert_eq!(core::mem::size_of::<Stat>(), 16);
    }

    #[test]
    fn cookie_key_value_is_pod() {
        // Two `u64`s, no padding: the byte layout shared with the eBPF reader.
        assert_eq!(core::mem::size_of::<CookieKeyValue>(), 16);
        let v = CookieKeyValue { k0: 1, k1: 2 };
        assert_eq!(v.k0, 1);
        assert_eq!(v.k1, 2);
    }
}
