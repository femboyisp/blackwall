//! Stateless TCP SYN-cookie encoding and validation (keyed SipHash-2-4).
//!
//! A SYN-cookie packs a coarse time counter and an MSS-table index into the
//! TCP initial sequence number of a SYN-ACK, authenticated with a keyed
//! SipHash-2-4 tag, so the responder needs **no per-connection state**: the
//! cookie is fully recomputed from the returning ACK. This mirrors the shape
//! of Linux's `net/ipv4/syncookies.c`.
//!
//! The core (`make_cookie_raw` / `check_cookie_raw`) takes raw octet slices
//! and primitives only — no `String`/`Vec`/allocation in the hot path — so
//! the identical logic can be called from a `#![no_std]` eBPF crate (the B2
//! XDP promotion) and produce byte-identical cookies to this userspace tier.

use std::fmt;
use std::net::IpAddr;

use siphasher::sip::SipHasher24;

/// Plausible MSS values a stateless SYN-ACK can advertise, smallest first.
///
/// Mirrors the shape of Linux's `msstab`: [`mss_index_for`] picks the
/// largest entry that is less than or equal to the client's advertised MSS.
pub const MSS_TABLE: [u16; 8] = [216, 536, 1200, 1360, 1400, 1440, 1460, 8960];

/// Right-shift applied to the Unix timestamp (seconds) to obtain the coarse
/// time counter `t`. A shift of 6 yields 64-second time slots.
pub const COUNTER_SHIFT: u32 = 6;

/// Number of low bits of the SipHash output kept in the cookie (21 bits).
const HASH_MASK: u64 = 0x001F_FFFF;

/// Maximum size of the scratch buffer hashed per cookie: two 16-byte (IPv6)
/// addresses, two 2-byte ports, an 8-byte time counter, and a 1-byte MSS
/// index.
const MAX_TUPLE_BUF: usize = 16 + 2 + 16 + 2 + 8 + 1;

/// A 128-bit secret key for the SYN-cookie SipHash, with a redacted [`Debug`].
///
/// The key never appears in a `Debug`-formatted log or dumped config; the
/// caller owns generation and rotation (see the design's "Secret" note).
/// Mirrors `blackwall_core::Md5Secret`'s redaction pattern.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CookieKey([u8; 16]);

impl CookieKey {
    /// Wrap a 128-bit secret key.
    #[must_use]
    pub fn new(key: [u8; 16]) -> Self {
        Self(key)
    }

    /// Split the key into the `(k0, k1)` little-endian `u64` pair the keyed
    /// SipHash-2-4 constructor needs.
    #[must_use]
    pub fn to_u64_pair(self) -> (u64, u64) {
        let mut k0 = [0_u8; 8];
        let mut k1 = [0_u8; 8];
        k0.copy_from_slice(&self.0[0..8]);
        k1.copy_from_slice(&self.0[8..16]);
        (u64::from_le_bytes(k0), u64::from_le_bytes(k1))
    }
}

impl fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CookieKey(***)")
    }
}

/// The 4-tuple identifying a connection: source/destination address and
/// port. Supports both IPv4 and IPv6 (`IpAddr` is `Copy`, no allocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnTuple {
    /// Client (source) address.
    pub src: IpAddr,
    /// Client (source) port.
    pub src_port: u16,
    /// Server (destination) address.
    pub dst: IpAddr,
    /// Server (destination) port.
    pub dst_port: u16,
}

/// Write `addr`'s octets into `buf` and return how many bytes were written
/// (4 for IPv4, 16 for IPv6).
fn ip_addr_octets(addr: IpAddr, buf: &mut [u8; 16]) -> usize {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            buf[..octets.len()].copy_from_slice(&octets);
            octets.len()
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            buf[..octets.len()].copy_from_slice(&octets);
            octets.len()
        }
    }
}

/// Pick the MSS-table index (0..=7) whose value is the largest entry in
/// [`MSS_TABLE`] that is less than or equal to `client_mss`. Falls back to
/// index 0 (the smallest table entry) if `client_mss` is smaller than every
/// table entry.
#[must_use]
pub fn mss_index_for(client_mss: u16) -> u8 {
    let mut idx: u8 = 0;
    for (i, &mss) in MSS_TABLE.iter().enumerate() {
        if mss <= client_mss {
            // `i` ranges over `0..MSS_TABLE.len()` (8), always fits in `u8`.
            idx = u8::try_from(i).unwrap_or(idx);
        }
    }
    idx
}

/// Decode the MSS-table index (bits 21..=23) out of a cookie value.
fn decode_mss_index(cookie: u32) -> u8 {
    let idx = (cookie >> 21) & 0x7;
    // Masked to 3 bits, always < 8, always fits in `u8`.
    u8::try_from(idx).unwrap_or(0)
}

/// Hash the connection tuple, time counter, and MSS index with the keyed
/// SipHash-2-4, then assemble the cookie: top byte is the low 8 bits of `t`,
/// next 3 bits are `mss_index`, and the low 21 bits are the truncated hash.
fn cookie_for_slot(
    key: &CookieKey,
    src_octets: &[u8],
    src_port: u16,
    dst_octets: &[u8],
    dst_port: u16,
    mss_index: u8,
    t: u64,
) -> u32 {
    let mut buf = [0_u8; MAX_TUPLE_BUF];
    let mut pos = 0_usize;

    buf[pos..pos + src_octets.len()].copy_from_slice(src_octets);
    pos += src_octets.len();

    let src_port_bytes = src_port.to_be_bytes();
    buf[pos..pos + src_port_bytes.len()].copy_from_slice(&src_port_bytes);
    pos += src_port_bytes.len();

    buf[pos..pos + dst_octets.len()].copy_from_slice(dst_octets);
    pos += dst_octets.len();

    let dst_port_bytes = dst_port.to_be_bytes();
    buf[pos..pos + dst_port_bytes.len()].copy_from_slice(&dst_port_bytes);
    pos += dst_port_bytes.len();

    let t_bytes = t.to_be_bytes();
    buf[pos..pos + t_bytes.len()].copy_from_slice(&t_bytes);
    pos += t_bytes.len();

    buf[pos] = mss_index;
    pos += 1;

    let (k0, k1) = key.to_u64_pair();
    let hasher = SipHasher24::new_with_keys(k0, k1);
    let hash = hasher.hash(&buf[..pos]);

    // `t & 0xFF` is < 256 by construction, always fits in `u8`.
    let t_low = u8::try_from(t & 0xFF).unwrap_or(0);
    // `hash & HASH_MASK` is < 2^21 by construction, always fits in `u32`.
    let hash_low = u32::try_from(hash & HASH_MASK).unwrap_or(0);

    (u32::from(t_low) << 24) | (u32::from(mss_index & 0x7) << 21) | hash_low
}

/// Low-level cookie construction over raw address octets, ports, MSS, and
/// the current time. This is the `no_std`-friendly core B2's eBPF crate
/// calls directly (no `IpAddr`, no allocation): `src_octets`/`dst_octets`
/// are the address's canonical bytes (4 for IPv4, 16 for IPv6).
///
/// Returns `(cookie_seq, mss_used)`.
#[must_use]
pub fn make_cookie_raw(
    key: &CookieKey,
    src_octets: &[u8],
    src_port: u16,
    dst_octets: &[u8],
    dst_port: u16,
    client_mss: u16,
    now_secs: u64,
) -> (u32, u16) {
    let mss_index = mss_index_for(client_mss);
    let mss_used = MSS_TABLE[usize::from(mss_index)];
    let t = now_secs >> COUNTER_SHIFT;
    let cookie = cookie_for_slot(
        key, src_octets, src_port, dst_octets, dst_port, mss_index, t,
    );
    (cookie, mss_used)
}

/// Low-level cookie validation over raw address octets, ports, the ACK's
/// sequence number, and the current time. The `no_std`-friendly counterpart
/// to [`make_cookie_raw`].
///
/// The ACK carries `ack_seq == cookie_seq + 1`. Recomputes the expected
/// cookie for both the current time slot and the previous one (tolerating a
/// slot boundary crossing / one RTT of delay); returns the decoded MSS if
/// either matches, `None` otherwise.
#[must_use]
pub fn check_cookie_raw(
    key: &CookieKey,
    src_octets: &[u8],
    src_port: u16,
    dst_octets: &[u8],
    dst_port: u16,
    ack_seq: u32,
    now_secs: u64,
) -> Option<u16> {
    let cookie = ack_seq.wrapping_sub(1);
    let mss_index = decode_mss_index(cookie);
    let t_now = now_secs >> COUNTER_SHIFT;

    for t in [t_now, t_now.wrapping_sub(1)] {
        let expected = cookie_for_slot(
            key, src_octets, src_port, dst_octets, dst_port, mss_index, t,
        );
        if expected == cookie {
            return Some(MSS_TABLE[usize::from(mss_index)]);
        }
    }
    None
}

/// Build a SYN-cookie for `tuple` and the client's advertised MSS.
///
/// Returns `(cookie_seq, mss_used)`: `cookie_seq` is the TCP initial sequence
/// number to send in the SYN-ACK, and `mss_used` is the MSS value (from
/// [`MSS_TABLE`]) to echo in the MSS option.
#[must_use]
pub fn make_cookie(
    key: &CookieKey,
    tuple: &ConnTuple,
    client_mss: u16,
    now_secs: u64,
) -> (u32, u16) {
    let mut src_buf = [0_u8; 16];
    let src_len = ip_addr_octets(tuple.src, &mut src_buf);
    let mut dst_buf = [0_u8; 16];
    let dst_len = ip_addr_octets(tuple.dst, &mut dst_buf);

    make_cookie_raw(
        key,
        &src_buf[..src_len],
        tuple.src_port,
        &dst_buf[..dst_len],
        tuple.dst_port,
        client_mss,
        now_secs,
    )
}

/// Validate a returning ACK's sequence number against `tuple`.
///
/// The ACK carries `ack_seq == cookie_seq + 1`. Tolerates a time-slot
/// boundary (checks both the current and previous 64-second slot). Returns
/// the MSS to use for the connection if the cookie is valid, `None`
/// otherwise (spoofed, stray, or expired).
#[must_use]
pub fn check_cookie(
    key: &CookieKey,
    tuple: &ConnTuple,
    ack_seq: u32,
    now_secs: u64,
) -> Option<u16> {
    let mut src_buf = [0_u8; 16];
    let src_len = ip_addr_octets(tuple.src, &mut src_buf);
    let mut dst_buf = [0_u8; 16];
    let dst_len = ip_addr_octets(tuple.dst, &mut dst_buf);

    check_cookie_raw(
        key,
        &src_buf[..src_len],
        tuple.src_port,
        &dst_buf[..dst_len],
        tuple.dst_port,
        ack_seq,
        now_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const KEY: CookieKey = CookieKey([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]);
    const OTHER_KEY: CookieKey = CookieKey([
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ]);

    const NOW: u64 = 1_000_000;

    fn v4_tuple() -> ConnTuple {
        ConnTuple {
            src: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            src_port: 54_321,
            dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_port: 443,
        }
    }

    fn v6_tuple() -> ConnTuple {
        ConnTuple {
            src: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            src_port: 54_321,
            dst: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            dst_port: 443,
        }
    }

    #[test]
    fn cookie_validates_at_same_slot() {
        let tuple = v4_tuple();
        let (seq, mss) = make_cookie(&KEY, &tuple, 1460, NOW);
        assert_eq!(
            check_cookie(&KEY, &tuple, seq.wrapping_add(1), NOW),
            Some(mss)
        );
    }

    #[test]
    fn cookie_validates_at_next_slot() {
        let tuple = v4_tuple();
        let (seq, mss) = make_cookie(&KEY, &tuple, 1460, NOW);
        let next_slot_now = NOW + 64;
        assert_eq!(
            check_cookie(&KEY, &tuple, seq.wrapping_add(1), next_slot_now),
            Some(mss)
        );
    }

    #[test]
    fn cookie_fails_two_slots_later() {
        let tuple = v4_tuple();
        let (seq, _mss) = make_cookie(&KEY, &tuple, 1460, NOW);
        let two_slots_later = NOW + 200;
        assert_eq!(
            check_cookie(&KEY, &tuple, seq.wrapping_add(1), two_slots_later),
            None
        );
    }

    #[test]
    fn cookie_fails_for_different_tuple() {
        let tuple = v4_tuple();
        let (seq, _mss) = make_cookie(&KEY, &tuple, 1460, NOW);

        let mut wrong_port_tuple = tuple;
        wrong_port_tuple.src_port = tuple.src_port.wrapping_add(1);

        assert_eq!(
            check_cookie(&KEY, &wrong_port_tuple, seq.wrapping_add(1), NOW),
            None
        );
    }

    #[test]
    fn cookie_fails_for_flipped_ack_bit() {
        let tuple = v4_tuple();
        let (seq, _mss) = make_cookie(&KEY, &tuple, 1460, NOW);
        let tampered_ack = seq.wrapping_add(1) ^ 0x0000_0100;
        assert_eq!(check_cookie(&KEY, &tuple, tampered_ack, NOW), None);
    }

    #[test]
    fn cookie_fails_for_wrong_key() {
        let tuple = v4_tuple();
        let (seq, _mss) = make_cookie(&KEY, &tuple, 1460, NOW);
        assert_eq!(
            check_cookie(&OTHER_KEY, &tuple, seq.wrapping_add(1), NOW),
            None
        );
    }

    #[test]
    fn mss_round_trips_through_the_table() {
        let tuple = v4_tuple();
        let (seq, mss) = make_cookie(&KEY, &tuple, 1500, NOW);
        assert_eq!(mss, 1460, "1460 is the largest table entry <= 1500");
        assert_eq!(
            check_cookie(&KEY, &tuple, seq.wrapping_add(1), NOW),
            Some(1460)
        );
    }

    #[test]
    fn mss_falls_back_to_smallest_entry_when_client_mss_too_small() {
        assert_eq!(mss_index_for(100), 0);
        assert_eq!(MSS_TABLE[usize::from(mss_index_for(100))], 216);
    }

    #[test]
    fn mss_picks_exact_and_largest_matching_entries() {
        assert_eq!(MSS_TABLE[usize::from(mss_index_for(1200))], 1200);
        assert_eq!(MSS_TABLE[usize::from(mss_index_for(9000))], 8960);
    }

    #[test]
    fn ipv6_tuple_round_trips() {
        let tuple = v6_tuple();
        let (seq, mss) = make_cookie(&KEY, &tuple, 1460, NOW);
        assert_eq!(
            check_cookie(&KEY, &tuple, seq.wrapping_add(1), NOW),
            Some(mss)
        );
    }

    #[test]
    fn raw_form_matches_conn_tuple_form() {
        let tuple = v4_tuple();
        let src_octets = match tuple.src {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => unreachable!("test tuple is v4"),
        };
        let dst_octets = match tuple.dst {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => unreachable!("test tuple is v4"),
        };

        let via_tuple = make_cookie(&KEY, &tuple, 1460, NOW);
        let via_raw = make_cookie_raw(
            &KEY,
            &src_octets,
            tuple.src_port,
            &dst_octets,
            tuple.dst_port,
            1460,
            NOW,
        );
        assert_eq!(via_tuple, via_raw);

        let (seq, _mss) = via_tuple;
        let ack = seq.wrapping_add(1);
        assert_eq!(
            check_cookie(&KEY, &tuple, ack, NOW),
            check_cookie_raw(
                &KEY,
                &src_octets,
                tuple.src_port,
                &dst_octets,
                tuple.dst_port,
                ack,
                NOW
            )
        );
    }

    #[test]
    fn cookie_key_debug_is_redacted() {
        let key = CookieKey::new([0xAB; 16]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "CookieKey(***)");
        assert!(!debug.contains("AB"));
        assert!(!debug.contains("171")); // 0xAB as decimal, in case of accidental derive
    }
}
