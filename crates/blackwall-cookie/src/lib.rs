//! Shared `#![no_std]` core of the Blackwall TCP SYN-cookie (keyed
//! SipHash-2-4), reusable from both the userspace deception tier
//! (`blackwall-deception`) and the in-kernel XDP data plane
//! (`blackwall-xdp-ebpf`, sub-project B2).
//!
//! A SYN-cookie packs a coarse time counter and an MSS-table index into the
//! TCP initial sequence number of a SYN-ACK, authenticated with a keyed
//! SipHash-2-4 tag, so the responder needs **no per-connection state**: the
//! cookie is fully recomputed from the returning ACK. This mirrors the shape
//! of Linux's `net/ipv4/syncookies.c`.
//!
//! This crate is the literal, single source of the cookie math: raw octet
//! slices and primitives only, no allocation, no `std`. Both call sites
//! ([`make_cookie_raw`] / [`check_cookie_raw`]) compile this exact code, so
//! userspace and XDP are guaranteed to produce byte-identical cookies for the
//! same key, tuple, MSS, and time — there is no second implementation to
//! drift out of sync. See `blackwall-deception::cookie` for the
//! `std`-flavored wrappers (`ConnTuple`, `CookieKey`, `IpAddr` handling) built
//! on top of this core.
#![no_std]

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
#[expect(
    clippy::too_many_arguments,
    reason = "raw tuple fields, no std/alloc struct available in this no_std core"
)]
// `#[inline(always)]`: in the eBPF data plane (`blackwall-xdp-ebpf`) this is
// reached from two call sites (the IPv4 and IPv6 SYN-cookie fast paths). With
// more than one caller the BPF backend would otherwise emit it out-of-line, and
// its lowered >5-argument signature is rejected by the BPF calling convention
// ("stack arguments are not supported"). Forcing inlining keeps every call a
// leaf within the XDP program, as it already was for the single-caller v4 path.
#[inline(always)]
fn cookie_for_slot(
    key_k0: u64,
    key_k1: u64,
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

    let hasher = SipHasher24::new_with_keys(key_k0, key_k1);
    let hash = hasher.hash(&buf[..pos]);

    // `t & 0xFF` is < 256 by construction, always fits in `u8`.
    let t_low = u8::try_from(t & 0xFF).unwrap_or(0);
    // `hash & HASH_MASK` is < 2^21 by construction, always fits in `u32`.
    let hash_low = u32::try_from(hash & HASH_MASK).unwrap_or(0);

    (u32::from(t_low) << 24) | (u32::from(mss_index & 0x7) << 21) | hash_low
}

/// Low-level cookie construction over raw address octets, ports, MSS, and
/// the current time.
///
/// This is the `no_std` core: no `IpAddr`, no allocation, no key type — the
/// 128-bit secret key is passed as the pre-split `(k0, k1)` little-endian
/// `u64` pair the keyed SipHash-2-4 constructor needs (mirrors
/// `blackwall-deception::CookieKey::to_u64_pair`). `src_octets`/`dst_octets`
/// are the address's canonical bytes (4 for IPv4, 16 for IPv6).
///
/// Returns `(cookie_seq, mss_used)`.
#[expect(
    clippy::too_many_arguments,
    reason = "raw tuple fields, no std/alloc struct available in this no_std core"
)]
// `#[inline(always)]`: forced inlining so the BPF backend never outlines this
// >5-argument function (its stack-argument calling convention is unsupported on
// BPF). It is called from both the IPv4 and IPv6 in-kernel SYN-cookie fast
// paths in `blackwall-xdp-ebpf`; see the note on [`cookie_for_slot`].
#[inline(always)]
#[must_use]
pub fn make_cookie_raw(
    key_k0: u64,
    key_k1: u64,
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
        key_k0, key_k1, src_octets, src_port, dst_octets, dst_port, mss_index, t,
    );
    (cookie, mss_used)
}

/// Low-level cookie validation over raw address octets, ports, the ACK's
/// sequence number, and the current time. The `no_std` counterpart to
/// [`make_cookie_raw`].
///
/// The ACK carries `ack_seq == cookie_seq + 1`. Recomputes the expected
/// cookie for both the current time slot and the previous one (tolerating a
/// slot boundary crossing / one RTT of delay); returns the decoded MSS if
/// either matches, `None` otherwise.
#[expect(
    clippy::too_many_arguments,
    reason = "raw tuple fields, no std/alloc struct available in this no_std core"
)]
#[must_use]
pub fn check_cookie_raw(
    key_k0: u64,
    key_k1: u64,
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
            key_k0, key_k1, src_octets, src_port, dst_octets, dst_port, mss_index, t,
        );
        if expected == cookie {
            return Some(MSS_TABLE[usize::from(mss_index)]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const K0: u64 = 0x0706_0504_0302_0100;
    const K1: u64 = 0x0f0e_0d0c_0b0a_0908;
    const OTHER_K0: u64 = 0xf7f6_f5f4_f3f2_f1f0;
    const OTHER_K1: u64 = 0xfffe_fdfc_fbfa_f9f8;

    const NOW: u64 = 1_000_000;

    const SRC: [u8; 4] = [203, 0, 113, 7];
    const SRC_PORT: u16 = 54_321;
    const DST: [u8; 4] = [198, 51, 100, 1];
    const DST_PORT: u16 = 443;

    const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    #[test]
    fn cookie_validates_at_same_slot() {
        let (seq, mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        assert_eq!(
            check_cookie_raw(
                K0,
                K1,
                &SRC,
                SRC_PORT,
                &DST,
                DST_PORT,
                seq.wrapping_add(1),
                NOW
            ),
            Some(mss)
        );
    }

    #[test]
    fn cookie_validates_at_next_slot() {
        let (seq, mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        let next_slot_now = NOW + 64;
        assert_eq!(
            check_cookie_raw(
                K0,
                K1,
                &SRC,
                SRC_PORT,
                &DST,
                DST_PORT,
                seq.wrapping_add(1),
                next_slot_now
            ),
            Some(mss)
        );
    }

    #[test]
    fn cookie_fails_two_slots_later() {
        let (seq, _mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        let two_slots_later = NOW + 200;
        assert_eq!(
            check_cookie_raw(
                K0,
                K1,
                &SRC,
                SRC_PORT,
                &DST,
                DST_PORT,
                seq.wrapping_add(1),
                two_slots_later
            ),
            None
        );
    }

    #[test]
    fn cookie_fails_for_different_tuple() {
        let (seq, _mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        let wrong_port = SRC_PORT.wrapping_add(1);
        assert_eq!(
            check_cookie_raw(
                K0,
                K1,
                &SRC,
                wrong_port,
                &DST,
                DST_PORT,
                seq.wrapping_add(1),
                NOW
            ),
            None
        );
    }

    #[test]
    fn cookie_fails_for_flipped_ack_bit() {
        let (seq, _mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        let tampered_ack = seq.wrapping_add(1) ^ 0x0000_0100;
        assert_eq!(
            check_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, tampered_ack, NOW),
            None
        );
    }

    #[test]
    fn cookie_fails_for_wrong_key() {
        let (seq, _mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        assert_eq!(
            check_cookie_raw(
                OTHER_K0,
                OTHER_K1,
                &SRC,
                SRC_PORT,
                &DST,
                DST_PORT,
                seq.wrapping_add(1),
                NOW
            ),
            None
        );
    }

    #[test]
    fn mss_round_trips_through_the_table() {
        let (seq, mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1500, NOW);
        assert_eq!(mss, 1460, "1460 is the largest table entry <= 1500");
        assert_eq!(
            check_cookie_raw(
                K0,
                K1,
                &SRC,
                SRC_PORT,
                &DST,
                DST_PORT,
                seq.wrapping_add(1),
                NOW
            ),
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
        let (seq, mss) = make_cookie_raw(K0, K1, &SRC6, SRC_PORT, &DST6, DST_PORT, 1460, NOW);
        assert_eq!(
            check_cookie_raw(
                K0,
                K1,
                &SRC6,
                SRC_PORT,
                &DST6,
                DST_PORT,
                seq.wrapping_add(1),
                NOW
            ),
            Some(mss)
        );
    }

    /// Golden vector: a fixed (key, tuple, mss, time) pins a hard-coded `u32`
    /// cookie. This is B2.1's byte-identical guarantee — the raw core lives
    /// in exactly one place (this crate), so there is no second
    /// implementation (e.g. a future XDP re-implementation) that could
    /// silently diverge from it; any change to the wire format or hash
    /// mixing here will break this test.
    #[test]
    fn golden_vector_v4_cookie() {
        let (seq, mss) = make_cookie_raw(K0, K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
        assert_eq!(
            seq, 0x09D7_DE6F,
            "golden v4 cookie changed: hash core drifted"
        );
        assert_eq!(mss, 1460);
    }

    /// Golden vector for the IPv6 tuple.
    #[test]
    fn golden_vector_v6_cookie() {
        let (seq, mss) = make_cookie_raw(K0, K1, &SRC6, SRC_PORT, &DST6, DST_PORT, 1460, NOW);
        assert_eq!(
            seq, 0x09DF_596A,
            "golden v6 cookie changed: hash core drifted"
        );
        assert_eq!(mss, 1460);
    }
}
