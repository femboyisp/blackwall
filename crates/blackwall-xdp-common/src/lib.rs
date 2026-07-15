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
/// A TCP SYN that cleared every gate (protected prefix + port, per-source
/// `RATE` budget, valid `COOKIE_KEY`) but was denied a SipHash-cookie SYN-ACK
/// because the global per-CPU [`TxBucket`] mint budget (sub-project X3) was
/// exhausted. The SYN falls through to its normal non-cookie verdict instead
/// of being answered via `XDP_TX`. Distinguishing this from [`REASON_PASS`]
/// lets userspace tell "the box is at its configured SYN-ACK ceiling" apart
/// from "nothing matched the fast path".
pub const REASON_SYNCOOKIE_TXCAPPED: u32 = 5;
/// Number of reason codes (stats array length).
pub const REASON_COUNT: u32 = 6;

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
///
/// # Race-free RMW (X1): per-CPU fallback
///
/// A `bpf_spin_lock`-guarded single shared bucket (one `LruHashMap` entry per
/// source, locked around the refill + decrement) was attempted first and
/// **rejected by the verifier** on this toolchain: aya-ebpf 0.1.1's `#[map]`
/// macro emits the legacy `bpf_map_def`-based `maps` ELF section rather than
/// a BTF-defined map, so aya never populates
/// `btf_key_type_id`/`btf_value_type_id` at map-creation time and the kernel
/// refuses `bpf_spin_lock` with `map 'RATE' has to have BTF in order to use
/// bpf_spin_lock` (reproduced live via `BPF_PROG_TEST_RUN`, kernel 6.18).
/// Fixing that would mean hand-rolling a BTF-defined-map ELF layout aya-ebpf
/// 0.1.1 doesn't emit for `#[map]` statics -- out of scope here.
///
/// The shipped fix instead makes `RATE` an `LruPerCpuHashMap` (see the `RATE`
/// map declaration in `blackwall-xdp-ebpf/src/main.rs`): each CPU gets its
/// own independent [`RateBucket`] copy for a given source, so
/// `bpf_map_lookup_elem` from the eBPF program is inherently isolated per CPU
/// (the kernel indexes it by the running CPU) and the refill/decrement RMW in
/// `over_rate` needs no lock -- there is no other CPU that can observe or
/// mutate the same memory.
///
/// This is race-free but **looser than the single shared-bucket design**: a
/// source's effective admitted rate becomes up to `N_cpus x configured
/// burst` (RSS can spread one spoofed-source flood across every RX
/// queue/CPU, each with its own full token bucket) rather than the exact
/// configured limit -- never *tighter*, only looser. Userspace
/// summing/reconciling per-CPU bucket state into a single reported rate is a
/// follow-on (not implemented here); today each CPU is seeded with the same
/// `tokens = burst` on install.
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

/// Value of the single-entry, per-CPU `TX_BUDGET` map: the global SYN-cookie
/// `XDP_TX` mint-rate token bucket (sub-project X3).
///
/// # Why a *global* cap on top of the per-source `RATE` limiter
///
/// [`RateBucket`] throttles per **source** address, but a spoofed SYN flood
/// rotates through addresses the attacker does not own -- each spoofed source
/// gets its own fresh, never-reused bucket, so the per-source limiter never
/// engages and the in-kernel cookie fast path mints (and `XDP_TX`-bounces) a
/// SYN-ACK for every single spoofed SYN. `TxBucket` bounds the **aggregate**
/// mint rate regardless of how many distinct (spoofed) sources are involved,
/// turning an unbounded gain-1 reflector into one with a hard ceiling.
///
/// # Per-CPU fallback (mirrors [`RateBucket`])
///
/// Same X1 rationale applies here: this toolchain's `#[map]` macro cannot
/// emit a BTF-defined map, so a `bpf_spin_lock`-guarded single shared bucket
/// is rejected by the verifier. `TX_BUDGET` is instead a `PerCpuArray` with
/// one slot -- each CPU holds its own independent copy, so the refill/decrement
/// RMW in `tx_budget_ok` needs no lock. The **aggregate** ceiling across the
/// box is therefore up to `N_cpus x rate_pps` admitted SYN-ACKs per second,
/// not the single configured `rate_pps` -- looser than the nominal rate under
/// RSS spread, never tighter (same tradeoff [`RateBucket`] documents).
///
/// # `rate_pps == 0` means "not configured"
///
/// Unlike [`RateBucket`] (which is per-source and simply has no entry when
/// unconfigured, so the `HashMap` lookup misses and the caller never
/// throttles), `TX_BUDGET` is a `PerCpuArray` -- slot `0` always exists, even
/// before userspace ever writes to it, and reads back as all-zero. The eBPF
/// side's `tx_budget_ok` treats `rate_pps == 0` (the zero-initialised default,
/// or a value userspace explicitly leaves at zero) as "cap not configured" and
/// never throttles -- this is what keeps the fast path's pre-X3 behavior (and
/// tests) unchanged until Task 3's userspace setter installs a nonzero rate.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxBucket {
    /// Tokens currently available.
    pub tokens: u64,
    /// `bpf_ktime_get_ns()` of the last refill.
    pub last_ns: u64,
    /// Refill rate in packets (SYN-ACKs) per second. `0` means the cap is not
    /// configured (see the struct-level doc comment) -- `tx_budget_ok` never
    /// throttles in that case.
    pub rate_pps: u64,
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

/// Number of packet bytes snapshotted into a [`CaptureFrame`] (sub-project
/// B4.1). A fixed cap keeps the ring record a compile-time-sized POD the eBPF
/// side can `reserve`; 96 bytes covers Ethernet + IPv4/IPv6 + TCP/UDP headers
/// (enough to identify a flow) while staying small. The eBPF program stores
/// `cap_len = min(frame_len, CAP_SNAP_LEN)` actual bytes; userspace reads only
/// the first `cap_len`.
pub const CAP_SNAP_LEN: usize = 96;

/// Fixed header the eBPF capture path writes ahead of the packet snapshot in
/// each [`CaptureFrame`] ring record (sub-project B4.1), parsed by the
/// userspace pcap encoder.
///
/// `#[repr(C)]` with the `u64` first and four `u32`s after it, so the layout is
/// exactly 24 bytes with no interior or trailing padding — the byte contract
/// shared between the in-kernel writer and the userspace reader. All fields are
/// stored in host-native byte order (the eBPF program and userspace reader
/// share the machine's endianness, exactly as [`RateBucket`]/[`CookieKeyValue`]
/// already do).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureRecord {
    /// `bpf_ktime_get_ns()` at the decision — nanoseconds since boot
    /// (`CLOCK_MONOTONIC`), not wall-clock epoch time.
    pub timestamp_ns: u64,
    /// The `REASON_*` code of the decision that acted on this packet.
    pub reason: u32,
    /// The `XDP_*` verdict the program returned for this packet (the raw
    /// `xdp_action` value: `XDP_DROP`/`XDP_PASS`/`XDP_TX`/`XDP_REDIRECT`).
    pub verdict: u32,
    /// Original frame length in bytes (may exceed [`CAP_SNAP_LEN`]).
    pub pkt_len: u32,
    /// Number of packet bytes actually snapshotted into the frame
    /// (`min(pkt_len, CAP_SNAP_LEN)`); the reader ignores bytes past this.
    pub cap_len: u32,
}

/// One ring-buffer record: the fixed [`CaptureRecord`] header immediately
/// followed by a fixed [`CAP_SNAP_LEN`]-byte snapshot buffer (sub-project
/// B4.1).
///
/// A compile-time-sized `#[repr(C)]` POD (24 + 96 = 120 bytes, 8-byte aligned)
/// so the eBPF side can `RingBuf::reserve::<CaptureFrame>()` it in one shot. The
/// snapshot buffer is fixed-length for the verifier's sake; only the header's
/// `cap_len` bytes are meaningful, the tail is unspecified.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CaptureFrame {
    /// The record header.
    pub header: CaptureRecord,
    /// Packet snapshot; only `header.cap_len` leading bytes are valid.
    pub data: [u8; CAP_SNAP_LEN],
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
    fn tx_bucket_is_pod_no_padding() {
        // Three `u64`s, no padding: the byte layout shared with the eBPF
        // `TX_BUDGET` reader/writer.
        assert_eq!(core::mem::size_of::<TxBucket>(), 24);
        assert_eq!(core::mem::align_of::<TxBucket>(), 8);
        let b = TxBucket {
            tokens: 1,
            last_ns: 2,
            rate_pps: 3,
        };
        assert_eq!(b.tokens, 1);
        assert_eq!(b.last_ns, 2);
        assert_eq!(b.rate_pps, 3);
    }

    #[test]
    fn reason_syncookie_txcapped_is_last_and_bumps_count() {
        assert_eq!(REASON_SYNCOOKIE_TXCAPPED, 5);
        assert_eq!(REASON_COUNT, 6);
    }

    #[test]
    fn capture_record_layout_is_24_bytes_no_padding() {
        // The header contract: u64 timestamp + four u32s, 8-byte aligned, no
        // interior or trailing padding — 24 bytes exactly.
        assert_eq!(core::mem::size_of::<CaptureRecord>(), 24);
        assert_eq!(core::mem::align_of::<CaptureRecord>(), 8);
    }

    #[test]
    fn capture_frame_is_header_plus_snapshot() {
        // 24-byte header + 96-byte snapshot, 8-byte aligned (so the eBPF ring
        // `reserve` alignment assertion `8 % align == 0` holds).
        assert_eq!(core::mem::size_of::<CaptureFrame>(), 24 + CAP_SNAP_LEN);
        assert_eq!(core::mem::align_of::<CaptureFrame>(), 8);
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
