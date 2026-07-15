//! Blackwall XDP filter data plane (`xdp_filter`).
//!
//! Parses `Ethernet -> IPv4/IPv6` with explicit bounds checks, then applies, in
//! order, per source address: (1) an LPM blocklist drop, (2) a per-source LRU
//! token-bucket rate-limit drop, (3) — for an IPv4 **or IPv6** TCP **SYN** (ACK
//! clear) — an in-kernel SipHash-cookie **SYN-ACK** answered via `XDP_TX`
//! (sub-project B2.2 for IPv4, B2.3c for IPv6), and otherwise (4) pass. Every
//! decision bumps a per-CPU stats counter
//! keyed by reason code. Map names (`BLOCK_V4`, `BLOCK_V6`, `RATE`, `STATS`)
//! and the shared POD layouts in `blackwall-xdp-common` form the contract
//! consumed by the userspace loader.
//!
//! # In-kernel SYN-cookie (B2.2)
//!
//! On an IPv4 TCP segment with SYN set and ACK clear, [`try_synack_v4`]
//! transforms the packet **in place, at the same byte length**, into a SYN-ACK
//! whose sequence number is a stateless SipHash SYN-cookie (computed by the
//! shared [`blackwall_cookie`] core, byte-identical to the userspace deception
//! tier) and bounces it back out the ingress interface with `XDP_TX`, absorbing
//! SYN floods at the driver level ahead of nft. A legitimate client's
//! subsequent ACK is **not** validated here — it falls through to `XDP_PASS`
//! and the existing userspace NFQUEUE tier validates the cookie (with the same
//! key) and serves the banner.
//!
//! # Production cookie key + time base (B2.3a)
//!
//! The cookie secret is no longer a compile-time constant: it is read from the
//! single-entry `COOKIE_KEY` BPF map, populated from userspace
//! ([`blackwall_xdp::XdpDataplane::set_cookie_key`]) with the same 128-bit
//! secret the NFQUEUE tier validates against. If the map entry is absent (key
//! never installed) the SYN handler bails to `XDP_PASS` rather than mint a
//! cookie under a zero/garbage key.
//!
//! The cookie time base is now [`bpf_ktime_get_ns`] (nanoseconds since boot,
//! `CLOCK_MONOTONIC`) divided down to seconds — a real, monotonic clock rather
//! than a fixed constant. **Cross-tier requirement:** the userspace responder
//! that validates the returning ACK must slot the cookie against the *same*
//! clock. As of B2.3c-2a the userspace NFQUEUE responder also reads
//! `CLOCK_MONOTONIC` and shares this tier's cookie secret via the
//! Postgres-backed `cookie_secret` (B2.3c-1), so both tiers now agree on the
//! same key and the same 64-second time slot.
//!
//! # Protected-prefix + protected-port gating (B2.3b)
//!
//! The SYN-cookie fast path is **safety-gated**: [`try_synack_v4`] mints a
//! SYN-ACK only when the SYN's *destination* IP LPM-matches a protected
//! deception prefix in the userspace-populated [`PROTECT_V4`] trie **and** its
//! *destination* TCP port is present in [`PROTECT_PORT`]. Either miss falls
//! through to `XDP_PASS`, leaving real services on non-deception prefixes and
//! ports untouched — critical, because once a cookie key is loaded an ungated
//! handler would hijack every inbound TCP connection on the box. Both maps are
//! empty until userspace installs entries
//! (`blackwall_xdp::XdpDataplane::set_protected_prefixes` /
//! `set_protected_ports`), so before configuration the fast path answers
//! nothing — even with a cookie key present.
//!
//! # IPv6 fast path (B2.3c)
//!
//! [`try_synack_v6`] is the IPv6 mirror of [`try_synack_v4`]: it answers an IPv6
//! TCP SYN whose destination LPM-matches the [`PROTECT_V6`] trie and whose port
//! is in the shared [`PROTECT_PORT`] set, rewriting the frame in place into a
//! SYN-ACK carrying the same stateless SipHash cookie (computed over the 16-byte
//! v6 addresses) and bouncing it with `XDP_TX`. IPv6 has no L3 header checksum,
//! and the TCP checksum's pseudo-header covers the 16-byte addresses + 32-bit
//! TCP length + next-header byte — the two structural differences from v4.
//!
//! # `as`-cast exemption
//!
//! Unlike the rest of the Blackwall workspace, this eBPF crate is **exempt from
//! the no-`as`-cast guideline**. Raw pointer construction for the verifier
//! (`(start + offset) as *const T`) and bounds-derived length arithmetic have no
//! ergonomic checked-conversion equivalent in `#![no_std]` eBPF context, so
//! `as` is used deliberately in those idioms. The userspace crates keep the
//! no-`as` rule.
#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_xdp_load_bytes};
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{HashMap, LpmTrie, LruPerCpuHashMap, PerCpuArray, RingBuf, XskMap};
use aya_ebpf::programs::XdpContext;
use blackwall_cookie::make_cookie_raw;
use blackwall_xdp_common::{
    CaptureFrame, CaptureRecord, CookieKeyValue, RateBucket, Stat, TxBucket, CAP_SNAP_LEN,
    REASON_BLOCKLIST, REASON_COUNT, REASON_PASS, REASON_RATELIMIT, REASON_REDIRECT,
    REASON_SYNCOOKIE, REASON_SYNCOOKIE_TXCAPPED,
};
use core::mem;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;

#[map]
static BLOCK_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(65536, 1);
#[map]
static BLOCK_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(65536, 1);
/// Per-source token bucket, keyed by 16-byte source (v4 zero-padded). An
/// `LruPerCpuHashMap` (X1 fallback — see [`RateBucket`]'s doc comment for why
/// a single `bpf_spin_lock`-guarded bucket was rejected by the verifier on
/// this toolchain): each CPU holds its own independent bucket for a given
/// source, so `over_rate`'s refill/decrement RMW is inherently race-free
/// (never observed or mutated by another CPU) at the cost of an effective
/// per-source limit of up to `N_cpus × configured burst` under an
/// RSS-spread flood, rather than the exact configured value.
#[map]
static RATE: LruPerCpuHashMap<[u8; 16], RateBucket> =
    LruPerCpuHashMap::with_max_entries(1_048_576, 0);
#[map]
static STATS: PerCpuArray<Stat> = PerCpuArray::with_max_entries(REASON_COUNT, 0);
/// Single-slot (index `0`) global per-CPU SYN-cookie `XDP_TX` mint-rate token
/// bucket (sub-project X3 — see [`TxBucket`]'s doc comment for the full
/// rationale and the per-CPU aggregate-ceiling tradeoff). Zero-initialised
/// (`rate_pps == 0`) until userspace writes a nonzero rate, which
/// [`tx_budget_ok`] treats as "cap not configured" so the fast path's pre-X3
/// behavior is unchanged by default.
#[map]
static TX_BUDGET: PerCpuArray<TxBucket> = PerCpuArray::with_max_entries(1, 0);
/// Single-entry map (key `0`) holding the 128-bit SYN-cookie secret, pre-split
/// into the SipHash `(k0, k1)` pair (see [`CookieKeyValue`]). Populated from
/// userspace before the program answers any SYN; an absent entry makes the SYN
/// handler bail to `XDP_PASS` rather than mint a cookie under a garbage key. A
/// `HashMap` (not an `Array`) is used precisely so *absence* is observable — a
/// one-element `Array` would always return a zeroed value, indistinguishable
/// from an unconfigured key.
#[map]
static COOKIE_KEY: HashMap<u32, CookieKeyValue> = HashMap::with_max_entries(1, 0);
/// Fixed map key of the sole [`COOKIE_KEY`] entry.
const COOKIE_KEY_SLOT: u32 = 0;
/// Protected IPv4 deception prefixes (the box's *own* addresses that run the
/// deception tier). The SYN-cookie fast path answers a SYN only if its
/// **destination** IP LPM-matches an entry here; a miss falls through to
/// `XDP_PASS` so real services on non-deception prefixes are never hijacked.
/// Mirrors [`BLOCK_V4`]'s `{prefixlen:u32, addr:[u8;4]}` LPM-key layout, but is
/// a *destination* allowlist rather than a source blocklist. Empty until
/// userspace installs prefixes, so an unconfigured box answers no SYNs.
#[map]
static PROTECT_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(65536, 1);
/// Protected IPv6 deception prefixes — the IPv6 counterpart of [`PROTECT_V4`]
/// (sub-project B2.3c). The SYN-cookie fast path answers an IPv6 SYN only if its
/// **destination** address LPM-matches an entry here; a miss falls through to
/// `XDP_PASS`. Mirrors [`BLOCK_V6`]'s `{prefixlen:u32, addr:[u8;16]}` LPM-key
/// layout, but is a *destination* allowlist rather than a source blocklist.
/// Empty until userspace installs prefixes, so an unconfigured box answers no
/// IPv6 SYNs.
#[map]
static PROTECT_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(65536, 1);
/// Protected TCP **destination** ports (the configured deception ports). The
/// SYN-cookie fast path answers a SYN only if its destination TCP port is
/// present here. A `HashMap` used as a set (value is an ignored `1u8`); keyed
/// by the port's host-native `u16` value — the eBPF side reads the destination
/// port with [`load_be16`] (yielding the numeric port), and userspace inserts
/// the same numeric `u16`, so both agree without any extra byte-swap. Empty
/// until userspace installs ports.
#[map]
static PROTECT_PORT: HashMap<u16, u8> = HashMap::with_max_entries(65536, 0);
/// AF_XDP socket array (sub-project B3.1): one entry per RX queue, populated
/// from userspace ([`blackwall_xdp::AfXdpReceiver`]) with a bound `AF_XDP`
/// socket's fd. The redirect fast path hands a matching frame to the socket
/// bound at the frame's own `rx_queue_index`. Empty until userspace registers a
/// socket, so an unconfigured box redirects nothing (the `redirect` fallback
/// action is `XDP_PASS`).
#[map]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);
/// UDP **destination** ports whose IPv4 datagrams are redirected to the `AF_XDP`
/// socket in [`XSKS`] (sub-project B3.1). A `HashMap` used as a set (value is an
/// ignored `1u8`), keyed by the host-native numeric `u16` port — userspace
/// inserts the same numeric value the eBPF side reads via [`load_be16`]. Empty
/// until userspace installs a port, so no traffic is diverted by default.
///
/// B3.2: the real deception-tier use case will replace this simple port set with
/// the actual redirect condition (e.g. per-flow / per-prefix marks).
#[map]
static REDIRECT_PORT: HashMap<u16, u8> = HashMap::with_max_entries(65536, 0);
/// xdpcap-style packet-capture ring (sub-project B4.1): when capture is enabled
/// the decision path pushes a [`CaptureFrame`] (fixed [`CaptureRecord`] header +
/// up to [`CAP_SNAP_LEN`] snapshot bytes) here for the userspace reader
/// ([`blackwall_xdp::XdpCapture`]) to drain and emit as pcap. 256 KiB (a
/// power-of-2 page multiple, as the kernel requires). The daemon pins this map
/// to bpffs so a separate `blackwalld xdp capture` process can open the same
/// ring. When [`CAPTURE_ENABLED`] is unset the decision path never touches this
/// ring, so an idle box pays only a single flag lookup — no ring work.
#[map]
static CAPTURE: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Single-entry (key `0`) capture on/off flag (sub-project B4.1), mirroring
/// [`COOKIE_KEY`]'s single-flag-map pattern: absent or `0` means capture is
/// disabled, `1` means enabled. Userspace sets it before draining and clears it
/// on stop/drop. A `HashMap` (not an `Array`) so *absence* is the natural
/// disabled state. The daemon pins this map to bpffs alongside [`CAPTURE`].
#[map]
static CAPTURE_ENABLED: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);
/// Fixed map key of the sole [`CAPTURE_ENABLED`] entry.
const CAPTURE_ENABLED_SLOT: u32 = 0;

// Absolute packet offsets for the Ethernet + IPv4 (IHL 5) + TCP layout the
// SYN-cookie fast path operates on. Every access is still `ptr_at`
// bounds-checked; these name the byte positions, they do not assert them.
/// Ethernet destination MAC.
const OFF_MAC_DST: usize = 0;
/// Ethernet source MAC.
const OFF_MAC_SRC: usize = 6;
/// IPv4 header start (after the Ethernet header).
const OFF_IP: usize = EthHdr::LEN;
/// IPv4 header-checksum field.
const OFF_IP_CHECK: usize = OFF_IP + 10;
/// IPv4 source address.
const OFF_IP_SRC: usize = OFF_IP + 12;
/// IPv4 destination address.
const OFF_IP_DST: usize = OFF_IP + 16;
/// TCP header start (Ethernet + 20-byte IPv4 header).
const OFF_TCP: usize = OFF_IP + Ipv4Hdr::LEN;
/// TCP source port.
const OFF_TCP_SRCPORT: usize = OFF_TCP;
/// TCP destination port.
const OFF_TCP_DSTPORT: usize = OFF_TCP + 2;
/// UDP destination port (same byte position as the TCP destination port for the
/// fixed Ethernet + IPv4(IHL 5) + L4 layout: the L4 header starts at [`OFF_TCP`]
/// and both TCP and UDP carry the destination port at header offset 2).
const OFF_UDP_DSTPORT: usize = OFF_TCP + 2;
/// TCP sequence number.
const OFF_TCP_SEQ: usize = OFF_TCP + 4;
/// TCP acknowledgment number.
const OFF_TCP_ACK: usize = OFF_TCP + 8;
/// TCP data-offset byte (high nibble = header words, low nibble reserved).
const OFF_TCP_DATAOFF: usize = OFF_TCP + 12;
/// TCP flags byte (CWR..FIN); the data-offset nibble is in the byte before it.
const OFF_TCP_FLAGS: usize = OFF_TCP + 13;
/// TCP window field.
const OFF_TCP_WINDOW: usize = OFF_TCP + 14;
/// TCP checksum field.
const OFF_TCP_CHECK: usize = OFF_TCP + 16;
/// TCP urgent-pointer field.
const OFF_TCP_URG: usize = OFF_TCP + 18;
/// TCP options region (after the fixed 20-byte TCP header).
const OFF_TCP_OPTS: usize = OFF_TCP + 20;

// Absolute packet offsets for the Ethernet + IPv6 (fixed 40-byte header) + TCP
// layout the IPv6 SYN-cookie fast path operates on. IPv6 has no IHL and no
// header checksum; the fixed header is always 40 bytes, so TCP begins at
// `EthHdr::LEN + 40`. Every access is still `ptr_at` bounds-checked.
/// IPv6 header start (after the Ethernet header; same position as [`OFF_IP`]).
const OFF_IP6: usize = EthHdr::LEN;
/// IPv6 source address (16 bytes at header offset 8).
const OFF_IP6_SRC: usize = OFF_IP6 + 8;
/// IPv6 destination address (16 bytes at header offset 24).
const OFF_IP6_DST: usize = OFF_IP6 + 24;
/// TCP header start (Ethernet + 40-byte fixed IPv6 header).
const OFF_TCP6: usize = OFF_IP6 + Ipv6Hdr::LEN;
/// TCP source port (IPv6).
const OFF_TCP6_SRCPORT: usize = OFF_TCP6;
/// TCP destination port (IPv6).
const OFF_TCP6_DSTPORT: usize = OFF_TCP6 + 2;
/// TCP sequence number (IPv6).
const OFF_TCP6_SEQ: usize = OFF_TCP6 + 4;
/// TCP acknowledgment number (IPv6).
const OFF_TCP6_ACK: usize = OFF_TCP6 + 8;
/// TCP data-offset byte (IPv6).
const OFF_TCP6_DATAOFF: usize = OFF_TCP6 + 12;
/// TCP flags byte (IPv6).
const OFF_TCP6_FLAGS: usize = OFF_TCP6 + 13;
/// TCP window field (IPv6).
const OFF_TCP6_WINDOW: usize = OFF_TCP6 + 14;
/// TCP checksum field (IPv6).
const OFF_TCP6_CHECK: usize = OFF_TCP6 + 16;
/// TCP urgent-pointer field (IPv6).
const OFF_TCP6_URG: usize = OFF_TCP6 + 18;
/// TCP options region (IPv6; after the fixed 20-byte TCP header).
const OFF_TCP6_OPTS: usize = OFF_TCP6 + 20;

/// TCP flags for a bare SYN-ACK: ACK (0x10) | SYN (0x02), all others clear.
const TCP_FLAGS_SYN_ACK: u8 = 0x12;
/// Advertised window in the SYN-ACK; mirrors the userspace tier's
/// `STATELESS_WINDOW` so the two responders look identical on the wire.
const SYNACK_WINDOW: u16 = 65535;
/// Default client MSS assumed when the SYN carries no MSS option (mirrors
/// `blackwall_deception::transport::packet::DEFAULT_CLIENT_MSS`).
const DEFAULT_CLIENT_MSS: u16 = 1460;
/// Upper bound on the TCP options region in bytes (data-offset nibble is 4
/// bits, so the whole TCP header is at most 60 bytes: 60 - 20 = 40).
const MAX_TCP_OPTS: usize = 40;
/// Upper bound (bytes) on the TCP segment the checksum covers. A SYN carries no
/// payload, so the segment is just the header (<= 60 bytes); segments larger
/// than this bail to `XDP_PASS` rather than emit a wrong checksum. B2.2 scope.
const MAX_TCP_SEG: usize = 64;

/// Nanoseconds per second, dividing [`bpf_ktime_get_ns`] down to the
/// seconds-since-boot the cookie core slots (`>> COUNTER_SHIFT`) internally.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Fixed burst cap for the global per-CPU [`TX_BUDGET`] token bucket
/// (sub-project X3). Unlike [`RateBucket`], [`TxBucket`] carries no per-instance
/// `burst` field (see its doc comment), so the cap is this compile-time
/// constant: a round number comfortably above any sane sustained per-CPU
/// SYN-ACK burst, so a correctly configured `rate_pps` is never truncated by
/// this ceiling -- it only guards against `tokens` growing without bound
/// between refills (e.g. after a long idle period).
const TX_BUDGET_BURST: u64 = 1_000_000;

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    Ok(ptr_at::<T>(ctx, offset)? as *mut T)
}

/// Bounds-checked single-byte load from the packet at `offset`.
#[inline(always)]
fn load_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    let p: *const u8 = ptr_at(ctx, offset)?;
    // SAFETY: `ptr_at` bounds-checked one byte at `offset` against `data_end`.
    Ok(unsafe { *p })
}

/// Bounds-checked single-byte store into the packet at `offset`.
#[inline(always)]
fn store_u8(ctx: &XdpContext, offset: usize, value: u8) -> Result<(), ()> {
    let p: *mut u8 = ptr_at_mut(ctx, offset)?;
    // SAFETY: `ptr_at_mut` bounds-checked one writable byte at `offset`.
    unsafe { *p = value };
    Ok(())
}

/// Load a big-endian `u16` from the packet at `offset`.
#[inline(always)]
fn load_be16(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let hi = load_u8(ctx, offset)?;
    let lo = load_u8(ctx, offset + 1)?;
    Ok((u16::from(hi) << 8) | u16::from(lo))
}

/// Store a `u16` big-endian into the packet at `offset`.
#[inline(always)]
fn store_be16(ctx: &XdpContext, offset: usize, value: u16) -> Result<(), ()> {
    store_u8(ctx, offset, (value >> 8) as u8)?;
    store_u8(ctx, offset + 1, (value & 0xff) as u8)
}

/// Load a big-endian `u32` from the packet at `offset`.
#[inline(always)]
fn load_be32(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let hi = load_be16(ctx, offset)?;
    let lo = load_be16(ctx, offset + 2)?;
    Ok((u32::from(hi) << 16) | u32::from(lo))
}

/// Store a `u32` big-endian into the packet at `offset`.
#[inline(always)]
fn store_be32(ctx: &XdpContext, offset: usize, value: u32) -> Result<(), ()> {
    store_be16(ctx, offset, (value >> 16) as u16)?;
    store_be16(ctx, offset + 2, (value & 0xffff) as u16)
}

/// Load a 16-byte address from the packet at `offset` with a **single**
/// bounds-checked read, returned as a stack array. Used for the IPv6 src/dst
/// addresses: reading all 16 bytes in one `ptr_at` (as [`ipv4_checksum`] does
/// for the 20-byte IPv4 header) keeps the verifier happy, whereas a per-byte
/// loop summed against `data_end` is rejected after bpf-linker coalesces the
/// guards.
#[inline(always)]
fn load_addr16(ctx: &XdpContext, offset: usize) -> Result<[u8; 16], ()> {
    let p: *const [u8; 16] = ptr_at(ctx, offset)?;
    // SAFETY: `ptr_at` bounds-checked all 16 bytes at `offset` against `data_end`.
    Ok(unsafe { *p })
}

/// Ones-complement partial sum of a 16-byte address as eight big-endian 16-bit
/// words — the IPv6 TCP-checksum pseudo-header contribution of one address.
/// Returned as a `u32` accumulator the caller folds with the rest of the sum.
#[inline(always)]
fn sum_addr16(addr: &[u8; 16]) -> u32 {
    let mut sum: u32 = 0;
    for k in 0..8 {
        sum += u32::from(u16::from_be_bytes([addr[k * 2], addr[k * 2 + 1]]));
    }
    sum
}

/// Swap `N` consecutive bytes at `a` with the `N` at `b` (constant `N` keeps
/// the loop verifier-friendly). Used to exchange MAC/IP/port pairs in place.
#[inline(always)]
fn swap_bytes<const N: usize>(ctx: &XdpContext, a: usize, b: usize) -> Result<(), ()> {
    for k in 0..N {
        let x = load_u8(ctx, a + k)?;
        let y = load_u8(ctx, b + k)?;
        store_u8(ctx, a + k, y)?;
        store_u8(ctx, b + k, x)?;
    }
    Ok(())
}

/// Fold a 32-bit ones-complement accumulator down to the final 16-bit Internet
/// checksum. Two unrolled folds cover any accumulator this program produces
/// (bounded well under `2^20`), avoiding a `while` loop.
#[inline(always)]
fn fold_checksum(sum: u32) -> u16 {
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

fn count(reason: u32, bytes: u64) {
    if let Some(s) = STATS.get_ptr_mut(reason) {
        // SAFETY: `get_ptr_mut` returned a valid pointer into this CPU's slot
        // for `reason` (< REASON_COUNT); it is exclusively ours for this call.
        unsafe {
            (*s).packets += 1;
            (*s).bytes += bytes;
        }
    }
}

/// True if userspace has enabled packet capture (the [`CAPTURE_ENABLED`] flag
/// entry is present and non-zero). This is the short-circuit that keeps capture
/// zero-cost beyond a single map lookup when disabled.
#[inline(always)]
fn capture_enabled() -> bool {
    // SAFETY: `CAPTURE_ENABLED` is only ever read here; the returned reference is
    // consumed (copied to a bool) before any map mutation, of which this program
    // performs none on it.
    matches!(unsafe { CAPTURE_ENABLED.get(&CAPTURE_ENABLED_SLOT) }, Some(&v) if v != 0)
}

/// Copy exactly `N` bytes from the packet at offset 0 (Ethernet L2) into `dst`
/// with `bpf_xdp_load_bytes`, returning `true` on success.
///
/// `N` is a compile-time constant, so the verifier sees a nonzero, in-range
/// length — a runtime `min(frame_len, CAP_SNAP_LEN)` is rejected as a
/// possibly-zero-sized read. The helper bounds-checks the packet read itself and
/// returns non-zero (→ `false`) when the frame is shorter than `N`, so the caller
/// can fall to a smaller tier. `dst` must have room for at least `N` bytes.
#[inline(always)]
fn snapshot_bytes<const N: usize>(ctx: &XdpContext, dst: *mut core::ffi::c_void) -> bool {
    // SAFETY: `dst` is the reserved ring slot's `CAP_SNAP_LEN`-byte snapshot
    // buffer (`CAP_SNAP_LEN >= N`), and `bpf_xdp_load_bytes` bounds-checks the
    // packet read against the frame length, returning an error for a short frame.
    unsafe { bpf_xdp_load_bytes(ctx.ctx, 0, dst, N as u32) == 0 }
}

/// Record the decision `(reason, verdict)` for `ctx` into the [`CAPTURE`] ring
/// when capture is enabled (sub-project B4.1). No-op — a single flag lookup and
/// return — when disabled, so it is safe to call on every verdict.
///
/// Reserves one fixed [`CaptureFrame`] slot, writes the header, snapshots up to
/// [`CAP_SNAP_LEN`] bytes of the frame from offset 0 (Ethernet L2) with the
/// bounds-checking `bpf_xdp_load_bytes` helper, and submits it. If the ring is
/// full (`reserve` returns `None`) or the snapshot copy fails the sample is
/// dropped silently — capture never affects the verdict.
#[inline(always)]
fn capture(ctx: &XdpContext, reason: u32, verdict: u32, frame_len: u64) {
    if !capture_enabled() {
        return;
    }
    let Some(mut entry) = CAPTURE.reserve::<CaptureFrame>(0) else {
        // Ring full: drop this sample rather than block or fail the verdict.
        return;
    };
    let frame = entry.as_mut_ptr();
    // SAFETY: `frame` is the reserved ring slot; `data` is its `CAP_SNAP_LEN`-byte
    // snapshot buffer, valid to hand to the snapshot helper as the destination.
    let dst = unsafe { (*frame).data.as_mut_ptr() } as *mut core::ffi::c_void;
    // Snapshot from offset 0 (Ethernet L2) in descending fixed-size tiers. Each
    // `snapshot_bytes` call passes a *compile-time constant* length, so the
    // verifier sees a nonzero, in-range size (a runtime `min(frame_len,
    // CAP_SNAP_LEN)` is rejected as a possibly-zero-sized read, and a per-byte
    // copy loop trips the verifier's coalesced `data_end` guards — see
    // `ipv4_checksum`). The largest tier the frame can satisfy wins; a frame too
    // short even for the smallest tier is dropped. Short frames are truncated to
    // the largest tier they fit (fine for header inspection).
    let cap_len = if snapshot_bytes::<{ CAP_SNAP_LEN }>(ctx, dst) {
        CAP_SNAP_LEN as u32
    } else if snapshot_bytes::<64>(ctx, dst) {
        64
    } else if snapshot_bytes::<32>(ctx, dst) {
        32
    } else if snapshot_bytes::<20>(ctx, dst) {
        20
    } else if snapshot_bytes::<14>(ctx, dst) {
        14
    } else {
        0
    };
    if cap_len == 0 {
        // Frame shorter than the smallest tier: discard so the reader never sees
        // a header-only record.
        entry.discard(0);
        return;
    }
    // SAFETY: `bpf_ktime_get_ns` is always safe to call from XDP context.
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    // SAFETY: `frame` is the reserved, writable ring slot; writing the header
    // initialises the record the reader parses.
    unsafe {
        (*frame).header = CaptureRecord {
            timestamp_ns,
            reason,
            verdict,
            pkt_len: frame_len as u32,
            cap_len,
        };
    }
    entry.submit(0);
}

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    try_filter(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let frame_len = (ctx.data_end() - ctx.data()) as u64;
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    // SAFETY: `ptr_at` bounds-checked `EthHdr` bytes against `data_end`.
    let ethertype = unsafe { (*eth).ether_type };
    match ethertype {
        EtherType::Ipv4 => {
            let ip: *const Ipv4Hdr = ptr_at(ctx, OFF_IP)?;
            // SAFETY: `ptr_at` bounds-checked the IPv4 header.
            let src = unsafe { (*ip).src_addr() }.octets();
            if blocked_v4(src) {
                count(REASON_BLOCKLIST, frame_len);
                capture(ctx, REASON_BLOCKLIST, xdp_action::XDP_DROP, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
            let mut key16 = [0u8; 16];
            key16[..4].copy_from_slice(&src);
            if over_rate(key16) {
                count(REASON_RATELIMIT, frame_len);
                capture(ctx, REASON_RATELIMIT, xdp_action::XDP_DROP, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
            // B3.1: divert IPv4 UDP datagrams whose destination port is in the
            // userspace-populated REDIRECT_PORT set to the AF_XDP socket in XSKS.
            // A miss (non-UDP, IP options present, port not configured) bails and
            // falls through to the SYN-cookie/PASS behavior below.
            if let Ok(action) = try_redirect_udp_v4(ctx) {
                count(REASON_REDIRECT, frame_len);
                capture(ctx, REASON_REDIRECT, action, frame_len);
                return Ok(action);
            }
            // Absorb a TCP SYN in-kernel with a SipHash-cookie SYN-ACK
            // (`XDP_TX`); anything else (non-TCP, non-SYN, malformed options)
            // bails out of this fast path and falls through to `XDP_PASS`.
            if let Ok(action) = try_synack_v4(ctx) {
                count(REASON_SYNCOOKIE, frame_len);
                // Snapshot before the in-place SYN->SYN-ACK rewrite has left the
                // reply on the wire; the frame now holds the rewritten SYN-ACK.
                capture(ctx, REASON_SYNCOOKIE, action, frame_len);
                return Ok(action);
            }
        }
        EtherType::Ipv6 => {
            let ip: *const Ipv6Hdr = ptr_at(ctx, OFF_IP)?;
            // SAFETY: `ptr_at` bounds-checked the IPv6 header.
            let src = unsafe { (*ip).src_addr() }.octets();
            if blocked_v6(src) {
                count(REASON_BLOCKLIST, frame_len);
                capture(ctx, REASON_BLOCKLIST, xdp_action::XDP_DROP, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
            if over_rate(src) {
                count(REASON_RATELIMIT, frame_len);
                capture(ctx, REASON_RATELIMIT, xdp_action::XDP_DROP, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
            // Absorb an IPv6 TCP SYN in-kernel with a SipHash-cookie SYN-ACK
            // (`XDP_TX`); anything else (non-TCP next-header, non-SYN, malformed
            // options, unprotected dst) bails out of this fast path and falls
            // through to `XDP_PASS`. Mirrors the IPv4 `try_synack_v4` call.
            if let Ok(action) = try_synack_v6(ctx) {
                count(REASON_SYNCOOKIE, frame_len);
                // Snapshot after the in-place SYN->SYN-ACK rewrite: the frame now
                // holds the rewritten SYN-ACK about to leave on the wire.
                capture(ctx, REASON_SYNCOOKIE, action, frame_len);
                return Ok(action);
            }
        }
        _ => {}
    }
    count(REASON_PASS, frame_len);
    capture(ctx, REASON_PASS, xdp_action::XDP_PASS, frame_len);
    Ok(xdp_action::XDP_PASS)
}

/// Mint the stateless SipHash SYN-cookie for the packet's IPv6 connection tuple,
/// reading the (pre-swap) tuple straight from the packet at the v6 header
/// offsets. Returns `(cookie_seq, mss_used)`, or `Err(())` when the cookie key
/// is absent (never installed) — the caller **must** invoke this before any
/// packet mutation so that a bail leaves the frame untouched.
///
/// `#[inline(never)]`: this is deliberately its own bpf-to-bpf subprogram, so
/// the SipHash scratch buffer (bigger for v6's 16-byte addresses) and the call
/// into the `siphasher` hash routine live on *this* frame rather than inflating
/// [`try_synack_v6`]. That splits the IPv6 cookie chain into
/// `xdp_filter` → `try_synack_v6` → `compute_cookie_v6` → `siphasher::hash`,
/// four small frames whose sizes sum under the 512-byte `MAX_BPF_STACK` limit —
/// a single self-contained v6 synack subprogram (like the v4 one) would exceed
/// it. The v4 path keeps its cookie inline because its 4-byte-address scratch is
/// small enough to fit self-contained.
#[inline(never)]
fn compute_cookie_v6(ctx: &XdpContext) -> Result<(u32, u16), ()> {
    // Read the secret from the userspace-populated map. Absent => bail so the
    // caller falls through to `XDP_PASS`; never mint under a zero/garbage key.
    let (k0, k1) = cookie_keys()?;
    // Cookie time base: real monotonic seconds-since-boot (`CLOCK_MONOTONIC`);
    // `make_cookie_raw` slots it with `>> COUNTER_SHIFT` internally. The
    // userspace responder validates the returning ACK against the same clock.
    // SAFETY: `bpf_ktime_get_ns` is always safe to call from XDP context.
    let now_secs = unsafe { bpf_ktime_get_ns() } / NS_PER_SEC;
    let src = load_addr16(ctx, OFF_IP6_SRC)?;
    let dst = load_addr16(ctx, OFF_IP6_DST)?;
    let src_port = load_be16(ctx, OFF_TCP6_SRCPORT)?;
    let dst_port = load_be16(ctx, OFF_TCP6_DSTPORT)?;
    let client_mss = parse_mss(ctx, OFF_TCP6_OPTS)?;
    Ok(make_cookie_raw(
        k0, k1, &src, src_port, &dst, dst_port, client_mss, now_secs,
    ))
}

/// Attempt the B2.2 in-kernel SYN-cookie transform on an IPv4 packet.
///
/// Returns `Ok(XDP_TX)` if the packet was an IPv4 (IHL 5) TCP SYN (ACK clear)
/// **destined for a protected deception prefix + port** (the B2.3b gate) with
/// room in its options for a 4-byte MSS option, and was rewritten in place —
/// same byte length — into a SipHash-cookie SYN-ACK ready to bounce back out the
/// ingress interface. Returns `Err(())` for anything else (non-TCP, IP options
/// present, not a SYN, destination not in [`PROTECT_V4`]/[`PROTECT_PORT`], no
/// options room, or a segment larger than [`MAX_TCP_SEG`]); the caller then
/// falls through to `XDP_PASS`.
///
/// All bounds are validated *before* any mutation, so a bail can never leave a
/// half-rewritten packet on the wire.
///
/// `#[inline(never)]`: emitted as its own bpf-to-bpf subprogram, self-contained
/// (the SipHash cookie is minted inline here). Its deepest chain is `xdp_filter`
/// → `try_synack_v4` → `siphasher::hash`, well under the 512-byte
/// `MAX_BPF_STACK` budget. The IPv6 twin instead offloads the cookie to the
/// [`compute_cookie_v6`] subprogram, because the larger 16-byte-address scratch
/// would otherwise bust the budget (see [`try_synack_v6`]).
#[inline(never)]
fn try_synack_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let ip: *const Ipv4Hdr = ptr_at(ctx, OFF_IP)?;
    // SAFETY: `ptr_at` bounds-checked the 20-byte IPv4 header.
    let ihl = unsafe { (*ip).ihl() };
    // SAFETY: same bounds-checked header.
    let proto = unsafe { (*ip).proto };
    if ihl != 5 || proto != IpProto::Tcp {
        return Err(());
    }
    // SAFETY: same bounds-checked header; `tot_len` is stored big-endian.
    let ip_total = usize::from(u16::from_be(unsafe { (*ip).tot_len }));

    let tcp: *const TcpHdr = ptr_at(ctx, OFF_TCP)?;
    // SAFETY: `ptr_at` bounds-checked the fixed 20-byte TCP header.
    let is_syn = unsafe { (*tcp).syn() } == 1;
    // SAFETY: same bounds-checked header.
    let is_ack = unsafe { (*tcp).ack() } == 1;
    if !is_syn || is_ack {
        return Err(());
    }

    // B2.3b gating (SAFETY-CRITICAL): only answer a SYN destined for one of the
    // box's own protected deception prefixes AND a configured deception port.
    // Read the destination IP + port (both in already-bounds-checked headers)
    // and require BOTH the O(1) port-set membership and the LPM prefix match;
    // either miss bails to `XDP_PASS` (frame untouched) so real services on
    // non-deception ports/prefixes pass straight through. Without this an
    // ungated handler would mint a SYN-ACK for every inbound TCP SYN once a
    // cookie key is loaded, hijacking the whole box.
    let dst = [
        load_u8(ctx, OFF_IP_DST)?,
        load_u8(ctx, OFF_IP_DST + 1)?,
        load_u8(ctx, OFF_IP_DST + 2)?,
        load_u8(ctx, OFF_IP_DST + 3)?,
    ];
    let dst_port = load_be16(ctx, OFF_TCP_DSTPORT)?;
    if !protected_port(dst_port) || !protected_v4(dst) {
        return Err(());
    }

    // SAFETY: same bounds-checked header.
    let doff = usize::from(unsafe { (*tcp).doff() });
    if doff < 5 {
        return Err(());
    }
    let tcp_hdr_len = doff * 4;
    let options_len = tcp_hdr_len - 20;
    // Need at least a 4-byte MSS option's worth of options room, and cap the
    // segment the checksum covers (a SYN has no payload).
    if options_len < 4 || options_len > MAX_TCP_OPTS {
        return Err(());
    }
    // A SYN carries no payload: require the IP total length to be exactly the
    // IPv4 + TCP headers. This makes the checksummed TCP segment equal to the
    // header region we rewrite (so no access reads past what we validate) and
    // is the B2.2 scope (TCP Fast Open payloads are out of scope).
    if ip_total != 20 + tcp_hdr_len {
        return Err(());
    }
    let seg_len = tcp_hdr_len;
    if seg_len > MAX_TCP_SEG {
        return Err(());
    }

    // Read the client's 4-tuple, ISN, and advertised MSS.
    let src = [
        load_u8(ctx, OFF_IP_SRC)?,
        load_u8(ctx, OFF_IP_SRC + 1)?,
        load_u8(ctx, OFF_IP_SRC + 2)?,
        load_u8(ctx, OFF_IP_SRC + 3)?,
    ];
    // `dst` and `dst_port` were already read above for the B2.3b gating.
    let src_port = load_be16(ctx, OFF_TCP_SRCPORT)?;
    let client_seq = load_be32(ctx, OFF_TCP_SEQ)?;
    let client_mss = parse_mss(ctx, OFF_TCP_OPTS)?;

    // Read the secret from the userspace-populated map. Absent (never installed)
    // => bail to `XDP_PASS`; we never mint a cookie under a zero/garbage key.
    let (k0, k1) = cookie_keys()?;
    // Cookie time base: real monotonic seconds-since-boot (`CLOCK_MONOTONIC`);
    // `make_cookie_raw` slots it with `>> COUNTER_SHIFT` internally.
    // SAFETY: `bpf_ktime_get_ns` is always safe to call from XDP context.
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let now_secs = now_ns / NS_PER_SEC;

    // X3: the global per-CPU mint budget, checked immediately before minting.
    // A SYN that cleared every other gate (protected prefix+port, per-source
    // `over_rate`, a valid cookie key) but exceeds the box's aggregate budget
    // falls through to its normal non-cookie verdict instead of being answered.
    if !tx_budget_ok(now_ns) {
        let frame_len = (ctx.data_end() - ctx.data()) as u64;
        count(REASON_SYNCOOKIE_TXCAPPED, frame_len);
        return Err(());
    }

    // Compute the stateless SYN-cookie with the shared no_std core.
    let (cookie_seq, mss) =
        make_cookie_raw(k0, k1, &src, src_port, &dst, dst_port, client_mss, now_secs);

    let ack = client_seq.wrapping_add(1);

    // --- in-place, same-length SYN -> SYN-ACK surgery ---
    // Reflect the frame: swap MACs, IP addresses, TCP ports.
    swap_bytes::<6>(ctx, OFF_MAC_DST, OFF_MAC_SRC)?;
    swap_bytes::<4>(ctx, OFF_IP_SRC, OFF_IP_DST)?;
    swap_bytes::<2>(ctx, OFF_TCP_SRCPORT, OFF_TCP_DSTPORT)?;
    // Data offset kept, reserved nibble cleared; seq = cookie; ack =
    // client_seq + 1; flags = SYN|ACK only; fixed window; zeroed urgent pointer.
    store_u8(ctx, OFF_TCP_DATAOFF, (doff << 4) as u8)?;
    store_be32(ctx, OFF_TCP_SEQ, cookie_seq)?;
    store_be32(ctx, OFF_TCP_ACK, ack)?;
    store_u8(ctx, OFF_TCP_FLAGS, TCP_FLAGS_SYN_ACK)?;
    store_be16(ctx, OFF_TCP_WINDOW, SYNACK_WINDOW)?;
    store_be16(ctx, OFF_TCP_URG, 0)?;
    // Rewrite the options region in place: one 4-byte MSS option, NOP-padded to
    // the original options length so the data-offset and total length are
    // unchanged (no resize).
    write_mss_option(ctx, OFF_TCP_OPTS, options_len, mss)?;

    // IPv4 header checksum: recomputed over the fixed 20-byte header.
    store_be16(ctx, OFF_IP_CHECK, 0)?;
    let ip_check = ipv4_checksum(ctx)?;
    store_be16(ctx, OFF_IP_CHECK, ip_check)?;

    // TCP checksum: computed *analytically* from the exact header/options bytes
    // we just wrote plus the (swap-invariant) pseudo-header. A variable-length
    // re-read of the segment is rejected by the verifier (it cannot relate the
    // runtime data-offset to `data_end`), and it is unnecessary — every byte of
    // the reply's TCP segment is a value we chose here.
    let mut sum: u32 = 0;
    // Pseudo-header: source + destination address (the address sum is invariant
    // under the src/dst swap, so the pre-swap octets are fine), protocol, and
    // the TCP segment length.
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += u32::from(IpProto::Tcp as u8);
    sum += seg_len as u32;
    // TCP header words. Ports are swapped; the checksum and urgent-pointer words
    // are zero and contribute nothing.
    sum += u32::from(dst_port); // reply source port = original destination port
    sum += u32::from(src_port); // reply destination port = original source port
    sum += (cookie_seq >> 16) + (cookie_seq & 0xffff);
    sum += (ack >> 16) + (ack & 0xffff);
    sum += ((doff as u32) << 12) | 0x0012; // data-offset word | SYN|ACK flags
    sum += u32::from(SYNACK_WINDOW);
    // Options: one MSS option (kind 2, len 4, mss) then NOP padding, which is an
    // even number of 0x01 bytes (options length is a multiple of 4), i.e.
    // whole 0x0101 words.
    sum += 0x0204;
    sum += u32::from(mss);
    let nop_words = (options_len - 4) / 2;
    sum += (nop_words as u32) * 0x0101;
    let tcp_check = fold_checksum(sum);
    store_be16(ctx, OFF_TCP_CHECK, tcp_check)?;

    Ok(xdp_action::XDP_TX)
}

/// Attempt the B2.3c in-kernel SYN-cookie transform on an **IPv6** packet — the
/// IPv6 mirror of [`try_synack_v4`].
///
/// Returns `Ok(XDP_TX)` if the packet was an IPv6 TCP SYN (ACK clear) whose
/// next-header is TCP (no extension-header chain) **destined for a protected
/// deception prefix + port** (the [`PROTECT_V6`] / [`PROTECT_PORT`] gate) with
/// room in its options for a 4-byte MSS option, rewritten in place — same byte
/// length — into a SipHash-cookie SYN-ACK ready to bounce back out. Returns
/// `Err(())` for anything else (next-header ≠ TCP, not a SYN, destination not in
/// [`PROTECT_V6`]/[`PROTECT_PORT`], no options room, a segment larger than
/// [`MAX_TCP_SEG`], or a payload present); the caller then falls through to
/// `XDP_PASS`.
///
/// Key differences from the IPv4 path:
/// - The IPv6 header is a fixed 40 bytes (no IHL); only a `next_hdr == TCP`
///   packet is handled — any extension header bails to `XDP_PASS`.
/// - IPv6 has **no** header checksum, so none is recomputed.
/// - The TCP checksum's pseudo-header covers the 16-byte v6 src/dst addresses,
///   the 32-bit TCP length, and the next-header byte (6) — differing from v4's
///   4-byte-address pseudo-header.
///
/// All bounds are validated *before* any mutation, so a bail can never leave a
/// half-rewritten packet on the wire.
///
/// `#[inline(never)]`, and — unlike the self-contained [`try_synack_v4`] — the
/// SipHash cookie is offloaded to the dedicated [`compute_cookie_v6`] subprogram
/// so this frame stays small. The deepest chain `xdp_filter` → `try_synack_v6` →
/// `compute_cookie_v6` → `siphasher::hash` then fits the 512-byte `MAX_BPF_STACK`
/// budget, which a self-contained v6 synack (16-byte-address scratch) would not.
#[inline(never)]
fn try_synack_v6(ctx: &XdpContext) -> Result<u32, ()> {
    let ip: *const Ipv6Hdr = ptr_at(ctx, OFF_IP6)?;
    // SAFETY: `ptr_at` bounds-checked the fixed 40-byte IPv6 header.
    let next_hdr = unsafe { (*ip).next_hdr };
    // Only bare TCP is handled: an extension-header chain would push the TCP
    // header past OFF_TCP6, so anything but next-header TCP bails to `XDP_PASS`.
    if next_hdr != IpProto::Tcp {
        return Err(());
    }
    // SAFETY: same bounds-checked header; `payload_len` is stored big-endian.
    // With no extension headers this equals the TCP segment length.
    let payload_len = usize::from(u16::from_be(unsafe { (*ip).payload_len }));

    let tcp: *const TcpHdr = ptr_at(ctx, OFF_TCP6)?;
    // SAFETY: `ptr_at` bounds-checked the fixed 20-byte TCP header.
    let is_syn = unsafe { (*tcp).syn() } == 1;
    // SAFETY: same bounds-checked header.
    let is_ack = unsafe { (*tcp).ack() } == 1;
    if !is_syn || is_ack {
        return Err(());
    }

    // B2.3c gating (SAFETY-CRITICAL): only answer a SYN destined for one of the
    // box's own protected IPv6 deception prefixes AND a configured deception
    // port (ports are family-agnostic, so the same [`PROTECT_PORT`] set is
    // reused). Either miss bails to `XDP_PASS` (frame untouched). The addresses
    // are re-read after the swap for the checksum (below) rather than kept live
    // across `compute_cookie_v6` — keeping them off this frame across that call is a
    // `MAX_BPF_STACK` economy (see [`try_synack_v4`]).
    let dst_port = load_be16(ctx, OFF_TCP6_DSTPORT)?;
    if !protected_port(dst_port) || !protected_v6(load_addr16(ctx, OFF_IP6_DST)?) {
        return Err(());
    }

    // SAFETY: same bounds-checked header.
    let doff = usize::from(unsafe { (*tcp).doff() });
    if doff < 5 {
        return Err(());
    }
    let tcp_hdr_len = doff * 4;
    let options_len = tcp_hdr_len - 20;
    if options_len < 4 || options_len > MAX_TCP_OPTS {
        return Err(());
    }
    // A SYN carries no payload: require the IPv6 payload length to equal the TCP
    // header (no extension headers, no data), so the checksummed segment equals
    // the header region we rewrite. TCP Fast Open payloads are out of scope.
    if payload_len != tcp_hdr_len {
        return Err(());
    }
    let seg_len = tcp_hdr_len;
    if seg_len > MAX_TCP_SEG {
        return Err(());
    }

    // Read the tuple pieces needed for the checksum/ack; the MSS and cookie come
    // from [`compute_cookie_v6`]. `dst_port` was read above for the B2.3c gating.
    // The 16-byte addresses are *not* read here: they are only needed for the
    // pseudo-header sum below, and reading them after the cookie call (and the
    // swap) keeps nothing address-sized live across `compute_cookie_v6`, which the
    // verifier would otherwise spill onto this frame — the difference between
    // fitting and busting the `MAX_BPF_STACK` chain budget.
    let src_port = load_be16(ctx, OFF_TCP6_SRCPORT)?;
    let client_seq = load_be32(ctx, OFF_TCP6_SEQ)?;
    let ack = client_seq.wrapping_add(1);

    // X3: the global per-CPU mint budget, checked immediately before minting
    // (mirrors `try_synack_v4`) — a SYN that cleared every other gate
    // (protected prefix+port, per-source `over_rate`) but exceeds the box's
    // aggregate budget falls through instead of paying for the SipHash cookie
    // that `compute_cookie_v6` would otherwise compute.
    // SAFETY: `bpf_ktime_get_ns` is always safe to call from XDP context.
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if !tx_budget_ok(now_ns) {
        let frame_len = (ctx.data_end() - ctx.data()) as u64;
        count(REASON_SYNCOOKIE_TXCAPPED, frame_len);
        return Err(());
    }

    // Compute the stateless SYN-cookie **before** any mutation (bails to `Err` —
    // hence `XDP_PASS`, frame untouched — if the cookie key is absent), over the
    // 16-byte v6 addresses read from the packet.
    let (cookie_seq, mss) = compute_cookie_v6(ctx)?;

    // --- in-place, same-length SYN -> SYN-ACK surgery ---
    // Reflect the frame: swap MACs, IPv6 addresses, TCP ports. Data offset kept
    // (reserved nibble cleared); seq = cookie; ack = client_seq + 1; flags =
    // SYN|ACK only; fixed window; zeroed urgent pointer.
    swap_bytes::<6>(ctx, OFF_MAC_DST, OFF_MAC_SRC)?;
    swap_bytes::<16>(ctx, OFF_IP6_SRC, OFF_IP6_DST)?;
    swap_bytes::<2>(ctx, OFF_TCP6_SRCPORT, OFF_TCP6_DSTPORT)?;
    store_u8(ctx, OFF_TCP6_DATAOFF, (doff << 4) as u8)?;
    store_be32(ctx, OFF_TCP6_SEQ, cookie_seq)?;
    store_be32(ctx, OFF_TCP6_ACK, ack)?;
    store_u8(ctx, OFF_TCP6_FLAGS, TCP_FLAGS_SYN_ACK)?;
    store_be16(ctx, OFF_TCP6_WINDOW, SYNACK_WINDOW)?;
    store_be16(ctx, OFF_TCP6_URG, 0)?;
    // Rewrite the options region in place: one 4-byte MSS option, NOP-padded to
    // the original options length so the header keeps its byte length.
    write_mss_option(ctx, OFF_TCP6_OPTS, options_len, mss)?;

    // IPv6 has NO header checksum — nothing to recompute at L3.

    // TCP checksum: computed *analytically* from the exact header/options bytes
    // we just wrote plus the IPv6 pseudo-header (the 16-byte source + destination
    // addresses, the 32-bit TCP length, and the next-header byte). The two
    // addresses are read from the packet *now* (post-swap); the address sum is
    // swap-invariant, so this is correct, and it keeps them off the frame across
    // the earlier `compute_cookie_v6` call.
    // Address pseudo-header sum: read the two addresses from the packet now
    // (post-swap; the sum is swap-invariant) and fold them one at a time so only
    // one 16-byte scratch array is live at once and none crossed `compute_cookie_v6`.
    let mut sum: u32 = sum_addr16(&load_addr16(ctx, OFF_IP6_SRC)?);
    sum += sum_addr16(&load_addr16(ctx, OFF_IP6_DST)?);
    sum += u32::from(IpProto::Tcp as u8); // next header = 6
    sum += seg_len as u32; // TCP length (SYN has no payload => header length)
    sum += u32::from(dst_port); // reply source port = original destination port
    sum += u32::from(src_port); // reply destination port = original source port
    sum += (cookie_seq >> 16) + (cookie_seq & 0xffff);
    sum += (ack >> 16) + (ack & 0xffff);
    sum += ((doff as u32) << 12) | 0x0012; // data-offset word | SYN|ACK flags
    sum += u32::from(SYNACK_WINDOW);
    // Options: one MSS option (kind 2, len 4, mss) then NOP padding, which is an
    // even number of 0x01 bytes (options length is a multiple of 4), i.e. whole
    // 0x0101 words.
    sum += 0x0204;
    sum += u32::from(mss);
    let nop_words = (options_len - 4) / 2;
    sum += (nop_words as u32) * 0x0101;
    let tcp_check = fold_checksum(sum);
    store_be16(ctx, OFF_TCP6_CHECK, tcp_check)?;

    Ok(xdp_action::XDP_TX)
}

/// Attempt the B3.1 `AF_XDP` redirect on an IPv4 packet.
///
/// Returns `Ok(action)` — the result of [`XskMap::redirect`], i.e.
/// `XDP_REDIRECT` on success or the `XDP_PASS` fallback when no socket is bound
/// at the frame's RX queue — if the packet is an IPv4 (IHL 5) **UDP** datagram
/// whose destination port is present in the userspace-populated [`REDIRECT_PORT`]
/// set. Returns `Err(())` for anything else (non-UDP, IP options present, port
/// not configured), so the caller falls through to the SYN-cookie/`XDP_PASS`
/// path unchanged.
///
/// The redirect targets the socket bound at this frame's own `rx_queue_index`:
/// `XskMap::redirect` only delivers to a socket bound on the same RX queue the
/// packet arrived on, so the map index must be that queue id.
fn try_redirect_udp_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let ip: *const Ipv4Hdr = ptr_at(ctx, OFF_IP)?;
    // SAFETY: `ptr_at` bounds-checked the 20-byte IPv4 header.
    let ihl = unsafe { (*ip).ihl() };
    // SAFETY: same bounds-checked header.
    let proto = unsafe { (*ip).proto };
    // Only the fixed IHL-5 layout is handled: with IP options the L4 header (and
    // thus the UDP destination port) would not sit at `OFF_UDP_DSTPORT`.
    if ihl != 5 || proto != IpProto::Udp {
        return Err(());
    }
    // `load_be16` bounds-checks the two destination-port bytes against `data_end`.
    let dst_port = load_be16(ctx, OFF_UDP_DSTPORT)?;
    if !redirect_port(dst_port) {
        return Err(());
    }
    // SAFETY: `ctx.ctx` is the verifier-provided `*mut xdp_md`, valid for the
    // duration of the program; `rx_queue_index` is a plain `u32` field.
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    // The low two bits of the flags are the fallback return code used when no
    // socket is bound at `queue_id`; `XDP_PASS` lets such a frame reach the stack
    // instead of being dropped.
    Ok(XSKS
        .redirect(queue_id, u64::from(xdp_action::XDP_PASS))
        .unwrap_or(xdp_action::XDP_PASS))
}

/// True if `port` (a UDP datagram's destination port) is a configured redirect
/// port in [`REDIRECT_PORT`]. An empty map matches nothing, so an unconfigured
/// box diverts no traffic.
fn redirect_port(port: u16) -> bool {
    // SAFETY: `REDIRECT_PORT` is only ever read; the returned reference is dropped
    // (converted to a bool) before any map mutation, of which this program
    // performs none on `REDIRECT_PORT`.
    unsafe { REDIRECT_PORT.get(&port) }.is_some()
}

/// Read the SipHash `(k0, k1)` cookie secret from the [`COOKIE_KEY`] map.
///
/// Returns `Err(())` if the entry is absent (the key was never installed from
/// userspace), so the caller falls through to `XDP_PASS` instead of minting a
/// cookie under a zero/garbage key. The `(k0, k1)` split was performed once, in
/// userspace (`blackwall_xdp::keys::encode_cookie_key`), matching
/// `blackwall_deception::CookieKey::to_u64_pair`.
#[inline(always)]
fn cookie_keys() -> Result<(u64, u64), ()> {
    // SAFETY: `COOKIE_KEY` is a `HashMap` value we only read; the returned
    // reference is used (copied out) before any further map mutation, of which
    // this program performs none on `COOKIE_KEY`.
    let value = unsafe { COOKIE_KEY.get(&COOKIE_KEY_SLOT) }.ok_or(())?;
    Ok((value.k0, value.k1))
}

/// Return the client's advertised MSS if the **first** TCP option is an MSS
/// option (kind 2, len 4), else [`DEFAULT_CLIENT_MSS`].
///
/// B2.2 reads the MSS only at this fixed position — where Linux and most stacks
/// place it (MSS is conventionally the first SYN option) — because a general,
/// runtime-offset option walk is rejected by the eBPF verifier (it cannot bound
/// an accumulating cursor against `data_end`). A SYN whose MSS sits after a
/// NOP/SACK-permitted/timestamp/window-scale option simply gets the default MSS
/// in its cookie; full option walking is deferred. Every access here is a
/// constant offset, so it is trivially bounds-checked.
fn parse_mss(ctx: &XdpContext, opts_off: usize) -> Result<u16, ()> {
    let kind = load_u8(ctx, opts_off)?;
    let len = load_u8(ctx, opts_off + 1)?;
    if kind == 2 && len == 4 {
        return load_be16(ctx, opts_off + 2);
    }
    Ok(DEFAULT_CLIENT_MSS)
}

/// Write a single 4-byte MSS option at the start of the options region
/// (`opts_off`), then NOP-pad (`0x01`) out to `options_len` so the TCP header
/// keeps its original byte length. `options_len` is `>= 4` (validated by the
/// caller) and `<= MAX_TCP_OPTS`. Shared by the IPv4 and IPv6 fast paths, which
/// pass their respective options offset ([`OFF_TCP_OPTS`] / [`OFF_TCP6_OPTS`]).
fn write_mss_option(
    ctx: &XdpContext,
    opts_off: usize,
    options_len: usize,
    mss: u16,
) -> Result<(), ()> {
    store_u8(ctx, opts_off, 2)?; // kind = MSS
    store_u8(ctx, opts_off + 1, 4)?; // len = 4
    store_be16(ctx, opts_off + 2, mss)?;
    for k in 4..MAX_TCP_OPTS {
        if k >= options_len {
            break;
        }
        store_u8(ctx, opts_off + k, 1)?; // NOP padding
    }
    Ok(())
}

/// Recompute the IPv4 header checksum over the 20-byte header (IHL 5). The
/// checksum field must already be zeroed by the caller.
///
/// The header is copied onto the stack with a **single** bounds-checked 20-byte
/// load, then summed from the stack array. Summing the packet word-by-word
/// instead makes the verifier reject the program: bpf-linker unrolls the loop
/// and coalesces the per-word `data_end` guards, after which the verifier can
/// no longer prove the later words are in range.
fn ipv4_checksum(ctx: &XdpContext) -> Result<u16, ()> {
    let p: *const [u8; 20] = ptr_at(ctx, OFF_IP)?;
    // SAFETY: `ptr_at` bounds-checked all 20 header bytes against `data_end`.
    let bytes = unsafe { *p };
    let mut sum: u32 = 0;
    for k in 0..10 {
        sum += u32::from(u16::from_be_bytes([bytes[k * 2], bytes[k * 2 + 1]]));
    }
    Ok(fold_checksum(sum))
}

fn blocked_v4(addr: [u8; 4]) -> bool {
    let key = Key::new(32, addr);
    BLOCK_V4.get(&key).is_some()
}

/// True if `dst` (a SYN's destination IPv4) LPM-matches a protected deception
/// prefix in [`PROTECT_V4`]. Looked up with a full 32-bit key so the trie
/// returns the longest matching configured prefix. An empty trie matches
/// nothing, so an unconfigured box gates every SYN to `XDP_PASS`.
fn protected_v4(dst: [u8; 4]) -> bool {
    let key = Key::new(32, dst);
    PROTECT_V4.get(&key).is_some()
}

/// True if `port` (a SYN's destination TCP port) is a configured deception port
/// in [`PROTECT_PORT`]. An empty map matches nothing.
fn protected_port(port: u16) -> bool {
    // SAFETY: `PROTECT_PORT` is only ever read; the returned reference is dropped
    // (converted to a bool) before any map mutation, of which this program
    // performs none on `PROTECT_PORT`.
    unsafe { PROTECT_PORT.get(&port) }.is_some()
}

fn blocked_v6(addr: [u8; 16]) -> bool {
    let key = Key::new(128, addr);
    BLOCK_V6.get(&key).is_some()
}

/// True if `dst` (a SYN's destination IPv6) LPM-matches a protected deception
/// prefix in [`PROTECT_V6`]. Looked up with a full 128-bit key so the trie
/// returns the longest matching configured prefix. An empty trie matches
/// nothing, so an unconfigured box gates every IPv6 SYN to `XDP_PASS`.
fn protected_v6(dst: [u8; 16]) -> bool {
    let key = Key::new(128, dst);
    PROTECT_V6.get(&key).is_some()
}

/// Token-bucket check keyed by 16-byte source (v4 zero-padded). Returns `true`
/// if the packet exceeds the source's budget and should be dropped. Sources
/// with no existing bucket are unconfigured and always pass.
///
/// # Race-free RMW (X1): per-CPU fallback
///
/// `RATE` is an `LruPerCpuHashMap` (see [`RateBucket`]'s doc comment and the
/// `RATE` declaration above for why a single shared, `bpf_spin_lock`-guarded
/// bucket was rejected by the verifier on this toolchain), so
/// `RATE.get_ptr_mut` always returns a pointer to *this* CPU's own copy of
/// the bucket: the kernel indexes per-CPU map lookups by the running CPU, so
/// no other CPU can observe or mutate the same memory concurrently. The
/// refill + decrement below is therefore already race-free with no lock
/// needed -- at the cost of an effective per-source limit of up to
/// `N_cpus × configured burst` under an RSS-spread flood (never tighter,
/// only looser than the configured value).
fn over_rate(src: [u8; 16]) -> bool {
    // SAFETY: `bpf_ktime_get_ns` is always safe to call from XDP context.
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(b) = RATE.get_ptr_mut(&src) {
        // SAFETY: `get_ptr_mut` returned a valid, exclusively-held pointer to
        // this CPU's copy of this source's bucket for the duration of this
        // call; no other CPU can alias it (per-CPU map lookup).
        unsafe {
            let elapsed_ns = now.saturating_sub((*b).last_ns);
            // Plain 64-bit `wrapping_mul` lowers to a single BPF multiply;
            // `saturating_mul`/`overflowing_mul` would emit an unsupported
            // 128-bit `__multi3`. The product is bounded below by `.min(burst)`,
            // so wraparound at absurd elapsed values cannot over-credit tokens.
            let refill = elapsed_ns.wrapping_mul((*b).rate_pps) / 1_000_000_000;
            (*b).tokens = ((*b).tokens.saturating_add(refill)).min((*b).burst);
            (*b).last_ns = now;
            if (*b).tokens == 0 {
                return true;
            }
            (*b).tokens -= 1;
        }
    }
    false
}

/// Check and consume one token from the global per-CPU SYN-cookie `XDP_TX`
/// mint budget (sub-project X3). Returns `true` if a SYN-ACK may be minted,
/// `false` if the caller must bail without minting.
///
/// Callers invoke this **after** SYN validation, the [`protected_v4`]/
/// [`protected_v6`]/[`protected_port`] gating, and the per-source [`over_rate`]
/// check (checked earlier, in [`try_filter`], before [`try_synack_v4`]/
/// [`try_synack_v6`] are even called) -- so a non-SYN, unprotected-destination,
/// or already per-source-limited packet never consumes global budget. The
/// check sits immediately before the cookie is actually minted.
///
/// `rate_pps == 0` (the [`TX_BUDGET`] slot's zero-initialised default) means
/// the cap has never been configured by userspace and this always returns
/// `true` -- see [`TxBucket`]'s doc comment. Once `rate_pps` is nonzero, the
/// refill/decrement mirrors [`over_rate`] exactly: 64-bit-only math
/// (`wrapping_mul` then `.min(TX_BUDGET_BURST)`; `saturating_mul`/
/// `overflowing_mul` would emit an unsupported 128-bit `__multi3` on this
/// target), so wraparound at absurd elapsed values cannot over-credit tokens.
///
/// Per-CPU (see [`TX_BUDGET`]'s doc comment): `get_ptr_mut` returns a pointer
/// to *this* CPU's own slot, so the RMW below is inherently race-free with no
/// lock needed -- at the cost of an aggregate ceiling of `N_cpus x rate_pps`
/// across the box, mirroring `over_rate`'s X1 per-CPU tradeoff.
#[inline(always)]
fn tx_budget_ok(now: u64) -> bool {
    let Some(b) = TX_BUDGET.get_ptr_mut(0) else {
        // No slot at index 0 (unreachable in practice: `with_max_entries(1, 0)`
        // always has one): fail open, same as the "not configured" case.
        return true;
    };
    // SAFETY: `get_ptr_mut` returned a valid pointer to this CPU's own single
    // TX_BUDGET slot; it is exclusively ours for the duration of this call (no
    // other CPU can observe or mutate a per-CPU map's slot for this CPU).
    unsafe {
        if (*b).rate_pps == 0 {
            // Cap not configured: never throttle (pre-X3 behavior).
            return true;
        }
        let elapsed_ns = now.saturating_sub((*b).last_ns);
        let refill = elapsed_ns.wrapping_mul((*b).rate_pps) / NS_PER_SEC;
        (*b).tokens = ((*b).tokens.saturating_add(refill)).min(TX_BUDGET_BURST);
        (*b).last_ns = now;
        if (*b).tokens == 0 {
            return false;
        }
        (*b).tokens -= 1;
    }
    true
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
