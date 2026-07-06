//! Blackwall XDP filter data plane (`xdp_filter`).
//!
//! Parses `Ethernet -> IPv4/IPv6` with explicit bounds checks, then applies, in
//! order, per source address: (1) an LPM blocklist drop, (2) a per-source LRU
//! token-bucket rate-limit drop, and otherwise (3) pass. Every decision bumps a
//! per-CPU stats counter keyed by reason code. Map names (`BLOCK_V4`,
//! `BLOCK_V6`, `RATE`, `STATS`) and the shared POD layouts in
//! `blackwall-xdp-common` form the contract consumed by the userspace loader.
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
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{LpmTrie, LruHashMap, PerCpuArray};
use aya_ebpf::programs::XdpContext;
use blackwall_cookie::{check_cookie_raw, make_cookie_raw};
use blackwall_xdp_common::{
    RateBucket, Stat, REASON_BLOCKLIST, REASON_COUNT, REASON_PASS, REASON_RATELIMIT,
};
use core::mem;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

#[map]
static BLOCK_V4: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(65536, 1);
#[map]
static BLOCK_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(65536, 1);
#[map]
static RATE: LruHashMap<[u8; 16], RateBucket> = LruHashMap::with_max_entries(1_048_576, 0);
#[map]
static STATS: PerCpuArray<Stat> = PerCpuArray::with_max_entries(REASON_COUNT, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
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

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    // B2.1 reference: prove the shared `#![no_std]` SYN-cookie core
    // (`blackwall-cookie`) links and is callable from this
    // `bpfel-unknown-none` program, so the future in-kernel B2 SYN-cookie is
    // byte-identical to the userspace deception tier's. Not yet wired into
    // this program's packet path (that lands in B2.2, once the cookie is
    // threaded through TCP SYN/ACK handling here); the result is discarded
    // through `black_box` so LTO can't eliminate the call, without changing
    // this program's pass/drop decisions.
    let _ = core::hint::black_box(syn_cookie_reference());
    try_filter(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

/// B2.1 proof that [`blackwall_cookie`]'s raw core builds and links for the
/// `bpfel-unknown-none` target: makes and immediately validates a cookie for
/// the exact same key/tuple/MSS/time as `blackwall_cookie`'s own
/// `golden_vector_v4_cookie` test, so a successful call here at
/// `BPF_PROG_TEST_RUN` time corroborates that golden vector from inside the
/// bpf target too. XDP-side cookie generation (reading the real SYN/ACK
/// tuple off the wire) is B2.2.
#[inline(always)]
fn syn_cookie_reference() -> bool {
    const KEY_K0: u64 = 0x0706_0504_0302_0100;
    const KEY_K1: u64 = 0x0f0e_0d0c_0b0a_0908;
    const SRC: [u8; 4] = [203, 0, 113, 7];
    const DST: [u8; 4] = [198, 51, 100, 1];
    const SRC_PORT: u16 = 54_321;
    const DST_PORT: u16 = 443;
    const NOW: u64 = 1_000_000;

    let (cookie, mss) = make_cookie_raw(KEY_K0, KEY_K1, &SRC, SRC_PORT, &DST, DST_PORT, 1460, NOW);
    let ack = cookie.wrapping_add(1);
    check_cookie_raw(KEY_K0, KEY_K1, &SRC, SRC_PORT, &DST, DST_PORT, ack, NOW) == Some(mss)
}

fn try_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let frame_len = (ctx.data_end() - ctx.data()) as u64;
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    // SAFETY: `ptr_at` bounds-checked `EthHdr` bytes against `data_end`.
    let ethertype = unsafe { (*eth).ether_type };
    match ethertype {
        EtherType::Ipv4 => {
            let ip: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
            // SAFETY: `ptr_at` bounds-checked the IPv4 header.
            let src = unsafe { (*ip).src_addr() }.octets();
            if blocked_v4(src) {
                count(REASON_BLOCKLIST, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
            let mut key16 = [0u8; 16];
            key16[..4].copy_from_slice(&src);
            if over_rate(key16) {
                count(REASON_RATELIMIT, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        EtherType::Ipv6 => {
            let ip: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
            // SAFETY: `ptr_at` bounds-checked the IPv6 header.
            let src = unsafe { (*ip).src_addr() }.octets();
            if blocked_v6(src) {
                count(REASON_BLOCKLIST, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
            if over_rate(src) {
                count(REASON_RATELIMIT, frame_len);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        _ => {}
    }
    count(REASON_PASS, frame_len);
    Ok(xdp_action::XDP_PASS)
}

fn blocked_v4(addr: [u8; 4]) -> bool {
    let key = Key::new(32, addr);
    BLOCK_V4.get(&key).is_some()
}

fn blocked_v6(addr: [u8; 16]) -> bool {
    let key = Key::new(128, addr);
    BLOCK_V6.get(&key).is_some()
}

/// Token-bucket check keyed by 16-byte source (v4 zero-padded). Returns `true`
/// if the packet exceeds the source's budget and should be dropped. Sources
/// with no existing bucket are unconfigured and always pass.
fn over_rate(src: [u8; 16]) -> bool {
    // SAFETY: `bpf_ktime_get_ns` is always safe to call from XDP context.
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(b) = RATE.get_ptr_mut(&src) {
        // SAFETY: `get_ptr_mut` returned a valid, exclusively-held pointer to
        // this source's bucket for the duration of this call.
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
