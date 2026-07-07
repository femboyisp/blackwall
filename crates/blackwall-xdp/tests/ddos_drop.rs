//! Kernel-bound DDoS-lab XDP gate (sub-project B4.2).
//!
//! Floods the **real** `xdp_filter` program with live traffic over a veth pair
//! and asserts the two source-keyed mitigations engage end-to-end under real
//! kernel traffic:
//!
//! 1. **Blocklist DROP** — a blocklisted source's UDP flood is dropped
//!    (`REASON_BLOCKLIST` rises by ~K and those frames never `REASON_PASS`),
//!    while a non-blocklisted source's identical flood passes (control).
//! 2. **Rate-limit under load** — a per-source token bucket (`pps`/`burst`)
//!    admits a burst then drops the sustained excess: a fast flood of M frames
//!    from one source yields `REASON_RATELIMIT > 0` *and* a bounded number of
//!    `REASON_PASS` (≈ `burst`).
//!
//! The rate limiter is **time/rate-dependent** and cannot be exercised by
//! `BPF_PROG_TEST_RUN` (single-shot, no wall-clock between runs): only a real
//! sustained flood against the live program proves the bucket engages. This is
//! the final "full B" validation.
//!
//! The harness mirrors `afxdp_redirect.rs`: a self-cleaning veth pair, the real
//! [`blackwall_xdp::XdpDataplane`] attached to `veth_a`, and raw `AF_PACKET`
//! frame injection on the peer end (`veth_b`) so frames arrive on `veth_a`'s
//! ingress where the program runs. Stats are read via [`XdpDataplane::stats`]
//! (the same per-CPU `STATS` sum the `blackwalld xdp stats` CLI reports), using
//! before/after deltas so the assertions are immune to unrelated counter state.
//!
//! Requires root (`CAP_NET_ADMIN` + `CAP_NET_RAW`); run serially in the lab CI
//! job: `sudo -n <bin> --ignored --nocapture --test-threads=1`.
#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use blackwall_core::XdpMode;
use blackwall_xdp::XdpDataplane;
use ipnet::IpNet;

/// UDP destination port for the flood frames. Not a redirect/deception port, so
/// frames flow straight through the blocklist -> rate-limit -> pass pipeline.
const FLOOD_DPORT: u16 = 40_000;

/// A veth pair that deletes itself (and its peer) on drop. IPv6 is disabled on
/// both ends before they come up so no link-local ND/MLD chatter reaches the
/// filter and inflates the `REASON_PASS` counter the rate-limit test bounds.
struct VethPair {
    a: String,
    b: String,
}

impl VethPair {
    /// Create `veth_a`/`veth_b`, both brought up with IPv6 disabled. Names are
    /// PID-unique so parallel/rerun tests do not collide.
    fn create() -> Self {
        let pid = std::process::id();
        let a = format!("bwda{pid}");
        let b = format!("bwdb{pid}");
        // Best-effort teardown of any stale pair from a crashed prior run.
        let _ = Command::new("ip").args(["link", "del", &a]).output();
        run_ip(&["link", "add", &a, "type", "veth", "peer", "name", &b]);
        // Silence IPv6 autoconf on both ends before they come up (best-effort:
        // a missing knob only means a little background PASS traffic).
        disable_ipv6(&a);
        disable_ipv6(&b);
        run_ip(&["link", "set", &a, "up"]);
        run_ip(&["link", "set", &b, "up"]);
        Self { a, b }
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", &self.a]).output();
    }
}

/// Disable IPv6 on `ifname` (best-effort — ignore failure).
fn disable_ipv6(ifname: &str) {
    let _ = Command::new("sysctl")
        .arg("-qw")
        .arg(format!("net.ipv6.conf.{ifname}.disable_ipv6=1"))
        .output();
}

/// Run an `ip` command, panicking with its stderr on failure.
fn run_ip(args: &[&str]) {
    let out = Command::new("ip")
        .args(args)
        .output()
        .expect("spawn ip command");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The kernel `ifindex` of `ifname`.
fn ifindex(ifname: &str) -> u32 {
    let idx =
        std::fs::read_to_string(format!("/sys/class/net/{ifname}/ifindex")).expect("read ifindex");
    idx.trim().parse().expect("parse ifindex")
}

/// Build an `Ethernet + IPv4 + UDP` frame from source `src` to `dst_port`, with
/// a 4-byte marker payload. The eBPF filter is **source-keyed** (it drops/limits
/// the sender), so `src` selects which mitigation the frame exercises.
fn udp_frame(src: [u8; 4], dst_port: u16, marker: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 8 + 4];
    // Ethernet: broadcast dst, arbitrary src, EtherType IPv4. XDP runs on ingress
    // regardless of dst MAC, so broadcast reaches the filter on the peer.
    p[0..6].copy_from_slice(&[0xff; 6]);
    p[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x0b]);
    p[12] = 0x08;
    p[13] = 0x00;
    // IPv4 (IHL 5), total length = 20 + 8 + 4.
    p[14] = 0x45;
    let tot_len = 20u16 + 8 + 4;
    p[16..18].copy_from_slice(&tot_len.to_be_bytes());
    p[22] = 64; // TTL
    p[23] = 17; // UDP
    p[26..30].copy_from_slice(&src); // src IP (drives the source-keyed verdict)
    p[30..34].copy_from_slice(&[198, 51, 100, 1]); // dst IP
    p[34..36].copy_from_slice(&40_000u16.to_be_bytes()); // src port
    p[36..38].copy_from_slice(&dst_port.to_be_bytes()); // dst port
    p[38..40].copy_from_slice(&(8u16 + 4).to_be_bytes()); // UDP length
    p[42..46].copy_from_slice(&marker);
    p
}

/// A raw `AF_PACKET` socket pre-bound to one interface's egress, reused to blast
/// many frames at line rate (one persistent fd — no per-frame socket setup — so
/// the flood is fast enough that the token bucket refills negligibly during it).
struct Sender {
    fd: libc::c_int,
    addr: libc::sockaddr_ll,
}

impl Sender {
    /// Open an `AF_PACKET` `SOCK_RAW` socket targeting `ifname`'s egress.
    fn open(ifname: &str) -> Self {
        // ETH_P_ALL, network byte order.
        let proto = u16::try_from(libc::ETH_P_ALL)
            .expect("ETH_P_ALL fits in u16")
            .to_be();
        // SAFETY: standard AF_PACKET raw socket creation.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(proto)) };
        assert!(
            fd >= 0,
            "AF_PACKET socket: {}",
            std::io::Error::last_os_error()
        );

        // SAFETY: `sockaddr_ll` is a plain C struct; an all-zero bit pattern is a
        // valid, unspecified address that we fully populate below.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = u16::try_from(libc::AF_PACKET).expect("AF_PACKET fits in u16");
        addr.sll_protocol = proto;
        addr.sll_ifindex = i32::try_from(ifindex(ifname)).expect("ifindex fits in i32");
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
        Self { fd, addr }
    }

    /// Transmit `frame` once. Returns `true` if the whole frame was sent.
    fn send(&self, frame: &[u8]) -> bool {
        // SAFETY: `self.fd` is our raw socket; `frame` is a valid buffer of
        // `frame.len()` bytes; `self.addr` is a correctly-initialised
        // `sockaddr_ll` of matching size, borrowed read-only for this call.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                0,
                std::ptr::addr_of!(self.addr).cast::<libc::sockaddr>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
                    .expect("sockaddr_ll size fits in socklen_t"),
            )
        };
        usize::try_from(sent).unwrap_or(0) == frame.len()
    }

    /// Blast `frame` `count` times back-to-back, returning the number that were
    /// fully transmitted.
    fn flood(&self, frame: &[u8], count: u32) -> u32 {
        let mut ok = 0;
        for _ in 0..count {
            if self.send(frame) {
                ok += 1;
            }
        }
        ok
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        // SAFETY: closing our own fd.
        unsafe { libc::close(self.fd) };
    }
}

#[test]
#[ignore = "requires root + CAP_NET_ADMIN/RAW; run in the lab CI job"]
fn blocklisted_source_flood_is_dropped_and_clean_source_passes() {
    let veth = VethPair::create();
    let mut dp = XdpDataplane::attach(&veth.a, XdpMode::Auto).expect("attach xdp_filter to veth_a");

    // Blocklist one source; a second, untouched source is the pass control.
    let blocked_src = [10, 77, 0, 9];
    let clean_src = [10, 77, 0, 1];
    dp.block("10.77.0.9/32".parse::<IpNet>().expect("parse blocked net"))
        .expect("install blocklist entry");

    let sender = Sender::open(&veth.b);
    const K: u32 = 50;

    // --- Phase 1: flood from the blocklisted source. ---
    let before = dp.stats();
    let sent_blocked = sender.flood(
        &udp_frame(blocked_src, FLOOD_DPORT, [0xb1, 0xac, 0x6e, 0xd0]),
        K,
    );
    assert_eq!(sent_blocked, K, "all blocklisted frames should transmit");
    let after_block = dp.stats();

    let blocklist_delta = after_block.dropped_blocklist.packets - before.dropped_blocklist.packets;
    let pass_delta_block = after_block.passed.packets - before.passed.packets;

    // ~all K blocklisted frames were dropped by the blocklist (upper bound K:
    // only our frames use that source, so nothing else can add to it; lower
    // bound allows a couple of frames lost in transit on a busy box).
    assert!(
        blocklist_delta >= u64::from(K) - u64::from(K / 10) && blocklist_delta <= u64::from(K),
        "blocklist drops ({blocklist_delta}) should be ~K={K}"
    );
    // Because every frame gets exactly one verdict, ~all K accounted as
    // blocklist drops proves those frames did NOT pass. With IPv6 silenced the
    // only PASS traffic in this window would be stray background, bounded tiny.
    assert!(
        pass_delta_block <= 5,
        "blocklisted flood must not raise REASON_PASS (delta {pass_delta_block})"
    );

    // --- Phase 2: identical flood from a NON-blocklisted source passes. ---
    let sent_clean = sender.flood(
        &udp_frame(clean_src, FLOOD_DPORT, [0xc1, 0xea, 0x00, 0x01]),
        K,
    );
    assert_eq!(sent_clean, K, "all clean frames should transmit");
    let after_clean = dp.stats();

    let pass_delta_clean = after_clean.passed.packets - after_block.passed.packets;
    let blocklist_delta_clean =
        after_clean.dropped_blocklist.packets - after_block.dropped_blocklist.packets;
    // The clean source's frames pass (background only ever adds, so >= K-slack).
    assert!(
        pass_delta_clean >= u64::from(K) - u64::from(K / 10),
        "clean-source flood should pass ~K={K} (delta {pass_delta_clean})"
    );
    // ...and the clean flood adds no blocklist drops.
    assert_eq!(
        blocklist_delta_clean, 0,
        "clean-source flood must not be blocklist-dropped"
    );
}

#[test]
#[ignore = "requires root + CAP_NET_ADMIN/RAW; run in the lab CI job"]
fn rate_limited_source_under_load_admits_a_burst_then_drops_the_excess() {
    // The key B4.2 test: prove the time-dependent token bucket engages under a
    // sustained flood — a burst is admitted, the excess is dropped — which
    // BPF_PROG_TEST_RUN (single-shot) structurally cannot show.
    let veth = VethPair::create();
    let mut dp = XdpDataplane::attach(&veth.a, XdpMode::Auto).expect("attach xdp_filter to veth_a");

    let src = [10, 77, 0, 9];
    let pps: u64 = 100;
    let burst: u64 = 20;
    dp.rate_limit(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 9)), pps, burst)
        .expect("install rate limit");

    let sender = Sender::open(&veth.b);
    // M well above `burst`, blasted as fast as possible (>> `pps`), so the
    // bucket admits ~`burst` then drops the rest.
    const M: u32 = 200;

    let before = dp.stats();
    let sent = sender.flood(&udp_frame(src, FLOOD_DPORT, [0xf1, 0x00, 0x0d, 0x00]), M);
    assert_eq!(sent, M, "all flood frames should transmit");
    let after = dp.stats();

    let passed = after.passed.packets - before.passed.packets;
    let ratelimited = after.dropped_ratelimit.packets - before.dropped_ratelimit.packets;
    let total = passed + ratelimited;

    // The flood actually landed on the filter (guards a false "0 passed"
    // because nothing arrived): ~all M frames got a pass/ratelimit verdict.
    assert!(
        total >= u64::from(M) - u64::from(M / 10),
        "flood did not land: passed {passed} + ratelimited {ratelimited} = {total}, want ~M={M}"
    );
    // The limiter engaged and dropped the sustained majority (expect ~M-burst).
    assert!(
        ratelimited > 0,
        "rate limiter never engaged (ratelimit drops = 0)"
    );
    assert!(
        ratelimited >= u64::from(M) / 2,
        "rate limiter should drop the majority under load (dropped {ratelimited} of {M})"
    );
    // A burst WAS admitted — some frames passed — but only ~`burst` of them,
    // far below M. Generous upper slack absorbs the negligible refill during the
    // sub-millisecond flood; it stays well under M, so "burst then drop excess"
    // holds.
    assert!(passed >= 1, "no burst was admitted (0 passed)");
    assert!(
        passed <= burst + 30,
        "admitted far more than a burst ({passed} passed, burst={burst})"
    );
}
