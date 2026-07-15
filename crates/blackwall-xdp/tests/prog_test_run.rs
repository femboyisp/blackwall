//! Kernel-bound: exercises the compiled `xdp_filter` program end-to-end via the
//! `BPF_PROG_TEST_RUN` bpf(2) command.
//!
//! Requires root and a recent kernel; run in the lab CI job:
//! `sudo -n cargo test -p blackwall-xdp --test prog_test_run -- --ignored`.
//!
//! aya 0.13.1 exposes no `Xdp::test_run` wrapper, so we issue the `bpf(2)`
//! syscall directly against the loaded program fd. The kernel writes the
//! program's return value (an `XDP_*` action) back into the attr's `retval`.
#![cfg(target_os = "linux")]

use std::os::fd::{AsFd, AsRawFd};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::HashMap;
use aya::programs::Xdp;
use aya::Ebpf;

/// `bpf(2)` command number for `BPF_PROG_TEST_RUN`.
const BPF_PROG_TEST_RUN: core::ffi::c_long = 10;

/// `XDP_DROP` action code (see `bpf.h`).
const XDP_DROP: u32 = 1;
/// `XDP_PASS` action code.
const XDP_PASS: u32 = 2;
/// `XDP_TX` action code (bounce the (rewritten) frame back out the ingress
/// interface).
const XDP_TX: u32 = 3;
/// `STATS` per-CPU array index for redirect decisions
/// (`blackwall_xdp_common::REASON_REDIRECT`, sub-project B3.1).
const REASON_REDIRECT: u32 = 4;

/// A `STATS` per-CPU counter entry, byte-identical to
/// `blackwall_xdp_common::Stat`. Declared locally so the test can give it an
/// [`aya::Pod`] impl.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct StatPod {
    packets: u64,
    bytes: u64,
}

// SAFETY: `#[repr(C)]` `Copy` plain-old-data of two `u64`s — a valid, fixed
// 16-byte per-CPU BPF map value with no padding or pointers.
unsafe impl aya::Pod for StatPod {}

/// Sum the per-CPU `STATS` packet counter at `reason` across all CPUs.
fn stat_packets(bpf: &mut Ebpf, reason: u32) -> u64 {
    use aya::maps::PerCpuArray;
    let stats: PerCpuArray<_, StatPod> =
        PerCpuArray::try_from(bpf.map_mut("STATS").expect("STATS map present"))
            .expect("STATS is a PerCpuArray");
    let values = stats.get(&reason, 0).expect("read STATS reason");
    values.iter().map(|v| v.packets).sum()
}

/// Test SYN-cookie secret installed into the `COOKIE_KEY` map before the run
/// (B2.3a: the key is no longer baked into the eBPF program — it is delivered
/// via the map). Bytes `0x00..=0x0f`, matching the cookie crate's golden-vector
/// `(k0, k1)`.
const COOKIE_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// `COOKIE_KEY` map value: the pre-split SipHash `(k0, k1)` pair, byte-identical
/// to `blackwall_xdp_common::CookieKeyValue`. Declared locally so the test can
/// give it an [`aya::Pod`] impl (the crate's own newtype is private).
#[repr(C)]
#[derive(Clone, Copy)]
struct CookieKeyValue {
    k0: u64,
    k1: u64,
}

// SAFETY: `#[repr(C)]` `Copy` plain-old-data of two `u64`s — a valid, fixed
// 16-byte BPF map value with no padding or pointers.
unsafe impl aya::Pod for CookieKeyValue {}

/// Read `CLOCK_MONOTONIC` seconds-since-boot — the same clock base
/// `bpf_ktime_get_ns()` uses in-kernel, so the test can reconstruct the cookie
/// time slot the eBPF program saw.
fn clock_monotonic_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable `timespec`; `clock_gettime` fills it and
    // returns 0 on success.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, core::ptr::addr_of_mut!(ts)) };
    assert_eq!(
        rc,
        0,
        "clock_gettime(CLOCK_MONOTONIC) failed: {}",
        std::io::Error::last_os_error()
    );
    u64::try_from(ts.tv_sec).expect("monotonic seconds are non-negative")
}

/// Install the test cookie secret into the loaded object's `COOKIE_KEY` map.
fn install_cookie_key(bpf: &mut Ebpf, key: [u8; 16]) {
    let (k0, k1) = cookie_keys(key);
    let mut map: HashMap<_, u32, CookieKeyValue> =
        HashMap::try_from(bpf.map_mut("COOKIE_KEY").expect("COOKIE_KEY map present"))
            .expect("COOKIE_KEY is a HashMap");
    map.insert(0u32, CookieKeyValue { k0, k1 }, 0)
        .expect("insert cookie key");
}

/// Install a protected IPv4 deception prefix into `PROTECT_V4` (B2.3b gating):
/// the SYN's destination IP must LPM-match one of these for the fast path to
/// answer it.
fn install_protect_prefix(bpf: &mut Ebpf, prefixlen: u32, addr: [u8; 4]) {
    let mut map: LpmTrie<_, [u8; 4], u8> =
        LpmTrie::try_from(bpf.map_mut("PROTECT_V4").expect("PROTECT_V4 map present"))
            .expect("PROTECT_V4 is an LpmTrie");
    map.insert(&Key::new(prefixlen, addr), 1, 0)
        .expect("insert protected prefix");
}

/// Install a protected IPv6 deception prefix into `PROTECT_V6` (B2.3c gating):
/// the IPv6 SYN's destination address must LPM-match one of these for the fast
/// path to answer it.
fn install_protect_prefix_v6(bpf: &mut Ebpf, prefixlen: u32, addr: [u8; 16]) {
    let mut map: LpmTrie<_, [u8; 16], u8> =
        LpmTrie::try_from(bpf.map_mut("PROTECT_V6").expect("PROTECT_V6 map present"))
            .expect("PROTECT_V6 is an LpmTrie");
    map.insert(&Key::new(prefixlen, addr), 1, 0)
        .expect("insert protected v6 prefix");
}

/// Install a UDP destination port into `REDIRECT_PORT` (B3.1): an IPv4 UDP
/// datagram to this port is redirected to the `AF_XDP` socket in `XSKS`.
fn install_redirect_port(bpf: &mut Ebpf, port: u16) {
    let mut map: HashMap<_, u16, u8> = HashMap::try_from(
        bpf.map_mut("REDIRECT_PORT")
            .expect("REDIRECT_PORT map present"),
    )
    .expect("REDIRECT_PORT is a HashMap");
    map.insert(port, 1u8, 0).expect("insert redirect port");
}

/// Install a protected TCP destination port into `PROTECT_PORT` (B2.3b gating):
/// the SYN's destination port must be present here for the fast path to answer
/// it. Keyed by the host-native numeric port `u16`, matching the eBPF read.
fn install_protect_port(bpf: &mut Ebpf, port: u16) {
    let mut map: HashMap<_, u16, u8> = HashMap::try_from(
        bpf.map_mut("PROTECT_PORT")
            .expect("PROTECT_PORT map present"),
    )
    .expect("PROTECT_PORT is a HashMap");
    map.insert(port, 1u8, 0).expect("insert protected port");
}

/// The `BPF_PROG_TEST_RUN` slice of `union bpf_attr`, matching the kernel layout.
///
/// The trailing [`BpfProgTestRun::_pad`] is **load-bearing**: the struct's 8-byte
/// alignment (it holds `u64` fields) would otherwise leave 4 uninitialised
/// padding bytes after `batch_size`. The kernel's `CHECK_ATTR(BPF_PROG_TEST_RUN)`
/// requires every byte of the passed attr *after* the last recognised field
/// (`batch_size`) to be zero, so stale stack bytes in that padding make the
/// `bpf(2)` call fail with `EINVAL`. Declaring the pad as an explicit zeroed
/// field guarantees it is cleared.
#[repr(C)]
#[derive(Default)]
struct BpfProgTestRun {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _pad: u32,
}

/// Address of a byte slice as a `u64`, without an `as` cast.
fn slice_addr(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.as_ptr().addr()).expect("pointer fits in u64")
}

/// Run `xdp_filter` (identified by `prog_fd`) over `frame` and return its
/// `XDP_*` action together with the (possibly rewritten) output frame the
/// kernel produced.
fn run_xdp_out(prog_fd: i32, frame: &[u8]) -> (u32, Vec<u8>) {
    let mut data_out = vec![0u8; 4096];
    let data_out_addr = u64::try_from(data_out.as_mut_ptr().addr()).expect("pointer fits in u64");
    let mut attr = BpfProgTestRun {
        prog_fd: u32::try_from(prog_fd).expect("fd is non-negative"),
        data_size_in: u32::try_from(frame.len()).expect("frame len fits in u32"),
        data_size_out: u32::try_from(data_out.len()).expect("out len fits in u32"),
        data_in: slice_addr(frame),
        data_out: data_out_addr,
        repeat: 1,
        ..BpfProgTestRun::default()
    };
    let attr_size =
        core::ffi::c_long::try_from(core::mem::size_of::<BpfProgTestRun>()).expect("attr size");

    // SAFETY: `attr` is a correctly-shaped `bpf_attr` test-run request; the
    // kernel reads `attr_size` bytes and writes `retval`/`duration` back into
    // it. `data_in`/`data_out` point at live buffers held for the whole call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            core::ptr::addr_of_mut!(attr),
            attr_size,
        )
    };
    assert_eq!(
        ret,
        0,
        "BPF_PROG_TEST_RUN failed: {}",
        std::io::Error::last_os_error()
    );
    let out_len = usize::try_from(attr.data_size_out).expect("out len fits in usize");
    data_out.truncate(out_len);
    (attr.retval, data_out)
}

/// Run `xdp_filter` over `frame` and return only its `XDP_*` action.
fn run_xdp(prog_fd: i32, frame: &[u8]) -> u32 {
    run_xdp_out(prog_fd, frame).0
}

/// Minimal Ethernet + IPv4 frame carrying the given source address.
fn eth_ipv4(src: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20];
    // EtherType = IPv4.
    p[12] = 0x08;
    p[13] = 0x00;
    // IPv4 version (4) + IHL (5).
    p[14] = 0x45;
    // Source address at IPv4 header offset 12 (absolute 26).
    p[26..30].copy_from_slice(&src);
    p
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn blocked_source_is_dropped_others_pass() {
    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");

    // Block 198.51.100.9/32 in the source blocklist.
    {
        let mut block: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(bpf.map_mut("BLOCK_V4").expect("BLOCK_V4 map present"))
                .expect("BLOCK_V4 is an LpmTrie");
        block
            .insert(&Key::new(32, [198, 51, 100, 9]), 1, 0)
            .expect("insert blocklist entry");
    }

    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    let blocked = run_xdp(prog_fd, &eth_ipv4([198, 51, 100, 9]));
    assert_eq!(blocked, XDP_DROP, "blocked source should be dropped");

    let allowed = run_xdp(prog_fd, &eth_ipv4([203, 0, 113, 5]));
    assert_eq!(allowed, XDP_PASS, "non-blocked source should pass");
}

// --- B2.2: in-kernel SipHash-cookie SYN-ACK via XDP_TX ---

/// Client MAC used in the crafted SYN (becomes the reply's *destination* MAC).
const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
/// Server MAC used in the crafted SYN (becomes the reply's *source* MAC).
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Byte offsets into an `Ethernet + IPv4(IHL5) + TCP` frame (mirrors the eBPF).
const IP: usize = 14;
const TCP: usize = 34;

/// Byte offsets into an `Ethernet + IPv6(40) + TCP` frame (mirrors the eBPF).
const IP6: usize = 14;
const TCP6: usize = 54;

/// Build an `Ethernet + IPv4 + TCP SYN` frame carrying a single 4-byte MSS
/// option (TCP data-offset 6). Input header checksums are left zero: the eBPF
/// program never validates them, it only *recomputes* the reply's checksums.
fn eth_ipv4_tcp_syn(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    mss: u16,
) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 24];
    // Ethernet: dst = server, src = client, EtherType IPv4.
    p[0..6].copy_from_slice(&SERVER_MAC);
    p[6..12].copy_from_slice(&CLIENT_MAC);
    p[12] = 0x08;
    p[13] = 0x00;
    // IPv4 header (IHL 5).
    p[IP] = 0x45;
    let tot_len = u16::try_from(20 + 24).expect("tot_len fits in u16");
    p[IP + 2..IP + 4].copy_from_slice(&tot_len.to_be_bytes());
    p[IP + 8] = 64; // TTL
    p[IP + 9] = 6; // protocol = TCP
    p[IP + 12..IP + 16].copy_from_slice(&src_ip);
    p[IP + 16..IP + 20].copy_from_slice(&dst_ip);
    // TCP header.
    p[TCP..TCP + 2].copy_from_slice(&src_port.to_be_bytes());
    p[TCP + 2..TCP + 4].copy_from_slice(&dst_port.to_be_bytes());
    p[TCP + 4..TCP + 8].copy_from_slice(&seq.to_be_bytes());
    p[TCP + 12] = 6 << 4; // data offset = 6 words (24 bytes), reserved 0
    p[TCP + 13] = 0x02; // SYN
    p[TCP + 14..TCP + 16].copy_from_slice(&64_240u16.to_be_bytes()); // window
                                                                     // Options: MSS (kind 2, len 4).
    p[TCP + 20] = 2;
    p[TCP + 21] = 4;
    p[TCP + 22..TCP + 24].copy_from_slice(&mss.to_be_bytes());
    p
}

/// Build an `Ethernet + IPv6 + TCP SYN` frame carrying a single 4-byte MSS
/// option (TCP data-offset 6). The IPv6 fixed header is 40 bytes, next-header
/// TCP, payload length = the 24-byte TCP segment. No L3 checksum exists in IPv6;
/// the eBPF program only recomputes the reply's TCP checksum.
fn eth_ipv6_tcp_syn(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    mss: u16,
) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 40 + 24];
    // Ethernet: dst = server, src = client, EtherType IPv6 (0x86DD).
    p[0..6].copy_from_slice(&SERVER_MAC);
    p[6..12].copy_from_slice(&CLIENT_MAC);
    p[12] = 0x86;
    p[13] = 0xDD;
    // IPv6 header: version 6 in the high nibble of the first byte.
    p[IP6] = 0x60;
    // Payload length = the TCP segment length (header + options, no data).
    let payload_len = u16::try_from(24).expect("payload_len fits in u16");
    p[IP6 + 4..IP6 + 6].copy_from_slice(&payload_len.to_be_bytes());
    p[IP6 + 6] = 6; // next header = TCP
    p[IP6 + 7] = 64; // hop limit
    p[IP6 + 8..IP6 + 24].copy_from_slice(&src_ip);
    p[IP6 + 24..IP6 + 40].copy_from_slice(&dst_ip);
    // TCP header.
    p[TCP6..TCP6 + 2].copy_from_slice(&src_port.to_be_bytes());
    p[TCP6 + 2..TCP6 + 4].copy_from_slice(&dst_port.to_be_bytes());
    p[TCP6 + 4..TCP6 + 8].copy_from_slice(&seq.to_be_bytes());
    p[TCP6 + 12] = 6 << 4; // data offset = 6 words (24 bytes), reserved 0
    p[TCP6 + 13] = 0x02; // SYN
    p[TCP6 + 14..TCP6 + 16].copy_from_slice(&64_240u16.to_be_bytes()); // window
                                                                       // Options: MSS (kind 2, len 4).
    p[TCP6 + 20] = 2;
    p[TCP6 + 21] = 4;
    p[TCP6 + 22..TCP6 + 24].copy_from_slice(&mss.to_be_bytes());
    p
}

/// Build an `Ethernet + IPv4 + UDP` frame (8-byte UDP header, no payload)
/// carrying the given destination port — used to exercise the B3.1 redirect
/// fast path.
fn eth_ipv4_udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 8];
    p[0..6].copy_from_slice(&SERVER_MAC);
    p[6..12].copy_from_slice(&CLIENT_MAC);
    p[12] = 0x08;
    p[13] = 0x00;
    // IPv4 header (IHL 5).
    p[IP] = 0x45;
    let tot_len = u16::try_from(20 + 8).expect("tot_len fits in u16");
    p[IP + 2..IP + 4].copy_from_slice(&tot_len.to_be_bytes());
    p[IP + 8] = 64; // TTL
    p[IP + 9] = 17; // protocol = UDP
    p[IP + 12..IP + 16].copy_from_slice(&src_ip);
    p[IP + 16..IP + 20].copy_from_slice(&dst_ip);
    // UDP header: src port, dst port, length, checksum(0).
    p[TCP..TCP + 2].copy_from_slice(&src_port.to_be_bytes());
    p[TCP + 2..TCP + 4].copy_from_slice(&dst_port.to_be_bytes());
    p[TCP + 4..TCP + 6].copy_from_slice(&8u16.to_be_bytes());
    p
}

/// B3.1: a UDP datagram whose destination port is in `REDIRECT_PORT` takes the
/// `XskMap` redirect fast path (bumping the `REASON_REDIRECT` counter); a
/// datagram to any other port is not diverted and passes through unchanged.
///
/// The `XSKS` map is left empty (no bound socket). For an `XSKMAP`,
/// `bpf_redirect_map` on an empty slot returns the *fallback* action
/// immediately, so the program returns the `XDP_PASS` fallback rather than
/// `XDP_REDIRECT` — the retval alone therefore cannot distinguish the redirect
/// branch from a plain pass. The definitive evidence that the branch executed is
/// the per-CPU `REASON_REDIRECT` stat, which `BPF_PROG_TEST_RUN` updates. The
/// live end-to-end redirect (a real bound socket actually receiving the frame)
/// is covered by the `afxdp_redirect` veth integration test.
#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn udp_to_redirect_port_takes_the_xsk_redirect_branch() {
    let redirect_port = 9999u16;

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    install_redirect_port(&mut bpf, redirect_port);
    let prog_fd = {
        let prog: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .expect("xdp_filter program present")
            .try_into()
            .expect("program is an Xdp");
        prog.load().expect("verify + load xdp_filter");
        prog.fd().expect("program fd").as_fd().as_raw_fd()
    };

    let hit = eth_ipv4_udp([203, 0, 113, 7], [198, 51, 100, 1], 40_000, redirect_port);
    run_xdp(prog_fd, &hit);
    assert_eq!(
        stat_packets(&mut bpf, REASON_REDIRECT),
        1,
        "a UDP datagram to a redirect port must take the XSK redirect branch"
    );

    let miss = eth_ipv4_udp([203, 0, 113, 7], [198, 51, 100, 1], 40_000, 1234);
    let (miss_action, miss_out) = run_xdp_out(prog_fd, &miss);
    assert_eq!(
        miss_action, XDP_PASS,
        "a UDP datagram to a non-redirect port must pass through"
    );
    assert_eq!(
        miss_out, miss,
        "a passed UDP datagram must be byte-for-byte unchanged"
    );
    assert_eq!(
        stat_packets(&mut bpf, REASON_REDIRECT),
        1,
        "a non-redirect UDP datagram must not bump the redirect counter"
    );
}

/// Build an `Ethernet + IPv4 + TCP ACK` frame (no SYN, one MSS option) — the
/// eBPF SYN-cookie fast path must ignore it and `XDP_PASS` it unchanged.
fn eth_ipv4_tcp_ack(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    let mut p = eth_ipv4_tcp_syn(src_ip, dst_ip, 54_321, 443, 0x1122_3344, 1460);
    p[TCP + 13] = 0x10; // ACK only, SYN clear
    p
}

/// Read a big-endian `u16` at `off`.
fn be16(p: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([p[off], p[off + 1]])
}

/// Read a big-endian `u32` at `off`.
fn be32(p: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]])
}

/// Fold a ones-complement accumulator to 16 bits.
fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum & 0xffff).expect("folded sum is 16-bit")
}

/// Ones-complement sum of the `len` bytes of `p` starting at `off`
/// (big-endian 16-bit words, trailing odd byte padded low).
fn ones_sum(p: &[u8], off: usize, len: usize) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 2 <= len {
        sum += u32::from(be16(p, off + i));
        i += 2;
    }
    if i < len {
        sum += u32::from(p[off + i]) << 8;
    }
    sum
}

/// Split the 128-bit key into the SipHash `(k0, k1)` little-endian pair the way
/// both the eBPF program and `blackwall_deception::CookieKey` do.
fn cookie_keys(key: [u8; 16]) -> (u64, u64) {
    let mut k0 = [0u8; 8];
    let mut k1 = [0u8; 8];
    k0.copy_from_slice(&key[0..8]);
    k1.copy_from_slice(&key[8..16]);
    (u64::from_le_bytes(k0), u64::from_le_bytes(k1))
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn syn_is_answered_with_a_map_keyed_cookie_syn_ack_via_xdp_tx() {
    let client_ip = [203, 0, 113, 7];
    let server_ip = [198, 51, 100, 1];
    let client_port = 54_321u16;
    let server_port = 443u16;
    let client_seq = 0x1122_3344u32;
    let client_mss = 1460u16;

    let (k0, k1) = cookie_keys(COOKIE_KEY);

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    // B2.3a: deliver the cookie secret via the map (no longer a program const).
    install_cookie_key(&mut bpf, COOKIE_KEY);
    // B2.3b: the SYN's dst (198.51.100.1:443) must match a protected prefix AND
    // a protected port for the fast path to answer it.
    install_protect_prefix(&mut bpf, 24, [198, 51, 100, 0]);
    install_protect_port(&mut bpf, server_port);
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    // Build the input frame *after* loading the program: `BPF_PROG_TEST_RUN`'s
    // input-buffer handling is sensitive to the process heap layout, and the
    // existing B1 test loads first for the same reason.
    let syn = eth_ipv4_tcp_syn(
        client_ip,
        server_ip,
        client_port,
        server_port,
        client_seq,
        client_mss,
    );
    // B2.3a: the eBPF cookie time base is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC),
    // which we cannot pin, so the expected cookie is computed dynamically.
    // Snapshot the same clock right around the run and accept any of the three
    // adjacent 64-second slots — one slot of tolerance covers a boundary crossing
    // between this read and the kernel's ktime read.
    let now_secs = clock_monotonic_secs();
    let (action, out) = run_xdp_out(prog_fd, &syn);
    let slot = now_secs >> blackwall_cookie::COUNTER_SHIFT;
    // MSS is time-independent, so any candidate slot yields the same value.
    let expected_mss = blackwall_cookie::make_cookie_raw(
        k0,
        k1,
        &client_ip,
        client_port,
        &server_ip,
        server_port,
        client_mss,
        slot << blackwall_cookie::COUNTER_SHIFT,
    )
    .1;
    let expected_cookies: Vec<u32> = [slot.wrapping_sub(1), slot, slot + 1]
        .into_iter()
        .map(|s| {
            blackwall_cookie::make_cookie_raw(
                k0,
                k1,
                &client_ip,
                client_port,
                &server_ip,
                server_port,
                client_mss,
                s << blackwall_cookie::COUNTER_SHIFT,
            )
            .0
        })
        .collect();

    assert_eq!(action, XDP_TX, "a SYN must be answered via XDP_TX");
    assert_eq!(
        out.len(),
        syn.len(),
        "the reply must be the same byte length"
    );

    // Ethernet: MACs swapped.
    assert_eq!(
        &out[0..6],
        &CLIENT_MAC,
        "reply dst MAC = original src (client)"
    );
    assert_eq!(
        &out[6..12],
        &SERVER_MAC,
        "reply src MAC = original dst (server)"
    );

    // IPv4: addresses swapped, still TCP.
    assert_eq!(
        &out[IP + 12..IP + 16],
        &server_ip,
        "reply src IP = original dst"
    );
    assert_eq!(
        &out[IP + 16..IP + 20],
        &client_ip,
        "reply dst IP = original src"
    );
    assert_eq!(out[IP + 9], 6, "still protocol TCP");

    // TCP: ports swapped, seq = cookie, ack = client_seq + 1, SYN|ACK only.
    assert_eq!(
        be16(&out, TCP),
        server_port,
        "reply src port = original dst"
    );
    assert_eq!(
        be16(&out, TCP + 2),
        client_port,
        "reply dst port = original src"
    );
    let actual_cookie = be32(&out, TCP + 4);
    assert!(
        expected_cookies.contains(&actual_cookie),
        "reply seq {actual_cookie:#010x} must be a map-keyed SYN-cookie for an \
         adjacent monotonic slot (candidates: {expected_cookies:#010x?})"
    );
    assert_eq!(
        be32(&out, TCP + 8),
        client_seq.wrapping_add(1),
        "reply ack must be client_seq + 1"
    );
    assert_eq!(out[TCP + 13], 0x12, "flags must be SYN|ACK only");
    assert_eq!(
        be16(&out, TCP + 14),
        65535,
        "window must be the fixed value"
    );

    // MSS option echoed back in the reply.
    assert_eq!(out[TCP + 20], 2, "first option is MSS (kind 2)");
    assert_eq!(out[TCP + 21], 4, "MSS option length 4");
    assert_eq!(
        be16(&out, TCP + 22),
        expected_mss,
        "MSS echoes the cookie's MSS"
    );

    // IPv4 header checksum valid: summing all 20 header bytes folds to 0xFFFF.
    assert_eq!(
        fold(ones_sum(&out, IP, 20)),
        0xFFFF,
        "IPv4 header checksum must be valid"
    );

    // TCP checksum valid: pseudo-header + segment folds to 0xFFFF.
    let seg_len = out.len() - TCP;
    let mut tcp_sum = 0u32;
    tcp_sum += ones_sum(&out, IP + 12, 4); // source addr
    tcp_sum += ones_sum(&out, IP + 16, 4); // dest addr
    tcp_sum += u32::from(6u16); // protocol
    tcp_sum += u32::from(u16::try_from(seg_len).expect("seg len fits in u16")); // TCP length
    tcp_sum += ones_sum(&out, TCP, seg_len);
    assert_eq!(fold(tcp_sum), 0xFFFF, "TCP checksum must be valid");
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn non_syn_tcp_passes_through_unchanged() {
    let ack = eth_ipv4_tcp_ack([203, 0, 113, 7], [198, 51, 100, 1]);

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    let (action, out) = run_xdp_out(prog_fd, &ack);
    assert_eq!(action, XDP_PASS, "a non-SYN TCP segment must pass through");
    assert_eq!(out, ack, "a passed packet must be byte-for-byte unchanged");
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn syn_without_a_cookie_key_passes_through_unchanged() {
    // B2.3a fallback: with the `COOKIE_KEY` map left empty, the SYN handler must
    // never mint a cookie under a garbage key — it bails to `XDP_PASS` and the
    // frame is returned untouched for the userspace tier to handle.
    let syn = eth_ipv4_tcp_syn(
        [203, 0, 113, 7],
        [198, 51, 100, 1],
        54_321,
        443,
        0x1122_3344,
        1460,
    );

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    // Install the protected prefix + port so the SYN clears the B2.3b gate; the
    // *only* reason it must still pass through is the deliberately-absent cookie
    // key (B2.3a guard), isolating that guard from the gating.
    install_protect_prefix(&mut bpf, 24, [198, 51, 100, 0]);
    install_protect_port(&mut bpf, 443);
    // Deliberately do NOT install a cookie key.
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    let (action, out) = run_xdp_out(prog_fd, &syn);
    assert_eq!(
        action, XDP_PASS,
        "a SYN with no cookie key installed must pass through"
    );
    assert_eq!(out, syn, "a passed SYN must be byte-for-byte unchanged");
}

// --- B2.3b: protected-prefix + protected-port gating ---

/// The protected deception prefix + port the gating tests install: a SYN's
/// destination must match BOTH for the fast path to answer it.
const PROTECT_PREFIX: [u8; 4] = [10, 0, 0, 0];
/// Protected deception port used by the gating tests.
const PROTECT_TCP_PORT: u16 = 8080;

/// Load `xdp_filter` from `bpf` with a valid cookie key **and** the protected
/// prefix `10.0.0.0/24` + port `8080` installed, returning the program fd. The
/// caller keeps `bpf` alive so the fd (and its maps) stay valid.
fn load_with_cookie_and_gate(bpf: &mut Ebpf) -> i32 {
    install_cookie_key(bpf, COOKIE_KEY);
    install_protect_prefix(bpf, 24, PROTECT_PREFIX);
    install_protect_port(bpf, PROTECT_TCP_PORT);
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    prog.fd().expect("program fd").as_fd().as_raw_fd()
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn syn_to_protected_prefix_and_port_is_answered_via_xdp_tx() {
    // Destination 10.0.0.1:8080 matches BOTH the protected prefix and port, so
    // (with a valid cookie key) the SYN is answered in-kernel via XDP_TX.
    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    let prog_fd = load_with_cookie_and_gate(&mut bpf);

    let syn = eth_ipv4_tcp_syn(
        [203, 0, 113, 7],
        [10, 0, 0, 1],
        54_321,
        PROTECT_TCP_PORT,
        0x1122_3344,
        1460,
    );
    let action = run_xdp(prog_fd, &syn);
    assert_eq!(
        action, XDP_TX,
        "a SYN to a protected prefix + port must be answered via XDP_TX"
    );
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn syn_to_protected_prefix_but_unprotected_port_passes_through_unchanged() {
    // Destination 10.0.0.1:22 — dst IP is in the protected prefix, but port 22
    // is NOT a protected deception port, so the gate must let it pass untouched
    // (a real SSH service on the box must never be hijacked by the fast path).
    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    let prog_fd = load_with_cookie_and_gate(&mut bpf);

    let syn = eth_ipv4_tcp_syn(
        [203, 0, 113, 7],
        [10, 0, 0, 1],
        54_321,
        22,
        0x1122_3344,
        1460,
    );
    let (action, out) = run_xdp_out(prog_fd, &syn);
    assert_eq!(
        action, XDP_PASS,
        "a SYN to a protected prefix on an unprotected port must pass through"
    );
    assert_eq!(
        out, syn,
        "a gated (passed) SYN must be byte-for-byte unchanged"
    );
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn syn_to_protected_port_but_unprotected_prefix_passes_through_unchanged() {
    // Destination 192.168.1.1:8080 — port 8080 is protected, but the dst IP is
    // NOT in any protected prefix, so the gate must let it pass untouched (a
    // real service on a non-deception address must never be hijacked).
    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    let prog_fd = load_with_cookie_and_gate(&mut bpf);

    let syn = eth_ipv4_tcp_syn(
        [203, 0, 113, 7],
        [192, 168, 1, 1],
        54_321,
        PROTECT_TCP_PORT,
        0x1122_3344,
        1460,
    );
    let (action, out) = run_xdp_out(prog_fd, &syn);
    assert_eq!(
        action, XDP_PASS,
        "a SYN to a protected port on an unprotected prefix must pass through"
    );
    assert_eq!(
        out, syn,
        "a gated (passed) SYN must be byte-for-byte unchanged"
    );
}

// --- B2.3c: in-kernel IPv6 SipHash-cookie SYN-ACK via XDP_TX ---

/// Client IPv6 address in the crafted v6 SYN (`2001:db8::7`).
const CLIENT_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07,
];
/// Server (deception) IPv6 address in the crafted v6 SYN (`2001:db8:0:1::1`),
/// inside the protected `2001:db8::/32` prefix.
const SERVER_IP6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
/// Protected IPv6 deception prefix (`2001:db8::/32`) the v6 gating tests install.
const PROTECT_PREFIX6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn syn_is_answered_with_a_golden_cookie_syn_ack_via_xdp_tx_v6() {
    let client_port = 54_321u16;
    let server_port = 443u16;
    let client_seq = 0x1122_3344u32;
    let client_mss = 1460u16;

    let (k0, k1) = cookie_keys(COOKIE_KEY);

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    // B2.3a: deliver the cookie secret via the map (shared with the v4 path).
    install_cookie_key(&mut bpf, COOKIE_KEY);
    // B2.3c: the SYN's dst ([2001:db8:0:1::1]:443) must match a protected v6
    // prefix AND a protected port (the port set is shared across families).
    install_protect_prefix_v6(&mut bpf, 32, PROTECT_PREFIX6);
    install_protect_port(&mut bpf, server_port);
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    let syn = eth_ipv6_tcp_syn(
        CLIENT_IP6,
        SERVER_IP6,
        client_port,
        server_port,
        client_seq,
        client_mss,
    );
    // The eBPF cookie time base is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC), which
    // we cannot pin, so accept any of the three adjacent 64-second slots.
    let now_secs = clock_monotonic_secs();
    let (action, out) = run_xdp_out(prog_fd, &syn);
    let slot = now_secs >> blackwall_cookie::COUNTER_SHIFT;
    let expected_mss = blackwall_cookie::make_cookie_raw(
        k0,
        k1,
        &CLIENT_IP6,
        client_port,
        &SERVER_IP6,
        server_port,
        client_mss,
        slot << blackwall_cookie::COUNTER_SHIFT,
    )
    .1;
    // Cross-check: the in-kernel cookie (over the 16-byte v6 addresses) must
    // equal the userspace `make_cookie_raw` computed here with the same tuple.
    let expected_cookies: Vec<u32> = [slot.wrapping_sub(1), slot, slot + 1]
        .into_iter()
        .map(|s| {
            blackwall_cookie::make_cookie_raw(
                k0,
                k1,
                &CLIENT_IP6,
                client_port,
                &SERVER_IP6,
                server_port,
                client_mss,
                s << blackwall_cookie::COUNTER_SHIFT,
            )
            .0
        })
        .collect();

    assert_eq!(action, XDP_TX, "a v6 SYN must be answered via XDP_TX");
    assert_eq!(
        out.len(),
        syn.len(),
        "the reply must be the same byte length"
    );

    // Ethernet: MACs swapped.
    assert_eq!(&out[0..6], &CLIENT_MAC, "reply dst MAC = original src");
    assert_eq!(&out[6..12], &SERVER_MAC, "reply src MAC = original dst");
    assert_eq!(&out[12..14], &[0x86, 0xDD], "still EtherType IPv6");

    // IPv6: addresses swapped, still next-header TCP.
    assert_eq!(
        &out[IP6 + 8..IP6 + 24],
        &SERVER_IP6,
        "reply src IP = original dst"
    );
    assert_eq!(
        &out[IP6 + 24..IP6 + 40],
        &CLIENT_IP6,
        "reply dst IP = original src"
    );
    assert_eq!(out[IP6 + 6], 6, "still next-header TCP");

    // TCP: ports swapped, seq = cookie, ack = client_seq + 1, SYN|ACK only.
    assert_eq!(
        be16(&out, TCP6),
        server_port,
        "reply src port = original dst"
    );
    assert_eq!(
        be16(&out, TCP6 + 2),
        client_port,
        "reply dst port = original src"
    );
    let actual_cookie = be32(&out, TCP6 + 4);
    assert!(
        expected_cookies.contains(&actual_cookie),
        "reply seq {actual_cookie:#010x} must be a v6 SYN-cookie for an adjacent \
         monotonic slot (candidates: {expected_cookies:#010x?})"
    );
    assert_eq!(
        be32(&out, TCP6 + 8),
        client_seq.wrapping_add(1),
        "reply ack must be client_seq + 1"
    );
    assert_eq!(out[TCP6 + 13], 0x12, "flags must be SYN|ACK only");
    assert_eq!(
        be16(&out, TCP6 + 14),
        65535,
        "window must be the fixed value"
    );

    // MSS option echoed back in the reply.
    assert_eq!(out[TCP6 + 20], 2, "first option is MSS (kind 2)");
    assert_eq!(out[TCP6 + 21], 4, "MSS option length 4");
    assert_eq!(
        be16(&out, TCP6 + 22),
        expected_mss,
        "MSS echoes the cookie's MSS"
    );

    // TCP checksum valid over the IPv6 pseudo-header (16-byte src + dst
    // addresses, next-header 6, 32-bit TCP length) + the TCP segment.
    let seg_len = out.len() - TCP6;
    let mut tcp_sum = 0u32;
    tcp_sum += ones_sum(&out, IP6 + 8, 16); // source addr
    tcp_sum += ones_sum(&out, IP6 + 24, 16); // dest addr
    tcp_sum += u32::from(6u16); // next header
    tcp_sum += u32::from(u16::try_from(seg_len).expect("seg len fits in u16")); // TCP length
    tcp_sum += ones_sum(&out, TCP6, seg_len);
    assert_eq!(
        fold(tcp_sum),
        0xFFFF,
        "TCP checksum over the IPv6 pseudo-header must be valid"
    );
}

#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn v6_syn_to_unprotected_prefix_or_port_passes_through_unchanged() {
    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
    install_cookie_key(&mut bpf, COOKIE_KEY);
    // Only 2001:db8::/32 + port 443 are protected.
    install_protect_prefix_v6(&mut bpf, 32, PROTECT_PREFIX6);
    install_protect_port(&mut bpf, 443);
    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    // Protected prefix but unprotected port (22) must pass through untouched.
    let wrong_port = eth_ipv6_tcp_syn(CLIENT_IP6, SERVER_IP6, 54_321, 22, 0x1122_3344, 1460);
    let (action, out) = run_xdp_out(prog_fd, &wrong_port);
    assert_eq!(
        action, XDP_PASS,
        "a v6 SYN to a protected prefix on an unprotected port must pass"
    );
    assert_eq!(out, wrong_port, "a gated (passed) v6 SYN must be unchanged");

    // Protected port but the dst is outside any protected prefix (2001:db9::1).
    let mut off_prefix_ip = SERVER_IP6;
    off_prefix_ip[3] = 0xb9; // 2001:db9:... — outside 2001:db8::/32
    let wrong_prefix = eth_ipv6_tcp_syn(CLIENT_IP6, off_prefix_ip, 54_321, 443, 0x1122_3344, 1460);
    let (action, out) = run_xdp_out(prog_fd, &wrong_prefix);
    assert_eq!(
        action, XDP_PASS,
        "a v6 SYN to a protected port on an unprotected prefix must pass"
    );
    assert_eq!(
        out, wrong_prefix,
        "a gated (passed) v6 SYN must be unchanged"
    );
}

// --- B4.1: xdpcap-style packet capture ---

/// End-to-end capture: enable the `CAPTURE_ENABLED` flag, run one frame through
/// the program, and confirm a `CaptureRecord` (verdict + reason + lengths + the
/// L2 snapshot) lands in the `CAPTURE` ring — the same ring the userspace
/// `XdpCapture` reader drains and the pure `pcap` encoder serialises.
#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn enabled_capture_pushes_a_record_for_the_acted_packet() {
    use aya::maps::RingBuf;

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");

    // Enable capture (single-entry flag map, key 0 -> 1).
    {
        let mut flag: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("CAPTURE_ENABLED")
                .expect("CAPTURE_ENABLED map present"),
        )
        .expect("CAPTURE_ENABLED is a HashMap");
        flag.insert(0u32, 1u8, 0).expect("enable capture");
    }

    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    // A plain (non-blocked, non-SYN) IPv4 frame: falls through to XDP_PASS.
    let frame = eth_ipv4([203, 0, 113, 5]);
    let action = run_xdp(prog_fd, &frame);
    assert_eq!(action, XDP_PASS, "plain frame passes");

    // Drain the ring and parse the single record with the crate's pure parser.
    let mut ring =
        RingBuf::try_from(bpf.map_mut("CAPTURE").expect("CAPTURE map present")).expect("ring");
    let item = ring.next().expect("one capture record present");
    let parsed = blackwall_xdp::pcap::parse_record(&item).expect("record parses");

    // REASON_PASS == 0, verdict XDP_PASS == 2, original length is the frame len.
    assert_eq!(parsed.record.reason, 0, "reason = PASS");
    assert_eq!(parsed.record.verdict, XDP_PASS, "verdict = XDP_PASS");
    assert_eq!(
        parsed.record.pkt_len,
        u32::try_from(frame.len()).unwrap(),
        "pkt_len = original frame length"
    );
    // The 34-byte frame is snapshotted at the 32-byte tier; the bytes match the
    // head of the frame.
    assert_eq!(parsed.record.cap_len, 32, "cap_len = 32-byte tier");
    assert_eq!(parsed.data.len(), 32);
    assert_eq!(&parsed.data[..], &frame[..32], "snapshot = frame head");
    assert!(parsed.record.timestamp_ns > 0, "timestamp recorded");

    drop(item);
    assert!(ring.next().is_none(), "exactly one record was captured");
}

/// With capture **disabled** (the default — flag absent), running frames pushes
/// nothing into the ring: the zero-overhead-when-off guarantee.
#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn disabled_capture_pushes_nothing() {
    use aya::maps::RingBuf;

    let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");

    let prog: &mut Xdp = bpf
        .program_mut("xdp_filter")
        .expect("xdp_filter program present")
        .try_into()
        .expect("program is an Xdp");
    prog.load().expect("verify + load xdp_filter");
    let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

    // Never touch CAPTURE_ENABLED: capture is off.
    for _ in 0..4 {
        run_xdp(prog_fd, &eth_ipv4([203, 0, 113, 5]));
    }

    let mut ring =
        RingBuf::try_from(bpf.map_mut("CAPTURE").expect("CAPTURE map present")).expect("ring");
    assert!(
        ring.next().is_none(),
        "capture disabled: the ring must stay empty"
    );
}

// --- X1: race-free per-source RATE bucket ---
//
// The feasibility spike attempted a single shared bucket (one `LruHashMap`
// entry per source) guarded by a `bpf_spin_lock` field. The verifier rejected
// it on this toolchain/kernel: `map 'RATE' has to have BTF in order to use
// bpf_spin_lock` — aya-ebpf 0.1.1's `#[map]` macro emits the legacy
// `bpf_map_def`-based `maps` ELF section, not a BTF-defined map, so aya never
// populates `btf_key_type_id`/`btf_value_type_id` at map-creation time. The
// shipped fix is the fallback: `RATE` is now an `LruPerCpuHashMap`, so each
// CPU's copy of a source's bucket is independent and the refill/decrement
// needs no lock (see `blackwall_xdp_common::RateBucket`'s and
// `blackwall-xdp-ebpf`'s `RATE`/`over_rate` doc comments for the full
// rationale and the `N_cpus × configured burst` looser-bound trade-off).

/// `#[repr(transparent)]` newtype so the foreign
/// [`blackwall_xdp_common::RateBucket`] POD can carry an [`aya::Pod`] impl
/// (the orphan rule forbids implementing it directly) — mirrors the
/// production `RateBucketPod` in `blackwall_xdp::dataplane`.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct RateBucketPod(blackwall_xdp_common::RateBucket);

// SAFETY: `RateBucket` is a `#[repr(C)]` `Copy + 'static` plain-old-data
// struct of four `u64` fields; `#[repr(transparent)]` makes `RateBucketPod`
// share its exact layout, so it is byte-for-byte valid as a BPF map value.
unsafe impl aya::Pod for RateBucketPod {}

/// Install a fresh token bucket for `addr` (v4, zero-padded into the low four
/// bytes of the 16-byte key exactly like the eBPF program's own key) on
/// *every* CPU's slot, with `rate_pps = 0` so the burst is never refilled
/// mid-test — the (N+1)th packet on the pinned CPU is guaranteed to see zero
/// tokens. Mirrors the production `XdpDataplane::rate_limit` per-CPU seeding
/// (`RATE` is an `LruPerCpuHashMap`, X1 fallback).
fn install_rate_bucket(bpf: &mut Ebpf, addr: [u8; 4], burst: u64) {
    use aya::maps::{PerCpuHashMap, PerCpuValues};
    use aya::util::nr_cpus;

    let mut map: PerCpuHashMap<_, [u8; 16], RateBucketPod> =
        PerCpuHashMap::try_from(bpf.map_mut("RATE").expect("RATE map present"))
            .expect("RATE is a PerCpuHashMap");
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&addr);
    let bucket = blackwall_xdp_common::RateBucket {
        tokens: burst,
        last_ns: 0,
        rate_pps: 0,
        burst,
    };
    let cpus = nr_cpus().expect("nr_cpus");
    let values =
        PerCpuValues::try_from(vec![RateBucketPod(bucket); cpus]).expect("build per-CPU values");
    map.insert(key, values, 0).expect("insert rate bucket");
}

/// Pin the calling thread to CPU 0 for the duration of `f`, restoring the
/// original affinity mask afterward.
///
/// `RATE` is per-CPU (X1 fallback), so `BPF_PROG_TEST_RUN` must execute every
/// packet in a burst sequence on the *same* CPU: otherwise the scheduler
/// could migrate the calling thread between calls and each packet would hit
/// a different, independently-full per-CPU bucket rather than draining one.
fn pin_to_cpu0<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: `old`/`only0` are zero-initialised, correctly-sized `cpu_set_t`
    // buffers; `sched_getaffinity`/`sched_setaffinity` with pid `0` operate on
    // the calling thread and write/read exactly `size_of::<cpu_set_t>()`
    // bytes into/from them.
    unsafe {
        let mut old: libc::cpu_set_t = std::mem::zeroed();
        let rc = libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut old);
        assert_eq!(
            rc,
            0,
            "sched_getaffinity failed: {}",
            std::io::Error::last_os_error()
        );

        let mut only0: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(0, &mut only0);
        let rc =
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const only0);
        assert_eq!(
            rc,
            0,
            "sched_setaffinity(cpu0) failed: {}",
            std::io::Error::last_os_error()
        );

        let result = f();

        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const old);
        assert_eq!(
            rc,
            0,
            "sched_setaffinity(restore) failed: {}",
            std::io::Error::last_os_error()
        );

        result
    }
}

/// X1: the verifier must accept `RATE`'s `LruPerCpuHashMap` value
/// (`prog.load()` below is the load/verify check) and, pinned to a single
/// CPU so every `BPF_PROG_TEST_RUN` call hits the same per-CPU bucket slot,
/// sequential calls must enforce the token bucket exactly as before X1: the
/// first `burst` packets from one source are admitted, the next is dropped
/// with `REASON_RATELIMIT`.
#[test]
#[ignore = "requires root + recent kernel; run in the lab CI job"]
fn rate_limited_source_is_admitted_up_to_burst_then_dropped() {
    const SRC: [u8; 4] = [203, 0, 113, 42];
    const BURST: u64 = 3;

    pin_to_cpu0(|| {
        let mut bpf = Ebpf::load(blackwall_xdp::PROGRAM_OBJECT).expect("load eBPF object");
        install_rate_bucket(&mut bpf, SRC, BURST);

        let prog: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .expect("xdp_filter program present")
            .try_into()
            .expect("program is an Xdp");
        // The load/verify step is itself the X1 spike assertion: the verifier
        // must accept the `LruPerCpuHashMap` RATE map value on this kernel.
        prog.load()
            .expect("verify + load xdp_filter (per-CPU RATE map value)");
        let prog_fd = prog.fd().expect("program fd").as_fd().as_raw_fd();

        let frame = eth_ipv4(SRC);
        for i in 0..BURST {
            let action = run_xdp(prog_fd, &frame);
            assert_eq!(action, XDP_PASS, "packet {i} within burst must be admitted");
        }
        assert_eq!(
            stat_packets(&mut bpf, blackwall_xdp_common::REASON_RATELIMIT),
            0,
            "no packet within the burst should be rate-limited"
        );

        let over_burst = run_xdp(prog_fd, &frame);
        assert_eq!(
            over_burst, XDP_DROP,
            "the (burst + 1)th packet must be rate-limited"
        );
        assert_eq!(
            stat_packets(&mut bpf, blackwall_xdp_common::REASON_RATELIMIT),
            1,
            "exactly one packet must be counted as rate-limited"
        );
    });
}
