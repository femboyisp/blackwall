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
use aya::programs::Xdp;
use aya::Ebpf;

/// `bpf(2)` command number for `BPF_PROG_TEST_RUN`.
const BPF_PROG_TEST_RUN: core::ffi::c_long = 10;

/// `XDP_DROP` action code (see `bpf.h`).
const XDP_DROP: u32 = 1;
/// `XDP_PASS` action code.
const XDP_PASS: u32 = 2;

/// The `BPF_PROG_TEST_RUN` slice of `union bpf_attr`, matching the kernel layout.
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
}

/// Address of a byte slice as a `u64`, without an `as` cast.
fn slice_addr(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.as_ptr().addr()).expect("pointer fits in u64")
}

/// Run `xdp_filter` (identified by `prog_fd`) over `frame` and return its
/// `XDP_*` action.
fn run_xdp(prog_fd: i32, frame: &[u8]) -> u32 {
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
    // Keep the output buffer alive across the syscall above.
    drop(data_out);
    attr.retval
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
