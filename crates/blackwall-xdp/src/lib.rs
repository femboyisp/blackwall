//! Userspace control plane for the Blackwall XDP data plane.
pub mod keys;

/// The compiled `bpfel-unknown-none` object for the `xdp_filter` program,
/// embedded at build time from the `blackwall-xdp-ebpf` crate.
///
/// Load it with [`aya::Ebpf::load`]; it exposes the `xdp_filter` program and the
/// `BLOCK_V4`, `BLOCK_V6`, `RATE`, and `STATS` maps.
pub static PROGRAM_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/blackwall-xdp"));
