//! Paced `AF_PACKET` send loop.

use crate::error::{Result, TrafficGenError};
use crate::pattern::{build_frame, FrameParams};
use crate::rate::{Bound, Rate, RatePlan};
use crate::report::{flow_key_for_pattern, FlowCounts, SendReport};
use crate::spec::GenSpec;
use libc;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::Instant;

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0xff; 6];
const ETH_P_ALL: u16 = 0x0003;

/// Send `spec`'s patterns concurrently to `dst`:`dst_port` over `iface` until
/// `bound`.
///
/// # Errors
/// [`TrafficGenError::Io`] on socket failure, [`TrafficGenError::Build`] on a
/// frame build failure.
pub fn run_send(
    iface: &str,
    dst: Ipv4Addr,
    dst_port: u16,
    spec: &GenSpec,
    bound: Bound,
) -> Result<SendReport> {
    let ifindex = iface_index(iface)?;
    // AF_PACKET wants the protocol in network byte order (htons(ETH_P_ALL)).
    let sock = Socket::new(
        Domain::PACKET,
        Type::RAW,
        Some(Protocol::from(i32::from(ETH_P_ALL.to_be()))),
    )
    .map_err(|e| TrafficGenError::Io(format!("socket: {e}")))?;
    let sll = sockaddr_ll(ifindex);

    let src_ip = crate::io::ipv4_of(iface)?;
    // Per-pattern state: a RatePlan + a running seq_index + counters.
    let mut plans: Vec<(usize, RatePlan, u64, FlowCounts)> = spec
        .patterns
        .iter()
        .enumerate()
        .map(|(i, ps)| {
            (
                i,
                RatePlan::new(Rate::Pps(ps.pps), bound),
                0u64,
                FlowCounts::default(),
            )
        })
        .collect();

    let start = Instant::now();
    let mut total = FlowCounts::default();
    let mut target_pps = 0u64;
    for ps in &spec.patterns {
        target_pps += ps.pps;
    }

    loop {
        let elapsed = start.elapsed();
        let mut any_active = false;
        for (idx, plan, sent, counts) in &mut plans {
            if plan.finished(elapsed, *sent) {
                continue;
            }
            any_active = true;
            let due = plan.due(elapsed, *sent);
            let ps = &spec.patterns[*idx];
            for _ in 0..due {
                let params = FrameParams {
                    src_mac: SRC_MAC,
                    dst_mac: DST_MAC,
                    src_ip: std::net::IpAddr::V4(src_ip),
                    dst_ip: std::net::IpAddr::V4(dst),
                    dst_port,
                    payload_len: 64,
                };
                let frame = build_frame(&ps.pattern, &params, *sent)?;
                let res = sendto_ll(&sock, &frame, &sll);
                if res.is_ok() {
                    *sent += 1;
                    counts.packets += 1;
                    let blen = u64::try_from(frame.len()).unwrap_or(0);
                    counts.bytes += blen;
                    total.packets += 1;
                    total.bytes += blen;
                }
            }
        }
        if !any_active {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let mut per_pattern = BTreeMap::new();
    for (idx, _, _, counts) in &plans {
        per_pattern.insert(
            flow_key_for_pattern(&spec.patterns[*idx].pattern).to_owned(),
            *counts,
        );
    }
    Ok(SendReport {
        target_pps,
        elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        sent: total,
        per_pattern,
    })
}

// --- libc-level helpers (AF_PACKET sockaddr_ll + sendto) ---

/// Resolve an interface name to its kernel index.
fn iface_index(iface: &str) -> Result<u32> {
    let cname = CString::new(iface).map_err(|e| TrafficGenError::Io(e.to_string()))?;
    // SAFETY: `cname` is a valid NUL-terminated C string that outlives the call.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(TrafficGenError::Io(format!(
            "if_nametoindex({iface}) failed"
        )));
    }
    Ok(idx)
}

/// Build a `sockaddr_ll` for `ifindex`, addressed to the broadcast MAC.
fn sockaddr_ll(ifindex: u32) -> libc::sockaddr_ll {
    // SAFETY: `sockaddr_ll` is plain old data; an all-zero value is a valid start.
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = u16::try_from(libc::AF_PACKET).unwrap_or(0);
    sll.sll_protocol = ETH_P_ALL.to_be();
    sll.sll_ifindex = i32::try_from(ifindex).unwrap_or(0);
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&DST_MAC);
    sll
}

/// Send one frame via `libc::sendto` on an `AF_PACKET` socket.
fn sendto_ll(sock: &Socket, frame: &[u8], sll: &libc::sockaddr_ll) -> std::io::Result<()> {
    let addr = std::ptr::from_ref(sll).cast::<libc::sockaddr>();
    let len = u32::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap_or(0);
    // SAFETY: `frame` is a readable slice of `frame.len()` bytes; `addr` points to a
    // valid `sockaddr_ll` of `len` bytes; the fd is an open AF_PACKET socket.
    let n = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            addr,
            len,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
