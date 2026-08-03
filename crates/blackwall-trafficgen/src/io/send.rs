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
        // Frames owed by each flow this pass, computed against a single `elapsed`
        // snapshot so the counts stay in proportion to each flow's pps.
        let mut any_active = false;
        let mut dues = vec![0u64; plans.len()];
        for (i, (_idx, plan, sent, _counts)) in plans.iter().enumerate() {
            if plan.finished(elapsed, *sent) {
                continue;
            }
            any_active = true;
            dues[i] = plan.due(elapsed, *sent);
        }
        if !any_active {
            break;
        }
        // Emit round-robin across flows rather than draining each flow's whole
        // due before the next: when the tx ring saturates and `sendto` starts
        // returning ENOBUFS (silently dropped below), interleaving spreads those
        // drops across all flows in proportion to their due, instead of letting
        // the high-rate flows at the front of the list starve the tail (benign).
        for i in interleave_order(&dues) {
            let (idx, _plan, sent, counts) = &mut plans[i];
            let ps = &spec.patterns[*idx];
            let params = FrameParams {
                src_mac: SRC_MAC,
                dst_mac: DST_MAC,
                src_ip: std::net::IpAddr::V4(src_ip),
                dst_ip: std::net::IpAddr::V4(dst),
                dst_port,
                payload_len: 64,
            };
            let frame = build_frame(&ps.pattern, &params, *sent)?;
            if sendto_ll(&sock, &frame, &sll).is_ok() {
                *sent += 1;
                counts.packets += 1;
                let blen = u64::try_from(frame.len()).unwrap_or(0);
                counts.bytes += blen;
                total.packets += 1;
                total.bytes += blen;
            }
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

/// Round-robin emission order across flows for one send pass: given each flow's
/// frame `dues` for this pass, return one flow index per frame, cycling flows so
/// a low-rate flow's frames are interleaved with — not queued behind — a
/// high-rate flow's. Draining each flow's whole due in list order lets the tx
/// ring fill on the high-rate flows at the front, so every flow after them eats
/// the resulting ENOBUFS drops; interleaving spreads the drops in proportion to
/// each flow's due, so no flow (notably `benign`, last in the spec) is starved
/// below its share. Total frame count is unchanged — only the order differs.
fn interleave_order(dues: &[u64]) -> Vec<usize> {
    let total: u64 = dues.iter().copied().sum();
    let mut order = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    let mut remaining = dues.to_vec();
    let mut progress = true;
    while progress {
        progress = false;
        for (i, r) in remaining.iter_mut().enumerate() {
            if *r == 0 {
                continue;
            }
            *r -= 1;
            order.push(i);
            progress = true;
        }
    }
    order
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

#[cfg(test)]
mod tests {
    use super::interleave_order;

    #[test]
    fn interleave_is_round_robin_not_drain_in_order() {
        // A high-rate flow (idx 0) and a single-frame low-rate flow (idx 1):
        // the low-rate frame lands second, not last, so a saturated tx ring
        // can't drop it after already accepting all of flow 0.
        assert_eq!(interleave_order(&[3, 1]), vec![0, 1, 0, 0]);
        // Three flows cycle in order until each is drained.
        assert_eq!(interleave_order(&[2, 2, 1]), vec![0, 1, 2, 0, 1]);
    }

    #[test]
    fn interleave_preserves_total_and_per_flow_counts() {
        let dues = [50, 20, 5, 1, 1];
        let order = interleave_order(&dues);
        assert_eq!(order.len(), 77);
        for (flow, &due) in dues.iter().enumerate() {
            let got = order.iter().filter(|&&i| i == flow).count();
            assert_eq!(u64::try_from(got).unwrap(), due, "flow {flow}");
        }
    }

    #[test]
    fn interleave_of_all_zero_is_empty() {
        assert!(interleave_order(&[0, 0, 0]).is_empty());
    }
}
