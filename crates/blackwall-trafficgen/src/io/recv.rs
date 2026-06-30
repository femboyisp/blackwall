//! `AF_PACKET` receive sink: classify + count, with a `/proc/net/dev` cross-check.

use crate::error::{Result, TrafficGenError};
use crate::flow::classify;
use crate::report::{flow_key, FlowCounts, RecvReport};
use libc;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Read;
use std::mem;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const ETH_P_ALL: u16 = 0x0003;

/// Bind an `AF_PACKET` sink on `iface`, write `ready_path` once bound, capture +
/// classify for `duration`, then write the `RecvReport` JSON to `report_path`.
///
/// # Errors
/// [`TrafficGenError::Io`] on socket/filesystem failure.
pub fn run_recv(
    iface: &str,
    ready_path: &str,
    report_path: &str,
    duration: Duration,
) -> Result<RecvReport> {
    // Remove any stale sentinel + report from a previous run so the lab's
    // file-present probe is fresh and `verify` can only read this run's report.
    let _ = std::fs::remove_file(ready_path);
    let _ = std::fs::remove_file(report_path);

    let rx_before = proc_rx_packets(iface)?;
    // AF_PACKET wants the protocol in network byte order (htons(ETH_P_ALL)) so
    // the sink captures every incoming frame regardless of EtherType.
    let sock = Socket::new(
        Domain::PACKET,
        Type::RAW,
        Some(Protocol::from(i32::from(ETH_P_ALL.to_be()))),
    )
    .map_err(|e| TrafficGenError::Io(format!("socket: {e}")))?;
    // Bind to the interface index (libc sockaddr_ll), then mark ready.
    bind_ll(&sock, iface)?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| TrafficGenError::Io(format!("set_read_timeout: {e}")))?;
    std::fs::write(ready_path, b"ready")
        .map_err(|e| TrafficGenError::Io(format!("write ready: {e}")))?;

    let mut per_flow: BTreeMap<String, FlowCounts> = BTreeMap::new();
    let mut total = FlowCounts::default();
    let mut buf = [0u8; 2048];
    let start = Instant::now();
    while start.elapsed() < duration {
        match (&sock).read(&mut buf) {
            Ok(n) if n > 0 => {
                let frame = &buf[..n];
                let class = classify(frame);
                let entry = per_flow.entry(flow_key(class).to_owned()).or_default();
                entry.packets += 1;
                let blen = u64::try_from(n).unwrap_or(0);
                entry.bytes += blen;
                total.packets += 1;
                total.bytes += blen;
            }
            _ => {} // timeout / would-block: loop and re-check elapsed
        }
    }
    let rx_after = proc_rx_packets(iface)?;

    let report = RecvReport {
        elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        total,
        kernel_rx_packets: rx_after.saturating_sub(rx_before),
        per_flow,
    };
    std::fs::write(report_path, report.to_json()?)
        .map_err(|e| TrafficGenError::Io(format!("write report: {e}")))?;
    Ok(report)
}

/// rx_packets for `iface` from `/proc/net/dev`.
fn proc_rx_packets(iface: &str) -> Result<u64> {
    let text = std::fs::read_to_string("/proc/net/dev")
        .map_err(|e| TrafficGenError::Io(format!("read /proc/net/dev: {e}")))?;
    for line in text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix(iface) {
            if let Some(rest) = rest.strip_prefix(':') {
                if let Some(rx_packets) = rest.split_whitespace().nth(1) {
                    return rx_packets
                        .parse()
                        .map_err(|e| TrafficGenError::Io(format!("parse rx: {e}")));
                }
            }
        }
    }
    Err(TrafficGenError::Io(format!(
        "iface {iface} not in /proc/net/dev"
    )))
}

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
    sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    sll
}

/// Bind an `AF_PACKET` socket to `iface` using a `libc::sockaddr_ll`.
fn bind_ll(sock: &Socket, iface: &str) -> Result<()> {
    let ifindex = iface_index(iface)?;
    let sll = sockaddr_ll(ifindex);
    let addr = std::ptr::from_ref(&sll).cast::<libc::sockaddr>();
    let len = u32::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap_or(0);
    // SAFETY: `addr` points to a valid `sockaddr_ll` of `len` bytes; the fd is open.
    let rc = unsafe { libc::bind(sock.as_raw_fd(), addr, len) };
    if rc != 0 {
        return Err(TrafficGenError::Io(format!(
            "bind {iface}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
