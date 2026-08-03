//! Thin `AF_PACKET` send/receive I/O. Coverage-excluded; validated by the lab.

pub mod connect;
pub mod recv;
pub mod send;

use crate::error::{Result, TrafficGenError};
use std::net::Ipv4Addr;

/// The interface in this namespace that carries the lab-assigned IPv4 (the veth).
///
/// Selected by "has a global IPv4", not "first non-`lo` link": a fresh netns in
/// some environments (notably the CI runner's container) auto-creates tunnel
/// devices (`sit0`/`tunl0`/`ip6tnl0`) that sort ahead of the veth in `ip link
/// show` but carry no address. Binding `AF_PACKET` to a tunnel stub sends into
/// the void — the sink sees `kernel_rx_packets: 0` and `send`'s fidelity check
/// fails — even though the veth is fine. Both endpoints of the lab link have an
/// IPv4 (the `/30`), so scanning IPv4 assignments picks the veth on each side.
///
/// # Errors
/// [`TrafficGenError::Io`] if no such interface exists or `ip` fails.
pub fn first_non_loopback_iface() -> Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .map_err(|e| TrafficGenError::Io(format!("ip addr: {e}")))?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // "<idx>: <iface>    inet 10.0.0.1/30 ... scope global <iface>"
        let name = line.split_whitespace().nth(1).unwrap_or("");
        if !name.is_empty() && name != "lo" && !name.starts_with("ifb") {
            return Ok(name.to_owned());
        }
    }
    Err(TrafficGenError::Io(
        "no non-loopback interface with an IPv4 address".to_owned(),
    ))
}

/// The first IPv4 address on `iface`.
///
/// # Errors
/// [`TrafficGenError::Io`] if none is found.
pub fn ipv4_of(iface: &str) -> Result<Ipv4Addr> {
    let out = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", iface])
        .output()
        .map_err(|e| TrafficGenError::Io(format!("ip addr: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let cidr = text
        .split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
        .ok_or_else(|| TrafficGenError::Io("no inet addr".to_owned()))?;
    cidr.split('/')
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|e| TrafficGenError::Io(format!("parse ipv4: {e}")))
}
