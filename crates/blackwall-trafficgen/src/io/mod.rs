//! Thin `AF_PACKET` send/receive I/O. Coverage-excluded; validated by the lab.

pub mod connect;
pub mod recv;
pub mod send;

use crate::error::{Result, TrafficGenError};
use std::net::Ipv4Addr;

/// First interface in this namespace that is not `lo`/`ifb*` (the veth).
///
/// # Errors
/// [`TrafficGenError::Io`] if no such interface exists or `ip` fails.
pub fn first_non_loopback_iface() -> Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .map_err(|e| TrafficGenError::Io(format!("ip link: {e}")))?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = line
            .split(':')
            .nth(1)
            .map(str::trim)
            .and_then(|n| n.split('@').next())
            .map(str::trim)
            .unwrap_or("");
        if !name.is_empty() && name != "lo" && !name.starts_with("ifb") {
            return Ok(name.to_owned());
        }
    }
    Err(TrafficGenError::Io("no non-loopback interface".to_owned()))
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
