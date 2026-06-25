//! Pure parser for `/proc/net/{tcp,tcp6,udp,udp6}` listening sockets.

use crate::error::DiscoveryError;
use blackwall_core::L4Proto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A socket the host is listening on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    /// Local bind address.
    pub addr: IpAddr,
    /// Transport protocol.
    pub proto: L4Proto,
    /// Local port.
    pub port: u16,
}

/// Parse one `/proc/net` file body. Returns only listening sockets: TCP rows in
/// state `0A` (LISTEN), and UDP rows whose remote address is `0` (UNCONN).
pub fn parse_proc_net(
    contents: &str,
    proto: L4Proto,
    is_ipv6: bool,
) -> Result<Vec<ListeningSocket>, DiscoveryError> {
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let local = parts[1];
        let remote = parts[2];
        let state = parts[3];
        let listening = match proto {
            L4Proto::Tcp => state.eq_ignore_ascii_case("0A"),
            L4Proto::Udp => {
                remote.split(':').next() == Some("00000000")
                    || remote.split(':').next() == Some("00000000000000000000000000000000")
            }
        };
        if !listening {
            continue;
        }
        let (addr_hex, port_hex) = local
            .split_once(':')
            .ok_or_else(|| DiscoveryError::Parse(format!("bad local address: {local}")))?;
        let port = u16::from_str_radix(port_hex, 16)
            .map_err(|_| DiscoveryError::Parse(format!("bad port: {port_hex}")))?;
        let addr = if is_ipv6 {
            IpAddr::V6(parse_ipv6(addr_hex)?)
        } else {
            IpAddr::V4(parse_ipv4(addr_hex)?)
        };
        out.push(ListeningSocket { addr, proto, port });
    }
    Ok(out)
}

fn parse_ipv4(hex: &str) -> Result<Ipv4Addr, DiscoveryError> {
    let raw = u32::from_str_radix(hex, 16)
        .map_err(|_| DiscoveryError::Parse(format!("bad ipv4: {hex}")))?;
    // /proc stores the address little-endian within the host's byte order.
    Ok(Ipv4Addr::from(raw.to_be()))
}

fn parse_ipv6(hex: &str) -> Result<Ipv6Addr, DiscoveryError> {
    if hex.len() != 32 {
        return Err(DiscoveryError::Parse(format!("bad ipv6 length: {hex}")));
    }
    let mut octets = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let word = std::str::from_utf8(chunk)
            .ok()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .ok_or_else(|| DiscoveryError::Parse(format!("bad ipv6 word: {hex}")))?;
        // Each 32-bit group is stored little-endian.
        let be = word.to_le_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&be);
    }
    Ok(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 203.0.113.5 = CB007105; little-endian in /proc => 057100CB. Port 443 = 01BB.
    const TCP_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 057100CB:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100
   1: 057100CB:C350 0A1B2C3D:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000 100
";

    #[test]
    fn parses_only_listening_tcp() {
        let socks = parse_proc_net(TCP_FIXTURE, L4Proto::Tcp, false).expect("parse");
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].addr, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(socks[0].port, 443);
    }

    #[test]
    fn rejects_bad_port() {
        let bad = "header\n   0: 057100CB:ZZZZ 00000000:0000 0A x x x x x x 1\n";
        assert!(parse_proc_net(bad, L4Proto::Tcp, false).is_err());
    }
}
