//! Pure builders for each traffic [`Pattern`]. Every builder is a deterministic
//! function of its [`FrameParams`] and a `seq_index`, returning one complete
//! Ethernet frame's bytes. No I/O, no randomness.

use crate::error::{Result, TrafficGenError};
use etherparse::PacketBuilder;
use std::net::IpAddr;

/// Per-frame addressing + sizing shared by all patterns.
#[derive(Debug, Clone)]
pub struct FrameParams {
    /// Source MAC (a fixed locally-administered dummy in the lab).
    pub src_mac: [u8; 6],
    /// Destination MAC (broadcast in the lab — no ARP needed).
    pub dst_mac: [u8; 6],
    /// Source IP (the attacker, or a spoofed/reflector address per pattern).
    pub src_ip: IpAddr,
    /// Destination IP (the victim).
    pub dst_ip: IpAddr,
    /// Destination L4 port for unicast attack/benign patterns.
    pub dst_port: u16,
    /// UDP/benign payload length in bytes.
    pub payload_len: u16,
}

/// One traffic pattern. `build_frame` dispatches on this.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Volumetric UDP flood to `dst_port`.
    UdpFlood,
    /// TCP SYN flood; `spoof_src` rotates the source IP as well as the port.
    SynFlood {
        /// Rotate the source IP address (spoofing) in addition to the port.
        spoof_src: bool,
    },
    /// Reflection/amplification: a large UDP "reply" from a reflector port.
    Reflection(ReflProto),
    /// A deliberately malformed frame of the given kind.
    Malformed(MalformedKind),
    /// Steady benign UDP flow (the legit baseline).
    Benign,
}

/// Reflection protocols modeled by direct injection of the amplified reply.
#[derive(Debug, Clone, Copy)]
pub enum ReflProto {
    /// DNS reflection (UDP source port 53).
    Dns,
    /// NTP reflection (UDP source port 123).
    Ntp,
}

/// The specific way a [`Pattern::Malformed`] frame is broken.
#[derive(Debug, Clone, Copy)]
pub enum MalformedKind {
    /// Valid frame with a corrupted IPv4 header checksum.
    BadIpChecksum,
    /// Frame truncated so the L4 header is incomplete.
    TruncatedL4,
    /// TCP with an impossible flag combination (SYN+FIN+RST).
    IllegalTcpFlags,
    /// IPv4 total-length field set larger than the real packet.
    BadIpTotalLen,
}

/// `base + (seq_index % span)`, computed without `as` casts.
#[must_use]
pub fn rotate_port(base: u16, seq_index: u64, span: u16) -> u16 {
    let span = u64::from(span).max(1);
    let offset = seq_index % span;
    // offset < span <= u16::MAX, so the truncating conversion is lossless.
    let offset = u16::try_from(offset).unwrap_or(0);
    base.wrapping_add(offset)
}

/// Build one frame for `pattern`.
///
/// # Errors
/// Returns [`TrafficGenError::Build`] if `etherparse` serialization fails.
pub fn build_frame(pattern: &Pattern, params: &FrameParams, seq_index: u64) -> Result<Vec<u8>> {
    match pattern {
        Pattern::UdpFlood => {
            build_udp(params, rotate_port(1024, seq_index, 60000), params.dst_port)
        }
        Pattern::Benign => build_udp(params, rotate_port(40000, seq_index, 1000), params.dst_port),
        // Extended in Task 3.
        _ => Err(TrafficGenError::Build(
            "pattern not yet implemented".to_owned(),
        )),
    }
}

/// Build an Ethernet+IP+UDP frame with the given source/destination ports.
fn build_udp(params: &FrameParams, src_port: u16, dst_port: u16) -> Result<Vec<u8>> {
    let payload = vec![0u8; usize::from(params.payload_len)];
    let builder = PacketBuilder::ethernet2(params.src_mac, params.dst_mac);
    let builder = match (params.src_ip, params.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => builder.ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => builder.ipv6(s.octets(), d.octets(), 64),
        _ => return Err(TrafficGenError::Build("mismatched IP families".to_owned())),
    };
    let builder = builder.udp(src_port, dst_port);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut buf, &payload)
        .map_err(|e| TrafficGenError::Build(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};
    use std::net::{IpAddr, Ipv4Addr};

    fn v4_params() -> FrameParams {
        FrameParams {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0xff; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_port: 80,
            payload_len: 16,
        }
    }

    #[test]
    fn udp_flood_builds_parseable_udp_to_dst_port() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::UdpFlood, &p, 5).expect("build");
        let sliced = SlicedPacket::from_ethernet(&bytes).expect("parse");
        match sliced.net.as_ref().expect("net") {
            NetSlice::Ipv4(ip) => {
                assert_eq!(ip.header().destination_addr(), Ipv4Addr::new(10, 0, 0, 1));
            }
            _ => panic!("expected ipv4"),
        }
        match sliced.transport.as_ref().expect("transport") {
            TransportSlice::Udp(udp) => assert_eq!(udp.destination_port(), 80),
            _ => panic!("expected udp"),
        }
    }

    #[test]
    fn udp_flood_rotates_source_port_by_seq_index() {
        let p = v4_params();
        let a = build_frame(&Pattern::UdpFlood, &p, 0).unwrap();
        let b = build_frame(&Pattern::UdpFlood, &p, 1).unwrap();
        let sport = |f: &[u8]| match SlicedPacket::from_ethernet(f).unwrap().transport.unwrap() {
            TransportSlice::Udp(u) => u.source_port(),
            _ => unreachable!(),
        };
        assert_ne!(
            sport(&a),
            sport(&b),
            "source port must rotate with seq_index"
        );
    }

    #[test]
    fn benign_builds_low_port_udp() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::Benign, &p, 3).expect("build");
        let sliced = SlicedPacket::from_ethernet(&bytes).expect("parse");
        assert!(matches!(
            sliced.transport.as_ref().unwrap(),
            TransportSlice::Udp(_)
        ));
    }

    #[test]
    fn rotate_port_wraps_within_span() {
        assert_eq!(rotate_port(1024, 0, 100), 1024);
        assert_eq!(rotate_port(1024, 250, 100), 1024 + 50);
    }
}
