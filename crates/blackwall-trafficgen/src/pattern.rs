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
        // Source-port span 1024..31023 is deliberately disjoint from the benign
        // flow's 40000..40999 window so the receiver never misclassifies a flood
        // frame as benign (both share dst_port 80). See `flow::classify`.
        Pattern::UdpFlood => {
            build_udp(params, rotate_port(1024, seq_index, 30000), params.dst_port)
        }
        Pattern::Benign => build_udp(params, rotate_port(40000, seq_index, 1000), params.dst_port),
        Pattern::SynFlood { spoof_src } => build_syn(params, seq_index, *spoof_src),
        Pattern::Reflection(proto) => {
            let src_port = match proto {
                ReflProto::Dns => 53,
                ReflProto::Ntp => 123,
            };
            // Amplified reply: large UDP FROM the reflector port TO the victim.
            let mut big = params.clone();
            big.payload_len = 1400;
            build_udp(&big, src_port, rotate_port(20000, seq_index, 1000))
        }
        Pattern::Malformed(kind) => {
            let mut buf = match kind {
                MalformedKind::IllegalTcpFlags => build_syn_fin_rst(params)?,
                _ => build_udp(params, rotate_port(1024, seq_index, 60000), params.dst_port)?,
            };
            corrupt(&mut buf, *kind);
            Ok(buf)
        }
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

/// Build an Ethernet+IPv4/6+TCP-SYN frame; optionally rotate the source IP.
fn build_syn(params: &FrameParams, seq_index: u64, spoof_src: bool) -> Result<Vec<u8>> {
    let src_ip = if spoof_src {
        rotate_ip(params.src_ip, seq_index)
    } else {
        params.src_ip
    };
    let src_port = rotate_port(1024, seq_index, 60000);
    let builder = PacketBuilder::ethernet2(params.src_mac, params.dst_mac);
    let builder = match (src_ip, params.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => builder.ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => builder.ipv6(s.octets(), d.octets(), 64),
        _ => return Err(TrafficGenError::Build("mismatched IP families".to_owned())),
    };
    let builder = builder.tcp(src_port, params.dst_port, 0, 65535).syn();
    let mut buf = Vec::with_capacity(builder.size(0));
    builder
        .write(&mut buf, &[])
        .map_err(|e| TrafficGenError::Build(e.to_string()))?;
    Ok(buf)
}

/// Build a TCP frame with the impossible SYN+FIN+RST flag combination.
fn build_syn_fin_rst(params: &FrameParams) -> Result<Vec<u8>> {
    let builder = PacketBuilder::ethernet2(params.src_mac, params.dst_mac);
    let builder = match (params.src_ip, params.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => builder.ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => builder.ipv6(s.octets(), d.octets(), 64),
        _ => return Err(TrafficGenError::Build("mismatched IP families".to_owned())),
    };
    let builder = builder
        .tcp(1024, params.dst_port, 0, 65535)
        .syn()
        .fin()
        .rst();
    let mut buf = Vec::with_capacity(builder.size(0));
    builder
        .write(&mut buf, &[])
        .map_err(|e| TrafficGenError::Build(e.to_string()))?;
    Ok(buf)
}

/// Rotate an IPv4 source address by `seq_index` (low octet); IPv6 unchanged for
/// the lab (spoofing is exercised on IPv4 SYN floods).
fn rotate_ip(ip: IpAddr, seq_index: u64) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mut o = v4.octets();
            o[3] = o[3].wrapping_add(u8::try_from(seq_index % 250).unwrap_or(0));
            IpAddr::V4(std::net::Ipv4Addr::from(o))
        }
        IpAddr::V6(_) => ip,
    }
}

/// Corrupt a freshly-built valid frame in the way `kind` prescribes.
fn corrupt(buf: &mut Vec<u8>, kind: MalformedKind) {
    match kind {
        MalformedKind::BadIpChecksum => {
            // Flip the stored IPv4 checksum bytes (14 + 10 .. 14 + 12).
            buf[24] ^= 0xff;
            buf[25] ^= 0xff;
        }
        MalformedKind::TruncatedL4 => {
            // Cut the frame inside the L4 header (keep eth + ip + 2 L4 bytes).
            buf.truncate(36);
        }
        MalformedKind::BadIpTotalLen => {
            // Overwrite IPv4 total-length (bytes 16..18) with a too-large value.
            let bogus = u16::MAX.to_be_bytes();
            buf[16] = bogus[0];
            buf[17] = bogus[1];
        }
        MalformedKind::IllegalTcpFlags => {
            // Already malformed by construction in build_syn_fin_rst.
        }
    }
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

    #[test]
    fn syn_flood_sets_syn_only() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::SynFlood { spoof_src: false }, &p, 7).unwrap();
        let sliced = SlicedPacket::from_ethernet(&bytes).unwrap();
        match sliced.transport.as_ref().unwrap() {
            TransportSlice::Tcp(tcp) => {
                assert!(tcp.syn() && !tcp.fin() && !tcp.rst() && !tcp.ack());
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn syn_flood_spoof_rotates_source_ip() {
        let p = v4_params();
        let a = build_frame(&Pattern::SynFlood { spoof_src: true }, &p, 0).unwrap();
        let b = build_frame(&Pattern::SynFlood { spoof_src: true }, &p, 1).unwrap();
        let src = |f: &[u8]| match SlicedPacket::from_ethernet(f).unwrap().net.unwrap() {
            NetSlice::Ipv4(ip) => ip.header().source_addr(),
            _ => unreachable!(),
        };
        assert_ne!(src(&a), src(&b), "spoofed source IP must rotate");
    }

    #[test]
    fn reflection_dns_sources_from_port_53() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::Reflection(ReflProto::Dns), &p, 1).unwrap();
        let sliced = SlicedPacket::from_ethernet(&bytes).unwrap();
        match sliced.transport.as_ref().unwrap() {
            TransportSlice::Udp(u) => assert_eq!(u.source_port(), 53),
            _ => panic!("expected udp"),
        }
    }

    #[test]
    fn malformed_bad_checksum_differs_from_recomputed() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::Malformed(MalformedKind::BadIpChecksum), &p, 0).unwrap();
        // Stored checksum (bytes 24..26) must NOT equal the checksum recomputed
        // over the IPv4 header — that's the malformation.
        let stored = u16::from_be_bytes([bytes[24], bytes[25]]);
        let recomputed = ipv4_header_checksum(&bytes[14..34]);
        assert_ne!(stored, recomputed);
    }

    #[test]
    fn malformed_truncated_l4_has_no_transport() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::Malformed(MalformedKind::TruncatedL4), &p, 0).unwrap();
        // etherparse must fail to produce a transport header (frame cut short).
        let parsed = SlicedPacket::from_ethernet(&bytes);
        let truncated = match parsed {
            Err(_) => true,
            Ok(s) => s.transport.is_none(),
        };
        assert!(
            truncated,
            "truncated frame must not yield a transport header"
        );
    }

    #[test]
    fn malformed_illegal_flags_sets_syn_fin_rst() {
        let p = v4_params();
        let bytes =
            build_frame(&Pattern::Malformed(MalformedKind::IllegalTcpFlags), &p, 0).unwrap();
        let sliced = SlicedPacket::from_ethernet(&bytes).unwrap();
        match sliced.transport.as_ref().unwrap() {
            TransportSlice::Tcp(tcp) => assert!(tcp.syn() && tcp.fin() && tcp.rst()),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn malformed_bad_total_len_exceeds_frame() {
        let p = v4_params();
        let bytes = build_frame(&Pattern::Malformed(MalformedKind::BadIpTotalLen), &p, 0).unwrap();
        let total_len = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
        // total-length claims more than the actual IP packet (frame len - eth 14).
        assert!(total_len > bytes.len() - 14);
    }

    // Test helper: standard one's-complement IPv4 header checksum.
    fn ipv4_header_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            // skip the checksum field itself (bytes 10..12 of the IP header)
            if i == 10 {
                i += 2;
                continue;
            }
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let folded = u16::try_from(sum & 0xffff).unwrap_or(0);
        !folded
    }
}
