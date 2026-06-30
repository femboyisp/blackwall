//! Pure classification of a received frame into the [`FlowClass`] it belongs
//! to, used by the receiver sink to count per-pattern delivery.

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// Which traffic flow a received frame belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowClass {
    /// Volumetric UDP flood.
    UdpFlood,
    /// TCP SYN flood.
    SynFlood,
    /// Reflection/amplification reply (UDP from port 53/123).
    Reflection,
    /// Benign baseline flow.
    Benign,
    /// A detectably-malformed frame.
    Malformed,
    /// Anything unrecognized.
    Unknown,
}

/// The benign flow's destination port and source-port range (see `pattern.rs`).
const BENIGN_DST_PORT: u16 = 80;
const BENIGN_SRC_LO: u16 = 40000;
const BENIGN_SRC_HI: u16 = 40999;

/// Classify one Ethernet frame.
#[must_use]
pub fn classify(frame: &[u8]) -> FlowClass {
    // Try to parse and check for IPv4 header size claims.
    // If the frame is too short to contain the claimed IPv4 payload, it's malformed.
    if frame.len() >= 34 {
        // Frame is at least ethernet (14) + minimal IPv4 (20)
        // Check the IPv4 total-length field at offset 16-17 (after 14-byte ethernet)
        let claimed_len = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        if claimed_len > frame.len() - 14 {
            return FlowClass::Malformed;
        }
    }

    let Ok(sliced) = SlicedPacket::from_ethernet(frame) else {
        return FlowClass::Unknown;
    };

    // IPv4 checksum validity check.
    if let Some(NetSlice::Ipv4(ip)) = sliced.net.as_ref() {
        let hdr = ip.header().slice();
        if hdr.len() >= 20 {
            let stored = u16::from_be_bytes([hdr[10], hdr[11]]);
            if stored != ipv4_checksum(&hdr[..20]) {
                return FlowClass::Malformed;
            }
        }
    }

    match sliced.transport.as_ref() {
        None => {
            // If we successfully parsed the network layer but have no transport,
            // it's malformed (truncated L4). Otherwise, unknown.
            if sliced.net.is_some() {
                FlowClass::Malformed
            } else {
                FlowClass::Unknown
            }
        }
        Some(TransportSlice::Tcp(tcp)) => {
            if tcp.syn() && tcp.fin() && tcp.rst() {
                FlowClass::Malformed
            } else if tcp.syn() && !tcp.ack() {
                FlowClass::SynFlood
            } else {
                FlowClass::Unknown
            }
        }
        Some(TransportSlice::Udp(udp)) => {
            let sport = udp.source_port();
            let dport = udp.destination_port();
            if sport == 53 || sport == 123 {
                FlowClass::Reflection
            } else if dport == BENIGN_DST_PORT && (BENIGN_SRC_LO..=BENIGN_SRC_HI).contains(&sport) {
                FlowClass::Benign
            } else {
                FlowClass::UdpFlood
            }
        }
        _ => FlowClass::Unknown,
    }
}

/// One's-complement IPv4 header checksum over a 20-byte header (checksum field
/// at bytes 10..12 treated as zero).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
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
    !u16::try_from(sum & 0xffff).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{build_frame, FrameParams, MalformedKind, Pattern, ReflProto};
    use std::net::{IpAddr, Ipv4Addr};

    fn params() -> FrameParams {
        FrameParams {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0xff; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_port: 80,
            payload_len: 16,
        }
    }

    fn classify_pattern(p: &Pattern) -> FlowClass {
        classify(&build_frame(p, &params(), 1).unwrap())
    }

    #[test]
    fn classifies_each_pattern() {
        assert_eq!(classify_pattern(&Pattern::UdpFlood), FlowClass::UdpFlood);
        assert_eq!(classify_pattern(&Pattern::Benign), FlowClass::Benign);
        assert_eq!(
            classify_pattern(&Pattern::SynFlood { spoof_src: false }),
            FlowClass::SynFlood
        );
        assert_eq!(
            classify_pattern(&Pattern::Reflection(ReflProto::Dns)),
            FlowClass::Reflection
        );
        assert_eq!(
            classify_pattern(&Pattern::Reflection(ReflProto::Ntp)),
            FlowClass::Reflection
        );
    }

    #[test]
    fn classifies_all_malformed_kinds_as_malformed() {
        for kind in [
            MalformedKind::BadIpChecksum,
            MalformedKind::TruncatedL4,
            MalformedKind::IllegalTcpFlags,
            MalformedKind::BadIpTotalLen,
        ] {
            assert_eq!(
                classify_pattern(&Pattern::Malformed(kind)),
                FlowClass::Malformed,
                "{kind:?} must classify as Malformed"
            );
        }
    }

    #[test]
    fn classifies_garbage_as_unknown() {
        assert_eq!(classify(&[0u8; 4]), FlowClass::Unknown);
    }
}
