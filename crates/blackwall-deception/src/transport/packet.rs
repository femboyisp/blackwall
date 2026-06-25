//! ICMP echo reply construction from raw IPv4/IPv6 packets.

use etherparse::{
    Icmpv4Header, Icmpv4Type, Icmpv6Header, Icmpv6Type, Ipv4Header, Ipv6Header, PacketHeaders,
    TransportHeader,
};

/// Parse a raw IPv4 packet containing an ICMP echo request and return the
/// corresponding echo reply bytes, with source and destination addresses
/// swapped and all checksums recomputed.
///
/// Returns `None` if the packet is not a valid IPv4 ICMP echo request.
pub fn icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    let headers = PacketHeaders::from_ip_slice(request).ok()?;

    let net = headers.net?;
    let (ip_hdr, _) = net.ipv4_ref()?;
    let ip_hdr = ip_hdr.clone();

    let icmp4 = match headers.transport? {
        TransportHeader::Icmpv4(h) => h,
        _ => return None,
    };

    let echo_hdr = match icmp4.icmp_type {
        Icmpv4Type::EchoRequest(e) => e,
        _ => return None,
    };

    let payload = headers.payload.slice().to_owned();

    // Build reply ICMP header with recomputed checksum.
    let reply_icmp = Icmpv4Header::with_checksum(Icmpv4Type::EchoReply(echo_hdr), &payload);

    // Build reply IPv4 header with swapped addresses.
    let payload_len = u16::try_from(reply_icmp.header_len() + payload.len()).ok()?;
    let mut reply_ip = Ipv4Header::new(
        payload_len,
        ip_hdr.time_to_live,
        ip_hdr.protocol,
        ip_hdr.destination, // swap: original dst becomes new src
        ip_hdr.source,      // swap: original src becomes new dst
    )
    .ok()?;
    reply_ip.header_checksum = reply_ip.calc_header_checksum();

    let mut out =
        Vec::with_capacity(reply_ip.header_len() + reply_icmp.header_len() + payload.len());
    reply_ip.write(&mut out).ok()?;
    reply_icmp.write(&mut out).ok()?;
    out.extend_from_slice(&payload);
    Some(out)
}

/// Parse a raw IPv6 packet containing an ICMPv6 echo request and return the
/// corresponding echo reply bytes, with source and destination addresses
/// swapped and all checksums recomputed.
///
/// Returns `None` if the packet is not a valid IPv6 ICMPv6 echo request.
pub fn icmpv6_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    let headers = PacketHeaders::from_ip_slice(request).ok()?;

    let net = headers.net?;
    let (ip_hdr, _) = net.ipv6_ref()?;
    let ip_hdr = ip_hdr.clone();

    let icmp6 = match headers.transport? {
        TransportHeader::Icmpv6(h) => h,
        _ => return None,
    };

    let echo_hdr = match icmp6.icmp_type {
        Icmpv6Type::EchoRequest(e) => e,
        _ => return None,
    };

    let payload = headers.payload.slice().to_owned();

    // Build reply ICMPv6 header. The pseudo-header checksum requires the
    // *reply* source/destination, i.e. the original destination/source.
    let reply_icmp = Icmpv6Header::with_checksum(
        Icmpv6Type::EchoReply(echo_hdr),
        ip_hdr.destination, // becomes new source
        ip_hdr.source,      // becomes new destination
        &payload,
    )
    .ok()?;

    // Build reply IPv6 header with swapped addresses.
    let payload_len = u16::try_from(reply_icmp.header_len() + payload.len()).ok()?;
    let reply_ip = Ipv6Header {
        traffic_class: ip_hdr.traffic_class,
        flow_label: ip_hdr.flow_label,
        payload_length: payload_len,
        next_header: ip_hdr.next_header,
        hop_limit: ip_hdr.hop_limit,
        source: ip_hdr.destination, // swap
        destination: ip_hdr.source, // swap
    };

    let mut out = Vec::with_capacity(Ipv6Header::LEN + reply_icmp.header_len() + payload.len());
    reply_ip.write(&mut out).ok()?;
    reply_icmp.write(&mut out).ok()?;
    out.extend_from_slice(&payload);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{IcmpEchoHeader, IpNumber, Ipv6FlowLabel, PacketBuilder};

    fn build_icmpv4_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let echo = IcmpEchoHeader { id, seq };
        let icmp = Icmpv4Header::with_checksum(Icmpv4Type::EchoRequest(echo), data);
        let payload_len = u16::try_from(icmp.header_len() + data.len()).unwrap();
        let mut ip = Ipv4Header::new(payload_len, 64, IpNumber::ICMP, src, dst).unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        let mut pkt = Vec::new();
        ip.write(&mut pkt).unwrap();
        icmp.write(&mut pkt).unwrap();
        pkt.extend_from_slice(data);
        pkt
    }

    fn build_icmpv6_request(
        src: [u8; 16],
        dst: [u8; 16],
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let echo = IcmpEchoHeader { id, seq };
        let icmp =
            Icmpv6Header::with_checksum(Icmpv6Type::EchoRequest(echo), src, dst, data).unwrap();
        let payload_len = u16::try_from(icmp.header_len() + data.len()).unwrap();
        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: Ipv6FlowLabel::ZERO,
            payload_length: payload_len,
            next_header: IpNumber::IPV6_ICMP,
            hop_limit: 64,
            source: src,
            destination: dst,
        };
        let mut pkt = Vec::new();
        ip.write(&mut pkt).unwrap();
        icmp.write(&mut pkt).unwrap();
        pkt.extend_from_slice(data);
        pkt
    }

    #[test]
    fn icmpv4_echo_reply_roundtrip() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let data = b"hello world";
        let request = build_icmpv4_request(src, dst, 42, 7, data);

        let reply = icmp_echo_reply(&request).expect("reply should be Some");
        let parsed = PacketHeaders::from_ip_slice(&reply).unwrap();

        let net = parsed.net.unwrap();
        let (ip4, _) = net.ipv4_ref().unwrap();
        let ip4 = ip4.clone();
        assert_eq!(ip4.source, dst, "source should be the original destination");
        assert_eq!(
            ip4.destination, src,
            "destination should be the original source"
        );

        let icmp = match parsed.transport.unwrap() {
            TransportHeader::Icmpv4(h) => h,
            _ => panic!("expected ICMPv4"),
        };
        let echo_reply = match icmp.icmp_type {
            Icmpv4Type::EchoReply(e) => e,
            _ => panic!("expected EchoReply"),
        };
        assert_eq!(echo_reply.id, 42, "reply id must match request id");
        assert_eq!(echo_reply.seq, 7, "reply seq must match request seq");
        assert_eq!(parsed.payload.slice(), data);
    }

    #[test]
    fn icmpv6_echo_reply_roundtrip() {
        let src = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let data = b"ping6 data";
        let request = build_icmpv6_request(src, dst, 1, 2, data);

        let reply = icmpv6_echo_reply(&request).expect("reply should be Some");
        let parsed = PacketHeaders::from_ip_slice(&reply).unwrap();

        let net = parsed.net.unwrap();
        let (ip6, _) = net.ipv6_ref().unwrap();
        let ip6 = ip6.clone();
        assert_eq!(ip6.source, dst, "source should be the original destination");
        assert_eq!(
            ip6.destination, src,
            "destination should be the original source"
        );

        let icmp = match parsed.transport.unwrap() {
            TransportHeader::Icmpv6(h) => h,
            _ => panic!("expected ICMPv6"),
        };
        let echo_reply = match icmp.icmp_type {
            Icmpv6Type::EchoReply(e) => e,
            _ => panic!("expected EchoReply"),
        };
        assert_eq!(echo_reply.id, 1, "reply id must match request id");
        assert_eq!(echo_reply.seq, 2, "reply seq must match request seq");
        assert_eq!(parsed.payload.slice(), data);
    }

    #[test]
    fn tcp_packet_returns_none() {
        // PacketBuilder::ipv4 produces a raw IP packet (no ethernet header).
        let mut pkt = Vec::new();
        let builder = PacketBuilder::ipv4([1, 2, 3, 4], [5, 6, 7, 8], 64).tcp(1234, 80, 0, 65535);
        pkt.resize(builder.size(0), 0);
        builder.write(&mut pkt, &[]).unwrap();
        assert!(
            icmp_echo_reply(&pkt).is_none(),
            "TCP packet should return None"
        );
    }

    #[test]
    fn non_echo_icmpv4_returns_none() {
        // Build an ICMPv4 EchoReply (not EchoRequest) and feed it to icmp_echo_reply.
        // The function must return None because the type is not EchoRequest.
        let echo = IcmpEchoHeader { id: 1, seq: 1 };
        let icmp = Icmpv4Header::with_checksum(Icmpv4Type::EchoReply(echo), b"");
        let payload_len = u16::try_from(icmp.header_len()).unwrap();
        let mut ip =
            Ipv4Header::new(payload_len, 64, IpNumber::ICMP, [1, 2, 3, 4], [5, 6, 7, 8]).unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        let mut pkt = Vec::new();
        ip.write(&mut pkt).unwrap();
        icmp.write(&mut pkt).unwrap();
        assert!(
            icmp_echo_reply(&pkt).is_none(),
            "EchoReply packet should return None for icmp_echo_reply"
        );
    }

    #[test]
    fn ipv4_packet_returns_none_for_icmpv6() {
        // An IPv4 packet fed into icmpv6_echo_reply must return None (no IPv6 header).
        let request = build_icmpv4_request([1, 2, 3, 4], [5, 6, 7, 8], 1, 1, b"");
        assert!(
            icmpv6_echo_reply(&request).is_none(),
            "IPv4 packet should return None for icmpv6_echo_reply"
        );
    }

    #[test]
    fn non_echo_icmpv6_returns_none() {
        // Build a ICMPv6 EchoReply and feed it to icmpv6_echo_reply.
        let src = [0u8; 16];
        let dst = [0u8; 15].iter().chain(&[2u8]).cloned().collect::<Vec<_>>();
        let dst: [u8; 16] = dst.try_into().unwrap();
        let echo = IcmpEchoHeader { id: 5, seq: 5 };
        let icmp = Icmpv6Header::with_checksum(Icmpv6Type::EchoReply(echo), src, dst, b"").unwrap();
        let payload_len = u16::try_from(icmp.header_len()).unwrap();
        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: Ipv6FlowLabel::ZERO,
            payload_length: payload_len,
            next_header: IpNumber::IPV6_ICMP,
            hop_limit: 64,
            source: src,
            destination: dst,
        };
        let mut pkt = Vec::new();
        ip.write(&mut pkt).unwrap();
        icmp.write(&mut pkt).unwrap();
        assert!(
            icmpv6_echo_reply(&pkt).is_none(),
            "EchoReply should return None for icmpv6_echo_reply"
        );
    }
}
