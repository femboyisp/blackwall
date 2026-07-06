//! ICMP echo reply and stateless TCP SYN-cookie packet construction from raw
//! IPv4/IPv6 packets.

use etherparse::{
    Icmpv4Header, Icmpv4Type, Icmpv6Header, Icmpv6Type, Ipv4Header, Ipv6Header, PacketHeaders,
    TcpHeader, TcpOptionElement, TransportHeader,
};

/// TCP advertised window size used by the stateless responder's replies.
///
/// A plausible, generous value; the stateless tier keeps no receive buffer of
/// its own, so this is purely cosmetic (it must merely look like a real
/// server to the client).
const STATELESS_WINDOW: u16 = 65535;

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

/// Recompute the TCP checksum of `tcp` against `ip4`, set `ip4`'s header
/// checksum, and serialize the resulting IPv4 + TCP (+ `payload`) datagram.
///
/// Returns `None` if the checksum computation overflows TCP's length limits
/// (payload too large) or if serialization fails.
fn write_ipv4_tcp(mut ip4: Ipv4Header, mut tcp: TcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
    tcp.checksum = tcp.calc_checksum_ipv4(&ip4, payload).ok()?;
    ip4.header_checksum = ip4.calc_header_checksum();

    let mut out = Vec::with_capacity(ip4.header_len() + tcp.header_len() + payload.len());
    ip4.write(&mut out).ok()?;
    tcp.write(&mut out).ok()?;
    out.extend_from_slice(payload);
    Some(out)
}

/// Recompute the TCP checksum of `tcp` against `ip6`'s pseudo-header and
/// serialize the resulting IPv6 + TCP (+ `payload`) datagram.
///
/// Returns `None` if the checksum computation overflows TCP's length limits
/// (payload too large) or if serialization fails.
fn write_ipv6_tcp(ip6: Ipv6Header, mut tcp: TcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
    tcp.checksum = tcp.calc_checksum_ipv6(&ip6, payload).ok()?;

    let mut out = Vec::with_capacity(Ipv6Header::LEN + tcp.header_len() + payload.len());
    ip6.write(&mut out).ok()?;
    tcp.write(&mut out).ok()?;
    out.extend_from_slice(payload);
    Some(out)
}

/// Build a reply IPv6 header with source/destination swapped relative to
/// `ip6` and `payload_length` set to `payload_length`.
fn swapped_ipv6_reply(ip6: &Ipv6Header, payload_length: u16) -> Ipv6Header {
    Ipv6Header {
        traffic_class: ip6.traffic_class,
        flow_label: ip6.flow_label,
        payload_length,
        next_header: ip6.next_header,
        hop_limit: ip6.hop_limit,
        source: ip6.destination, // swap
        destination: ip6.source, // swap
    }
}

/// Parse a raw IPv4 or IPv6 datagram carrying a TCP SYN and build the
/// stateless SYN-cookie SYN-ACK reply: source/destination addresses and TCP
/// ports are swapped, the sequence number is `cookie_seq` (the caller's
/// SYN-cookie, see `cookie::make_cookie`), the acknowledgment number is the
/// client's sequence number plus one, the SYN and ACK flags are set (and no
/// others), a single MSS option echoing `mss` is included, and the TCP/IP
/// checksums are recomputed.
///
/// Returns `None` if `request` is not a well-formed IPv4/IPv6 datagram
/// carrying a TCP segment with the SYN flag set and the ACK flag clear.
pub fn tcp_syn_ack(request: &[u8], cookie_seq: u32, mss: u16) -> Option<Vec<u8>> {
    let headers = PacketHeaders::from_ip_slice(request).ok()?;
    let net = headers.net?;

    let tcp = match headers.transport? {
        TransportHeader::Tcp(h) => h,
        _ => return None,
    };
    if !tcp.syn || tcp.ack {
        return None;
    }

    let mut reply_tcp = TcpHeader::new(
        tcp.destination_port,
        tcp.source_port,
        cookie_seq,
        STATELESS_WINDOW,
    );
    reply_tcp.syn = true;
    reply_tcp.ack = true;
    reply_tcp.acknowledgment_number = tcp.sequence_number.wrapping_add(1);
    reply_tcp
        .set_options(&[TcpOptionElement::MaximumSegmentSize(mss)])
        .ok()?;

    if let Some((ip4, _)) = net.ipv4_ref() {
        let payload_len = reply_tcp.header_len_u16();
        let reply_ip4 = Ipv4Header::new(
            payload_len,
            ip4.time_to_live,
            ip4.protocol,
            ip4.destination, // swap: original dst becomes new src
            ip4.source,      // swap: original src becomes new dst
        )
        .ok()?;
        write_ipv4_tcp(reply_ip4, reply_tcp, &[])
    } else if let Some((ip6, _)) = net.ipv6_ref() {
        let payload_len = reply_tcp.header_len_u16();
        let reply_ip6 = swapped_ipv6_reply(ip6, payload_len);
        write_ipv6_tcp(reply_ip6, reply_tcp, &[])
    } else {
        None
    }
}

/// Parse a raw IPv4 or IPv6 datagram carrying the client's TCP ACK that
/// completes a SYN-cookie handshake, and build the stateless tier's single
/// reply segment: a PSH|ACK|FIN carrying `banner` as payload, with
/// source/destination addresses and TCP ports swapped.
///
/// The reply's sequence number is the client's acknowledgment number (the
/// value the client already acked through the SYN-ACK), and the reply's
/// acknowledgment number is the client's sequence number plus the client's
/// payload length (usually zero, since a bare ACK carries no data). Both are
/// wrapping additions. TCP and IP checksums are recomputed.
///
/// Returns `None` if `ack_request` is not a well-formed IPv4/IPv6 datagram
/// carrying a TCP segment with the ACK flag set.
pub fn tcp_banner_fin(ack_request: &[u8], banner: &[u8]) -> Option<Vec<u8>> {
    let headers = PacketHeaders::from_ip_slice(ack_request).ok()?;
    let net = headers.net?;

    let tcp = match headers.transport? {
        TransportHeader::Tcp(h) => h,
        _ => return None,
    };
    if !tcp.ack {
        return None;
    }

    let client_payload_len = u32::try_from(headers.payload.slice().len()).ok()?;
    let reply_seq = tcp.acknowledgment_number;
    let reply_ack = tcp.sequence_number.wrapping_add(client_payload_len);

    let mut reply_tcp = TcpHeader::new(
        tcp.destination_port,
        tcp.source_port,
        reply_seq,
        STATELESS_WINDOW,
    );
    reply_tcp.psh = true;
    reply_tcp.ack = true;
    reply_tcp.fin = true;
    reply_tcp.acknowledgment_number = reply_ack;

    if let Some((ip4, _)) = net.ipv4_ref() {
        let payload_len = u16::try_from(reply_tcp.header_len() + banner.len()).ok()?;
        let reply_ip4 = Ipv4Header::new(
            payload_len,
            ip4.time_to_live,
            ip4.protocol,
            ip4.destination, // swap: original dst becomes new src
            ip4.source,      // swap: original src becomes new dst
        )
        .ok()?;
        write_ipv4_tcp(reply_ip4, reply_tcp, banner)
    } else if let Some((ip6, _)) = net.ipv6_ref() {
        let payload_len = u16::try_from(reply_tcp.header_len() + banner.len()).ok()?;
        let reply_ip6 = swapped_ipv6_reply(ip6, payload_len);
        write_ipv6_tcp(reply_ip6, reply_tcp, banner)
    } else {
        None
    }
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

    fn build_tcp_syn_v4(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(src, dst, 64)
            .tcp(src_port, dst_port, seq, 65535)
            .syn();
        let mut pkt = Vec::new();
        builder.write(&mut pkt, &[]).unwrap();
        pkt
    }

    fn build_tcp_syn_v6(
        src: [u8; 16],
        dst: [u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(src, dst, 64)
            .tcp(src_port, dst_port, seq, 65535)
            .syn();
        let mut pkt = Vec::new();
        builder.write(&mut pkt, &[]).unwrap();
        pkt
    }

    fn build_tcp_ack_v4(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(src, dst, 64)
            .tcp(src_port, dst_port, seq, 65535)
            .ack(ack);
        let mut pkt = Vec::new();
        builder.write(&mut pkt, payload).unwrap();
        pkt
    }

    fn build_tcp_ack_v6(
        src: [u8; 16],
        dst: [u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(src, dst, 64)
            .tcp(src_port, dst_port, seq, 65535)
            .ack(ack);
        let mut pkt = Vec::new();
        builder.write(&mut pkt, payload).unwrap();
        pkt
    }

    /// Pull the TCP header and IP header pair out of a serialized reply,
    /// panicking if the reply is not a well-formed IPv4+TCP datagram.
    fn parse_v4_tcp(pkt: &[u8]) -> (Ipv4Header, TcpHeader, Vec<u8>) {
        let parsed = PacketHeaders::from_ip_slice(pkt).unwrap();
        let net = parsed.net.unwrap();
        let (ip4, _) = net.ipv4_ref().unwrap();
        let ip4 = ip4.clone();
        let tcp = match parsed.transport.unwrap() {
            TransportHeader::Tcp(h) => h,
            other => panic!("expected TCP, got {other:?}"),
        };
        (ip4, tcp, parsed.payload.slice().to_owned())
    }

    /// Pull the TCP header and IP header pair out of a serialized reply,
    /// panicking if the reply is not a well-formed IPv6+TCP datagram.
    fn parse_v6_tcp(pkt: &[u8]) -> (Ipv6Header, TcpHeader, Vec<u8>) {
        let parsed = PacketHeaders::from_ip_slice(pkt).unwrap();
        let net = parsed.net.unwrap();
        let (ip6, _) = net.ipv6_ref().unwrap();
        let ip6 = ip6.clone();
        let tcp = match parsed.transport.unwrap() {
            TransportHeader::Tcp(h) => h,
            other => panic!("expected TCP, got {other:?}"),
        };
        (ip6, tcp, parsed.payload.slice().to_owned())
    }

    fn mss_option(tcp: &TcpHeader) -> Option<u16> {
        tcp.options_iterator().find_map(|opt| match opt {
            Ok(TcpOptionElement::MaximumSegmentSize(mss)) => Some(mss),
            _ => None,
        })
    }

    #[test]
    fn tcp_syn_ack_v4_builds_valid_syn_ack() {
        let client = [10, 0, 0, 1];
        let server = [10, 0, 0, 2];
        let request = build_tcp_syn_v4(client, server, 54_321, 443, 1_000);

        let reply = tcp_syn_ack(&request, 777, 1_400).expect("reply should be Some");
        let (ip4, tcp, payload) = parse_v4_tcp(&reply);

        assert_eq!(ip4.source, server, "source should be the original dest");
        assert_eq!(ip4.destination, client, "dest should be the original src");
        assert_eq!(tcp.source_port, 443);
        assert_eq!(tcp.destination_port, 54_321);
        assert!(tcp.syn && tcp.ack, "SYN and ACK must be set");
        assert!(
            !tcp.fin && !tcp.rst && !tcp.psh,
            "no other flags should be set"
        );
        assert_eq!(tcp.sequence_number, 777, "seq must be the cookie");
        assert_eq!(
            tcp.acknowledgment_number, 1_001,
            "ack must be client_seq + 1"
        );
        assert_eq!(mss_option(&tcp), Some(1_400));
        assert!(payload.is_empty());

        assert_eq!(
            tcp.checksum,
            tcp.calc_checksum_ipv4(&ip4, &payload).unwrap(),
            "TCP checksum must be valid"
        );
        assert_eq!(
            ip4.header_checksum,
            ip4.calc_header_checksum(),
            "IPv4 header checksum must be valid"
        );
    }

    #[test]
    fn tcp_syn_ack_v6_builds_valid_syn_ack() {
        let client = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let server = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let request = build_tcp_syn_v6(client, server, 54_321, 443, 2_000);

        let reply = tcp_syn_ack(&request, 4_242, 1_460).expect("reply should be Some");
        let (ip6, tcp, payload) = parse_v6_tcp(&reply);

        assert_eq!(ip6.source, server, "source should be the original dest");
        assert_eq!(ip6.destination, client, "dest should be the original src");
        assert_eq!(tcp.source_port, 443);
        assert_eq!(tcp.destination_port, 54_321);
        assert!(tcp.syn && tcp.ack, "SYN and ACK must be set");
        assert!(
            !tcp.fin && !tcp.rst && !tcp.psh,
            "no other flags should be set"
        );
        assert_eq!(tcp.sequence_number, 4_242, "seq must be the cookie");
        assert_eq!(
            tcp.acknowledgment_number, 2_001,
            "ack must be client_seq + 1"
        );
        assert_eq!(mss_option(&tcp), Some(1_460));

        assert_eq!(
            tcp.checksum,
            tcp.calc_checksum_ipv6(&ip6, &payload).unwrap(),
            "TCP checksum must be valid over the v6 pseudo-header"
        );
    }

    #[test]
    fn tcp_syn_ack_returns_none_for_non_syn() {
        // A bare ACK (no SYN) must not produce a SYN-ACK.
        let request = build_tcp_ack_v4([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1_000, 500, &[]);
        assert!(
            tcp_syn_ack(&request, 1, 1_400).is_none(),
            "non-SYN packet should return None"
        );
    }

    #[test]
    fn tcp_syn_ack_returns_none_for_non_tcp() {
        let request = build_icmpv4_request([10, 0, 0, 1], [10, 0, 0, 2], 1, 1, b"");
        assert!(
            tcp_syn_ack(&request, 1, 1_400).is_none(),
            "non-TCP packet should return None"
        );
    }

    #[test]
    fn tcp_banner_fin_v4_builds_valid_reply() {
        let client = [10, 0, 0, 1];
        let server = [10, 0, 0, 2];
        let banner = b"SSH-2.0-OpenSSH_9.0\r\n";
        // A bare ACK completing the handshake: no payload.
        let request = build_tcp_ack_v4(client, server, 54_321, 443, 5_000, 9_000, &[]);

        let reply = tcp_banner_fin(&request, banner).expect("reply should be Some");
        let (ip4, tcp, payload) = parse_v4_tcp(&reply);

        assert_eq!(ip4.source, server, "source should be the original dest");
        assert_eq!(ip4.destination, client, "dest should be the original src");
        assert_eq!(tcp.source_port, 443);
        assert_eq!(tcp.destination_port, 54_321);
        assert!(tcp.psh && tcp.ack && tcp.fin, "PSH|ACK|FIN must be set");
        assert!(!tcp.syn && !tcp.rst, "no other flags should be set");
        assert_eq!(
            tcp.sequence_number, 9_000,
            "reply seq must be the client's ack number"
        );
        assert_eq!(
            tcp.acknowledgment_number, 5_000,
            "reply ack must be client_seq + client_payload_len (0 here)"
        );
        assert_eq!(payload, banner);

        assert_eq!(
            tcp.checksum,
            tcp.calc_checksum_ipv4(&ip4, &payload).unwrap(),
            "TCP checksum must be valid"
        );
        assert_eq!(
            ip4.header_checksum,
            ip4.calc_header_checksum(),
            "IPv4 header checksum must be valid"
        );
    }

    #[test]
    fn tcp_banner_fin_v6_builds_valid_reply() {
        let client = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let server = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let banner = b"220 mail.example.net ESMTP\r\n";
        let request = build_tcp_ack_v6(client, server, 54_321, 25, 6_000, 10_000, &[]);

        let reply = tcp_banner_fin(&request, banner).expect("reply should be Some");
        let (ip6, tcp, payload) = parse_v6_tcp(&reply);

        assert_eq!(ip6.source, server, "source should be the original dest");
        assert_eq!(ip6.destination, client, "dest should be the original src");
        assert!(tcp.psh && tcp.ack && tcp.fin, "PSH|ACK|FIN must be set");
        assert_eq!(
            tcp.sequence_number, 10_000,
            "reply seq must be the client's ack number"
        );
        assert_eq!(
            tcp.acknowledgment_number, 6_000,
            "reply ack must be client_seq + client_payload_len (0 here)"
        );
        assert_eq!(payload, banner);

        assert_eq!(
            tcp.checksum,
            tcp.calc_checksum_ipv6(&ip6, &payload).unwrap(),
            "TCP checksum must be valid over the v6 pseudo-header"
        );
    }

    #[test]
    fn tcp_banner_fin_accounts_for_client_payload_len() {
        // A client ACK that also carries data must bump the reply's ack
        // number by the payload length, not just by one.
        let client = [10, 0, 0, 1];
        let server = [10, 0, 0, 2];
        let request = build_tcp_ack_v4(
            client,
            server,
            54_321,
            443,
            5_000,
            9_000,
            b"some client data",
        );

        let reply = tcp_banner_fin(&request, b"banner").expect("reply should be Some");
        let (_, tcp, _) = parse_v4_tcp(&reply);
        assert_eq!(
            tcp.acknowledgment_number,
            5_000 + u32::try_from(b"some client data".len()).unwrap()
        );
    }

    #[test]
    fn tcp_banner_fin_returns_none_for_non_ack() {
        let request = build_tcp_syn_v4([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1_000);
        assert!(
            tcp_banner_fin(&request, b"banner").is_none(),
            "non-ACK packet should return None"
        );
    }

    #[test]
    fn tcp_banner_fin_returns_none_for_non_tcp() {
        let request = build_icmpv4_request([10, 0, 0, 1], [10, 0, 0, 2], 1, 1, b"");
        assert!(
            tcp_banner_fin(&request, b"banner").is_none(),
            "non-TCP packet should return None"
        );
    }

    #[test]
    fn syn_cookie_and_banner_fin_seq_numbers_line_up_for_a_real_client() {
        // Simulate a full stateless handshake: client SYN -> our SYN-ACK
        // (carrying the cookie) -> client's follow-up ACK -> our banner+FIN.
        // The banner+FIN's sequence number must equal the cookie + 1, i.e.
        // exactly what the client acked, proving the arithmetic lines up
        // end-to-end rather than merely in isolation.
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 10];
        let client_isn = 1_000_u32;
        let cookie_seq = 555_000_u32;

        let syn = build_tcp_syn_v4(client, server, 54_321, 22, client_isn);
        let syn_ack = tcp_syn_ack(&syn, cookie_seq, 1_460).expect("syn-ack should be Some");
        let (_, syn_ack_tcp, _) = parse_v4_tcp(&syn_ack);
        assert_eq!(syn_ack_tcp.acknowledgment_number, client_isn + 1);
        assert_eq!(syn_ack_tcp.sequence_number, cookie_seq);

        // The client's follow-up ACK: its own seq advanced by one (the SYN
        // consumed a sequence number), acking cookie_seq + 1.
        let client_ack_num = cookie_seq.wrapping_add(1);
        let follow_up_ack = build_tcp_ack_v4(
            client,
            server,
            54_321,
            22,
            client_isn + 1,
            client_ack_num,
            &[],
        );

        let banner_fin =
            tcp_banner_fin(&follow_up_ack, b"SSH-2.0-OpenSSH_9.0\r\n").expect("reply should exist");
        let (_, banner_fin_tcp, _) = parse_v4_tcp(&banner_fin);
        assert_eq!(
            banner_fin_tcp.sequence_number, client_ack_num,
            "banner+FIN seq must equal what the client acked (cookie_seq + 1)"
        );
        assert_eq!(banner_fin_tcp.sequence_number, cookie_seq + 1);
    }
}
