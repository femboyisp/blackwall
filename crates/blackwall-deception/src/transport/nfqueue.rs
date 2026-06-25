//! NFQUEUE transport: intercepts packets from the kernel via NetFilter queues
//! and synthesises ICMP/ICMPv6 echo replies in userspace.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use nfq::{Queue, Verdict};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::error::DeceptionError;

use super::packet;

/// `IPPROTO_RAW` (255) — raw IP socket that accepts a hand-crafted IP header.
const IPPROTO_RAW: i32 = 255;

/// `IPPROTO_ICMPV6` (58) — ICMPv6 raw socket protocol number.
///
/// Linux does not support `IPV6_HDRINCL`, so ICMPv6 raw sockets must be
/// opened with this protocol; the kernel builds the IPv6 header itself.
const IPPROTO_ICMPV6: i32 = 58;

/// Open NFQUEUE number `queue_num` and handle packets in a blocking loop.
///
/// For each packet received:
/// - If it is an IPv4 ICMP echo request, an echo reply is sent via a raw
///   IPv4 socket and the original packet is dropped.
/// - If it is an IPv6 ICMPv6 echo request, an echo reply is sent via a raw
///   IPv6 socket and the original packet is dropped.
/// - All other packets are accepted unchanged.
///
/// This function runs indefinitely and only returns on error.
pub fn run(queue_num: u16) -> Result<(), DeceptionError> {
    let mut queue = Queue::open().map_err(DeceptionError::Io)?;
    queue.bind(queue_num).map_err(DeceptionError::Io)?;

    // Pre-open raw sockets for sending replies.
    let raw4 = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
        .map_err(DeceptionError::Io)?;
    raw4.set_header_included_v4(true)
        .map_err(DeceptionError::Io)?;

    // Linux ICMPv6 raw sockets have no IPV6_HDRINCL; the kernel builds the
    // IPv6 header from routing and the destination passed to sendto(2).
    // We therefore open the socket with IPPROTO_ICMPV6 (58) and send only
    // the ICMPv6 payload (bytes after the 40-byte IPv6 header).
    // TODO(sub-project B / M3): use IPV6_PKTINFO to bind the source address
    // to the specific deception IP rather than letting the kernel choose.
    let raw6 = Socket::new_raw(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(IPPROTO_ICMPV6)),
    )
    .map_err(DeceptionError::Io)?;

    loop {
        let mut msg = queue.recv().map_err(DeceptionError::Io)?;
        let pkt = msg.get_payload().to_owned();

        let version = pkt.first().map(|b| b >> 4);
        match version {
            Some(4) => {
                if let Some(reply) = packet::icmp_echo_reply(&pkt) {
                    send_raw4(&raw4, &reply)?;
                    msg.set_verdict(Verdict::Drop);
                } else {
                    msg.set_verdict(Verdict::Accept);
                }
            }
            Some(6) => {
                if let Some(reply) = packet::icmpv6_echo_reply(&pkt) {
                    send_raw6(&raw6, &reply)?;
                    msg.set_verdict(Verdict::Drop);
                } else {
                    msg.set_verdict(Verdict::Accept);
                }
            }
            _ => {
                msg.set_verdict(Verdict::Accept);
            }
        }

        queue.verdict(msg).map_err(DeceptionError::Io)?;
    }
}

/// Send `buf` (a complete IPv4 datagram including header) via the raw socket.
fn send_raw4(sock: &Socket, buf: &[u8]) -> Result<(), DeceptionError> {
    // Extract destination address from the IPv4 header (bytes 16–19).
    if buf.len() < 20 {
        return Err(DeceptionError::Protocol("IPv4 reply too short".into()));
    }
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let addr = SockAddr::from(SocketAddrV4::new(dst, 0));
    sock.send_to(buf, &addr).map_err(DeceptionError::Io)?;
    Ok(())
}

/// Send the ICMPv6 portion of `buf` (a complete IPv6 datagram) via the raw
/// socket.
///
/// Linux ICMPv6 raw sockets require sending only the ICMPv6 message (bytes
/// after the 40-byte IPv6 header); the kernel reconstructs the IPv6 header
/// using the destination address supplied to `sendto`.
fn send_raw6(sock: &Socket, buf: &[u8]) -> Result<(), DeceptionError> {
    // Extract destination address from the IPv6 header (bytes 24–39).
    if buf.len() < 40 {
        return Err(DeceptionError::Protocol("IPv6 reply too short".into()));
    }
    let dst_bytes: [u8; 16] = buf[24..40]
        .try_into()
        .map_err(|_| DeceptionError::Protocol("IPv6 dst slice wrong size".into()))?;
    let dst = Ipv6Addr::from(dst_bytes);
    let addr = SockAddr::from(SocketAddrV6::new(dst, 0, 0, 0));
    // Send only the ICMPv6 payload (skip the 40-byte IPv6 header); the kernel
    // builds the IPv6 header itself.
    sock.send_to(&buf[40..], &addr)
        .map_err(DeceptionError::Io)?;
    Ok(())
}
