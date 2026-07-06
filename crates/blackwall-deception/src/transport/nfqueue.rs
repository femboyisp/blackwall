//! NFQUEUE transport: intercepts packets from the kernel via NetFilter queues
//! and synthesises ICMP/ICMPv6 echo replies and stateless TCP SYN-cookie
//! replies in userspace.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::time::{SystemTime, UNIX_EPOCH};

use nfq::{Queue, Verdict};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::cookie::{check_cookie, make_cookie, ConnTuple, CookieKey};
use crate::error::DeceptionError;

use super::packet;

/// `IPPROTO_RAW` (255) — raw IP socket that accepts a hand-crafted IP header.
const IPPROTO_RAW: i32 = 255;

/// `IPPROTO_ICMPV6` (58) — ICMPv6 raw socket protocol number.
///
/// Linux does not support `IPV6_HDRINCL`, so ICMPv6 raw sockets must be
/// opened with this protocol; the kernel builds the IPv6 header itself.
const IPPROTO_ICMPV6: i32 = 58;

/// A lookup from a destination port to the banner bytes the stateless tier's
/// SYN-cookie ACK handler serves for that port.
///
/// A `Box<dyn Fn>` rather than a trait: the daemon composes this from
/// whatever banner store it already holds (e.g. `SharedBanners::current`),
/// and a closure is the smallest thing that lets it do so without a new
/// abstraction.
pub type BannerLookup = Box<dyn Fn(u16) -> Vec<u8> + Send>;

/// Open NFQUEUE number `queue_num` and handle packets in a blocking loop.
///
/// For each packet received:
/// - If it is an IPv4 ICMP echo request, an echo reply is sent via a raw
///   IPv4 socket and the original packet is dropped.
/// - If it is an IPv6 ICMPv6 echo request, an echo reply is sent via a raw
///   IPv6 socket and the original packet is dropped.
/// - If it is a TCP SYN (no ACK) to any destination reaching this queue, a
///   stateless SYN-cookie SYN-ACK is sent (see [`crate::cookie::make_cookie`]
///   and [`packet::tcp_syn_ack`]) and the SYN is dropped — the kernel never
///   sees it, so no connection state or backlog pressure is created.
/// - If it is a TCP ACK (no SYN) whose acknowledgment number carries a valid
///   SYN-cookie (see [`crate::cookie::check_cookie`]), a single stateless
///   banner segment followed by FIN is sent via `banners` and the ACK is
///   dropped. An ACK with an invalid or missing cookie is dropped silently.
/// - Any other TCP segment (RST/FIN/data with no matching cookie) is dropped
///   silently: the stateless tier keeps no state to continue a conversation
///   with.
/// - If it is an IPv4/IPv6 UDP datagram, the banner for its destination port
///   is looked up via `banners` and reflected back (truncated to at most the
///   request's payload length, see [`packet::udp_response`]) and the
///   datagram is dropped. A datagram with an empty payload (nothing safely
///   reflectable) is dropped without a reply. UDP is always stateless: it is
///   never accepted into the host stack for a deception port.
/// - All other packets are accepted unchanged.
///
/// This function runs indefinitely and only returns on error.
pub fn run(
    queue_num: u16,
    cookie_key: CookieKey,
    banners: BannerLookup,
) -> Result<(), DeceptionError> {
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

        let verdict = if let Some(info) = packet::parse_tcp_request(&pkt) {
            handle_tcp(&pkt, &info, &cookie_key, banners.as_ref(), &raw4, &raw6)?
        } else if let Some(info) = packet::parse_udp_request(&pkt) {
            handle_udp(&pkt, &info, banners.as_ref(), &raw4, &raw6)?
        } else {
            match pkt.first().map(|b| b >> 4) {
                Some(4) => {
                    if let Some(reply) = packet::icmp_echo_reply(&pkt) {
                        send_raw4(&raw4, &reply)?;
                        Verdict::Drop
                    } else {
                        Verdict::Accept
                    }
                }
                Some(6) => {
                    if let Some(reply) = packet::icmpv6_echo_reply(&pkt) {
                        send_raw6(&raw6, &reply)?;
                        Verdict::Drop
                    } else {
                        Verdict::Accept
                    }
                }
                _ => Verdict::Accept,
            }
        };

        msg.set_verdict(verdict);
        queue.verdict(msg).map_err(DeceptionError::Io)?;
    }
}

/// Dispatch a parsed TCP segment (`info`) to the stateless SYN-cookie state
/// machine, sending any reply via `raw4`/`raw6` and returning the verdict for
/// the original packet.
///
/// - SYN (no ACK): mint a cookie and reply with a SYN-ACK.
/// - ACK (no SYN): validate the cookie; on success, reply with a banner+FIN.
/// - Anything else (or an ACK with an invalid cookie): drop silently.
///
/// The tuple used for both minting and validating the cookie is built
/// directly from the segment's own src/dst/ports: on the returning ACK these
/// are the same orientation (client src, server dst) as they were on the
/// original SYN, so no swap is needed here (only the *replies* swap
/// src/dst).
fn handle_tcp(
    pkt: &[u8],
    info: &packet::TcpRequestInfo,
    cookie_key: &CookieKey,
    banners: &(dyn Fn(u16) -> Vec<u8> + Send),
    raw4: &Socket,
    raw6: &Socket,
) -> Result<Verdict, DeceptionError> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let tuple = ConnTuple {
        src: info.src,
        src_port: info.src_port,
        dst: info.dst,
        dst_port: info.dst_port,
    };

    if info.syn && !info.ack {
        let (cookie_seq, mss) = make_cookie(cookie_key, &tuple, info.client_mss, now_secs);
        if let Some(reply) = packet::tcp_syn_ack(pkt, cookie_seq, mss) {
            send_reply(&reply, raw4, raw6)?;
        }
        return Ok(Verdict::Drop);
    }

    if info.ack && !info.syn {
        if check_cookie(cookie_key, &tuple, info.ack_seq, now_secs).is_some() {
            let banner = banners(info.dst_port);
            if let Some(reply) = packet::tcp_banner_fin(pkt, &banner) {
                send_reply(&reply, raw4, raw6)?;
            }
        }
        return Ok(Verdict::Drop);
    }

    // RST/FIN/data with no matching cookie: nothing to continue statelessly.
    Ok(Verdict::Drop)
}

/// Dispatch a parsed UDP datagram (`info`) to the stateless reflector,
/// sending any reply via `raw4`/`raw6` and returning the verdict for the
/// original packet.
///
/// Always drops the original datagram: the stateless tier never lets a
/// deception-port UDP datagram reach the host stack, and never keeps
/// per-datagram state. The banner for the datagram's destination port is
/// looked up via `banners` and reflected back through
/// [`packet::udp_response`], which enforces the reflection-amplification
/// guard (the reply is truncated to at most the request's payload length,
/// and a zero-byte request payload yields no reply at all).
fn handle_udp(
    pkt: &[u8],
    info: &packet::UdpRequestInfo,
    banners: &(dyn Fn(u16) -> Vec<u8> + Send),
    raw4: &Socket,
    raw6: &Socket,
) -> Result<Verdict, DeceptionError> {
    let banner = banners(info.dst_port);
    if let Some(reply) = packet::udp_response(pkt, &banner) {
        send_reply(&reply, raw4, raw6)?;
    }
    Ok(Verdict::Drop)
}

/// Send a fully-built reply datagram (`reply`) via whichever raw socket
/// matches its IP version.
fn send_reply(reply: &[u8], raw4: &Socket, raw6: &Socket) -> Result<(), DeceptionError> {
    match reply.first().map(|b| b >> 4) {
        Some(4) => send_raw4(raw4, reply),
        Some(6) => send_raw6(raw6, reply),
        _ => Ok(()),
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
