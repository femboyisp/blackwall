//! NFQUEUE transport: intercepts packets from the kernel via NetFilter queues
//! and synthesises ICMP/ICMPv6 echo replies and stateless TCP SYN-cookie
//! replies in userspace.

use std::ffi::c_void;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nfq::{Queue, Verdict};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::cookie::{check_cookie, make_cookie, ConnTuple, CookieKey};
use crate::error::DeceptionError;

use super::metrics::StatelessMetrics;
use super::packet;
use super::traits::DeceptionTransport;

/// `IPPROTO_RAW` (255) — raw IP socket that accepts a hand-crafted IP header.
const IPPROTO_RAW: i32 = 255;

/// `IPPROTO_TCP` (6) — TCP protocol number (IPv6 raw socket / next-header).
const IPPROTO_TCP: i32 = 6;

/// `IPPROTO_UDP` (17) — UDP protocol number (IPv6 raw socket / next-header).
const IPPROTO_UDP: i32 = 17;

/// `IPPROTO_ICMPV6` (58) — ICMPv6 raw socket protocol number / next-header.
///
/// Linux does not support `IPV6_HDRINCL`, so IPv6 raw sockets must be opened
/// with the L4 protocol they will send; the kernel builds the IPv6 header
/// itself and sets its Next Header field from the socket's protocol.
const IPPROTO_ICMPV6: i32 = 58;

/// The raw sockets the responder uses to inject replies onto the wire.
///
/// IPv4 uses a single header-included `IPPROTO_RAW` socket: the reply carries
/// its own hand-built IPv4 header. IPv6 has no `IPV6_HDRINCL`, so each L4
/// protocol needs its own raw socket opened with that protocol number — an
/// `IPPROTO_ICMPV6` socket can only emit ICMPv6, so TCP and UDP v6 replies need
/// their own `IPPROTO_TCP`/`IPPROTO_UDP` sockets (issue #128). The reply's
/// source address is pinned per-send with `IPV6_PKTINFO` (see [`send_v6_l4`]).
struct RawSockets {
    /// IPv4, header-included (`IPPROTO_RAW`).
    v4: Socket,
    /// IPv6 `IPPROTO_TCP` — stateless SYN-cookie SYN-ACK and banner+FIN.
    v6_tcp: Socket,
    /// IPv6 `IPPROTO_UDP` — stateless UDP reflection replies.
    v6_udp: Socket,
    /// IPv6 `IPPROTO_ICMPV6` — ICMPv6 echo replies.
    v6_icmp: Socket,
}

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
/// `metrics` is bumped on each reply actually sent (SYN-ACK, validated/
/// rejected ACK, UDP response) so `/metrics` reflects real replies rather
/// than mere receipt of a request.
///
/// This function runs indefinitely and only returns on error.
pub fn run(
    queue_num: u16,
    cookie_key: CookieKey,
    banners: BannerLookup,
    metrics: Arc<StatelessMetrics>,
) -> Result<(), DeceptionError> {
    let mut queue = Queue::open().map_err(DeceptionError::Io)?;
    queue.bind(queue_num).map_err(DeceptionError::Io)?;

    // Pre-open raw sockets for sending replies.
    let v4 = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
        .map_err(DeceptionError::Io)?;
    v4.set_header_included_v4(true)
        .map_err(DeceptionError::Io)?;

    // Linux IPv6 raw sockets have no IPV6_HDRINCL: the kernel builds the IPv6
    // header itself and sets its Next Header field from the socket's protocol.
    // A single IPPROTO_ICMPV6 socket can therefore only emit ICMPv6 messages,
    // so the stateless TCP (SYN-cookie SYN-ACK, banner+FIN) and UDP replies
    // each need a raw socket opened with their own protocol number (#128). The
    // per-send source address is pinned with IPV6_PKTINFO (see `send_v6_l4`).
    let v6_tcp = Socket::new_raw(Domain::IPV6, Type::RAW, Some(Protocol::from(IPPROTO_TCP)))
        .map_err(DeceptionError::Io)?;
    let v6_udp = Socket::new_raw(Domain::IPV6, Type::RAW, Some(Protocol::from(IPPROTO_UDP)))
        .map_err(DeceptionError::Io)?;
    let v6_icmp = Socket::new_raw(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(IPPROTO_ICMPV6)),
    )
    .map_err(DeceptionError::Io)?;
    let socks = RawSockets {
        v4,
        v6_tcp,
        v6_udp,
        v6_icmp,
    };

    loop {
        let mut msg = queue.recv().map_err(DeceptionError::Io)?;
        let pkt = msg.get_payload().to_owned();

        // A single reply that fails to send (e.g. a spoofed source address
        // that happens to land on a broadcast address, for which the kernel
        // rejects an unset-SO_BROADCAST raw socket with EACCES; or a
        // transient ENETUNREACH/EINVAL for a bogus attacker-controlled
        // address) must never take down the whole responder: that would let
        // a single crafted or spoofed packet in a flood turn the stateless
        // tier's own resilience into a self-inflicted denial of service for
        // every other, legitimate flow sharing this queue. So reply-send
        // errors are logged and the packet is dropped, not propagated;
        // only queue-level errors (`recv`/`verdict`) are fatal.
        let verdict = if let Some(info) = packet::parse_tcp_request(&pkt) {
            handle_tcp(&pkt, &info, &cookie_key, banners.as_ref(), &socks, &metrics)
                .unwrap_or_else(|e| drop_and_log("tcp", &e))
        } else if let Some(info) = packet::parse_udp_request(&pkt) {
            handle_udp(&pkt, &info, banners.as_ref(), &socks, &metrics)
                .unwrap_or_else(|e| drop_and_log("udp", &e))
        } else {
            match pkt.first().map(|b| b >> 4) {
                Some(4) => {
                    if let Some(reply) = packet::icmp_echo_reply(&pkt) {
                        if let Err(e) = send_reply(&reply, &socks) {
                            drop_and_log("icmp", &e);
                        }
                        Verdict::Drop
                    } else {
                        Verdict::Accept
                    }
                }
                Some(6) => {
                    if let Some(reply) = packet::icmpv6_echo_reply(&pkt) {
                        if let Err(e) = send_reply(&reply, &socks) {
                            drop_and_log("icmpv6", &e);
                        }
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

/// The stateless tier's [`DeceptionTransport`] impl: wraps [`run`] (this
/// module's blocking NFQUEUE loop) without changing its internals.
///
/// Holds exactly the already-constructed parameters `run` needs. `run` is a
/// blocking, synchronous loop, so [`DeceptionTransport::run`] offloads it
/// onto a blocking thread (as `blackwalld run` already did before this
/// transport existed) rather than blocking the async runtime.
pub struct NfqueueTransport {
    queue_num: u16,
    cookie_key: CookieKey,
    banners: BannerLookup,
    metrics: Arc<StatelessMetrics>,
}

impl NfqueueTransport {
    /// Build the stateless NFQUEUE transport for queue `queue_num`, using
    /// `cookie_key` to mint/validate SYN cookies and `banners` to look up the
    /// canned response for a destination port. `metrics` is shared with the
    /// `/metrics` endpoint.
    #[must_use]
    pub fn new(
        queue_num: u16,
        cookie_key: CookieKey,
        banners: BannerLookup,
        metrics: Arc<StatelessMetrics>,
    ) -> Self {
        Self {
            queue_num,
            cookie_key,
            banners,
            metrics,
        }
    }
}

#[async_trait]
impl DeceptionTransport for NfqueueTransport {
    fn name(&self) -> &str {
        "nfqueue-stateless"
    }

    async fn run(self: Box<Self>) {
        let Self {
            queue_num,
            cookie_key,
            banners,
            metrics,
        } = *self;
        // `run` is blocking/sync; run it on a blocking thread so it does not
        // stall the async runtime.
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(err) = run(queue_num, cookie_key, banners, metrics) {
                tracing::error!(%err, "nfqueue loop exited");
            }
        })
        .await;
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
    socks: &RawSockets,
    metrics: &StatelessMetrics,
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
            send_reply(&reply, socks)?;
            metrics.record_syn_cookie_sent();
        }
        return Ok(Verdict::Drop);
    }

    if info.ack && !info.syn {
        if check_cookie(cookie_key, &tuple, info.ack_seq, now_secs).is_some() {
            metrics.record_ack_validated();
            let banner = banners(info.dst_port);
            if let Some(reply) = packet::tcp_banner_fin(pkt, &banner) {
                send_reply(&reply, socks)?;
            }
        } else {
            metrics.record_ack_rejected();
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
    socks: &RawSockets,
    metrics: &StatelessMetrics,
) -> Result<Verdict, DeceptionError> {
    let banner = banners(info.dst_port);
    if let Some(reply) = packet::udp_response(pkt, &banner) {
        send_reply(&reply, socks)?;
        metrics.record_udp_response();
    }
    Ok(Verdict::Drop)
}

/// Log a per-packet reply-send failure (see the `run` loop's dispatch) and
/// yield the [`Verdict::Drop`] the caller falls back to.
///
/// Never propagated as fatal: the original packet is dropped either way (the
/// stateless tier keeps no state to retry), so a reply that could not be
/// sent is exactly as harmless to this responder's availability as one that
/// was never attempted.
fn drop_and_log(kind: &str, err: &DeceptionError) -> Verdict {
    eprintln!("blackwall-deception: nfqueue: {kind} reply send failed, dropping packet: {err}");
    Verdict::Drop
}

/// Send a fully-built reply datagram (`reply`) via whichever raw socket
/// matches its IP version (and, for IPv6, its L4 protocol).
fn send_reply(reply: &[u8], socks: &RawSockets) -> Result<(), DeceptionError> {
    match reply.first().map(|b| b >> 4) {
        Some(4) => send_raw4(&socks.v4, reply),
        Some(6) => send_raw6(socks, reply),
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

/// Send the L4 segment of `buf` (a complete IPv6 datagram) via the raw socket
/// matching its next-header, pinning the reply's source to the datagram's own
/// source address.
///
/// Linux IPv6 raw sockets have no `IPV6_HDRINCL`, so we strip the 40-byte IPv6
/// header the builders produced and hand the kernel only the L4 segment; the
/// kernel rebuilds the IPv6 header. The datagram is dispatched to the socket
/// whose protocol matches the next-header (byte 6): TCP, UDP or ICMPv6 — an
/// `IPPROTO_ICMPV6` socket cannot carry TCP/UDP, which was the #128 bug.
fn send_raw6(socks: &RawSockets, buf: &[u8]) -> Result<(), DeceptionError> {
    if buf.len() < 40 {
        return Err(DeceptionError::Protocol("IPv6 reply too short".into()));
    }
    // IPv6 header: next-header at byte 6, source at 8..24, destination at 24..40.
    let next_header = buf[6];
    let src_bytes: [u8; 16] = buf[8..24]
        .try_into()
        .map_err(|_| DeceptionError::Protocol("IPv6 src slice wrong size".into()))?;
    let dst_bytes: [u8; 16] = buf[24..40]
        .try_into()
        .map_err(|_| DeceptionError::Protocol("IPv6 dst slice wrong size".into()))?;
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);
    let l4 = &buf[40..];

    let sock = match i32::from(next_header) {
        IPPROTO_TCP => &socks.v6_tcp,
        IPPROTO_UDP => &socks.v6_udp,
        IPPROTO_ICMPV6 => &socks.v6_icmp,
        other => {
            return Err(DeceptionError::Protocol(format!(
                "unsupported IPv6 next-header {other}"
            )));
        }
    };
    send_v6_l4(sock, src, dst, l4)
}

/// Send the L4 segment `l4` of an IPv6 reply via `sock`, with the IPv6 source
/// address pinned to `src` and the destination set to `dst`.
///
/// The kernel would otherwise choose the source by routing, but the builders in
/// [`super::packet`] computed each L4 checksum over a pseudo-header using the
/// deception IP the client targeted as the source; the kernel must use that
/// exact source or the checksum is wrong and the client discards the reply.
/// A per-reply source cannot be expressed with `bind(2)` (it varies per reply
/// across the managed prefix), so it is set per-message with an `IPV6_PKTINFO`
/// control message. `socket2` does not expose per-message `PKTINFO`, so this
/// drops to `libc::sendmsg` (mirroring the `libc` raw-socket precedent in
/// `blackwall-trafficgen`'s `io::send`).
fn send_v6_l4(
    sock: &Socket,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    l4: &[u8],
) -> Result<(), DeceptionError> {
    // Destination sockaddr. Raw sockets ignore the transport port, so it is 0.
    // SAFETY: `sockaddr_in6` is plain-old-data with no invalid bit patterns; an
    // all-zero value is a valid, fully-initialised base we then populate.
    let mut dst_sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    // `AF_INET6` is a small positive constant; the `try_from` (not `as`) cannot
    // truncate but keeps the crate free of `as` casts.
    dst_sa.sin6_family = u16::try_from(libc::AF_INET6).unwrap_or(0);
    dst_sa.sin6_addr.s6_addr = dst.octets();

    // A single iovec over the L4 segment; the kernel prepends the IPv6 header.
    let mut iov = libc::iovec {
        // `sendmsg` only reads through `iov_base`; `.cast_mut()` satisfies the
        // `*mut c_void` field type without implying write access.
        iov_base: l4.as_ptr().cast::<c_void>().cast_mut(),
        iov_len: l4.len(),
    };

    // Control buffer for exactly one IPV6_PKTINFO cmsg. Over-sized (one cmsg
    // needs 40 bytes here) and aligned to `cmsghdr` so `CMSG_FIRSTHDR` /
    // `CMSG_DATA` return valid, aligned pointers within it.
    #[repr(C, align(8))]
    struct CmsgBuf([u8; 64]);
    let mut cbuf = CmsgBuf([0u8; 64]);

    // `CMSG_LEN`/`CMSG_SPACE` take a `c_uint`; `in6_pktinfo` is 20 bytes, well
    // within `u32`, so `try_from` (not `as`) is exact.
    let pktinfo_len = u32::try_from(mem::size_of::<libc::in6_pktinfo>()).unwrap_or(0);

    // SAFETY: `msghdr` is plain-old-data; an all-zero value is a valid base.
    let mut mhdr: libc::msghdr = unsafe { mem::zeroed() };
    mhdr.msg_name = std::ptr::from_mut(&mut dst_sa).cast::<c_void>();
    mhdr.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap_or(0);
    mhdr.msg_iov = std::ptr::from_mut(&mut iov);
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = cbuf.0.as_mut_ptr().cast::<c_void>();
    // SAFETY: `CMSG_SPACE` is pure arithmetic over its argument (no memory
    // access); it is only `unsafe` in `libc` for signature-uniformity.
    mhdr.msg_controllen = usize::try_from(unsafe { libc::CMSG_SPACE(pktinfo_len) }).unwrap_or(0);

    // SAFETY: `msg_control` points at `cbuf`'s 64 aligned bytes and
    // `msg_controllen` is the space for one pktinfo cmsg, so `CMSG_FIRSTHDR`
    // returns either null or a valid, aligned `*mut cmsghdr` inside `cbuf`.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const mhdr) };
    if cmsg.is_null() {
        return Err(DeceptionError::Protocol(
            "CMSG_FIRSTHDR returned null".into(),
        ));
    }
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: src.octets(),
        },
        // 0 lets the kernel pick the outgoing interface by routing.
        ipi6_ifindex: 0,
    };
    // SAFETY: `cmsg` is a valid, writable, aligned `cmsghdr` within `cbuf`
    // (checked non-null above); `CMSG_DATA(cmsg)` is its 20-byte payload slot,
    // entirely inside the 64-byte buffer. `cmsg_len` is written via `try_into`
    // (its field type is `size_t`/`socklen_t` depending on libc) and the
    // pktinfo is written unaligned to avoid assuming the payload's alignment.
    unsafe {
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(pktinfo_len).try_into().unwrap_or(0);
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>(), pktinfo);
    }

    // SAFETY: `mhdr` describes a valid destination sockaddr, a single iovec over
    // `l4`'s readable bytes, and a well-formed control buffer holding one
    // IPV6_PKTINFO cmsg; `sock` is an open IPv6 raw socket. `sendmsg` only reads
    // through these for the duration of the call and retains nothing.
    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &raw const mhdr, 0) };
    if n < 0 {
        return Err(DeceptionError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `NfqueueTransport::new` only stores its parameters (opening the queue
    // and raw sockets happens in `run`, on first use), so `name()` is
    // testable without CAP_NET_ADMIN or a live NFQUEUE — unlike the rest of
    // this file, which is coverage-excluded for exactly that reason.
    #[test]
    fn nfqueue_transport_name() {
        let transport = NfqueueTransport::new(
            0,
            CookieKey::new([0u8; 16]),
            Box::new(|_port| Vec::new()),
            Arc::new(StatelessMetrics::new()),
        );
        assert_eq!(transport.name(), "nfqueue-stateless");
    }
}
