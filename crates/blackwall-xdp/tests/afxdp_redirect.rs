//! Kernel-bound end-to-end AF_XDP redirect test (sub-project B3.1).
//!
//! Creates a veth pair, attaches the real `xdp_filter` program (via
//! [`blackwall_xdp::XdpDataplane`]) to one end, binds an [`AfXdpSocket`] to its
//! RX queue and registers the socket into the `XSKS` map, installs a UDP redirect
//! port, then injects a UDP frame from the peer end and asserts the frame is
//! delivered to the `AF_XDP` socket rather than the kernel stack (B3.1 RX).
//!
//! A second test (B3.2) proves the symmetric TX path: it drives the same
//! responder logic the flow daemon runs — `recv_one` → `udp_l2_response`
//! (reflection-safe reply) → `send` — and captures the reply frame egressing
//! the veth, asserting a redirected UDP request gets a reflection-safe reply
//! **over AF_XDP** (addresses/ports swapped, payload truncated to the request).
//!
//! Requires root (`CAP_NET_ADMIN` + `CAP_NET_RAW`) and a kernel with
//! `CONFIG_XDP_SOCKETS`; run in the lab CI job:
//! `sudo -n <bin> --ignored --nocapture`.
//!
//! AF_XDP on veth is copy-mode only (no zero-copy); this is the B3.1/B3.2
//! foundation.
#![cfg(target_os = "linux")]

use std::process::Command;

use blackwall_core::XdpMode;
use blackwall_deception::transport::udp_l2_response;
use blackwall_xdp::{AfXdpSocket, XdpDataplane};

/// UDP destination port the redirect fast path diverts to the AF_XDP socket.
const REDIRECT_PORT: u16 = 9999;

/// A veth pair that deletes itself (and its peer) on drop.
struct VethPair {
    a: String,
    b: String,
}

impl VethPair {
    /// Create `veth_a`/`veth_b`, both brought up. Names are PID-unique so
    /// parallel/rerun tests do not collide.
    fn create() -> Self {
        let pid = std::process::id();
        let a = format!("bwxa{pid}");
        let b = format!("bwxb{pid}");
        // Best-effort teardown of any stale pair from a crashed prior run.
        let _ = Command::new("ip").args(["link", "del", &a]).output();
        run_ip(&["link", "add", &a, "type", "veth", "peer", "name", &b]);
        run_ip(&["link", "set", &a, "up"]);
        run_ip(&["link", "set", &b, "up"]);
        Self { a, b }
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", &self.a]).output();
    }
}

/// Run an `ip` command, panicking with its stderr on failure.
fn run_ip(args: &[&str]) {
    let out = Command::new("ip")
        .args(args)
        .output()
        .expect("spawn ip command");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The kernel `ifindex` of `ifname`.
fn ifindex(ifname: &str) -> u32 {
    let idx =
        std::fs::read_to_string(format!("/sys/class/net/{ifname}/ifindex")).expect("read ifindex");
    idx.trim().parse().expect("parse ifindex")
}

/// Build an `Ethernet + IPv4 + UDP` frame (broadcast dst MAC, no payload) to
/// `dst_port`, plus a 4-byte marker payload so we can recognise it on receipt.
fn udp_frame(dst_port: u16, marker: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 14 + 20 + 8 + 4];
    // Ethernet: broadcast dst, arbitrary src, EtherType IPv4. XDP runs on ingress
    // regardless of dst MAC, so broadcast reaches the filter on the peer.
    p[0..6].copy_from_slice(&[0xff; 6]);
    p[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x0b]);
    p[12] = 0x08;
    p[13] = 0x00;
    // IPv4 (IHL 5), total length = 20 + 8 + 4.
    p[14] = 0x45;
    let tot_len = 20u16 + 8 + 4;
    p[16..18].copy_from_slice(&tot_len.to_be_bytes());
    p[22] = 64; // TTL
    p[23] = 17; // UDP
    p[26..30].copy_from_slice(&[203, 0, 113, 7]); // src IP
    p[30..34].copy_from_slice(&[198, 51, 100, 1]); // dst IP
                                                   // UDP header + payload.
    p[34..36].copy_from_slice(&40_000u16.to_be_bytes()); // src port
    p[36..38].copy_from_slice(&dst_port.to_be_bytes()); // dst port
    p[38..40].copy_from_slice(&(8u16 + 4).to_be_bytes()); // UDP length
    p[42..46].copy_from_slice(&marker);
    p
}

/// Inject `frame` onto `ifname` (egress) via an `AF_PACKET` raw socket, so it
/// arrives on the veth peer's ingress.
fn inject(ifname: &str, frame: &[u8]) {
    // ETH_P_ALL, network byte order.
    let proto = u16::try_from(libc::ETH_P_ALL)
        .expect("ETH_P_ALL fits in u16")
        .to_be();
    // SAFETY: standard AF_PACKET raw socket creation.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(proto)) };
    assert!(
        fd >= 0,
        "AF_PACKET socket: {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: `sockaddr_ll` is a plain C struct; an all-zero bit pattern is a
    // valid, unspecified address that we fully populate below.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = u16::try_from(libc::AF_PACKET).expect("AF_PACKET fits in u16");
    addr.sll_protocol = proto;
    addr.sll_ifindex = i32::try_from(ifindex(ifname)).expect("ifindex fits in i32");
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    // SAFETY: `fd` is our raw socket; `frame` is a valid buffer of `frame.len()`
    // bytes; `addr` is a correctly-initialised `sockaddr_ll` of matching size.
    let sent = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
                .expect("sockaddr_ll size fits in socklen_t"),
        )
    };
    // SAFETY: closing our own fd.
    unsafe { libc::close(fd) };
    assert_eq!(
        usize::try_from(sent).unwrap_or(0),
        frame.len(),
        "sendto short/failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Build an `Ethernet + IPv4 + UDP` frame to `dst_port` carrying `payload`,
/// from `src_port` (so a reply's UDP destination port equals `src_port`).
fn udp_frame_with_payload(dst_port: u16, src_port: u16, payload: &[u8]) -> Vec<u8> {
    let plen = u16::try_from(payload.len()).expect("payload fits in u16");
    let mut p = vec![0u8; 14 + 20 + 8 + payload.len()];
    p[0..6].copy_from_slice(&[0xff; 6]); // dst MAC: broadcast
    p[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x0b]); // src MAC
    p[12] = 0x08;
    p[13] = 0x00;
    p[14] = 0x45; // IPv4, IHL 5
    let tot_len = 20u16 + 8 + plen;
    p[16..18].copy_from_slice(&tot_len.to_be_bytes());
    p[22] = 64; // TTL
    p[23] = 17; // UDP
    p[26..30].copy_from_slice(&[203, 0, 113, 7]); // src IP
    p[30..34].copy_from_slice(&[198, 51, 100, 1]); // dst IP
    p[34..36].copy_from_slice(&src_port.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    p[38..40].copy_from_slice(&(8u16 + plen).to_be_bytes()); // UDP length
    p[42..].copy_from_slice(payload);
    p
}

/// A bound `AF_PACKET` capture socket for one interface, with a receive
/// timeout, used to observe reply frames egressing the veth.
struct Capture {
    fd: libc::c_int,
}

impl Capture {
    /// Open an `AF_PACKET` `SOCK_RAW` socket bound to `ifname` with a 300 ms
    /// receive timeout.
    fn open(ifname: &str) -> Self {
        let proto = u16::try_from(libc::ETH_P_ALL)
            .expect("ETH_P_ALL fits in u16")
            .to_be();
        // SAFETY: standard AF_PACKET raw socket creation.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(proto)) };
        assert!(
            fd >= 0,
            "AF_PACKET capture socket: {}",
            std::io::Error::last_os_error()
        );

        // SAFETY: `sockaddr_ll` is a plain C struct; an all-zero pattern is a
        // valid unspecified address we populate below.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = u16::try_from(libc::AF_PACKET).expect("AF_PACKET fits in u16");
        addr.sll_protocol = proto;
        addr.sll_ifindex = i32::try_from(ifindex(ifname)).expect("ifindex fits in i32");
        // SAFETY: binding our own fd to a correctly-sized `sockaddr_ll`.
        let rc = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
                    .expect("sockaddr_ll size fits in socklen_t"),
            )
        };
        assert_eq!(rc, 0, "bind capture: {}", std::io::Error::last_os_error());

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 300_000,
        };
        // SAFETY: setting SO_RCVTIMEO on our own fd with a valid `timeval`.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast::<libc::c_void>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::timeval>())
                    .expect("timeval size fits in socklen_t"),
            );
        }
        Self { fd }
    }

    /// Receive one frame (up to 2048 bytes), or `None` on timeout.
    fn recv(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes; `recv`
        // writes at most that many and returns the count.
        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
            )
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(usize::try_from(n).unwrap_or(0));
        Some(buf)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: closing our own fd.
        unsafe { libc::close(self.fd) };
    }
}

#[test]
#[ignore = "requires root + CONFIG_XDP_SOCKETS; run in the lab CI job"]
fn udp_to_redirect_port_is_delivered_to_the_afxdp_socket() {
    let veth = VethPair::create();

    // Attach the real xdp_filter data plane to veth_a. Auto = native (veth
    // supports native XDP) with a generic-mode fallback.
    let dp = XdpDataplane::attach(&veth.a, XdpMode::Auto).expect("attach xdp_filter to veth_a");

    // Bind an AF_XDP socket to veth_a RX queue 0 and register it into XSKS.
    let mut receiver = AfXdpSocket::bind(&veth.a, 0).expect("bind AF_XDP socket on veth_a");
    // SAFETY: `receiver` owns the fd and outlives this registration (it is
    // dropped at the end of the test, after the map handle in `dp`).
    unsafe { dp.register_xsk(receiver.queue_id(), receiver.raw_fd()) }
        .expect("register xsk fd into XSKS");
    dp.set_redirect_ports(&[REDIRECT_PORT])
        .expect("install redirect port");

    // Inject the redirect-matching frame from the peer end.
    let marker = [0xde, 0xad, 0xbe, 0xef];
    inject(&veth.b, &udp_frame(REDIRECT_PORT, marker));

    // The frame must land on the AF_XDP socket.
    let mut buf = Vec::new();
    let mut got = false;
    // A few poll iterations to absorb scheduling latency between inject and RX.
    for _ in 0..10 {
        if receiver.recv_one(200, &mut buf).expect("recv_one") {
            got = true;
            break;
        }
    }
    assert!(got, "no frame delivered to the AF_XDP socket");
    assert!(
        buf.len() >= 46 && buf[42..46] == marker,
        "delivered frame did not carry the expected UDP marker payload (len {})",
        buf.len()
    );

    // Sanity: the redirect counter recorded the diversion.
    assert_eq!(
        dp.stats().redirected.packets,
        1,
        "exactly one frame should have been redirected"
    );
}

#[test]
#[ignore = "requires root + CONFIG_XDP_SOCKETS; run in the lab CI job"]
fn redirected_udp_gets_a_reflection_safe_reply_over_afxdp() {
    // Proves the B3.2 zero-copy round trip end-to-end: a UDP request redirected
    // to the AF_XDP socket is answered — via the exact responder pipeline the
    // flow daemon runs (`recv_one` -> `udp_l2_response` -> `send`) — with a
    // reflection-safe reply that egresses the veth.
    let veth = VethPair::create();
    let dp = XdpDataplane::attach(&veth.a, XdpMode::Auto).expect("attach xdp_filter to veth_a");

    let mut sock = AfXdpSocket::bind(&veth.a, 0).expect("bind AF_XDP socket on veth_a");
    // SAFETY: `sock` owns the fd and outlives this registration.
    unsafe { dp.register_xsk(sock.queue_id(), sock.raw_fd()) }.expect("register xsk fd into XSKS");
    dp.set_redirect_ports(&[REDIRECT_PORT])
        .expect("install redirect port");

    // Capture reply frames on the peer end before we inject the request.
    let capture = Capture::open(&veth.b);

    // Request: 40000 -> REDIRECT_PORT with a 16-byte payload. The banner is
    // longer, so the reflection guard must truncate the reply to 16 bytes.
    let client_port = 40_000u16;
    let request_payload = b"0123456789abcdef"; // 16 bytes
    let banner = b"blackwall-afxdp-udp-responder-banner"; // 36 bytes, > request
    inject(
        &veth.b,
        &udp_frame_with_payload(REDIRECT_PORT, client_port, request_payload),
    );

    // Responder loop: receive the redirected frame, build the reflection-safe
    // reply, transmit it over AF_XDP.
    let mut buf = Vec::new();
    let mut sent = false;
    for _ in 0..10 {
        if sock.recv_one(200, &mut buf).expect("recv_one") {
            let reply = udp_l2_response(&buf, banner).expect("reflection-safe reply built");
            sock.send(&reply).expect("send reply over AF_XDP TX");
            sent = true;
            break;
        }
    }
    assert!(sent, "no redirected frame arrived to answer");

    // Observe the reply egressing the veth. Filter to the reply direction
    // (inner UDP destination port == the client's source port).
    let mut reply = None;
    for _ in 0..20 {
        let Some(frame) = capture.recv() else {
            continue;
        };
        if frame.len() < 42 {
            continue;
        }
        if frame[12..14] != [0x08, 0x00] {
            continue; // not IPv4
        }
        if frame[23] != 17 {
            continue; // not UDP
        }
        let udp_dst = u16::from_be_bytes([frame[36], frame[37]]);
        if udp_dst == client_port {
            reply = Some(frame);
            break;
        }
    }
    let reply = reply.expect("reflection-safe UDP reply observed on the veth");

    // Inner IPv4: addresses swapped relative to the request.
    assert_eq!(
        &reply[26..30],
        &[198, 51, 100, 1],
        "reply src IP = request dst"
    );
    assert_eq!(
        &reply[30..34],
        &[203, 0, 113, 7],
        "reply dst IP = request src"
    );
    // UDP ports swapped.
    let udp_src = u16::from_be_bytes([reply[34], reply[35]]);
    assert_eq!(udp_src, REDIRECT_PORT, "reply src port = request dst");
    // Payload: truncated to the request length (amplification guard) and equal
    // to the banner prefix.
    let payload = &reply[42..];
    assert!(
        payload.len() <= request_payload.len(),
        "reply payload ({}) must not exceed request payload ({})",
        payload.len(),
        request_payload.len()
    );
    assert_eq!(
        payload,
        &banner[..request_payload.len()],
        "reply payload must be the banner truncated to the request length"
    );
}
