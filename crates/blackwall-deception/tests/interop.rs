//! Manual/netns interop exercise: stand up the deception data plane (real nft
//! ruleset -> TPROXY -> engine -> emulators) and serve a honeypot banner to a
//! scanner. Ignored in unit CI (needs CAP_NET_ADMIN + a netns); run by the lab
//! harness's deception-nft scenario.
//!
//!   cargo test -p blackwall-deception --test interop -- serves_deception_banner --ignored --nocapture

use blackwall_core::{AllowRule, L4Proto, Policy, PortState, ServiceTarget, Tenant};
use blackwall_deception::transport::{
    run_nfqueue, serve, SessionRecord, StatelessMetrics, TproxyListener,
};
use blackwall_deception::{default_registry, BannerStore, CookieKey, EngineLimits};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// First interface in the current netns that is neither `lo` nor `ifb*` — the veth.
fn first_non_loopback_iface() -> String {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .expect("run `ip -o link show`");
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = line
            .split(':')
            .nth(1)
            .map(str::trim)
            .and_then(|n| n.split('@').next())
            .map(str::trim)
            .unwrap_or("");
        if !name.is_empty() && name != "lo" && !name.starts_with("ifb") {
            return name.to_owned();
        }
    }
    panic!("no non-loopback interface in this netns");
}

/// The first IPv4 address configured on `iface` (e.g. `10.0.0.1`).
fn first_ipv4_of(iface: &str) -> std::net::Ipv4Addr {
    let out = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", iface])
        .output()
        .expect("run `ip -o -4 addr show`");
    let text = String::from_utf8_lossy(&out.stdout);
    // "<idx>: <iface>    inet 10.0.0.1/30 ..."
    let cidr = text
        .split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
        .expect("no inet addr on iface");
    cidr.split('/').next().unwrap().parse().expect("parse ipv4")
}

/// The first non-link-local IPv6 address configured on `iface` (e.g. the ULA
/// the lab allocated from the link's `subnet6`). Link-local `fe80::/10`
/// addresses are skipped: the scanner targets the routable deception address.
fn first_ipv6_of(iface: &str) -> std::net::Ipv6Addr {
    let out = std::process::Command::new("ip")
        .args(["-o", "-6", "addr", "show", "dev", iface])
        .output()
        .expect("run `ip -o -6 addr show`");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // "<idx>: <iface>    inet6 fd00::1/64 scope global ..."
        let Some(cidr) = line.split_whitespace().skip_while(|w| *w != "inet6").nth(1) else {
            continue;
        };
        let Some(addr): Option<std::net::Ipv6Addr> =
            cidr.split('/').next().and_then(|a| a.parse().ok())
        else {
            continue;
        };
        // Skip fe80::/10 link-local; the deception address is the ULA/global one.
        if addr.segments()[0] & 0xffc0 != 0xfe80 {
            return addr;
        }
    }
    panic!("no non-link-local IPv6 address on {iface}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs CAP_NET_ADMIN + a netns (nft + TPROXY); run in the lab"]
async fn serves_deception_banner() {
    let iface = first_non_loopback_iface();
    let addr = first_ipv4_of(&iface);

    // Minimal policy: this iface is managed, the prefix is the victim's own /32,
    // default Deception, no tenants -> every TCP port classifies as deception.
    let policy = Policy {
        interface: iface,
        // Both families are declared as managed prefixes: the v4 prefix is the
        // victim's own /32 (what the scanner hits); the v6 prefix exists only so
        // the dummy v6 owned address below is "within a managed prefix" (apply
        // validates that). No v6 traffic flows in this scenario.
        prefixes: vec![
            format!("{addr}/32").parse().expect("v4 prefix"),
            "fd00::/64".parse().expect("v6 prefix"),
        ],
        default_state: PortState::Deception,
        // One benign declared service per family so the nft `real_v4`/`real_v6`
        // sets are non-empty (an empty set makes `nft` reject the ruleset). Port
        // 8080 is real; port 22 stays unmatched -> deception -> tproxy.
        tenants: vec![Tenant {
            name: "lab".to_owned(),
            owned: vec![IpAddr::V4(addr), IpAddr::V6("fd00::1".parse().expect("v6"))],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 8080,
                target: ServiceTarget::Host,
                scope: None,
            }],
        }],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
        flowspec: None,
        metrics_listen: None,
        api: None,
        pops: Vec::new(),
        engine: blackwall_core::EngineConfig::default(),
        flowtable: None,
        xdp: None,
        stateless_tcp_ports: Vec::new(),
        protected_prefixes: Vec::new(),
        shadow: false,
        rpki_validator: None,
        rpki_check_interval: std::time::Duration::from_secs(3600),
    };

    // Apply the REAL nft ruleset: deception TCP on the prefix -> tproxy :61000
    // (no mark; no ip-rule plumbing needed — see the spec's TPROXY pin).
    blackwall_nft::apply(&policy).expect("nft apply");

    // Real emulators; the SSH emulator answers SSH-2.0-OpenSSH_9.6 on port 22.
    let banners = Arc::new(BannerStore::from_text("80 = nginx/1.24.0\\r\\n\n").expect("banners"));
    let registry = Arc::new(default_registry(banners));
    let listener = TproxyListener::bind("0.0.0.0:61000".parse().unwrap()).expect("bind tproxy");
    let (tx, mut rx) = mpsc::channel::<SessionRecord>(64);
    tokio::spawn(async move { while rx.recv().await.is_some() {} }); // drain sessions
    serve(
        listener,
        registry,
        tx,
        EngineLimits::default(),
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .await; // runs until the lab kills it
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs CAP_NET_ADMIN + a netns (nft + TPROXY); run in the lab"]
async fn serves_deception_under_load() {
    let iface = first_non_loopback_iface();
    let addr = first_ipv4_of(&iface);

    // Minimal policy: this iface is managed, the prefix is the victim's own /32,
    // default Deception, no tenants -> every TCP port classifies as deception.
    let policy = Policy {
        interface: iface,
        // Both families are declared as managed prefixes: the v4 prefix is the
        // victim's own /32 (what the scanner hits); the v6 prefix exists only so
        // the dummy v6 owned address below is "within a managed prefix" (apply
        // validates that). No v6 traffic flows in this scenario.
        prefixes: vec![
            format!("{addr}/32").parse().expect("v4 prefix"),
            "fd00::/64".parse().expect("v6 prefix"),
        ],
        default_state: PortState::Deception,
        // One benign declared service per family so the nft `real_v4`/`real_v6`
        // sets are non-empty (an empty set makes `nft` reject the ruleset). Port
        // 8080 is real; port 22 stays unmatched -> deception -> tproxy.
        tenants: vec![Tenant {
            name: "lab".to_owned(),
            owned: vec![IpAddr::V4(addr), IpAddr::V6("fd00::1".parse().expect("v6"))],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 8080,
                target: ServiceTarget::Host,
                scope: None,
            }],
        }],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
        flowspec: None,
        metrics_listen: None,
        api: None,
        pops: Vec::new(),
        engine: blackwall_core::EngineConfig::default(),
        flowtable: None,
        xdp: None,
        stateless_tcp_ports: Vec::new(),
        protected_prefixes: Vec::new(),
        shadow: false,
        rpki_validator: None,
        rpki_check_interval: std::time::Duration::from_secs(3600),
    };

    // Apply the REAL nft ruleset: deception TCP on the prefix -> tproxy :61000
    // (no mark; no ip-rule plumbing needed — see the spec's TPROXY pin).
    blackwall_nft::apply(&policy).expect("nft apply");

    // Real emulators; the SSH emulator answers SSH-2.0-OpenSSH_9.6 on port 22.
    let banners = Arc::new(BannerStore::from_text("80 = nginx/1.24.0\\r\\n\n").expect("banners"));
    let registry = Arc::new(default_registry(banners));
    let listener = TproxyListener::bind("0.0.0.0:61000".parse().unwrap()).expect("bind tproxy");
    let (tx, mut rx) = mpsc::channel::<SessionRecord>(64);
    tokio::spawn(async move { while rx.recv().await.is_some() {} }); // drain sessions

    // Lab value: a low-ish cap so a connect-flood clearly exceeds it and
    // drop-at-cap engages at CI-stable scale. Production default is 1024.
    let limits = EngineLimits {
        max_concurrent: 256,
        session_timeout: Duration::from_secs(60),
    };
    serve(
        listener,
        registry,
        tx,
        limits,
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .await; // runs until the lab kills it
}

/// The lab's file-present sentinel for this test: written just before the
/// (blocking, forever-running) NFQUEUE responder starts, so the
/// `deception-syncookie` scenario's `wait` step knows the responder is up
/// (the stateless tier has no listening socket, so `port-open:` cannot be
/// used here — see `blackwall-flow`'s `detects_live_sflow_attack` for the
/// same file-present pattern).
const SYNCOOKIE_READY_SENTINEL: &str = "/run/blackwall-lab/syncookie-ready";

/// Marker banner the stateless SYN-cookie responder serves on the stateless
/// port under test; the scenario's key assertion greps for this exact string
/// after a real client TCP handshake completes through the cookie tier.
const SYNCOOKIE_BANNER: &[u8] = b"STATELESS-COOKIE-OK\r\n";

#[test]
#[ignore = "needs CAP_NET_ADMIN + a netns (nft + raw sockets); run in the lab"]
fn serves_stateless_syn_cookie() {
    let iface = first_non_loopback_iface();
    let addr = first_ipv4_of(&iface);

    // Same shape as `serves_deception_under_load`: this iface is managed, the
    // prefix is the victim's own /32, default Deception. Unlike that test,
    // port 8080 must NOT be a tenant-allowed ("real") port here — a real port
    // is accepted straight to the host stack (rule 6) before the
    // stateless-tcp queue rule (rule 7) is ever reached, which would bypass
    // the cookie tier entirely. So the one benign declared service (needed
    // only so nft's `real_v4`/`real_v6` sets are non-empty) uses a different
    // port (9000), leaving 8080 unmatched -> deception -> routed by
    // `stateless_tcp_ports` to the NFQUEUE instead of tproxy.
    let policy = Policy {
        interface: iface,
        prefixes: vec![
            format!("{addr}/32").parse().expect("v4 prefix"),
            "fd00::/64".parse().expect("v6 prefix"),
        ],
        default_state: PortState::Deception,
        tenants: vec![Tenant {
            name: "lab".to_owned(),
            owned: vec![IpAddr::V4(addr), IpAddr::V6("fd00::1".parse().expect("v6"))],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 9000,
                target: ServiceTarget::Host,
                scope: None,
            }],
        }],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
        flowspec: None,
        metrics_listen: None,
        api: None,
        pops: Vec::new(),
        engine: blackwall_core::EngineConfig::default(),
        flowtable: None,
        xdp: None,
        // The stateless-tier port under test (Component 2c wiring): deception
        // TCP on 8080 is routed to the engine's NFQUEUE instead of tproxy.
        stateless_tcp_ports: vec![8080],
        protected_prefixes: Vec::new(),
        shadow: false,
        rpki_validator: None,
        rpki_check_interval: std::time::Duration::from_secs(3600),
    };

    // Apply the REAL nft ruleset: stateless-tcp TCP on 8080 -> nfqueue
    // (before the tproxy rule; see the render.rs Component 2c ordering test).
    blackwall_nft::apply(&policy).expect("nft apply");

    let cookie_key = CookieKey::new([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ]);
    // Any destination port reaching the queue gets the same recognizable
    // marker; only 8080 (the stateless port) and ICMP/UDP on the managed
    // prefix are ever queued here, so a distinct per-port table isn't needed.
    let banners: blackwall_deception::transport::BannerLookup =
        Box::new(|_port: u16| SYNCOOKIE_BANNER.to_vec());

    let _ = std::fs::remove_file(SYNCOOKIE_READY_SENTINEL); // fresh for the scenario's file-present probe
    std::fs::write(SYNCOOKIE_READY_SENTINEL, b"ok").expect("write sentinel");

    // Real end-to-end responder: opens the NFQUEUE + raw sockets and handles
    // SYN-cookie mint/validate + banner+FIN forever (the lab kills it at
    // teardown). This call blocks; it is not a stub.
    let metrics = Arc::new(StatelessMetrics::new());
    run_nfqueue(policy.engine.nfqueue_num, cookie_key, banners, metrics)
        .expect("nfqueue responder");
}

/// The IPv6 sibling of [`serves_stateless_syn_cookie`] — the #128 gate.
///
/// Same shape, but the stateless-tier port is reached over IPv6. Before #128
/// the v6 TCP SYN-cookie replies were pushed through an `IPPROTO_ICMPV6` raw
/// socket (which can only carry ICMPv6), so no SYN-ACK ever reached the wire
/// and the handshake could not complete; the fix sends each L4 protocol through
/// its own IPv6 raw socket with the source pinned via `IPV6_PKTINFO`. The
/// scenario's key assertion is a legit v6 `/dev/tcp` connect receiving the
/// marker banner, proving the v6 cookie handshake + fixed send path work end to
/// end. The policy is dual-stack only so nft's `real_v4`/`real_v6` sets are
/// both non-empty (an empty set makes `nft` reject the ruleset); the traffic
/// under test is v6.
#[test]
#[ignore = "needs CAP_NET_ADMIN + a netns (nft + raw sockets); run in the lab"]
fn serves_stateless_syn_cookie_v6() {
    let iface = first_non_loopback_iface();
    let addr6 = first_ipv6_of(&iface);

    // Mirror `serves_stateless_syn_cookie`, but the managed prefix under test is
    // the victim's own v6 /128 (what the scanner hits over IPv6). The lab link
    // is v6-only (the lab allocates one address family per link), so the iface
    // has no v4 address; a dummy static v4 prefix + owned address exists only so
    // nft's `real_v4` set is non-empty (an empty set makes `nft` reject the
    // ruleset) — the mirror of the dummy v6 in the v4 test. Port 8080 is left
    // unmatched -> deception -> routed by `stateless_tcp_ports` to the NFQUEUE;
    // the one benign declared service uses 9000 so 8080 never classifies as a
    // real (host-accepted) port.
    let dummy_v4: std::net::Ipv4Addr = "192.0.2.1".parse().expect("dummy v4");
    let policy = Policy {
        interface: iface,
        prefixes: vec![
            "192.0.2.0/24".parse().expect("v4 prefix"),
            format!("{addr6}/128").parse().expect("v6 prefix"),
        ],
        default_state: PortState::Deception,
        tenants: vec![Tenant {
            name: "lab".to_owned(),
            owned: vec![IpAddr::V4(dummy_v4), IpAddr::V6(addr6)],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 9000,
                target: ServiceTarget::Host,
                scope: None,
            }],
        }],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
        flowspec: None,
        metrics_listen: None,
        api: None,
        pops: Vec::new(),
        engine: blackwall_core::EngineConfig::default(),
        flowtable: None,
        xdp: None,
        stateless_tcp_ports: vec![8080],
        protected_prefixes: Vec::new(),
        shadow: false,
        rpki_validator: None,
        rpki_check_interval: std::time::Duration::from_secs(3600),
    };

    blackwall_nft::apply(&policy).expect("nft apply");

    let cookie_key = CookieKey::new([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ]);
    let banners: blackwall_deception::transport::BannerLookup =
        Box::new(|_port: u16| SYNCOOKIE_BANNER.to_vec());

    let _ = std::fs::remove_file(SYNCOOKIE_READY_SENTINEL); // fresh for the scenario's file-present probe
    std::fs::write(SYNCOOKIE_READY_SENTINEL, b"ok").expect("write sentinel");

    let metrics = Arc::new(StatelessMetrics::new());
    run_nfqueue(policy.engine.nfqueue_num, cookie_key, banners, metrics)
        .expect("nfqueue responder");
}
