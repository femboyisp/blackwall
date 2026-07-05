//! Manual/netns interop exercise: stand up the deception data plane (real nft
//! ruleset -> TPROXY -> engine -> emulators) and serve a honeypot banner to a
//! scanner. Ignored in unit CI (needs CAP_NET_ADMIN + a netns); run by the lab
//! harness's deception-nft scenario.
//!
//!   cargo test -p blackwall-deception --test interop -- serves_deception_banner --ignored --nocapture

use blackwall_core::{AllowRule, L4Proto, Policy, PortState, ServiceTarget, Tenant};
use blackwall_deception::transport::{serve, SessionRecord, TproxyListener};
use blackwall_deception::{default_registry, BannerStore, EngineLimits};
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
            }],
        }],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
        flowspec: None,
        metrics_listen: None,
        engine: blackwall_core::EngineConfig::default(),
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
            }],
        }],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
        flowspec: None,
        metrics_listen: None,
        engine: blackwall_core::EngineConfig::default(),
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
