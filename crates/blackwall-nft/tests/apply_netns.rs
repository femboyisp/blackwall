//! Applies a rendered ruleset inside a throwaway network namespace and checks
//! the table appears. Skips unless `BLACKWALL_NETNS_TESTS=1` and running as
//! root (the harness/CI sets these; ordinary `cargo test` skips it).

use blackwall_core::{AllowRule, L4Proto, Policy, PortState, ServiceTarget, Tenant};

fn enabled() -> bool {
    std::env::var("BLACKWALL_NETNS_TESTS").as_deref() == Ok("1")
}

fn sample() -> Policy {
    Policy {
        interface: "lo".to_owned(),
        prefixes: vec!["203.0.113.0/24".parse().expect("prefix")],
        default_state: PortState::Deception,
        tenants: vec![Tenant {
            name: "acme".to_owned(),
            owned: vec!["203.0.113.5".parse().expect("ip")],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 443,
                target: ServiceTarget::Host,
            }],
        }],
    }
}

#[test]
fn applies_in_netns() {
    if !enabled() {
        eprintln!("BLACKWALL_NETNS_TESTS != 1; skipping");
        return;
    }
    // Apply, then assert the table is present via `nft list ruleset`.
    blackwall_nft::apply(&sample()).expect("apply ruleset");
    let listing = std::process::Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .expect("run nft");
    let text = String::from_utf8_lossy(&listing.stdout);
    assert!(
        text.contains("table inet blackwall"),
        "ruleset missing: {text}"
    );
}
