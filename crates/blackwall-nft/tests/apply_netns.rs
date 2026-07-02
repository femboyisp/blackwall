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
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
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
    assert!(text.contains("tproxy"), "tproxy rule missing: {text}");
    assert!(text.contains("queue"), "queue rule missing: {text}");
}

/// Regression test: after applying a policy that includes a service, then
/// applying a second policy with that service removed, the service's address
/// must no longer appear in the real_v4 set.  This encodes the flush-table
/// atomicity guarantee: stale set elements from a prior apply must not persist.
#[test]
fn stale_set_elements_removed_on_second_apply() {
    if !enabled() {
        eprintln!("BLACKWALL_NETNS_TESTS != 1; skipping");
        return;
    }

    // First apply: policy with 203.0.113.5 TCP/443.
    let policy_with_service = sample();
    blackwall_nft::apply(&policy_with_service).expect("first apply");

    // Second apply: policy with no tenants (no services).
    let policy_empty = Policy {
        interface: "lo".to_owned(),
        prefixes: vec!["203.0.113.0/24".parse().expect("prefix")],
        default_state: PortState::Deception,
        tenants: vec![],
        shaping: Vec::new(),
        banner_flux: None,
        dns_flux: None,
        rtbh: None,
    };
    blackwall_nft::apply(&policy_empty).expect("second apply");

    let listing = std::process::Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .expect("run nft");
    let text = String::from_utf8_lossy(&listing.stdout);

    assert!(
        !text.contains("203.0.113.5"),
        "removed service address still present after second apply: {text}"
    );
}
