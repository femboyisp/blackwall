//! Manual/netns interop exercise: install CAKE on the node's veth via the real
//! `blackwall-shaper` apply path, exactly as `blackwalld`'s `shape` loop does
//! (minus the speedtest — a fixed bandwidth is used). Ignored in unit CI (needs
//! CAP_NET_ADMIN + a netns); run by the lab harness's shaper-cake scenario.
//!
//!   BW_SHAPE_DOWN=100 BW_SHAPE_UP=50 \
//!   cargo test -p blackwall-shaper --test interop -- applies_cake --ignored --nocapture

use blackwall_core::{ShapeBandwidth, ShapeRule};
use blackwall_shaper::{apply, plan_for};

fn env_u32(key: &str) -> u32 {
    std::env::var(key)
        .unwrap_or_else(|_| panic!("set {key}"))
        .parse()
        .unwrap_or_else(|e| panic!("{key} must be a u32: {e}"))
}

/// First interface in the current network namespace that is neither `lo` nor an
/// `ifb*` device — i.e. the node's veth. The test runs inside the node's netns
/// (the lab launches it via `ip netns exec`), so `ip link` lists that ns.
fn first_non_loopback_iface() -> String {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .expect("run `ip -o link show`");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // Format: "<idx>: <name>[@peer]: <flags> ..."
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
    panic!("no non-loopback interface found in this netns");
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + a netns; run in the lab"]
fn applies_cake() {
    let iface = first_non_loopback_iface();
    let rule = ShapeRule {
        iface: iface.clone(),
        download: ShapeBandwidth::Fixed(env_u32("BW_SHAPE_DOWN")), // -> ingress_mbit
        upload: ShapeBandwidth::Fixed(env_u32("BW_SHAPE_UP")),     // -> egress_mbit
        rtt_ms: Some(50),
    };
    let plan = plan_for(&rule, None).expect("plan_for");
    apply(&plan, "bwlab-ifb0").expect("apply CAKE");
    eprintln!("applied CAKE on {iface}");
}
