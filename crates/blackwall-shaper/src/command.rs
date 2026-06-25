//! Pure builders for the `tc`/`ip` commands that install CAKE shaping.
//!
//! Each command is a `Vec<String>` (argv, program first). Execution lives in
//! `apply.rs`; these builders are pure and unit-tested.

use crate::plan::ShapePlan;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

fn cake_qdisc(dev: &str, mbit: u32, rtt_ms: Option<u32>) -> Vec<String> {
    let bw = format!("{mbit}mbit");
    let mut cmd = argv(&[
        "tc",
        "qdisc",
        "replace",
        "dev",
        dev,
        "root",
        "cake",
        "bandwidth",
        &bw,
    ]);
    if let Some(rtt) = rtt_ms {
        cmd.push("rtt".to_owned());
        cmd.push(format!("{rtt}ms"));
    }
    cmd
}

/// Commands installing CAKE on the interface egress.
pub fn egress_commands(plan: &ShapePlan) -> Vec<Vec<String>> {
    vec![cake_qdisc(&plan.iface, plan.egress_mbit, plan.rtt_ms)]
}

/// Commands installing ingress shaping for `plan` via the IFB device `ifb`.
pub fn ingress_commands(plan: &ShapePlan, ifb: &str) -> Vec<Vec<String>> {
    vec![
        argv(&["ip", "link", "add", ifb, "type", "ifb"]),
        argv(&["ip", "link", "set", ifb, "up"]),
        argv(&[
            "tc",
            "qdisc",
            "replace",
            "dev",
            &plan.iface,
            "handle",
            "ffff:",
            "ingress",
        ]),
        argv(&[
            "tc",
            "filter",
            "replace",
            "dev",
            &plan.iface,
            "parent",
            "ffff:",
            "protocol",
            "all",
            "u32",
            "match",
            "u32",
            "0",
            "0",
            "action",
            "mirred",
            "egress",
            "redirect",
            "dev",
            ifb,
        ]),
        cake_qdisc(ifb, plan.ingress_mbit, plan.rtt_ms),
    ]
}

/// Best-effort teardown commands (run before re-applying for idempotence).
pub fn teardown_commands(iface: &str, ifb: &str) -> Vec<Vec<String>> {
    vec![
        argv(&["tc", "qdisc", "del", "dev", iface, "root"]),
        argv(&["tc", "qdisc", "del", "dev", iface, "ingress"]),
        argv(&["ip", "link", "del", ifb]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ShapePlan {
        ShapePlan {
            iface: "eth0".to_owned(),
            egress_mbit: 880,
            ingress_mbit: 940,
            rtt_ms: Some(50),
        }
    }

    #[test]
    fn egress_installs_cake_with_rtt() {
        let cmds = egress_commands(&plan());
        assert_eq!(cmds.len(), 1);
        let c = cmds[0].join(" ");
        assert_eq!(
            c,
            "tc qdisc replace dev eth0 root cake bandwidth 880mbit rtt 50ms"
        );
    }

    #[test]
    fn ingress_sets_up_ifb_and_cake() {
        let cmds = ingress_commands(&plan(), "ifb0");
        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        assert_eq!(joined[0], "ip link add ifb0 type ifb");
        assert!(joined
            .iter()
            .any(|c| c == "tc qdisc replace dev ifb0 root cake bandwidth 940mbit rtt 50ms"));
        assert_eq!(
            joined[3],
            "tc filter replace dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0"
        );
    }

    #[test]
    fn egress_without_rtt_omits_rtt() {
        let mut p = plan();
        p.rtt_ms = None;
        assert_eq!(
            egress_commands(&p)[0].join(" "),
            "tc qdisc replace dev eth0 root cake bandwidth 880mbit"
        );
    }
}
