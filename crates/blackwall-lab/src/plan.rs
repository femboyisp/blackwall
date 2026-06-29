//! Compile a validated topology into an ordered execution plan.

use crate::addr::AddressMap;
use crate::error::LabError;
use crate::render::render_bird;
use crate::topology::model::{DaemonKind, LinkKind, Node, Topology};
use std::net::IpAddr;

/// A single side-effecting operation the executor will carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Create a network namespace.
    CreateNetns(String),
    /// Bring up loopback inside a namespace.
    SetLoopbackUp(String),
    /// Create a veth pair (in the root namespace) with these two iface names.
    CreateVethPair {
        /// First iface name.
        a: String,
        /// Second iface name.
        b: String,
    },
    /// Move an interface into a namespace.
    MoveIface {
        /// Interface to move.
        iface: String,
        /// Destination namespace.
        netns: String,
    },
    /// Bring an interface up inside a namespace.
    SetIfaceUp {
        /// Namespace.
        netns: String,
        /// Interface.
        iface: String,
    },
    /// Assign an address to an interface inside a namespace.
    AddAddr {
        /// Namespace.
        netns: String,
        /// Interface.
        iface: String,
        /// Address.
        addr: IpAddr,
        /// Prefix length.
        prefix: u8,
    },
    /// Write a rendered config file the executor will place on disk.
    WriteConfig {
        /// Logical key (e.g. `bird:peer`).
        key: String,
        /// Rendered file contents.
        contents: String,
    },
    /// Launch a daemon inside a namespace.
    SpawnDaemon {
        /// Namespace.
        netns: String,
        /// Daemon kind.
        kind: DaemonKind,
        /// Config key (matches a prior `WriteConfig`).
        config_key: String,
        /// Owning node name.
        node: String,
    },
    /// Launch a process inside a namespace.
    SpawnRun {
        /// Namespace.
        netns: String,
        /// Process label.
        name: String,
        /// Command line (env resolved by the executor).
        cmd: String,
        /// Unresolved env pairs.
        env: Vec<(String, String)>,
    },
}

/// An ordered, dependency-sorted plan for one lab run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    /// Run identifier (namespaces/ifaces are prefixed with it).
    pub run_id: String,
    /// Namespaces to tear down, in creation order.
    pub netns: Vec<String>,
    /// Operations, in execution order.
    pub ops: Vec<Op>,
}

/// Namespace name for a node in a run.
#[must_use]
pub fn netns_name(run_id: &str, node: &str) -> String {
    format!("bw-{run_id}-{node}")
}

/// Interface name for a link side. Kept <= 15 bytes (Linux iface limit) by
/// using a short run id (6 chars) plus link index and side character.
#[must_use]
pub fn iface_name(run_id: &str, link_idx: usize, side: char) -> String {
    let name = format!("v{run_id}{link_idx}{side}");
    // Linux caps interface names at 15 bytes; run ids are 6 chars and link
    // counts are tiny, so this holds by construction — assert it anyway.
    debug_assert!(name.len() <= 15, "iface name `{name}` exceeds 15 bytes");
    name
}

/// Resolve the namespace for a node (explicit override or per-run default).
fn node_netns(run_id: &str, node: &Node) -> String {
    node.netns
        .clone()
        .unwrap_or_else(|| netns_name(run_id, &node.name))
}

/// Compile `topo` into an [`ExecutionPlan`].
///
/// # Errors
/// Returns [`LabError::Plan`] for an unrealized link kind, a missing address,
/// or a config-render failure.
pub fn compile(topo: &Topology, map: &AddressMap, run_id: &str) -> Result<ExecutionPlan, LabError> {
    let mut ops = Vec::new();
    let mut netns = Vec::new();

    // Phase 1: namespaces.
    for node in &topo.nodes {
        let ns = node_netns(run_id, node);
        ops.push(Op::CreateNetns(ns.clone()));
        ops.push(Op::SetLoopbackUp(ns.clone()));
        netns.push(ns);
    }

    // Phase 2: links (veth only in L1).
    for (idx, link) in topo.links.iter().enumerate() {
        if !matches!(link.kind, LinkKind::Veth) {
            return Err(LabError::Plan(format!(
                "link {idx} kind not realized in L1"
            )));
        }
        let a = iface_name(run_id, idx, 'a');
        let b = iface_name(run_id, idx, 'b');
        ops.push(Op::CreateVethPair {
            a: a.clone(),
            b: b.clone(),
        });

        let ends = [(&link.endpoints[0], &a), (&link.endpoints[1], &b)];
        for (ep, iface) in ends {
            let node = topo
                .nodes
                .iter()
                .find(|n| n.name == ep.node)
                .ok_or_else(|| LabError::Plan(format!("link {idx} unknown node `{}`", ep.node)))?;
            let ns = node_netns(run_id, node);
            ops.push(Op::MoveIface {
                iface: iface.clone(),
                netns: ns.clone(),
            });
            ops.push(Op::SetIfaceUp {
                netns: ns.clone(),
                iface: iface.clone(),
            });
            let (addr, prefix) = map.link_addr(idx, &ep.node).ok_or_else(|| {
                LabError::Plan(format!("no address for `{}` on link {idx}", ep.node))
            })?;
            ops.push(Op::AddAddr {
                netns: ns,
                iface: iface.clone(),
                addr,
                prefix,
            });
        }
    }

    // Phase 3: configs + daemons + runs.
    for node in &topo.nodes {
        let ns = node_netns(run_id, node);
        for daemon in &node.daemons {
            let config_key = match daemon.kind {
                DaemonKind::Bird => {
                    let contents = render_bird(node, topo, map)?;
                    let key = format!("bird:{}", node.name);
                    ops.push(Op::WriteConfig {
                        key: key.clone(),
                        contents,
                    });
                    key
                }
                DaemonKind::Knot => {
                    let conf = crate::render::render_knot_conf(daemon)?;
                    let zone = crate::render::render_zone(daemon)?;
                    let conf_key = format!("knot-conf:{}", node.name);
                    let zone_key = format!("knot-zone:{}", node.name);
                    ops.push(Op::WriteConfig { key: conf_key.clone(), contents: conf });
                    ops.push(Op::WriteConfig { key: zone_key, contents: zone });
                    conf_key
                }
                DaemonKind::WireGuard => {
                    return Err(LabError::Plan(format!(
                        "daemon {:?} not realized yet",
                        daemon.kind
                    )));
                }
            };
            ops.push(Op::SpawnDaemon {
                netns: ns.clone(),
                kind: daemon.kind,
                config_key,
                node: node.name.clone(),
            });
        }
        for run in &node.runs {
            ops.push(Op::SpawnRun {
                netns: ns.clone(),
                name: run.name.clone(),
                cmd: run.cmd.clone(),
                env: run.env.clone(),
            });
        }
    }

    Ok(ExecutionPlan {
        run_id: run_id.to_owned(),
        netns,
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::allocate;
    use crate::topology::model::*;
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    fn proof_topo() -> Topology {
        let mut settings = BTreeMap::new();
        for (k, v) in [
            ("local-as", "214806"),
            ("neighbor-node", "speaker"),
            ("neighbor-as", "214806"),
            ("import", "all"),
            ("passive", "yes"),
        ] {
            settings.insert(k.to_owned(), v.to_owned());
        }
        Topology {
            name: "t".to_owned(),
            nodes: vec![
                Node {
                    name: "peer".to_owned(),
                    netns: None,
                    loopback: None,
                    daemons: vec![Daemon {
                        kind: DaemonKind::Bird,
                        settings,
                    }],
                    runs: vec![],
                },
                Node {
                    name: "speaker".to_owned(),
                    netns: None,
                    loopback: None,
                    daemons: vec![],
                    runs: vec![RunSpec {
                        name: "speaker".to_owned(),
                        cmd: "run-interop".to_owned(),
                        env: vec![],
                        readiness: None,
                    }],
                },
            ],
            links: vec![Link {
                kind: LinkKind::Veth,
                endpoints: vec![
                    Endpoint {
                        node: "peer".to_owned(),
                        addr_override: None,
                    },
                    Endpoint {
                        node: "speaker".to_owned(),
                        addr_override: None,
                    },
                ],
                subnet_v4: Some("10.0.0.0/30".parse().unwrap()),
                subnet_v6: None,
            }],
        }
    }

    #[test]
    fn netns_and_iface_names_are_bounded() {
        // Linux interface names must be <= 15 bytes.
        let iface = iface_name("abc123", 0, 'a');
        assert!(iface.len() <= 15, "iface name too long: {iface}");
        assert_eq!(netns_name("abc123", "peer"), "bw-abc123-peer");
    }

    #[test]
    fn compiles_proof_slice_plan() {
        let topo = proof_topo();
        let map = allocate(&topo).unwrap();
        let plan = compile(&topo, &map, "abc123").unwrap();

        assert_eq!(plan.run_id, "abc123");
        assert_eq!(
            plan.netns,
            vec!["bw-abc123-peer".to_owned(), "bw-abc123-speaker".to_owned()]
        );

        // veth pair created once.
        let veths: Vec<_> = plan
            .ops
            .iter()
            .filter(|o| matches!(o, Op::CreateVethPair { .. }))
            .collect();
        assert_eq!(veths.len(), 1);

        // both addresses assigned in the right namespaces.
        assert!(plan.ops.iter().any(|o| matches!(o, Op::AddAddr { netns, addr, prefix, .. }
            if netns == "bw-abc123-peer" && addr == &"10.0.0.1".parse::<IpAddr>().unwrap() && *prefix == 30)));
        assert!(plan.ops.iter().any(|o| matches!(o, Op::AddAddr { netns, addr, prefix, .. }
            if netns == "bw-abc123-speaker" && addr == &"10.0.0.2".parse::<IpAddr>().unwrap() && *prefix == 30)));

        // bird config written for the peer, run spawned for the speaker.
        assert!(plan.ops.iter().any(|o| matches!(o, Op::WriteConfig { contents, .. } if contents.contains("protocol bgp peer_speaker"))));
        assert!(plan.ops.iter().any(|o| matches!(o, Op::SpawnDaemon { netns, kind, .. } if netns == "bw-abc123-peer" && *kind == DaemonKind::Bird)));
        assert!(plan.ops.iter().any(|o| matches!(o, Op::SpawnRun { netns, cmd, .. } if netns == "bw-abc123-speaker" && cmd == "run-interop")));

        // ordering: every CreateNetns precedes the first CreateVethPair.
        let first_veth = plan
            .ops
            .iter()
            .position(|o| matches!(o, Op::CreateVethPair { .. }))
            .unwrap();
        let last_netns = plan
            .ops
            .iter()
            .rposition(|o| matches!(o, Op::CreateNetns(_)))
            .unwrap();
        assert!(last_netns < first_veth);

        // ordering: every link op (addr assignment) precedes the first daemon/run.
        let last_link_op = plan
            .ops
            .iter()
            .rposition(|o| matches!(o, Op::MoveIface { .. } | Op::AddAddr { .. }))
            .unwrap();
        let first_spawn = plan
            .ops
            .iter()
            .position(|o| matches!(o, Op::SpawnDaemon { .. } | Op::SpawnRun { .. }))
            .unwrap();
        assert!(last_link_op < first_spawn);
    }

    #[test]
    fn compiles_knot_daemon() {
        use std::collections::BTreeMap;
        let mut settings = BTreeMap::new();
        for (k, v) in [("zone", "lab.test"), ("tsig-name", "lab-key"), ("tsig-algo", "hmac-sha256"), ("tsig-secret", "aGVsbG8=")] {
            settings.insert(k.to_owned(), v.to_owned());
        }
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![Node {
                name: "ns".to_owned(),
                netns: None,
                loopback: None,
                daemons: vec![Daemon { kind: DaemonKind::Knot, settings }],
                runs: vec![],
            }],
            links: vec![],
        };
        let map = allocate(&topo).unwrap();
        let plan = compile(&topo, &map, "run000").unwrap();

        assert!(plan.ops.iter().any(|o| matches!(o, Op::WriteConfig { key, contents }
            if key == "knot-conf:ns" && contents.contains("listen: 0.0.0.0@53"))));
        assert!(plan.ops.iter().any(|o| matches!(o, Op::WriteConfig { key, contents }
            if key == "knot-zone:ns" && contents.contains("$ORIGIN lab.test."))));
        assert!(plan.ops.iter().any(|o| matches!(o, Op::SpawnDaemon { kind, config_key, node, .. }
            if *kind == DaemonKind::Knot && config_key == "knot-conf:ns" && node == "ns")));
    }

    #[test]
    fn rejects_unrealized_link_kind() {
        let mut topo = proof_topo();
        topo.links[0].kind = LinkKind::WireGuard;
        let map = allocate(&topo).unwrap();
        assert!(matches!(
            compile(&topo, &map, "abc123"),
            Err(LabError::Plan(_))
        ));
    }
}
