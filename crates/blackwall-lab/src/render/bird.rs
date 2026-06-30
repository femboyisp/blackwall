//! Render a BIRD2 configuration for a node from its daemon settings.

use crate::addr::AddressMap;
use crate::error::LabError;
use crate::topology::model::{DaemonKind, Node, Topology};

/// Render the BIRD config for `node`'s `bird` daemon.
///
/// Reads the daemon's `local-as`, `neighbor-node`, `neighbor-as`, `import`,
/// and `passive` settings; the router id is the node's primary address and the
/// neighbor address is the neighbor node's primary address.
///
/// # Errors
/// Returns [`LabError::Plan`] if the node has no `bird` daemon, a required
/// setting is missing, or an address cannot be resolved.
pub fn render_bird(node: &Node, _topo: &Topology, map: &AddressMap) -> Result<String, LabError> {
    let daemon = node
        .daemons
        .iter()
        .find(|d| d.kind == DaemonKind::Bird)
        .ok_or_else(|| LabError::Plan(format!("node `{}` has no bird daemon", node.name)))?;

    let get = |key: &str| {
        daemon
            .settings
            .get(key)
            .cloned()
            .ok_or_else(|| LabError::Plan(format!("bird on `{}` missing `{key}`", node.name)))
    };

    let router_id = map
        .node_primary(&node.name)
        .ok_or_else(|| LabError::Plan(format!("no router id for `{}`", node.name)))?;
    let local_as = get("local-as")?;
    let neighbor_node = get("neighbor-node")?;
    let neighbor_as = get("neighbor-as")?;
    let import = get("import")?;
    let passive = daemon.settings.get("passive").map_or("no", String::as_str);
    let neighbor_addr = map
        .node_primary(&neighbor_node)
        .ok_or_else(|| LabError::Plan(format!("no address for neighbor `{neighbor_node}`")))?;

    Ok(format!(
        "log stderr all;\n\
router id {router_id};\n\
\n\
protocol device {{\n\
    scan time 5;\n\
}}\n\
\n\
protocol kernel {{\n\
    ipv4 {{ import none; export none; }};\n\
}}\n\
\n\
protocol bgp peer_{neighbor_node} {{\n\
    local as {local_as};\n\
    neighbor {neighbor_addr} as {neighbor_as};\n\
    passive {passive};\n\
    hold time 90;\n\
    keepalive time 30;\n\
    ipv4 {{\n\
        import {import};\n\
        export none;\n\
    }};\n\
}}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::allocate;
    use crate::topology::model::*;
    use std::collections::BTreeMap;

    fn proof_topo() -> Topology {
        let mut settings = BTreeMap::new();
        settings.insert("local-as".to_owned(), "214806".to_owned());
        settings.insert("neighbor-node".to_owned(), "speaker".to_owned());
        settings.insert("neighbor-as".to_owned(), "214806".to_owned());
        settings.insert("import".to_owned(), "all".to_owned());
        settings.insert("passive".to_owned(), "yes".to_owned());
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
                    runs: vec![],
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
    fn renders_passive_ibgp_peer() {
        let topo = proof_topo();
        let map = allocate(&topo).unwrap();
        let out = render_bird(&topo.nodes[0], &topo, &map).unwrap();
        let expected = "log stderr all;\n\
router id 10.0.0.1;\n\
\n\
protocol device {\n\
    scan time 5;\n\
}\n\
\n\
protocol kernel {\n\
    ipv4 { import none; export none; };\n\
}\n\
\n\
protocol bgp peer_speaker {\n\
    local as 214806;\n\
    neighbor 10.0.0.2 as 214806;\n\
    passive yes;\n\
    hold time 90;\n\
    keepalive time 30;\n\
    ipv4 {\n\
        import all;\n\
        export none;\n\
    };\n\
}\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn errors_when_node_has_no_bird_daemon() {
        let topo = proof_topo();
        let map = allocate(&topo).unwrap();
        assert!(matches!(
            render_bird(&topo.nodes[1], &topo, &map),
            Err(LabError::Plan(_))
        ));
    }
}
