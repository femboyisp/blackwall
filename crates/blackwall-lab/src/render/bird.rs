//! Render a BIRD2 configuration for a node from its daemon settings.

use crate::addr::AddressMap;
use crate::error::LabError;
use crate::topology::model::{DaemonKind, Node, Topology};
use std::net::IpAddr;

/// Render the BIRD config for `node`'s `bird` daemon.
///
/// Reads the daemon's `local-as`, `neighbor-node`, `neighbor-as`, `import`,
/// `passive`, and `flowspec` settings; the router id is the node's primary
/// address and the neighbor address is the neighbor node's primary address.
/// When `flowspec="yes"`, the `protocol bgp` block also gets `flow4`/`flow6`
/// channels (RFC 8955/8956) so the peer negotiates FlowSpec SAFI 133.
///
/// When the daemon has an `include-file` setting instead, the `protocol bgp`
/// block is *not* derived from `local-as`/`neighbor-node`/etc. at all: the
/// file's contents (blackwall's own generated `protocol bgp blackwall { ... }`
/// include — see `blackwalld bird-config` / `blackwall_bgp::render_bird_ibgp`)
/// are spliced in verbatim after the same router id / table / base-protocol
/// preamble. This is how the `bird-gen` lab scenario proves the *actual*
/// generated include establishes a real BIRD2 session, rather than the
/// lab's own hand-rolled approximation of one.
///
/// # Errors
/// Returns [`LabError::Plan`] if the node has no `bird` daemon, a required
/// setting is missing, an address cannot be resolved, or (`include-file`
/// mode) the file cannot be read.
pub fn render_bird(node: &Node, _topo: &Topology, map: &AddressMap) -> Result<String, LabError> {
    let daemon = node
        .daemons
        .iter()
        .find(|d| d.kind == DaemonKind::Bird)
        .ok_or_else(|| LabError::Plan(format!("node `{}` has no bird daemon", node.name)))?;

    let router_id = map
        .node_primary(&node.name)
        .ok_or_else(|| LabError::Plan(format!("no router id for `{}`", node.name)))?;
    let flowspec = daemon.settings.get("flowspec").is_some_and(|v| v == "yes");

    if let Some(path) = daemon.settings.get("include-file") {
        return render_bird_with_include(node, router_id, path, flowspec);
    }

    let get = |key: &str| {
        daemon
            .settings
            .get(key)
            .cloned()
            .ok_or_else(|| LabError::Plan(format!("bird on `{}` missing `{key}`", node.name)))
    };

    let local_as = get("local-as")?;
    let neighbor_node = get("neighbor-node")?;
    let neighbor_as = get("neighbor-as")?;
    let import = get("import")?;
    let passive = daemon.settings.get("passive").map_or("no", String::as_str);
    // Optional TCP-MD5 (RFC 2385): a `password="…"` setting emits BIRD's
    // `password` clause so the neighbor requires an authenticated session.
    let password = daemon
        .settings
        .get("password")
        .map(|p| format!("    password \"{p}\";\n"))
        .unwrap_or_default();
    let neighbor_addr = map
        .node_primary(&neighbor_node)
        .ok_or_else(|| LabError::Plan(format!("no address for neighbor `{neighbor_node}`")))?;
    let flow_tables = if flowspec {
        "flow4 table flow4tab;\nflow6 table flow6tab;\n\n"
    } else {
        ""
    };
    let flow_channels = if flowspec {
        "    flow4 { table flow4tab; import all; };\n    flow6 { table flow6tab; import all; };\n"
    } else {
        ""
    };
    // RFC 8955 §6 "safe update" validation requires the covering unicast
    // route's next hop to actually resolve; without a direct-route source,
    // BIRD treats it as unreachable and drops it at import (confirmed live
    // against BIRD 2.17.1). `protocol direct` imports the connected /30 so
    // next-hop resolution succeeds.
    let direct_proto = if flowspec {
        "protocol direct {\n    ipv4;\n    ipv6;\n    interface \"*\";\n}\n\n"
    } else {
        ""
    };

    Ok(format!(
        "log stderr all;\n\
router id {router_id};\n\
\n\
{flow_tables}\
protocol device {{\n\
    scan time 5;\n\
}}\n\
\n\
protocol kernel {{\n\
    ipv4 {{ import none; export none; }};\n\
}}\n\
\n\
{direct_proto}\
protocol bgp peer_{neighbor_node} {{\n\
    local as {local_as};\n\
    neighbor {neighbor_addr} as {neighbor_as};\n\
{password}\
    passive {passive};\n\
    hold time 90;\n\
    keepalive time 30;\n\
    ipv4 {{\n\
        import {import};\n\
        export none;\n\
    }};\n\
{flow_channels}\
}}\n"
    ))
}

/// Build the same router id / table / base-protocol preamble as
/// [`render_bird`]'s derived path, then splice in `include_path`'s raw
/// contents verbatim as the `protocol bgp` block — used by the `bird-gen`
/// scenario to peer real BIRD2 against blackwall's *actual* generated
/// include rather than a lab-approximated one.
fn render_bird_with_include(
    node: &Node,
    router_id: IpAddr,
    include_path: &str,
    flowspec: bool,
) -> Result<String, LabError> {
    let included = std::fs::read_to_string(include_path).map_err(|e| {
        LabError::Plan(format!(
            "bird on `{}`: reading include-file `{include_path}`: {e}",
            node.name
        ))
    })?;
    let flow_tables = if flowspec {
        "flow4 table flow4tab;\nflow6 table flow6tab;\n\n"
    } else {
        ""
    };
    Ok(format!(
        "log stderr all;\n\
router id {router_id};\n\
\n\
{flow_tables}\
protocol device {{\n\
    scan time 5;\n\
}}\n\
\n\
protocol kernel {{\n\
    ipv4 {{ import none; export none; }};\n\
}}\n\
\n\
{included}"
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
    fn renders_password_when_set() {
        let mut topo = proof_topo();
        topo.nodes[0].daemons[0]
            .settings
            .insert("password".to_owned(), "s3cr3t".to_owned());
        let map = allocate(&topo).unwrap();
        let out = render_bird(&topo.nodes[0], &topo, &map).unwrap();
        assert!(out.contains("    password \"s3cr3t\";\n"));
    }

    #[test]
    fn omits_password_when_unset() {
        let topo = proof_topo();
        let map = allocate(&topo).unwrap();
        let out = render_bird(&topo.nodes[0], &topo, &map).unwrap();
        assert!(!out.contains("password"));
    }

    #[test]
    fn renders_flow_channels_when_flowspec_enabled() {
        let mut topo = proof_topo();
        topo.nodes[0].daemons[0]
            .settings
            .insert("flowspec".to_owned(), "yes".to_owned());
        let map = allocate(&topo).unwrap();
        let out = render_bird(&topo.nodes[0], &topo, &map).unwrap();
        assert!(out.contains("flow4 table flow4tab;"));
        assert!(out.contains("flow6 table flow6tab;"));
        assert!(out.contains("flow4 { table flow4tab; import all; };"));
        assert!(out.contains("flow6 { table flow6tab; import all; };"));
        assert!(out.contains("protocol direct {"));
    }

    #[test]
    fn omits_flow_channels_when_flowspec_not_set() {
        let topo = proof_topo();
        let map = allocate(&topo).unwrap();
        let out = render_bird(&topo.nodes[0], &topo, &map).unwrap();
        assert!(!out.contains("flow4"));
        assert!(!out.contains("flow6"));
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

    #[test]
    fn include_file_splices_in_verbatim_and_skips_derived_settings() {
        // `include-file` mode ignores local-as/neighbor-node/etc entirely —
        // only `router_id`/`flowspec` (for the table preamble) still apply.
        let mut topo = proof_topo();
        let dir = std::env::temp_dir().join(format!(
            "blackwall-lab-render-bird-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blackwall-gen.conf");
        std::fs::write(
            &path,
            "protocol bgp blackwall {\n    local 10.0.0.1 as 65000;\n}\n",
        )
        .unwrap();

        topo.nodes[0].daemons[0].settings.clear();
        topo.nodes[0].daemons[0].settings.insert(
            "include-file".to_owned(),
            path.to_string_lossy().into_owned(),
        );
        topo.nodes[0].daemons[0]
            .settings
            .insert("flowspec".to_owned(), "yes".to_owned());

        let map = allocate(&topo).unwrap();
        let out = render_bird(&topo.nodes[0], &topo, &map).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(out.contains("router id 10.0.0.1;"));
        assert!(out.contains("flow4 table flow4tab;"));
        assert!(out.contains("protocol bgp blackwall {\n    local 10.0.0.1 as 65000;\n}\n"));
        assert!(!out.contains("protocol bgp peer_"));
    }

    #[test]
    fn include_file_missing_errors() {
        let mut topo = proof_topo();
        topo.nodes[0].daemons[0].settings.clear();
        topo.nodes[0].daemons[0].settings.insert(
            "include-file".to_owned(),
            "/nonexistent/blackwall-gen.conf".to_owned(),
        );
        let map = allocate(&topo).unwrap();
        assert!(matches!(
            render_bird(&topo.nodes[0], &topo, &map),
            Err(LabError::Plan(_))
        ));
    }
}
