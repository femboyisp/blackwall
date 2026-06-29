//! Parse a KDL manifest into a [`Manifest`].

use crate::error::LabError;
use crate::topology::model::*;
use ipnet::{Ipv4Net, Ipv6Net};
use kdl::{KdlDocument, KdlNode, KdlValue};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

/// Parse a KDL manifest string into a [`Manifest`].
///
/// # Errors
/// Returns [`LabError::Manifest`] for malformed KDL or unknown keywords.
pub fn parse_manifest(input: &str) -> Result<Manifest, LabError> {
    let doc: KdlDocument = input
        .parse()
        .map_err(|e: kdl::KdlError| LabError::Manifest(e.to_string()))?;

    let mut topology: Option<Topology> = None;
    let mut scenarios = Vec::new();

    for node in doc.nodes() {
        match node.name().value() {
            "topology" => {
                if topology.is_some() {
                    return Err(LabError::Manifest("multiple `topology` blocks".to_owned()));
                }
                topology = Some(parse_topology(node)?);
            }
            "scenario" => scenarios.push(parse_scenario(node)?),
            other => {
                return Err(LabError::Manifest(format!("unexpected top-level node `{other}`")));
            }
        }
    }

    let topology = topology.ok_or_else(|| LabError::Manifest("no `topology` block".to_owned()))?;
    Ok(Manifest { topology, scenarios })
}

/// First positional argument as a string, or an error labelled `what`.
fn first_arg(node: &KdlNode, what: &str) -> Result<String, LabError> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| value_to_string(e.value()))
        .ok_or_else(|| LabError::Manifest(format!("`{}` missing {what}", node.name().value())))
}

/// All positional arguments as strings, in order.
fn args(node: &KdlNode) -> Vec<String> {
    node.entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| value_to_string(e.value()))
        .collect()
}

/// A named property value as a string, if present.
fn prop(node: &KdlNode, key: &str) -> Option<String> {
    node.entries()
        .iter()
        .find(|e| e.name().map(kdl::KdlIdentifier::value) == Some(key))
        .and_then(|e| value_to_string(e.value()))
}

/// Stringify a scalar KDL value (string/int/bool).
fn value_to_string(v: &KdlValue) -> Option<String> {
    if let Some(s) = v.as_string() {
        Some(s.to_owned())
    } else if let Some(i) = v.as_integer() {
        Some(i.to_string())
    } else {
        v.as_bool().map(|b| b.to_string())
    }
}

fn parse_topology(node: &KdlNode) -> Result<Topology, LabError> {
    let name = first_arg(node, "name")?;
    let mut nodes = Vec::new();
    let mut links = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "node" => nodes.push(parse_node(child)?),
                "link" => links.push(parse_link(child)?),
                other => {
                    return Err(LabError::Manifest(format!("unexpected topology child `{other}`")));
                }
            }
        }
    }
    Ok(Topology { name, nodes, links })
}

fn parse_node(node: &KdlNode) -> Result<Node, LabError> {
    let name = first_arg(node, "name")?;
    let netns = prop(node, "netns");
    let loopback = match prop(node, "loopback") {
        Some(s) => Some(
            s.parse::<IpAddr>()
                .map_err(|e| LabError::Manifest(format!("bad loopback: {e}")))?,
        ),
        None => None,
    };
    let mut daemons = Vec::new();
    let mut runs = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "daemon" => daemons.push(parse_daemon(child)?),
                "run" => runs.push(parse_run(child)?),
                other => {
                    return Err(LabError::Manifest(format!("unexpected node child `{other}`")));
                }
            }
        }
    }
    Ok(Node { name, netns, loopback, daemons, runs })
}

fn parse_daemon(node: &KdlNode) -> Result<Daemon, LabError> {
    let kind = match first_arg(node, "kind")?.as_str() {
        "bird" => DaemonKind::Bird,
        "knot" => DaemonKind::Knot,
        "wireguard" => DaemonKind::WireGuard,
        other => return Err(LabError::Manifest(format!("unknown daemon kind `{other}`"))),
    };
    let mut settings = BTreeMap::new();
    for entry in node.entries() {
        if let Some(key) = entry.name() {
            if let Some(val) = value_to_string(entry.value()) {
                settings.insert(key.value().to_owned(), val);
            }
        }
    }
    Ok(Daemon { kind, settings })
}

fn parse_run(node: &KdlNode) -> Result<RunSpec, LabError> {
    let name = first_arg(node, "name")?;
    let cmd =
        prop(node, "cmd").ok_or_else(|| LabError::Manifest("`run` missing cmd".to_owned()))?;
    let env = match prop(node, "env") {
        Some(s) => parse_env(&s),
        None => Vec::new(),
    };
    let readiness = prop(node, "readiness");
    Ok(RunSpec { name, cmd, env, readiness })
}

/// Split `K1=V1 K2=V2` into ordered pairs (split each on the first `=`).
fn parse_env(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|pair| pair.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect()
}

fn parse_link(node: &KdlNode) -> Result<Link, LabError> {
    let endpoints: Vec<Endpoint> = args(node)
        .into_iter()
        .map(|node_name| Endpoint { node: node_name, addr_override: None })
        .collect();
    let kind = match prop(node, "kind").as_deref() {
        None | Some("veth") => LinkKind::Veth,
        Some("bridge") => LinkKind::Bridge,
        Some("wireguard") => LinkKind::WireGuard,
        Some(other) => return Err(LabError::Manifest(format!("unknown link kind `{other}`"))),
    };
    let mut subnet_v4 = None;
    let mut subnet_v6 = None;
    if let Some(s) = prop(node, "subnet") {
        assign_subnet(&s, &mut subnet_v4, &mut subnet_v6)?;
    }
    if let Some(s) = prop(node, "subnet6") {
        assign_subnet(&s, &mut subnet_v4, &mut subnet_v6)?;
    }
    Ok(Link { kind, endpoints, subnet_v4, subnet_v6 })
}

fn assign_subnet(
    s: &str,
    v4: &mut Option<Ipv4Net>,
    v6: &mut Option<Ipv6Net>,
) -> Result<(), LabError> {
    if let Ok(net) = s.parse::<Ipv4Net>() {
        *v4 = Some(net);
        Ok(())
    } else if let Ok(net) = s.parse::<Ipv6Net>() {
        *v6 = Some(net);
        Ok(())
    } else {
        Err(LabError::Manifest(format!("bad subnet `{s}`")))
    }
}

fn parse_scenario(node: &KdlNode) -> Result<Scenario, LabError> {
    let name = first_arg(node, "name")?;
    let mut steps = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() != "step" {
                return Err(LabError::Manifest(format!(
                    "unexpected scenario child `{}`",
                    child.name().value()
                )));
            }
            steps.push(parse_step(child)?);
        }
    }
    Ok(Scenario { name, steps })
}

fn parse_step(node: &KdlNode) -> Result<Step, LabError> {
    let kind = first_arg(node, "kind")?;
    let node_name = prop(node, "node")
        .ok_or_else(|| LabError::Manifest(format!("step `{kind}` missing node")))?;
    match kind.as_str() {
        "wait" => {
            let until = prop(node, "until")
                .ok_or_else(|| LabError::Manifest("wait missing until".to_owned()))?;
            let timeout = parse_duration(
                &prop(node, "timeout")
                    .ok_or_else(|| LabError::Manifest("wait missing timeout".to_owned()))?,
            )?;
            Ok(Step::Wait { node: node_name, until, timeout })
        }
        "exec" => Ok(Step::Exec {
            node: node_name,
            action: prop(node, "action"),
            cmd: prop(node, "cmd"),
        }),
        "assert" => {
            let cmd = prop(node, "cmd")
                .ok_or_else(|| LabError::Manifest("assert missing cmd".to_owned()))?;
            let timeout = parse_duration(
                &prop(node, "timeout")
                    .ok_or_else(|| LabError::Manifest("assert missing timeout".to_owned()))?,
            )?;
            let matcher = if let Some(s) = prop(node, "contains") {
                Matcher::Contains(s)
            } else if let Some(s) = prop(node, "equals") {
                Matcher::Equals(s)
            } else if let Some(s) = prop(node, "exit") {
                Matcher::Exit(
                    s.parse::<i32>()
                        .map_err(|e| LabError::Manifest(format!("bad exit code: {e}")))?,
                )
            } else {
                return Err(LabError::Manifest(
                    "assert needs contains|equals|exit".to_owned(),
                ));
            };
            Ok(Step::Assert { node: node_name, cmd, matcher, timeout })
        }
        other => Err(LabError::Manifest(format!("unknown step kind `{other}`"))),
    }
}

/// Parse a duration written as `<n>s` or `<n>ms`.
fn parse_duration(s: &str) -> Result<Duration, LabError> {
    if let Some(ms) = s.strip_suffix("ms") {
        ms.parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| LabError::Manifest(format!("bad duration `{s}`: {e}")))
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| LabError::Manifest(format!("bad duration `{s}`: {e}")))
    } else {
        Err(LabError::Manifest(format!("duration `{s}` needs unit s or ms")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;

    const PROOF: &str = r#"
topology "bgp-bird" {
    node "peer" {
        daemon "bird" local-as="214806" neighbor-node="speaker" neighbor-as="214806" import="all" passive="yes"
    }
    node "speaker" {
        run "speaker" cmd="run-interop" env="BW_BGP_PEER={peer.addr}:179 BW_BGP_ASN=214806"
    }
    link "peer" "speaker" subnet="10.0.0.0/30"
}

scenario "announces-host-route" {
    step wait node="peer" until="bgp-established" timeout="20s"
    step assert node="peer" cmd="birdc show route 203.0.113.7/32" contains="203.0.113.7/32" timeout="15s"
}
"#;

    #[test]
    fn parses_the_proof_slice() {
        let m = parse_manifest(PROOF).expect("parse");
        assert_eq!(m.topology.name, "bgp-bird");
        assert_eq!(m.topology.nodes.len(), 2);

        let peer = &m.topology.nodes[0];
        assert_eq!(peer.name, "peer");
        assert_eq!(peer.daemons.len(), 1);
        assert_eq!(peer.daemons[0].kind, DaemonKind::Bird);
        assert_eq!(peer.daemons[0].settings.get("local-as").map(String::as_str), Some("214806"));
        assert_eq!(
            peer.daemons[0].settings.get("neighbor-node").map(String::as_str),
            Some("speaker")
        );

        let speaker = &m.topology.nodes[1];
        assert_eq!(speaker.runs.len(), 1);
        assert_eq!(speaker.runs[0].cmd, "run-interop");
        assert_eq!(
            speaker.runs[0].env,
            vec![
                ("BW_BGP_PEER".to_owned(), "{peer.addr}:179".to_owned()),
                ("BW_BGP_ASN".to_owned(), "214806".to_owned()),
            ]
        );

        assert_eq!(m.topology.links.len(), 1);
        let link = &m.topology.links[0];
        assert_eq!(link.kind, LinkKind::Veth);
        assert_eq!(
            link.endpoints.iter().map(|e| e.node.as_str()).collect::<Vec<_>>(),
            vec!["peer", "speaker"]
        );
        assert_eq!(link.subnet_v4, Some("10.0.0.0/30".parse::<Ipv4Net>().unwrap()));
        assert_eq!(link.subnet_v6, None);

        assert_eq!(m.scenarios.len(), 1);
        let sc = &m.scenarios[0];
        assert_eq!(sc.name, "announces-host-route");
        assert_eq!(sc.steps.len(), 2);
        assert_eq!(
            sc.steps[0],
            Step::Wait {
                node: "peer".to_owned(),
                until: "bgp-established".to_owned(),
                timeout: Duration::from_secs(20)
            }
        );
        assert_eq!(
            sc.steps[1],
            Step::Assert {
                node: "peer".to_owned(),
                cmd: "birdc show route 203.0.113.7/32".to_owned(),
                matcher: Matcher::Contains("203.0.113.7/32".to_owned()),
                timeout: Duration::from_secs(15),
            }
        );
    }

    #[test]
    fn rejects_unknown_daemon_kind() {
        let src = r#"topology "t" { node "a" { daemon "frr" } }"#;
        let err = parse_manifest(src).unwrap_err();
        assert!(matches!(err, LabError::Manifest(_)));
    }

    #[test]
    fn parses_durations_in_ms() {
        let src = "topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step wait node=\"a\" until=\"x\" timeout=\"500ms\"\n}\n";
        let m = parse_manifest(src).unwrap();
        assert_eq!(
            m.scenarios[0].steps[0],
            Step::Wait {
                node: "a".to_owned(),
                until: "x".to_owned(),
                timeout: Duration::from_millis(500)
            }
        );
    }

    /// Assert that `src` is rejected with a [`LabError::Manifest`].
    fn rejected(src: &str) {
        assert!(
            matches!(parse_manifest(src), Err(LabError::Manifest(_))),
            "expected Manifest error for: {src}"
        );
    }

    #[test]
    fn rejects_top_level_structure_errors() {
        // Two `topology` blocks.
        rejected("topology \"a\" {\n}\ntopology \"b\" {\n}\n");
        // No `topology` block at all.
        rejected("scenario \"s\" {\n}\n");
        // An unexpected top-level node.
        rejected("foo \"x\"\n");
    }

    #[test]
    fn rejects_topology_errors() {
        // Topology missing its name argument.
        rejected("topology {\n    node \"a\"\n}\n");
        // Unexpected child of `topology` (neither node nor link).
        rejected("topology \"t\" {\n    widget \"w\"\n}\n");
    }

    #[test]
    fn rejects_node_errors() {
        // `run` missing its `cmd`.
        rejected("topology \"t\" {\n    node \"a\" {\n        run \"r\"\n    }\n}\n");
        // Unexpected child of a `node` (neither daemon nor run).
        rejected("topology \"t\" {\n    node \"a\" {\n        widget \"w\"\n    }\n}\n");
        // Bad loopback address.
        rejected("topology \"t\" {\n    node \"a\" loopback=\"not-an-ip\"\n}\n");
    }

    #[test]
    fn rejects_link_errors() {
        // Unknown link kind.
        rejected("topology \"t\" {\n    node \"a\"\n    node \"b\"\n    link \"a\" \"b\" kind=\"frob\"\n}\n");
        // Bad subnet CIDR.
        rejected("topology \"t\" {\n    node \"a\"\n    node \"b\"\n    link \"a\" \"b\" subnet=\"not-a-cidr\"\n}\n");
    }

    #[test]
    fn rejects_scenario_structure_errors() {
        // Unexpected child of a scenario (not `step`).
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    widget \"w\"\n}\n");
        // A `step` missing its `node`.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step wait until=\"x\" timeout=\"5s\"\n}\n");
        // Unknown step kind.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step frob node=\"a\"\n}\n");
    }

    #[test]
    fn rejects_wait_step_errors() {
        // Wait missing `until`.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step wait node=\"a\" timeout=\"5s\"\n}\n");
        // Wait missing `timeout`.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step wait node=\"a\" until=\"x\"\n}\n");
        // Timeout with no unit.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step wait node=\"a\" until=\"x\" timeout=\"5\"\n}\n");
        // Timeout with a bad unit.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step wait node=\"a\" until=\"x\" timeout=\"5h\"\n}\n");
    }

    #[test]
    fn rejects_assert_step_errors() {
        // Assert missing `cmd`.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step assert node=\"a\" contains=\"x\" timeout=\"5s\"\n}\n");
        // Assert missing `timeout`.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step assert node=\"a\" cmd=\"c\" contains=\"x\"\n}\n");
        // Assert with no matcher (no contains/equals/exit).
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step assert node=\"a\" cmd=\"c\" timeout=\"5s\"\n}\n");
        // Assert with a bad exit code.
        rejected("topology \"t\" {\n    node \"a\"\n}\nscenario \"s\" {\n    step assert node=\"a\" cmd=\"c\" exit=\"notanumber\" timeout=\"5s\"\n}\n");
    }
}
