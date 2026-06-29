//! Semantic validation of a parsed [`Topology`].

use crate::error::LabError;
use crate::topology::model::{LinkKind, Topology};
use std::collections::BTreeSet;

/// Validate a topology's internal consistency.
///
/// # Errors
/// Returns [`LabError::Validation`] if the topology is empty, has duplicate
/// node names, references an unknown node in a link, has a `veth` link without
/// exactly two endpoints, or has a link with no subnet.
pub fn validate(topo: &Topology) -> Result<(), LabError> {
    if topo.nodes.is_empty() {
        return Err(LabError::Validation("topology has no nodes".to_owned()));
    }

    let mut seen = BTreeSet::new();
    for node in &topo.nodes {
        if !seen.insert(node.name.as_str()) {
            return Err(LabError::Validation(format!("duplicate node name `{}`", node.name)));
        }
    }

    for (idx, link) in topo.links.iter().enumerate() {
        if matches!(link.kind, LinkKind::Veth) && link.endpoints.len() != 2 {
            return Err(LabError::Validation(format!("veth link {idx} needs exactly 2 endpoints")));
        }
        if link.endpoints.len() < 2 {
            return Err(LabError::Validation(format!("link {idx} needs at least 2 endpoints")));
        }
        if link.subnet_v4.is_none() && link.subnet_v6.is_none() {
            return Err(LabError::Validation(format!("link {idx} has no subnet")));
        }
        for ep in &link.endpoints {
            if !seen.contains(ep.node.as_str()) {
                return Err(LabError::Validation(format!(
                    "link {idx} references unknown node `{}`",
                    ep.node
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::model::*;

    fn node(name: &str) -> Node {
        Node { name: name.to_owned(), netns: None, loopback: None, daemons: vec![], runs: vec![] }
    }
    fn veth(a: &str, b: &str, subnet: Option<&str>) -> Link {
        Link {
            kind: LinkKind::Veth,
            endpoints: vec![
                Endpoint { node: a.to_owned(), addr_override: None },
                Endpoint { node: b.to_owned(), addr_override: None },
            ],
            subnet_v4: subnet.map(|s| s.parse().unwrap()),
            subnet_v6: None,
        }
    }

    #[test]
    fn accepts_a_valid_topology() {
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![node("a"), node("b")],
            links: vec![veth("a", "b", Some("10.0.0.0/30"))],
        };
        assert!(validate(&topo).is_ok());
    }

    #[test]
    fn rejects_empty_topology() {
        let topo = Topology { name: "t".to_owned(), nodes: vec![], links: vec![] };
        assert!(matches!(validate(&topo), Err(LabError::Validation(_))));
    }

    #[test]
    fn rejects_duplicate_node_names() {
        let topo =
            Topology { name: "t".to_owned(), nodes: vec![node("a"), node("a")], links: vec![] };
        assert!(matches!(validate(&topo), Err(LabError::Validation(_))));
    }

    #[test]
    fn rejects_dangling_endpoint() {
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![node("a"), node("b")],
            links: vec![veth("a", "ghost", Some("10.0.0.0/30"))],
        };
        assert!(matches!(validate(&topo), Err(LabError::Validation(_))));
    }

    #[test]
    fn rejects_veth_without_two_endpoints() {
        let mut link = veth("a", "b", Some("10.0.0.0/30"));
        link.endpoints.pop();
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![node("a"), node("b")],
            links: vec![link],
        };
        assert!(matches!(validate(&topo), Err(LabError::Validation(_))));
    }

    #[test]
    fn rejects_link_without_subnet() {
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![node("a"), node("b")],
            links: vec![veth("a", "b", None)],
        };
        assert!(matches!(validate(&topo), Err(LabError::Validation(_))));
    }
}
