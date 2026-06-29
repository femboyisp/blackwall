//! Deterministic address allocation and env-placeholder resolution.

use crate::error::LabError;
use crate::topology::model::Topology;
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Resolved addresses for a topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressMap {
    /// `(link index, node name)` -> `(address, prefix length)`.
    link: BTreeMap<(usize, String), (IpAddr, u8)>,
    /// `node name` -> loopback address.
    loopbacks: BTreeMap<String, IpAddr>,
}

impl AddressMap {
    /// Address + prefix length assigned to `node` on link `link_idx`.
    #[must_use]
    pub fn link_addr(&self, link_idx: usize, node: &str) -> Option<(IpAddr, u8)> {
        self.link.get(&(link_idx, node.to_owned())).copied()
    }

    /// The node's primary address: its loopback if set, else its address on
    /// the first link it participates in (by link index).
    #[must_use]
    pub fn node_primary(&self, node: &str) -> Option<IpAddr> {
        if let Some(lo) = self.loopbacks.get(node) {
            return Some(*lo);
        }
        self.link
            .iter()
            .filter(|((_, n), _)| n == node)
            .min_by_key(|((idx, _), _)| *idx)
            .map(|(_, (addr, _))| *addr)
    }
}

/// Allocate addresses for every link endpoint and loopback in `topo`.
///
/// For each link, endpoints are assigned the subnet's usable hosts in
/// declaration order (`/30` -> `.1`, `.2`); an endpoint's `addr_override`
/// takes precedence. IPv6 subnets allocate from their host iterator likewise.
///
/// # Errors
/// Returns [`LabError::Plan`] if a subnet has too few hosts for its endpoints,
/// or if a link has no subnet configured.
pub fn allocate(topo: &Topology) -> Result<AddressMap, LabError> {
    let mut link = BTreeMap::new();
    let mut loopbacks = BTreeMap::new();

    for node in &topo.nodes {
        if let Some(lo) = node.loopback {
            loopbacks.insert(node.name.clone(), lo);
        }
    }

    for (idx, l) in topo.links.iter().enumerate() {
        let (prefix, mut hosts): (u8, Box<dyn Iterator<Item = IpAddr>>) =
            if let Some(net) = l.subnet_v4 {
                (net.prefix_len(), Box::new(net.hosts().map(IpAddr::V4)))
            } else if let Some(net) = l.subnet_v6 {
                (net.prefix_len(), Box::new(net.hosts().map(IpAddr::V6)))
            } else {
                return Err(LabError::Plan(format!("link {idx} has no subnet")));
            };

        for ep in &l.endpoints {
            let addr = match ep.addr_override {
                Some(a) => a,
                None => hosts
                    .next()
                    .ok_or_else(|| LabError::Plan(format!("link {idx} subnet exhausted")))?,
            };
            link.insert((idx, ep.node.clone()), (addr, prefix));
        }
    }

    Ok(AddressMap { link, loopbacks })
}

/// Resolve `{node.addr}` / `{node.addr6}` placeholders in `template`.
///
/// `{x.addr}` expands to node `x`'s primary IPv4 address; `{x.addr6}` expands
/// to its primary IPv6 address.
///
/// # Errors
/// Returns [`LabError::Plan`] for an unterminated `{`, an unknown node, a
/// missing address family, or an unrecognised placeholder field.
pub fn resolve_env(template: &str, map: &AddressMap) -> Result<String, LabError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| LabError::Plan("unterminated `{` in env template".to_owned()))?;
        let token = &rest[open + 1..open + close];
        out.push_str(&resolve_token(token, map)?);
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve_token(token: &str, map: &AddressMap) -> Result<String, LabError> {
    let (node, field) = token
        .split_once('.')
        .ok_or_else(|| LabError::Plan(format!("bad placeholder `{token}`")))?;
    let want_v6 = field == "addr6";
    if field != "addr" && field != "addr6" {
        return Err(LabError::Plan(format!("unknown placeholder field `{field}`")));
    }
    let primary = map
        .node_primary(node)
        .ok_or_else(|| LabError::Plan(format!("unknown node `{node}` in placeholder")))?;
    match (primary, want_v6) {
        (IpAddr::V4(_), false) | (IpAddr::V6(_), true) => Ok(primary.to_string()),
        _ => Err(LabError::Plan(format!(
            "node `{node}` has no matching address family"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::model::*;
    use std::net::IpAddr;

    fn proof_topo() -> Topology {
        Topology {
            name: "t".to_owned(),
            nodes: vec![
                Node {
                    name: "peer".to_owned(),
                    netns: None,
                    loopback: None,
                    daemons: vec![],
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
    fn allocates_slash30_first_two_hosts() {
        let map = allocate(&proof_topo()).unwrap();
        assert_eq!(
            map.link_addr(0, "peer"),
            Some(("10.0.0.1".parse::<IpAddr>().unwrap(), 30))
        );
        assert_eq!(
            map.link_addr(0, "speaker"),
            Some(("10.0.0.2".parse::<IpAddr>().unwrap(), 30))
        );
    }

    #[test]
    fn node_primary_is_first_link_addr_without_loopback() {
        let map = allocate(&proof_topo()).unwrap();
        assert_eq!(
            map.node_primary("peer"),
            Some("10.0.0.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn node_primary_prefers_loopback() {
        let mut topo = proof_topo();
        topo.nodes[0].loopback = Some("10.255.0.1".parse().unwrap());
        let map = allocate(&topo).unwrap();
        assert_eq!(
            map.node_primary("peer"),
            Some("10.255.0.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn address_override_wins() {
        let mut topo = proof_topo();
        topo.links[0].endpoints[0].addr_override = Some("10.0.0.254".parse().unwrap());
        let map = allocate(&topo).unwrap();
        assert_eq!(
            map.link_addr(0, "peer"),
            Some(("10.0.0.254".parse::<IpAddr>().unwrap(), 30))
        );
    }

    #[test]
    fn resolves_env_placeholders() {
        let map = allocate(&proof_topo()).unwrap();
        assert_eq!(
            resolve_env("BW_BGP_PEER={peer.addr}:179", &map).unwrap(),
            "BW_BGP_PEER=10.0.0.1:179"
        );
    }

    #[test]
    fn resolve_env_errors_on_unknown_node() {
        let map = allocate(&proof_topo()).unwrap();
        assert!(matches!(
            resolve_env("{ghost.addr}", &map),
            Err(LabError::Plan(_))
        ));
    }

    #[test]
    fn allocates_errors_on_subnet_exhaustion() {
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![
                Node {
                    name: "a".to_owned(),
                    netns: None,
                    loopback: None,
                    daemons: vec![],
                    runs: vec![],
                },
                Node {
                    name: "b".to_owned(),
                    netns: None,
                    loopback: None,
                    daemons: vec![],
                    runs: vec![],
                },
                Node {
                    name: "c".to_owned(),
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
                        node: "a".to_owned(),
                        addr_override: None,
                    },
                    Endpoint {
                        node: "b".to_owned(),
                        addr_override: None,
                    },
                    Endpoint {
                        node: "c".to_owned(),
                        addr_override: None,
                    },
                ],
                subnet_v4: Some("10.0.0.0/30".parse().unwrap()),
                subnet_v6: None,
            }],
        };
        assert!(matches!(allocate(&topo), Err(LabError::Plan(_))));
    }

    #[test]
    fn resolve_env_errors_on_unterminated_brace() {
        let map = allocate(&proof_topo()).unwrap();
        assert!(matches!(
            resolve_env("BW_PEER={peer.addr", &map),
            Err(LabError::Plan(_))
        ));
    }

    #[test]
    fn resolves_addr6_and_errors_on_wrong_family() {
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![
                Node {
                    name: "peer".to_owned(),
                    netns: None,
                    loopback: None,
                    daemons: vec![],
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
                subnet_v4: None,
                subnet_v6: Some("fd00::/64".parse().unwrap()),
            }],
        };
        let map = allocate(&topo).unwrap();
        // `ipnet`'s host iterator for a /64 starts at the all-zeros host,
        // so the peer's first allocated v6 address is `fd00::`, not `fd00::1`.
        let peer_v6 = map.node_primary("peer").unwrap();
        assert_eq!(peer_v6, "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(resolve_env("{peer.addr6}", &map).unwrap(), peer_v6.to_string());
        assert!(matches!(
            resolve_env("{peer.addr}", &map),
            Err(LabError::Plan(_))
        ));
    }
}
