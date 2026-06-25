//! Parse Incus instance JSON into discoverable services.

use crate::error::DiscoveryError;
use crate::reconcile::{DiscoveredService, DiscoverySource};
use blackwall_core::{L4Proto, ServiceTarget};
use std::net::IpAddr;

/// An Incus instance relevant to discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Instance name.
    pub name: String,
    /// Addresses assigned to the instance.
    pub addresses: Vec<IpAddr>,
    /// Ports the instance opts into via `user.blackwall.ports`.
    pub ports: Vec<(L4Proto, u16)>,
}

/// Parse a `user.blackwall.ports` value, e.g. `"443/tcp, 80/tcp, 53/udp"`.
/// Malformed entries are skipped.
pub fn parse_ports(value: &str) -> Vec<(L4Proto, u16)> {
    let mut out = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        let Some((port_str, proto_str)) = entry.split_once('/') else {
            continue;
        };
        let Ok(port) = port_str.trim().parse::<u16>() else {
            continue;
        };
        let proto = match proto_str.trim().to_ascii_lowercase().as_str() {
            "tcp" => L4Proto::Tcp,
            "udp" => L4Proto::Udp,
            _ => continue,
        };
        out.push((proto, port));
    }
    out
}

/// Parse one Incus instance object (recursion=2 shape).
pub fn parse_instance(json: &str) -> Result<Instance, DiscoveryError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| DiscoveryError::Parse(e.to_string()))?;
    let name = v["name"]
        .as_str()
        .ok_or_else(|| DiscoveryError::Parse("instance missing name".to_owned()))?
        .to_owned();

    let ports = v["config"]["user.blackwall.ports"]
        .as_str()
        .map(parse_ports)
        .unwrap_or_default();

    let mut addresses = Vec::new();
    if let Some(networks) = v["state"]["network"].as_object() {
        for (iface, net) in networks {
            if iface == "lo" {
                continue;
            }
            if let Some(addrs) = net["addresses"].as_array() {
                for a in addrs {
                    if let Some(addr_str) = a["address"].as_str() {
                        if let Ok(addr) = addr_str.parse::<IpAddr>() {
                            addresses.push(addr);
                        }
                    }
                }
            }
        }
    }

    Ok(Instance {
        name,
        addresses,
        ports,
    })
}

/// Expand an instance into discovered services (addresses × ports).
pub fn instance_services(inst: &Instance) -> Vec<DiscoveredService> {
    let mut out = Vec::new();
    for &addr in &inst.addresses {
        for &(proto, port) in &inst.ports {
            out.push(DiscoveredService {
                addr,
                proto,
                port,
                target: ServiceTarget::Incus(inst.name.clone()),
                source: DiscoverySource::Incus,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_skips_malformed() {
        let ports = parse_ports("443/tcp, 80/tcp, garbage, 53/udp, 99999/tcp, 22/sctp");
        assert_eq!(
            ports,
            vec![(L4Proto::Tcp, 443), (L4Proto::Tcp, 80), (L4Proto::Udp, 53)]
        );
    }

    const INSTANCE_JSON: &str = r#"{
        "name": "web01",
        "config": { "user.blackwall.ports": "443/tcp,80/tcp" },
        "state": { "network": {
            "lo": { "addresses": [{ "address": "127.0.0.1" }] },
            "eth0": { "addresses": [
                { "address": "203.0.113.5" },
                { "address": "2001:db8::5" }
            ] }
        } }
    }"#;

    #[test]
    fn parses_instance_addresses_and_ports() {
        let inst = parse_instance(INSTANCE_JSON).expect("parse");
        assert_eq!(inst.name, "web01");
        assert_eq!(
            inst.addresses,
            vec![
                "203.0.113.5".parse::<IpAddr>().unwrap(),
                "2001:db8::5".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(inst.ports, vec![(L4Proto::Tcp, 443), (L4Proto::Tcp, 80)]);
    }

    #[test]
    fn instance_services_is_cartesian() {
        let inst = parse_instance(INSTANCE_JSON).expect("parse");
        let svcs = instance_services(&inst);
        assert_eq!(svcs.len(), 4); // 2 addrs × 2 ports
        assert!(svcs
            .iter()
            .all(|s| matches!(&s.target, ServiceTarget::Incus(n) if n == "web01")));
    }

    #[test]
    fn missing_name_errors() {
        assert!(parse_instance(r#"{"config":{}}"#).is_err());
    }
}
