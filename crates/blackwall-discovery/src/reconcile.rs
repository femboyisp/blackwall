//! Merge discovered services into a base policy to produce the effective one.

use blackwall_core::{AllowRule, L4Proto, Policy, ServiceTarget, Tenant};
use std::net::IpAddr;

/// Which discovery source produced a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// A socket the host itself is listening on.
    Host,
    /// A port an Incus instance opted into.
    Incus,
}

/// A service found by discovery, to be merged into the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredService {
    /// Address the service is exposed on.
    pub addr: IpAddr,
    /// Transport protocol.
    pub proto: L4Proto,
    /// Port number.
    pub port: u16,
    /// Forwarding target for the opened service.
    pub target: ServiceTarget,
    /// Which source discovered it.
    pub source: DiscoverySource,
}

/// The synthetic tenant name used for discovered addresses no configured tenant owns.
const DISCOVERED_TENANT: &str = "discovered";

/// Produce the effective policy by merging `discovered` into `base`.
///
/// Each discovered service whose address falls inside a managed prefix is added
/// as an `AllowRule` to the tenant that owns the address, or to a synthetic
/// `"discovered"` tenant when no configured tenant owns it. Services outside all
/// managed prefixes, and duplicates already present, are skipped.
///
/// Because [`AllowRule`] is not address-scoped, a discovered service attached to
/// a tenant opens that port on **all** addresses that tenant owns — consistent
/// with config-file allow semantics. Operators reading the audit log should
/// therefore expect to see a port opened on an address that was not itself
/// observed listening, if another address in the same tenant triggered the rule.
pub fn reconcile(base: &Policy, discovered: &[DiscoveredService]) -> Policy {
    let mut effective = base.clone();

    for svc in discovered {
        if !effective.prefixes.iter().any(|p| p.contains(&svc.addr)) {
            continue; // outside managed space
        }
        if service_exists(&effective, svc.addr, svc.proto, svc.port) {
            continue; // already open
        }
        let rule = AllowRule {
            proto: svc.proto,
            port: svc.port,
            target: svc.target.clone(),
        };
        match owning_tenant_index(&effective, svc.addr) {
            Some(idx) => effective.tenants[idx].allows.push(rule),
            None => attach_to_synthetic(&mut effective, svc.addr, rule),
        }
    }
    effective
}

fn service_exists(policy: &Policy, addr: IpAddr, proto: L4Proto, port: u16) -> bool {
    policy.tenants.iter().any(|t| {
        t.owned.contains(&addr) && t.allows.iter().any(|a| a.proto == proto && a.port == port)
    })
}

fn owning_tenant_index(policy: &Policy, addr: IpAddr) -> Option<usize> {
    policy.tenants.iter().position(|t| t.owned.contains(&addr))
}

fn attach_to_synthetic(policy: &mut Policy, addr: IpAddr, rule: AllowRule) {
    if let Some(t) = policy
        .tenants
        .iter_mut()
        .find(|t| t.name == DISCOVERED_TENANT)
    {
        if !t.owned.contains(&addr) {
            t.owned.push(addr);
        }
        t.allows.push(rule);
    } else {
        policy.tenants.push(Tenant {
            name: DISCOVERED_TENANT.to_owned(),
            owned: vec![addr],
            allows: vec![rule],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_core::PortState;
    use ipnet::IpNet;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn base_policy(tenants: Vec<Tenant>) -> Policy {
        Policy {
            interface: "eth0".to_owned(),
            prefixes: vec!["203.0.113.0/24".parse::<IpNet>().expect("prefix")],
            default_state: PortState::Deception,
            tenants,
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
        }
    }

    fn svc(addr: &str, port: u16, target: ServiceTarget) -> DiscoveredService {
        DiscoveredService {
            addr: ip(addr),
            proto: L4Proto::Tcp,
            port,
            target,
            source: DiscoverySource::Incus,
        }
    }

    #[test]
    fn adds_to_owning_tenant() {
        let base = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("203.0.113.5")],
            allows: vec![],
        }]);
        let eff = reconcile(
            &base,
            &[svc(
                "203.0.113.5",
                443,
                ServiceTarget::Incus("web01".to_owned()),
            )],
        );
        let acme = eff.tenants.iter().find(|t| t.name == "acme").unwrap();
        assert_eq!(acme.allows.len(), 1);
        assert_eq!(acme.allows[0].port, 443);
        assert!(eff.resolve().is_ok());
    }

    #[test]
    fn synthetic_tenant_for_unowned_in_prefix() {
        let base = base_policy(vec![]);
        let eff = reconcile(&base, &[svc("203.0.113.9", 80, ServiceTarget::Host)]);
        let disc = eff.tenants.iter().find(|t| t.name == "discovered").unwrap();
        assert_eq!(disc.owned, vec![ip("203.0.113.9")]);
        assert_eq!(disc.allows[0].port, 80);
        assert!(eff.resolve().is_ok());
    }

    #[test]
    fn skips_outside_prefix() {
        let base = base_policy(vec![]);
        let eff = reconcile(&base, &[svc("198.51.100.1", 80, ServiceTarget::Host)]);
        assert!(eff.tenants.is_empty());
    }

    #[test]
    fn skips_duplicate_service() {
        let base = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("203.0.113.5")],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 443,
                target: ServiceTarget::Host,
            }],
        }]);
        let eff = reconcile(
            &base,
            &[svc(
                "203.0.113.5",
                443,
                ServiceTarget::Incus("web01".to_owned()),
            )],
        );
        let acme = eff.tenants.iter().find(|t| t.name == "acme").unwrap();
        assert_eq!(acme.allows.len(), 1); // unchanged
    }
}
