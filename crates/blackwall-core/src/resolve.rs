//! Expansion of a [`Policy`] into a flat list of real services, with the
//! validation that catches policies the firewall could not safely apply.

use crate::{L4Proto, Policy, ServiceTarget};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A single concrete real-service mapping: one address, one proto, one port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedService {
    /// The address the service is exposed on.
    pub addr: IpAddr,
    /// Transport protocol.
    pub proto: L4Proto,
    /// Port number.
    pub port: u16,
    /// Forwarding target.
    pub target: ServiceTarget,
    /// Owning tenant name (for authz + audit).
    pub tenant: String,
}

/// Why a policy cannot be resolved/applied.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// A tenant owns an address that is not inside any managed prefix.
    #[error("address {0} is not within any managed prefix")]
    AddressOutsidePrefixes(IpAddr),
    /// Two tenants claim the same address.
    #[error("address {addr} is owned by both {} and {}", tenants.0, tenants.1)]
    DuplicateOwnership {
        /// The conflicting address.
        addr: IpAddr,
        /// The two tenants that both claim it.
        tenants: (String, String),
    },
    /// The same (addr, proto, port) is exposed more than once.
    #[error("service {addr} {proto}/{port} is defined more than once")]
    DuplicateService {
        /// Address.
        addr: IpAddr,
        /// Protocol.
        proto: L4Proto,
        /// Port.
        port: u16,
    },
}

impl Policy {
    /// Return the tenant that owns `addr`, if any.
    pub fn owner_of(&self, addr: IpAddr) -> Option<&str> {
        self.tenants
            .iter()
            .find(|t| t.owned.contains(&addr))
            .map(|t| t.name.as_str())
    }

    /// Expand tenants × owned addresses × allow rules into concrete services,
    /// validating ownership, prefix containment, and uniqueness.
    pub fn resolve(&self) -> Result<Vec<ResolvedService>, PolicyError> {
        // Detect duplicate ownership and prefix violations first.
        let mut seen_owner: Vec<(IpAddr, &str)> = Vec::new();
        for tenant in &self.tenants {
            for &addr in &tenant.owned {
                if !self.prefixes.iter().any(|p| p.contains(&addr)) {
                    return Err(PolicyError::AddressOutsidePrefixes(addr));
                }
                if let Some((_, other)) = seen_owner.iter().find(|(a, _)| *a == addr) {
                    return Err(PolicyError::DuplicateOwnership {
                        addr,
                        tenants: ((*other).to_owned(), tenant.name.clone()),
                    });
                }
                seen_owner.push((addr, &tenant.name));
            }
        }

        let mut out: Vec<ResolvedService> = Vec::new();
        for tenant in &self.tenants {
            for &addr in &tenant.owned {
                for allow in &tenant.allows {
                    // An address-scoped allow only applies to its own address.
                    if allow.scope.is_some_and(|scoped| scoped != addr) {
                        continue;
                    }
                    let dup = out
                        .iter()
                        .any(|s| s.addr == addr && s.proto == allow.proto && s.port == allow.port);
                    if dup {
                        return Err(PolicyError::DuplicateService {
                            addr,
                            proto: allow.proto,
                            port: allow.port,
                        });
                    }
                    out.push(ResolvedService {
                        addr,
                        proto: allow.proto,
                        port: allow.port,
                        target: allow.target.clone(),
                        tenant: tenant.name.clone(),
                    });
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowRule, PortState, Tenant};
    use ipnet::IpNet;

    fn prefix(s: &str) -> IpNet {
        s.parse().expect("valid prefix")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid ip")
    }

    fn base_policy(tenants: Vec<Tenant>) -> Policy {
        Policy {
            interface: "eth0".to_owned(),
            prefixes: vec![prefix("203.0.113.0/24")],
            default_state: PortState::Deception,
            tenants,
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
            rtbh: None,
            flowspec: None,
            metrics_listen: None,
            engine: crate::EngineConfig::default(),
            flowtable: None,
            xdp: None,
        }
    }

    #[test]
    fn resolves_tenant_allows_across_owned_addresses() {
        let policy = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("203.0.113.5"), ip("203.0.113.6")],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 443,
                target: ServiceTarget::Incus("web01".to_owned()),
                scope: None,
            }],
        }]);

        let resolved = policy.resolve().expect("valid policy");

        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|s| s.port == 443 && s.tenant == "acme"));
    }

    #[test]
    fn address_scoped_allow_resolves_only_for_its_address() {
        let policy = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("203.0.113.5"), ip("203.0.113.6")],
            allows: vec![AllowRule {
                proto: L4Proto::Tcp,
                port: 443,
                target: ServiceTarget::Host,
                scope: Some(ip("203.0.113.5")),
            }],
        }]);

        let resolved = policy.resolve().expect("valid policy");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].addr, ip("203.0.113.5"));
    }

    #[test]
    fn rejects_address_outside_prefixes() {
        let policy = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("198.51.100.1")],
            allows: vec![],
        }]);

        assert_eq!(
            policy.resolve(),
            Err(PolicyError::AddressOutsidePrefixes(ip("198.51.100.1")))
        );
    }

    #[test]
    fn rejects_duplicate_ownership() {
        let policy = base_policy(vec![
            Tenant {
                name: "acme".to_owned(),
                owned: vec![ip("203.0.113.5")],
                allows: vec![],
            },
            Tenant {
                name: "globex".to_owned(),
                owned: vec![ip("203.0.113.5")],
                allows: vec![],
            },
        ]);

        assert!(matches!(
            policy.resolve(),
            Err(PolicyError::DuplicateOwnership { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_service() {
        let policy = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("203.0.113.5")],
            allows: vec![
                AllowRule {
                    proto: L4Proto::Tcp,
                    port: 443,
                    target: ServiceTarget::Incus("a".to_owned()),
                    scope: None,
                },
                AllowRule {
                    proto: L4Proto::Tcp,
                    port: 443,
                    target: ServiceTarget::Incus("b".to_owned()),
                    scope: None,
                },
            ],
        }]);
        assert!(matches!(
            policy.resolve(),
            Err(PolicyError::DuplicateService { .. })
        ));
    }

    #[test]
    fn owner_of_finds_tenant() {
        let policy = base_policy(vec![Tenant {
            name: "acme".to_owned(),
            owned: vec![ip("203.0.113.5")],
            allows: vec![],
        }]);

        assert_eq!(policy.owner_of(ip("203.0.113.5")), Some("acme"));
        assert_eq!(policy.owner_of(ip("203.0.113.9")), None);
    }

    #[test]
    fn policy_error_display_address_outside_prefixes() {
        let addr = ip("10.0.0.1");
        let e = PolicyError::AddressOutsidePrefixes(addr);
        assert!(e.to_string().contains("10.0.0.1"));
        assert!(e.to_string().contains("managed prefix"));
    }

    #[test]
    fn policy_error_display_duplicate_ownership() {
        let e = PolicyError::DuplicateOwnership {
            addr: ip("203.0.113.5"),
            tenants: ("acme".to_owned(), "globex".to_owned()),
        };
        let s = e.to_string();
        assert!(s.contains("203.0.113.5"));
        assert!(s.contains("acme"));
        assert!(s.contains("globex"));
    }

    #[test]
    fn policy_error_display_duplicate_service() {
        let e = PolicyError::DuplicateService {
            addr: ip("203.0.113.5"),
            proto: L4Proto::Tcp,
            port: 443,
        };
        let s = e.to_string();
        assert!(s.contains("203.0.113.5"));
        assert!(s.contains("443"));
    }

    #[test]
    fn resolve_empty_policy_succeeds() {
        let policy = Policy {
            interface: "eth0".to_owned(),
            prefixes: vec![],
            default_state: PortState::Deception,
            tenants: vec![],
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
            rtbh: None,
            flowspec: None,
            metrics_listen: None,
            engine: crate::EngineConfig::default(),
            flowtable: None,
            xdp: None,
        };
        let resolved = policy.resolve().expect("empty policy resolves");
        assert!(resolved.is_empty());
    }
}
