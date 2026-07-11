//! Maps sFlow agent addresses to POP names + expected sampling rates, built
//! from the `pop` config directives.

use std::collections::HashMap;
use std::net::IpAddr;

/// What the collector knows about one POP agent.
#[derive(Debug, Clone)]
struct AgentInfo {
    name: String,
    expected_sampling: u32,
}

/// Registry of known POP agents. Absent agents are `"unknown"` with no expected
/// rate (trusted as-is, counted separately).
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    by_addr: HashMap<IpAddr, AgentInfo>,
}

impl AgentRegistry {
    /// Build from the policy's `pop` entries.
    pub fn from_entries(entries: &[blackwall_core::PopEntry]) -> Self {
        let mut by_addr = HashMap::new();
        for e in entries {
            by_addr.insert(
                e.agent,
                AgentInfo {
                    name: e.name.clone(),
                    expected_sampling: e.sampling,
                },
            );
        }
        Self { by_addr }
    }

    /// The POP name for an agent, or `"unknown"`.
    pub fn name(&self, agent: IpAddr) -> &str {
        self.by_addr
            .get(&agent)
            .map_or("unknown", |i| i.name.as_str())
    }

    /// The configured expected sampling rate for an agent, if known.
    pub fn expected_sampling(&self, agent: IpAddr) -> Option<u32> {
        self.by_addr.get(&agent).map(|i| i.expected_sampling)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn a(o: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, o))
    }

    #[test]
    fn names_known_and_unknown_agents() {
        let reg = AgentRegistry::from_entries(&[blackwall_core::PopEntry {
            name: "ord".into(),
            agent: a(8),
            sampling: 1000,
        }]);
        assert_eq!(reg.name(a(8)), "ord");
        assert_eq!(reg.expected_sampling(a(8)), Some(1000));
        assert_eq!(reg.name(a(9)), "unknown");
        assert_eq!(reg.expected_sampling(a(9)), None);
    }
}
