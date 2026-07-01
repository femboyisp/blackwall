//! Pure data model for lab topologies and scenarios.

use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

/// A parsed manifest: one topology plus zero or more scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The network topology to realize.
    pub topology: Topology,
    /// Scenarios (assertion sequences) to run against it.
    pub scenarios: Vec<Scenario>,
}

/// A network topology: a set of nodes joined by links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    /// Topology name (used in run/report labels).
    pub name: String,
    /// Nodes, in declaration order.
    pub nodes: Vec<Node>,
    /// Links, in declaration order (the index is the link id).
    pub links: Vec<Link>,
}

/// A single node — realized as a network namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Unique node name.
    pub name: String,
    /// Explicit namespace name; `None` means a per-run dedicated namespace.
    pub netns: Option<String>,
    /// Optional loopback address assigned inside the namespace.
    pub loopback: Option<IpAddr>,
    /// Daemons to launch on this node.
    pub daemons: Vec<Daemon>,
    /// Processes to launch on this node.
    pub runs: Vec<RunSpec>,
}

/// A routing/service daemon to run on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Daemon {
    /// Which daemon.
    pub kind: DaemonKind,
    /// Daemon parameters (KDL properties), e.g. `local-as` -> `214806`.
    pub settings: BTreeMap<String, String>,
}

/// Supported daemon kinds. L1 realizes only [`DaemonKind::Bird`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonKind {
    /// BIRD2 BGP/OSPF daemon.
    Bird,
    /// Knot authoritative DNS (modelled; realized in L2).
    Knot,
    /// hsflowd mod_pcap sFlow agent (realized in the flow-live increment).
    Hsflowd,
    /// WireGuard (modelled; realized in L3).
    WireGuard,
}

/// An arbitrary process to launch on a node (e.g. the binary under test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    /// Label for the process.
    pub name: String,
    /// Command line, run via `sh -c` inside the node namespace.
    pub cmd: String,
    /// Environment KEY/VALUE pairs; values may contain `{node.addr}` /
    /// `{node.addr6}` placeholders resolved at launch.
    pub env: Vec<(String, String)>,
    /// Optional readiness probe name.
    pub readiness: Option<String>,
}

/// A link between nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Link realization kind. L1 realizes only [`LinkKind::Veth`].
    pub kind: LinkKind,
    /// Endpoints; exactly two for a `veth` point-to-point link.
    pub endpoints: Vec<Endpoint>,
    /// IPv4 subnet for address allocation, if any.
    pub subnet_v4: Option<Ipv4Net>,
    /// IPv6 subnet for address allocation, if any.
    pub subnet_v6: Option<Ipv6Net>,
}

/// One end of a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Name of the node this endpoint attaches to.
    pub node: String,
    /// Explicit address override; `None` means allocate from the subnet.
    pub addr_override: Option<IpAddr>,
}

/// Link realization kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// veth pair (point-to-point).
    Veth,
    /// Linux bridge segment (modelled; realized in L3).
    Bridge,
    /// WireGuard tunnel (modelled; realized in L3).
    WireGuard,
}

/// A scenario: an ordered list of assertion/driver steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// Scenario name (becomes a JUnit testsuite name).
    pub name: String,
    /// Steps, in order.
    pub steps: Vec<Step>,
}

/// A single scenario step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Block until a named readiness probe passes, or `timeout` elapses.
    Wait {
        /// Node to probe.
        node: String,
        /// Probe name (e.g. `bgp-established`, `port-open:53`).
        until: String,
        /// Maximum time to wait.
        timeout: Duration,
    },
    /// Run a command/action on a node without asserting on its output.
    Exec {
        /// Node to run on.
        node: String,
        /// High-level action keyword, if any.
        action: Option<String>,
        /// Raw command, if any.
        cmd: Option<String>,
    },
    /// Run a command on a node and assert on its captured output/exit.
    Assert {
        /// Node to run on.
        node: String,
        /// Command to run.
        cmd: String,
        /// What to assert.
        matcher: Matcher,
        /// Poll until the matcher passes or `timeout` elapses.
        timeout: Duration,
    },
}

/// How an [`Step::Assert`] decides pass/fail from captured output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// stdout contains this substring.
    Contains(String),
    /// trimmed stdout equals this string.
    Equals(String),
    /// process exit code equals this value.
    Exit(i32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_a_minimal_topology() {
        let topo = Topology {
            name: "t".to_owned(),
            nodes: vec![Node {
                name: "a".to_owned(),
                netns: None,
                loopback: None,
                daemons: vec![],
                runs: vec![],
            }],
            links: vec![],
        };
        assert_eq!(topo.nodes.len(), 1);
        assert_eq!(topo.nodes[0].name, "a");
    }

    #[test]
    fn matcher_equality() {
        assert_eq!(Matcher::Exit(0), Matcher::Exit(0));
        assert_ne!(Matcher::Exit(0), Matcher::Exit(1));
    }
}
