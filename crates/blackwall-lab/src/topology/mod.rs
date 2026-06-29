//! Topology model, manifest parsing, and validation.

pub mod model;

pub use model::{
    Daemon, DaemonKind, Endpoint, Link, LinkKind, Manifest, Matcher, Node, RunSpec, Scenario,
    Step, Topology,
};
