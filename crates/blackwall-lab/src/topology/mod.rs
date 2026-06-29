//! Topology model, manifest parsing, and validation.

pub mod manifest;
pub mod model;
pub mod validate;

pub use manifest::parse_manifest;
pub use model::{
    Daemon, DaemonKind, Endpoint, Link, LinkKind, Manifest, Matcher, Node, RunSpec, Scenario, Step,
    Topology,
};
pub use validate::validate;
