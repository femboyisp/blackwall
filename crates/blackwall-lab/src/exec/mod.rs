//! Thin I/O layer: realize plans in network namespaces. Coverage-excluded.

pub(crate) mod netns;
pub(crate) mod proc;
pub mod runner;
