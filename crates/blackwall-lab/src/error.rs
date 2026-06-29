//! Error type for the lab harness.

use thiserror::Error;

/// Errors raised while parsing, validating, planning, or executing a lab.
///
/// Assertion *failures* are not errors — they are reported outcomes
/// (see [`crate::assert`]); these variants are for malformed input or
/// I/O that could not be carried out at all.
#[derive(Debug, Error)]
pub enum LabError {
    /// The KDL manifest was syntactically or structurally invalid.
    #[error("manifest: {0}")]
    Manifest(String),
    /// The topology was well-formed KDL but semantically invalid.
    #[error("validation: {0}")]
    Validation(String),
    /// The topology could not be compiled into an execution plan.
    #[error("plan: {0}")]
    Plan(String),
    /// A thin-IO step (namespace/process operation) failed.
    #[error("exec: {0}")]
    Exec(String),
}
