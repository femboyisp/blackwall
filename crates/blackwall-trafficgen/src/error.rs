//! Error type for the traffic generator.

use thiserror::Error;

/// Errors produced while building, sending, receiving, or reporting traffic.
#[derive(Debug, Error)]
pub enum TrafficGenError {
    /// A frame could not be built (e.g. `etherparse` serialization failed).
    #[error("frame build failed: {0}")]
    Build(String),
    /// A generation spec was invalid (bad rate, unknown pattern, …).
    #[error("invalid spec: {0}")]
    Spec(String),
    /// A socket or filesystem operation failed.
    #[error("io error: {0}")]
    Io(String),
    /// A report could not be read, parsed, or serialized.
    #[error("report error: {0}")]
    Report(String),
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, TrafficGenError>;
