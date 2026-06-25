//! Errors from the traffic shaper.

/// An error resolving or applying a shaping plan.
#[derive(Debug, thiserror::Error)]
pub enum ShaperError {
    /// A bandwidth could not be resolved (e.g. `auto` with no measurement).
    #[error("cannot resolve shaping bandwidth: {0}")]
    Resolve(String),
    /// A `tc`/`ip` command failed.
    #[error("shaping command failed: {0}")]
    Command(String),
}
