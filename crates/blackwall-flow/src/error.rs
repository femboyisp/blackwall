//! Errors from the flow-detection subsystem.

/// An error decoding a flow datagram.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The datagram was malformed or truncated.
    #[error("flow decode error: {0}")]
    Decode(String),
}
