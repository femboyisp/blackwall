//! Errors from the flow-detection subsystem.

/// An error from the flow-detection subsystem.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The datagram was malformed or truncated.
    #[error("flow decode error: {0}")]
    Decode(String),
    /// An I/O failure setting up or running the collector, such as binding the
    /// sFlow listen socket. Distinct from [`FlowError::Decode`] so a failed bind
    /// (a fatal startup fault) is not conflated with a malformed datagram (a
    /// per-packet, non-fatal condition).
    #[error("flow I/O error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::FlowError;

    #[test]
    fn variants_render_distinct_prefixes() {
        assert_eq!(
            FlowError::Decode("truncated".into()).to_string(),
            "flow decode error: truncated"
        );
        assert_eq!(
            FlowError::Io("bind 0.0.0.0:6343: address in use".into()).to_string(),
            "flow I/O error: bind 0.0.0.0:6343: address in use"
        );
    }
}
