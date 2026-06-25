//! Errors produced by service discovery.

/// An error discovering services.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// A response or file could not be parsed.
    #[error("discovery parse error: {0}")]
    Parse(String),
    /// Underlying I/O failed.
    #[error("discovery i/o: {0}")]
    Io(#[from] std::io::Error),
}
