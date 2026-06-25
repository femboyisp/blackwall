//! Errors produced by the deception engine.

/// An error answering deception traffic.
#[derive(Debug, thiserror::Error)]
pub enum DeceptionError {
    /// Underlying socket I/O failed.
    #[error("deception i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The client spoke something the emulator could not handle.
    #[error("protocol error: {0}")]
    Protocol(String),
}
