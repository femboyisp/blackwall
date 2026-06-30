//! Errors from the BGP speaker.

/// A BGP codec or session error.
#[derive(Debug, thiserror::Error)]
pub enum BgpError {
    /// A message could not be decoded (bad marker, truncation, bad length).
    #[error("bgp decode error: {0}")]
    Decode(String),
    /// A session-level failure (connect, handshake, socket).
    #[error("bgp session error: {0}")]
    Session(String),
}
