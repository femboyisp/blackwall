//! Errors from speedtest providers.

/// An error measuring with a speedtest provider.
#[derive(Debug, thiserror::Error)]
pub enum SpeedtestError {
    /// An HTTP/transport failure talking to the provider.
    #[error("speedtest http error: {0}")]
    Http(String),
    /// A provider response could not be parsed.
    #[error("speedtest parse error: {0}")]
    Parse(String),
    /// The provider did not respond within the configured timeout.
    #[error("speedtest timed out")]
    Timeout,
    /// No usable result was produced.
    #[error("speedtest produced no result")]
    NoResult,
}
