//! Errors from the DNS fast-flux subsystem.

/// An error building or sending a fast-flux update.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// A configuration/selection problem (bad pool, key parse, etc.).
    #[error("dns-flux config error: {0}")]
    Config(String),
    /// A failure sending the update (network, NOTAUTH, bad FQDN).
    #[error("dns-flux send error: {0}")]
    Send(String),
}
