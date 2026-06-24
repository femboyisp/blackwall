//! Errors from rendering/applying nftables rulesets.

/// An error applying a rendered ruleset to the kernel.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// `nft` rejected or failed to apply the ruleset.
    #[error("applying ruleset: {0}")]
    Apply(String),
}
