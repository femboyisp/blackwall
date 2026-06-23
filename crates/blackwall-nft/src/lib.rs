//! Render and apply Blackwall's nftables ruleset.

mod error;
mod render;

pub use error::NftError;
pub use render::{render, ruleset_json};
