//! Apply a rendered ruleset to the running kernel.

use crate::error::NftError;
use blackwall_core::Policy;
use nftables::helper;

/// Render `policy` and apply it to the kernel, replacing the prior
/// `inet blackwall` table. Requires `CAP_NET_ADMIN` (run as root).
pub fn apply(policy: &Policy) -> Result<(), NftError> {
    let ruleset = crate::render::render(policy).map_err(|e| NftError::Apply(e.to_string()))?;
    helper::apply_ruleset(&ruleset, None, None).map_err(|e| NftError::Apply(e.to_string()))?;
    Ok(())
}
