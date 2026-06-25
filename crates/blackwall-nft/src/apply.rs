//! Apply a rendered ruleset to the running kernel.

use crate::error::NftError;
use blackwall_core::Policy;
use nftables::helper;

/// Render `policy` and apply it to the kernel. Each call fully flushes and
/// replaces the prior `inet blackwall` table: the rendered ruleset first adds
/// the table (creating it if absent), then flushes it (atomically removing any
/// stale sets/chains from a previous apply), then re-adds all sets and chains
/// from the current policy. Services removed from the policy are therefore
/// guaranteed to be absent after apply completes.
///
/// Requires `CAP_NET_ADMIN` (run as root).
pub fn apply(policy: &Policy) -> Result<(), NftError> {
    let ruleset = crate::render::render(policy).map_err(|e| NftError::Apply(e.to_string()))?;
    helper::apply_ruleset(&ruleset).map_err(|e| NftError::Apply(e.to_string()))?;
    Ok(())
}
