//! Tenant + IP-assignment persistence helpers used within transactions.

// Intentionally thin: the transactional writes live in `Store::apply_policy`
// (lib.rs) because they must share one transaction. This module exists as the
// home for future tenant queries (lookups, per-tenant authz scoping).
