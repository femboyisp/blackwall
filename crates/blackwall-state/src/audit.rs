//! Audit-log helpers.

// The append happens inside `Store::apply_policy`'s transaction (lib.rs).
// `Store::audit_count` (lib.rs) is the first read accessor; richer queries
// land here as the API grows.
