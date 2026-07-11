//! Audit-log helpers.

// Appends happen inside `Store::apply_policy`'s transaction, or standalone
// via `Store::record_audit` (both in lib.rs). `Store::audit_count` and
// `Store::list_recent_audit` (lib.rs) are the read accessors; richer queries
// land here as the API grows.

/// One `audit_log` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Wall-clock milliseconds the entry was recorded.
    pub at_ms: u64,
    /// Who performed the action (e.g. `"test"`, an operator identity).
    pub actor: String,
    /// What happened (e.g. `"apply_policy"`).
    pub action: String,
    /// Structured detail attached to the entry.
    pub detail: serde_json::Value,
}
