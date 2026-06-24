//! Errors from the PostgreSQL state layer.

/// An error talking to the state database.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// A query or connection failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// A migration failure.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The policy could not be resolved before persisting.
    #[error("invalid policy: {0}")]
    Policy(#[from] blackwall_core::PolicyError),
}
