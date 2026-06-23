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
}
