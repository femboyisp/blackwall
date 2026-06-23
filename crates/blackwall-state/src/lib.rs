//! PostgreSQL persistence for Blackwall: tenants, IP assignments, services,
//! and the audit log.

mod error;

pub use error::StateError;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// A handle to the Blackwall state database.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connect to PostgreSQL at `database_url` (e.g.
    /// `postgres://blackwall:blackwall@localhost:5432/blackwall`).
    pub async fn connect(database_url: &str) -> Result<Store, StateError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Store { pool })
    }

    /// Run all pending migrations.
    pub async fn migrate(&self) -> Result<(), StateError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Borrow the underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the test database URL, or `None` when not configured (so unit
    /// runs without a database simply skip the DB-backed tests).
    fn test_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    #[tokio::test]
    async fn connect_and_migrate_is_idempotent() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("first migrate");
        store.migrate().await.expect("second migrate is a no-op");
    }
}
