//! PostgreSQL persistence for the shared SYN-cookie secret: a single
//! 128-bit key that must be byte-identical across every process that mints
//! or validates a SYN-cookie — the in-kernel XDP fast path (`blackwalld
//! flow`) and the userspace cookie responder (`blackwalld run`) are separate
//! processes, and a cookie minted by one must validate in the other.
//!
//! The secret lives in a singleton `cookie_secret` row (`id = 1`). Whichever
//! process boots first generates and inserts it; every other caller —
//! including one racing that very first insert — reads back the row that
//! actually won, so all processes converge on one shared key with no
//! coordination beyond the database.

use crate::{StateError, Store};

impl Store {
    /// Get-or-create the shared 128-bit SYN-cookie secret.
    ///
    /// This is the sole accessor both `blackwalld flow` (which loads the key
    /// into the XDP BPF map) and `blackwalld run` (the userspace cookie
    /// responder) call to obtain their cookie key, so the two independent
    /// processes agree on the same 16 bytes.
    ///
    /// Concurrency semantics (get-or-create, idempotent): a fresh 16-byte
    /// candidate is generated locally and an `INSERT ... ON CONFLICT (id) DO
    /// NOTHING` is issued for the singleton row. When two callers race on
    /// first boot, exactly one insert lands and the other is silently
    /// skipped — neither caller trusts its own locally-generated candidate
    /// past that point. Both then `SELECT` the row back and return *those*
    /// bytes, so concurrent callers always agree on the secret that actually
    /// made it into the table, never on whichever candidate they happened to
    /// generate. On every later call (including across process restarts)
    /// the insert is always a no-op and the existing row is returned
    /// unchanged, so the secret is stable for the lifetime of the database.
    pub async fn cookie_secret(&self) -> Result<[u8; 16], StateError> {
        let candidate = random_secret()?;

        sqlx::query(
            "INSERT INTO cookie_secret (id, secret) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
        )
        .bind(candidate.as_slice())
        .execute(self.pool())
        .await?;

        let row: (Vec<u8>,) = sqlx::query_as("SELECT secret FROM cookie_secret WHERE id = 1")
            .fetch_one(self.pool())
            .await?;

        <[u8; 16]>::try_from(row.0.as_slice())
            .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))
    }
}

/// Generate 16 random bytes for a candidate cookie secret by reading
/// `/dev/urandom` directly, mirroring `blackwalld`'s `random_cookie_key`
/// helper. This keeps `blackwall-state` free of a crypto/RNG dependency (and
/// of any reliance on a `pgcrypto` Postgres extension) for what is a rare,
/// one-shot-per-deployment generation.
fn random_secret() -> Result<[u8; 16], StateError> {
    use std::io::Read;
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| StateError::Db(sqlx::Error::Io(e)))?;
    Ok(bytes)
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
    async fn cookie_secret_creates_and_is_stable() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();

        let first = store.cookie_secret().await.unwrap();
        assert_eq!(first.len(), 16);

        let second = store.cookie_secret().await.unwrap();
        assert_eq!(
            first, second,
            "a second call must return the identical secret, not a fresh one"
        );
    }

    #[tokio::test]
    async fn cookie_secret_concurrent_calls_agree() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let store = store.clone();
            set.spawn(async move { store.cookie_secret().await.unwrap() });
        }

        let mut results = Vec::new();
        while let Some(res) = set.join_next().await {
            results.push(res.expect("task panicked"));
        }

        assert_eq!(results.len(), 8);
        let first = results[0];
        assert!(
            results.iter().all(|secret| *secret == first),
            "all concurrent callers must agree on the same secret, got {results:?}"
        );
    }
}
