//! PostgreSQL persistence for XDP desired-state: the active-entry mirror
//! (`xdp_entries`) and the append-only operator intent log (`xdp_requests`),
//! plus the [`Store`] methods and [`PgXdpJournal`] (a [`blackwall_xdp::manager::XdpJournal`])
//! that drive them.
//!
//! Unlike RTBH/FlowSpec, `xdp_entries` has no `announced_at`/`withdrawn_at`
//! lifecycle: a row's mere existence *is* "active". `xdp_record_apply`
//! replaces any existing row for the same identity (delete-then-insert) and
//! `xdp_record_remove` deletes it outright, so the mirror always matches the
//! `XdpController`'s in-memory active set 1:1.

use crate::{ipnetwork_addr, StateError, Store};
use blackwall_xdp::manager::{XdpJournal, XdpJournalError};
use blackwall_xdp::{XdpAction, XdpOrigin};
use std::net::IpAddr;
use std::sync::Arc;

/// Raw column tuple decoded from an `xdp_entries` row:
/// `(kind, target, prefixlen, rate_pps, burst, origin)`.
type XdpEntryTuple = (
    String,
    sqlx::types::ipnetwork::IpNetwork,
    Option<i32>,
    Option<i64>,
    Option<i64>,
    String,
);

/// Raw column tuple decoded from an `xdp_requests` row:
/// `(id, action, target, prefixlen, rate_pps, burst, created_by, status)`.
type XdpRequestTuple = (
    i64,
    String,
    sqlx::types::ipnetwork::IpNetwork,
    Option<i32>,
    Option<i64>,
    Option<i64>,
    String,
    String,
);

/// One row of the `xdp_entries` active-entry mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpEntryRow {
    /// `"block"` or `"rate_limit"`.
    pub kind: String,
    /// The blocked network's address, or the rate-limited source address.
    pub target: IpAddr,
    /// The blocked network's prefix length. `Some` for `kind = "block"`,
    /// `None` for `"rate_limit"` (a single host has no prefix of its own).
    pub prefixlen: Option<u8>,
    /// The rate-limit cap in packets/second. `Some` for `kind = "rate_limit"`,
    /// `None` for `"block"`.
    pub rate_pps: Option<u64>,
    /// The rate-limit's burst allowance in packets. `Some` for
    /// `kind = "rate_limit"`, `None` for `"block"`.
    pub burst: Option<u64>,
    /// `"auto"` or `"manual"`.
    pub origin: String,
}

/// One row of the `xdp_requests` append-only operator intent queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpRequestRow {
    /// Monotonically increasing request id.
    pub id: i64,
    /// `"block"`, `"unblock"`, `"rate_limit"`, or `"clear_rate"`.
    pub action: String,
    /// The target network's address, or the rate-limited source address.
    pub target: IpAddr,
    /// The blocked network's prefix length, when `action` concerns a block.
    pub prefixlen: Option<u8>,
    /// The requested rate-limit cap in packets/second, when `action` concerns
    /// a rate limit.
    pub rate_pps: Option<u64>,
    /// The requested rate-limit's burst allowance in packets, when `action`
    /// concerns a rate limit.
    pub burst: Option<u64>,
    /// Attribution for the request (`$USER@host` or `--operator`).
    pub created_by: String,
    /// `"pending"`, `"applied"`, or `"rejected"`.
    pub status: String,
}

impl Store {
    /// Insert (or replace) the active `xdp_entries` row identified by
    /// `kind` + `target` (+ `prefixlen` for a block). Any existing row for
    /// the same identity is deleted first (delete-then-insert), so at most
    /// one active row ever exists per identity.
    pub async fn xdp_record_apply(
        &self,
        kind: &str,
        target: IpAddr,
        prefixlen: Option<u8>,
        rate_pps: Option<u64>,
        burst: Option<u64>,
        origin: &str,
    ) -> Result<(), StateError> {
        let target_net = ipnetwork_addr(target);
        let prefixlen_i32 = prefixlen.map(i32::from);
        let rate_pps_i64 = rate_pps
            .map(i64::try_from)
            .transpose()
            .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
        let burst_i64 = burst
            .map(i64::try_from)
            .transpose()
            .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;

        let mut tx = self.pool().begin().await?;
        sqlx::query(
            "DELETE FROM xdp_entries \
             WHERE kind = $1 AND target = $2 AND prefixlen IS NOT DISTINCT FROM $3",
        )
        .bind(kind)
        .bind(target_net)
        .bind(prefixlen_i32)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO xdp_entries (kind, target, prefixlen, rate_pps, burst, origin) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(kind)
        .bind(target_net)
        .bind(prefixlen_i32)
        .bind(rate_pps_i64)
        .bind(burst_i64)
        .bind(origin)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete the active `xdp_entries` row identified by `kind` + `target`
    /// (+ `prefixlen` for a block). A no-op if no such row exists.
    pub async fn xdp_record_remove(
        &self,
        kind: &str,
        target: IpAddr,
        prefixlen: Option<u8>,
    ) -> Result<(), StateError> {
        let target_net = ipnetwork_addr(target);
        let prefixlen_i32 = prefixlen.map(i32::from);
        sqlx::query(
            "DELETE FROM xdp_entries \
             WHERE kind = $1 AND target = $2 AND prefixlen IS NOT DISTINCT FROM $3",
        )
        .bind(kind)
        .bind(target_net)
        .bind(prefixlen_i32)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// List all active `xdp_entries` rows.
    pub async fn xdp_active(&self) -> Result<Vec<XdpEntryRow>, StateError> {
        let rows: Vec<XdpEntryTuple> = sqlx::query_as(
            "SELECT kind, target, prefixlen, rate_pps, burst, origin FROM xdp_entries ORDER BY id",
        )
        .fetch_all(self.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (kind, target, prefixlen, rate_pps, burst, origin) in rows {
            let prefixlen = prefixlen
                .map(u8::try_from)
                .transpose()
                .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
            let rate_pps = rate_pps
                .map(u64::try_from)
                .transpose()
                .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
            let burst = burst
                .map(u64::try_from)
                .transpose()
                .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
            out.push(XdpEntryRow {
                kind,
                target: target.ip(),
                prefixlen,
                rate_pps,
                burst,
                origin,
            });
        }
        Ok(out)
    }

    /// Fetch all `xdp_requests` rows with `status = 'pending'`, ordered by id.
    pub async fn xdp_pending_requests(&self) -> Result<Vec<XdpRequestRow>, StateError> {
        let rows: Vec<XdpRequestTuple> = sqlx::query_as(
            "SELECT id, action, target, prefixlen, rate_pps, burst, created_by, status \
             FROM xdp_requests WHERE status = 'pending' ORDER BY id",
        )
        .fetch_all(self.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (id, action, target, prefixlen, rate_pps, burst, created_by, status) in rows {
            let prefixlen = prefixlen
                .map(u8::try_from)
                .transpose()
                .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
            let rate_pps = rate_pps
                .map(u64::try_from)
                .transpose()
                .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
            let burst = burst
                .map(u64::try_from)
                .transpose()
                .map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))?;
            out.push(XdpRequestRow {
                id,
                action,
                target: target.ip(),
                prefixlen,
                rate_pps,
                burst,
                created_by,
                status,
            });
        }
        Ok(out)
    }

    /// Update an `xdp_requests` row's `status`.
    pub async fn xdp_mark_request(&self, id: i64, status: &str) -> Result<(), StateError> {
        sqlx::query("UPDATE xdp_requests SET status = $2 WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

/// Map an [`XdpOrigin`] to its database text representation.
fn origin_str(origin: XdpOrigin) -> &'static str {
    match origin {
        XdpOrigin::Auto => "auto",
        XdpOrigin::Manual => "manual",
    }
}

/// A [`blackwall_xdp::manager::XdpJournal`] that mirrors XDP entries into the
/// `xdp_entries` table.
pub struct PgXdpJournal {
    store: Arc<Store>,
}

impl PgXdpJournal {
    /// Create a new journal wrapping `store`.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl XdpJournal for PgXdpJournal {
    /// Mirror `action` into `xdp_entries`: `Block`/`RateLimit` insert (or
    /// replace) the active row, `Unblock`/`ClearRate` delete it.
    ///
    /// `at_ms` is accepted for trait-signature parity with the other
    /// journals but unused here: `xdp_entries` has no announced/withdrawn
    /// lifecycle of its own (unlike RTBH/FlowSpec) — a row's `created_at` is
    /// DB-assigned (`DEFAULT now()`) and its mere existence is what "active"
    /// means.
    async fn record(
        &self,
        action: &XdpAction,
        origin: XdpOrigin,
        _at_ms: u64,
    ) -> Result<(), XdpJournalError> {
        let o = origin_str(origin);
        let result = match *action {
            XdpAction::Block { net } => {
                self.store
                    .xdp_record_apply("block", net.addr(), Some(net.prefix_len()), None, None, o)
                    .await
            }
            XdpAction::RateLimit { src, pps, burst } => {
                self.store
                    .xdp_record_apply("rate_limit", src, None, Some(pps), Some(burst), o)
                    .await
            }
            XdpAction::Unblock { net } => {
                self.store
                    .xdp_record_remove("block", net.addr(), Some(net.prefix_len()))
                    .await
            }
            XdpAction::ClearRate { src } => {
                self.store.xdp_record_remove("rate_limit", src, None).await
            }
        };
        result.map_err(|e| XdpJournalError(e.to_string()))
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
    async fn xdp_apply_and_active_roundtrip_block_and_rate_limit() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();

        let net_addr: IpAddr = "198.51.100.0".parse().unwrap();
        store
            .xdp_record_apply("block", net_addr, Some(24), None, None, "auto")
            .await
            .unwrap();
        let src: IpAddr = "203.0.113.9".parse().unwrap();
        store
            .xdp_record_apply("rate_limit", src, None, Some(1_000), Some(2_000), "auto")
            .await
            .unwrap();

        let active = store.xdp_active().await.unwrap();
        let block_row = active
            .iter()
            .find(|r| r.kind == "block" && r.target == net_addr)
            .expect("block row present");
        assert_eq!(block_row.prefixlen, Some(24));
        assert_eq!(block_row.rate_pps, None);
        assert_eq!(block_row.burst, None);
        assert_eq!(block_row.origin, "auto");

        let rl_row = active
            .iter()
            .find(|r| r.kind == "rate_limit" && r.target == src)
            .expect("rate_limit row present");
        assert_eq!(rl_row.prefixlen, None);
        assert_eq!(rl_row.rate_pps, Some(1_000));
        assert_eq!(rl_row.burst, Some(2_000));

        // Re-applying replaces (not duplicates) the row for the same identity.
        // A custom (non-default) burst independent of pps must round-trip too.
        store
            .xdp_record_apply("rate_limit", src, None, Some(500), Some(1_000), "manual")
            .await
            .unwrap();
        let active = store.xdp_active().await.unwrap();
        let matches: Vec<_> = active
            .iter()
            .filter(|r| r.kind == "rate_limit" && r.target == src)
            .collect();
        assert_eq!(matches.len(), 1, "re-apply must replace, not duplicate");
        assert_eq!(matches[0].rate_pps, Some(500));
        assert_eq!(matches[0].burst, Some(1_000));
        assert_eq!(matches[0].origin, "manual");

        store
            .xdp_record_remove("rate_limit", src, None)
            .await
            .unwrap();
        assert!(!store
            .xdp_active()
            .await
            .unwrap()
            .iter()
            .any(|r| r.kind == "rate_limit" && r.target == src));

        store
            .xdp_record_remove("block", net_addr, Some(24))
            .await
            .unwrap();
        assert!(!store
            .xdp_active()
            .await
            .unwrap()
            .iter()
            .any(|r| r.kind == "block" && r.target == net_addr));
    }

    #[tokio::test]
    async fn xdp_mark_request_transitions_status() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();

        let target: IpAddr = "203.0.113.44".parse().unwrap();
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO xdp_requests (action, target, prefixlen, rate_pps, burst, created_by) \
             VALUES ('block', $1, 32, NULL, NULL, 'op@host') RETURNING id",
        )
        .bind(ipnetwork_addr(target))
        .fetch_one(store.pool())
        .await
        .unwrap();
        let id = row.0;

        let pending = store.xdp_pending_requests().await.unwrap();
        assert!(pending.iter().any(|r| r.id == id && r.action == "block"));

        // A rate-limit request with a custom (pps != burst) burst must
        // round-trip through xdp_pending_requests unchanged.
        let rl_src: IpAddr = "203.0.113.45".parse().unwrap();
        let rl_row: (i64,) = sqlx::query_as(
            "INSERT INTO xdp_requests (action, target, prefixlen, rate_pps, burst, created_by) \
             VALUES ('rate_limit', $1, NULL, 500, 1000, 'op@host') RETURNING id",
        )
        .bind(ipnetwork_addr(rl_src))
        .fetch_one(store.pool())
        .await
        .unwrap();
        let pending = store.xdp_pending_requests().await.unwrap();
        let rl_pending = pending
            .iter()
            .find(|r| r.id == rl_row.0)
            .expect("rate_limit request present");
        assert_eq!(rl_pending.rate_pps, Some(500));
        assert_eq!(rl_pending.burst, Some(1_000));
        store.xdp_mark_request(rl_row.0, "applied").await.unwrap();

        store.xdp_mark_request(id, "applied").await.unwrap();
        assert!(
            !store
                .xdp_pending_requests()
                .await
                .unwrap()
                .iter()
                .any(|r| r.id == id),
            "an applied request must no longer appear in pending_requests"
        );

        store.xdp_mark_request(id, "rejected").await.unwrap();
        let row: (String,) = sqlx::query_as("SELECT status FROM xdp_requests WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(row.0, "rejected");
    }

    #[tokio::test]
    async fn pg_xdp_journal_maps_all_action_variants() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Arc::new(Store::connect(&url).await.unwrap());
        store.migrate().await.unwrap();
        let journal = PgXdpJournal::new(store.clone());

        let net: ipnet::IpNet = "198.51.100.128/25".parse().unwrap();
        journal
            .record(&XdpAction::Block { net }, XdpOrigin::Auto, 1_000)
            .await
            .unwrap();
        assert!(store
            .xdp_active()
            .await
            .unwrap()
            .iter()
            .any(|r| r.kind == "block" && r.target == net.addr()));

        journal
            .record(&XdpAction::Unblock { net }, XdpOrigin::Auto, 2_000)
            .await
            .unwrap();
        assert!(!store
            .xdp_active()
            .await
            .unwrap()
            .iter()
            .any(|r| r.kind == "block" && r.target == net.addr()));

        let src: IpAddr = "203.0.113.55".parse().unwrap();
        journal
            .record(
                &XdpAction::RateLimit {
                    src,
                    pps: 2_000,
                    burst: 2_000,
                },
                XdpOrigin::Manual,
                3_000,
            )
            .await
            .unwrap();
        let row = store
            .xdp_active()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.kind == "rate_limit" && r.target == src)
            .expect("rate_limit row present");
        assert_eq!(row.rate_pps, Some(2_000));
        assert_eq!(row.origin, "manual");

        journal
            .record(&XdpAction::ClearRate { src }, XdpOrigin::Manual, 4_000)
            .await
            .unwrap();
        assert!(!store
            .xdp_active()
            .await
            .unwrap()
            .iter()
            .any(|r| r.kind == "rate_limit" && r.target == src));
    }
}
