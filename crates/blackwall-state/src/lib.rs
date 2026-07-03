//! PostgreSQL persistence for Blackwall: tenants, IP assignments, services,
//! the audit log, and flow-based attack detections.

mod audit;
mod error;
mod flowspec;
mod rtbh;
mod services;
mod sessions;
mod tenants;

pub use error::StateError;
pub use flowspec::{FlowSpecRequestRow, FlowSpecRuleRow};
pub use rtbh::{RtbhBlackholeRow, RtbhRequestRow};
pub use services::StoredService;
pub use sessions::SessionRow;

use blackwall_core::{L4Proto, Policy, ServiceTarget};
use blackwall_flow::{Detection, DetectionEvent, MitigationSink, Severity};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// A handle to the Blackwall state database.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Raw column tuple decoded from a `flowspec_rules` row:
/// `(dst, proto, dst_port, rate::real, origin, announced_at_ms, withdrawn_at_ms)`.
type FlowSpecRuleTuple = (
    sqlx::types::ipnetwork::IpNetwork,
    i32,
    i32,
    f32,
    String,
    i64,
    Option<i64>,
);

/// Raw column tuple decoded from a `flowspec_requests` row:
/// `(id, dst, proto, dst_port, rate::real, action, created_by, status, note)`.
type FlowSpecRequestTuple = (
    i64,
    sqlx::types::ipnetwork::IpNetwork,
    i32,
    i32,
    f32,
    String,
    String,
    String,
    Option<String>,
);

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

    /// Replace all persisted tenants/assignments/services to match `policy`,
    /// in a single transaction, and append an audit entry. Returns the number
    /// of resolved services written.
    pub async fn apply_policy(&self, policy: &Policy, actor: &str) -> Result<usize, StateError> {
        let resolved = policy.resolve()?;

        let mut tx = self.pool.begin().await?;

        sqlx::query("TRUNCATE tenants RESTART IDENTITY CASCADE")
            .execute(&mut *tx)
            .await?;

        for tenant in &policy.tenants {
            let row: (i64,) = sqlx::query_as("INSERT INTO tenants (name) VALUES ($1) RETURNING id")
                .bind(&tenant.name)
                .fetch_one(&mut *tx)
                .await?;
            let tenant_id = row.0;
            for addr in &tenant.owned {
                sqlx::query("INSERT INTO ip_assignments (tenant_id, address) VALUES ($1, $2)")
                    .bind(tenant_id)
                    .bind(ipnetwork_addr(*addr))
                    .execute(&mut *tx)
                    .await?;
            }
        }

        // Look up tenant id for each service row.
        for svc in &resolved {
            let tenant_id: (i64,) = sqlx::query_as("SELECT id FROM tenants WHERE name = $1")
                .bind(&svc.tenant)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO services (tenant_id, address, proto, port, target) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(tenant_id.0)
            .bind(ipnetwork_addr(svc.addr))
            .bind(svc.proto.to_string())
            .bind(i32::from(svc.port))
            .bind(serde_json::to_value(&svc.target).map_err(|e| {
                StateError::Db(sqlx::Error::Decode(
                    format!("failed to serialize target: {e}").into(),
                ))
            })?)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            "INSERT INTO audit_log (actor, action, detail) VALUES ($1, 'apply_policy', $2)",
        )
        .bind(actor)
        .bind(serde_json::json!({ "services": resolved.len() }))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(resolved.len())
    }

    /// List all persisted services.
    pub async fn list_services(&self) -> Result<Vec<StoredService>, StateError> {
        let rows: Vec<(
            sqlx::types::ipnetwork::IpNetwork,
            String,
            i32,
            serde_json::Value,
            String,
        )> = sqlx::query_as(
            "SELECT s.address, s.proto, s.port, s.target, t.name \
             FROM services s JOIN tenants t ON t.id = s.tenant_id \
             ORDER BY s.address, s.port",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (addr, proto, port, target, tenant) in rows {
            let proto = match proto.as_str() {
                "tcp" => L4Proto::Tcp,
                "udp" => L4Proto::Udp,
                other => {
                    return Err(StateError::Db(sqlx::Error::Decode(
                        format!("unknown proto in services row: {other}").into(),
                    )))
                }
            };
            let port = u16::try_from(port).map_err(|_| {
                StateError::Db(sqlx::Error::Decode(
                    format!("port {port} out of u16 range").into(),
                ))
            })?;
            let target: ServiceTarget = serde_json::from_value(target).map_err(|e| {
                StateError::Db(sqlx::Error::Decode(
                    format!("failed to deserialize target: {e}").into(),
                ))
            })?;
            out.push(StoredService {
                address: addr.ip(),
                proto,
                port,
                target,
                tenant,
            });
        }
        Ok(out)
    }

    /// Append a deception-session audit row.
    pub async fn record_session(&self, s: &SessionRow) -> Result<(), StateError> {
        sqlx::query(
            "INSERT INTO deception_sessions \
             (local_addr, local_port, peer_addr, proto, emulator, bytes_in, bytes_out, note) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ipnetwork_addr(s.local_addr))
        .bind(i32::from(s.local_port))
        .bind(ipnetwork_addr(s.peer_addr))
        .bind(&s.proto)
        .bind(&s.emulator)
        .bind(s.bytes_in)
        .bind(s.bytes_out)
        .bind(s.note.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Count recorded deception sessions.
    pub async fn session_count(&self) -> Result<i64, StateError> {
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM deception_sessions")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// Count audit-log entries.
    pub async fn audit_count(&self) -> Result<i64, StateError> {
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// Count detection rows (active and cleared).
    pub async fn detection_count(&self) -> Result<i64, StateError> {
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM detections")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// Insert a new active detection row.
    pub async fn open_detection(&self, d: &Detection) -> Result<(), StateError> {
        let target = ipnetwork_addr(d.target);
        let proto = i32::from(d.proto);
        let severity = severity_str(d.severity);
        let top_sources = serde_json::Value::Array(
            d.top_sources
                .iter()
                .map(|(ip, pps)| serde_json::json!({ "ip": ip.to_string(), "pps": pps }))
                .collect(),
        );
        let top_ports = serde_json::Value::Array(
            d.top_ports
                .iter()
                .map(|(port, pps)| serde_json::json!({ "port": port, "pps": pps }))
                .collect(),
        );
        let first_seen_ms = i64::try_from(d.first_seen_ms).unwrap_or(i64::MAX);
        let last_seen_ms = i64::try_from(d.last_seen_ms).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO detections \
             (target, kind, observed_pps, observed_bps, proto, top_sources, top_ports, severity, first_seen, last_seen) \
             VALUES ($1, 'volumetric', $2, $3, $4, $5, $6, $7, \
                     to_timestamp($8::bigint / 1000.0), to_timestamp($9::bigint / 1000.0))",
        )
        .bind(target)
        .bind(d.observed_pps)
        .bind(d.observed_bps)
        .bind(proto)
        .bind(top_sources)
        .bind(top_ports)
        .bind(severity)
        .bind(first_seen_ms)
        .bind(last_seen_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update the active detection row for `target`.
    pub async fn update_detection(
        &self,
        target: IpAddr,
        pps: f64,
        bps: f64,
        last_seen_ms: u64,
    ) -> Result<(), StateError> {
        let target = ipnetwork_addr(target);
        let last_seen_ms = i64::try_from(last_seen_ms).unwrap_or(i64::MAX);
        sqlx::query(
            "UPDATE detections \
             SET observed_pps = $2, observed_bps = $3, last_seen = to_timestamp($4::bigint / 1000.0) \
             WHERE target = $1 AND cleared_at IS NULL",
        )
        .bind(target)
        .bind(pps)
        .bind(bps)
        .bind(last_seen_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark the active detection row for `target` as cleared.
    pub async fn clear_detection(&self, target: IpAddr, at_ms: u64) -> Result<(), StateError> {
        let target = ipnetwork_addr(target);
        let at_ms = i64::try_from(at_ms).unwrap_or(i64::MAX);
        sqlx::query(
            "UPDATE detections \
             SET cleared_at = to_timestamp($2::bigint / 1000.0) \
             WHERE target = $1 AND cleared_at IS NULL",
        )
        .bind(target)
        .bind(at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Insert or refresh the active `rtbh_blackholes` mirror row for
    /// `target`. If an active row already exists, its `origin` is upgraded
    /// per the announcement but never downgraded from `manual` to `auto`
    /// (an upsert can race a `manual_add` and must not clobber it).
    pub async fn record_blackhole(
        &self,
        target: IpAddr,
        origin: &str,
        at_ms: u64,
    ) -> Result<(), StateError> {
        let target = ipnetwork_addr(target);
        let at_ms = i64::try_from(at_ms).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO rtbh_blackholes (target, origin, announced_at) \
             VALUES ($1, $2, to_timestamp($3::bigint / 1000.0)) \
             ON CONFLICT (target) WHERE withdrawn_at IS NULL DO UPDATE SET \
             origin = CASE WHEN rtbh_blackholes.origin = 'manual' THEN 'manual' ELSE EXCLUDED.origin END",
        )
        .bind(target)
        .bind(origin)
        .bind(at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark the active `rtbh_blackholes` row for `target` as withdrawn. When
    /// `only_auto` is set, only a row with `origin = 'auto'` is cleared (the
    /// auto-path guard that keeps a Cleared event from withdrawing a manual
    /// blackhole).
    pub async fn clear_blackhole(
        &self,
        target: IpAddr,
        at_ms: u64,
        only_auto: bool,
    ) -> Result<(), StateError> {
        let target = ipnetwork_addr(target);
        let at_ms = i64::try_from(at_ms).unwrap_or(i64::MAX);
        let query = if only_auto {
            "UPDATE rtbh_blackholes SET withdrawn_at = to_timestamp($2::bigint / 1000.0) \
             WHERE target = $1 AND withdrawn_at IS NULL AND origin = 'auto'"
        } else {
            "UPDATE rtbh_blackholes SET withdrawn_at = to_timestamp($2::bigint / 1000.0) \
             WHERE target = $1 AND withdrawn_at IS NULL"
        };
        sqlx::query(query)
            .bind(target)
            .bind(at_ms)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all currently-active (not withdrawn) blackholes.
    pub async fn list_active_blackholes(&self) -> Result<Vec<RtbhBlackholeRow>, StateError> {
        let rows: Vec<(sqlx::types::ipnetwork::IpNetwork, String, i64, Option<i64>)> =
            sqlx::query_as(
                "SELECT target, origin, \
                    (EXTRACT(EPOCH FROM announced_at) * 1000)::bigint, \
                    (EXTRACT(EPOCH FROM withdrawn_at) * 1000)::bigint \
             FROM rtbh_blackholes WHERE withdrawn_at IS NULL ORDER BY target",
            )
            .fetch_all(&self.pool)
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (target, origin, announced_at_ms, withdrawn_at_ms) in rows {
            let announced_at_ms = u64::try_from(announced_at_ms).map_err(|_| {
                StateError::Db(sqlx::Error::Decode(
                    format!("announced_at_ms {announced_at_ms} out of u64 range").into(),
                ))
            })?;
            let withdrawn_at_ms = withdrawn_at_ms
                .map(u64::try_from)
                .transpose()
                .map_err(|_| {
                    StateError::Db(sqlx::Error::Decode(
                        "withdrawn_at_ms out of u64 range".into(),
                    ))
                })?;
            out.push(RtbhBlackholeRow {
                target: target.ip(),
                origin,
                announced_at_ms,
                withdrawn_at_ms,
            });
        }
        Ok(out)
    }

    /// Append an operator intent row to `rtbh_requests` (`status = 'pending'`
    /// by default). Returns the new row's id.
    pub async fn enqueue_request(
        &self,
        target: IpAddr,
        action: &str,
        created_by: &str,
    ) -> Result<i64, StateError> {
        let target = ipnetwork_addr(target);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO rtbh_requests (target, action, created_by) VALUES ($1, $2, $3) \
             RETURNING id",
        )
        .bind(target)
        .bind(action)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Fetch all requests with `status = 'pending'`, ordered by id.
    ///
    /// This is status-driven (not a watermark): every tick re-reads the
    /// genuinely-pending set, so a capacity-deferred add is naturally
    /// retried (it's still `pending`) and a restart never replays
    /// already-`applied`/`rejected` history.
    pub async fn pending_requests(&self) -> Result<Vec<RtbhRequestRow>, StateError> {
        let rows: Vec<(
            i64,
            sqlx::types::ipnetwork::IpNetwork,
            String,
            String,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, target, action, created_by, status, note \
             FROM rtbh_requests WHERE status = 'pending' ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows_to_requests(rows))
    }

    /// Mark any still-`pending` `add` request for `target` with `id <
    /// before_id` as `applied` (with a `"superseded by remove"` note), so a
    /// later remove cancels an earlier not-yet-applied add for the same
    /// target instead of letting it re-announce once capacity frees up.
    ///
    /// Scoped to `before_id` (the remove request's own id) so a re-add that
    /// races in after the remove was snapshotted — i.e. has a higher id than
    /// the remove — is never superseded by it.
    pub async fn supersede_pending_adds(
        &self,
        target: IpAddr,
        before_id: i64,
    ) -> Result<(), StateError> {
        let target = ipnetwork_addr(target);
        sqlx::query(
            "UPDATE rtbh_requests SET status = 'applied', note = 'superseded by remove', \
             applied_at = now() WHERE action = 'add' AND target = $1 AND status = 'pending' \
             AND id < $2",
        )
        .bind(target)
        .bind(before_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update a request's status (and optional note), stamping `applied_at`.
    pub async fn set_request_status(
        &self,
        id: i64,
        status: &str,
        note: Option<&str>,
    ) -> Result<(), StateError> {
        sqlx::query(
            "UPDATE rtbh_requests SET status = $2, note = $3, applied_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List requests, optionally filtered to a single `status`.
    pub async fn list_requests(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<RtbhRequestRow>, StateError> {
        let rows: Vec<(
            i64,
            sqlx::types::ipnetwork::IpNetwork,
            String,
            String,
            String,
            Option<String>,
        )> = match status_filter {
            Some(status) => {
                sqlx::query_as(
                    "SELECT id, target, action, created_by, status, note \
                     FROM rtbh_requests WHERE status = $1 ORDER BY id",
                )
                .bind(status)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT id, target, action, created_by, status, note \
                     FROM rtbh_requests ORDER BY id",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows_to_requests(rows))
    }

    /// Insert or refresh the active `flowspec_rules` mirror row for the
    /// `(dst, proto, dst_port)` flow key. If an active row already exists its
    /// `origin` is upgraded per the announcement but never downgraded from
    /// `manual` to `auto` (an upsert can race a `manual_add` and must not
    /// clobber it); the `rate` is always refreshed to the latest announcement.
    pub async fn record_flowspec(
        &self,
        dst: IpAddr,
        proto: u8,
        dst_port: u16,
        rate: f32,
        origin: &str,
        at_ms: u64,
    ) -> Result<(), StateError> {
        let dst = ipnetwork_addr(dst);
        let at_ms = i64::try_from(at_ms).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO flowspec_rules (dst, proto, dst_port, rate, origin, announced_at) \
             VALUES ($1, $2, $3, $4, $5, to_timestamp($6::bigint / 1000.0)) \
             ON CONFLICT (dst, proto, dst_port) WHERE withdrawn_at IS NULL DO UPDATE SET \
             origin = CASE WHEN flowspec_rules.origin = 'manual' THEN 'manual' ELSE EXCLUDED.origin END, \
             rate = EXCLUDED.rate",
        )
        .bind(dst)
        .bind(i32::from(proto))
        .bind(i32::from(dst_port))
        .bind(f64::from(rate))
        .bind(origin)
        .bind(at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark the active `flowspec_rules` row for the `(dst, proto, dst_port)`
    /// flow key as withdrawn. When `only_auto` is set, only a row with
    /// `origin = 'auto'` is cleared (the auto-path guard that keeps a Cleared
    /// event from withdrawing a manual rule).
    pub async fn clear_flowspec(
        &self,
        dst: IpAddr,
        proto: u8,
        dst_port: u16,
        at_ms: u64,
        only_auto: bool,
    ) -> Result<(), StateError> {
        let dst = ipnetwork_addr(dst);
        let at_ms = i64::try_from(at_ms).unwrap_or(i64::MAX);
        let query = if only_auto {
            "UPDATE flowspec_rules SET withdrawn_at = to_timestamp($4::bigint / 1000.0) \
             WHERE dst = $1 AND proto = $2 AND dst_port = $3 AND withdrawn_at IS NULL AND origin = 'auto'"
        } else {
            "UPDATE flowspec_rules SET withdrawn_at = to_timestamp($4::bigint / 1000.0) \
             WHERE dst = $1 AND proto = $2 AND dst_port = $3 AND withdrawn_at IS NULL"
        };
        sqlx::query(query)
            .bind(dst)
            .bind(i32::from(proto))
            .bind(i32::from(dst_port))
            .bind(at_ms)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all currently-active (not withdrawn) FlowSpec rules.
    ///
    /// `rate` is selected as `::real` so SQLx decodes it straight into `f32`
    /// (avoiding a forbidden `f64 as f32` narrowing cast).
    pub async fn list_active_flowspec(&self) -> Result<Vec<FlowSpecRuleRow>, StateError> {
        let rows: Vec<FlowSpecRuleTuple> = sqlx::query_as(
            "SELECT dst, proto, dst_port, rate::real, origin, \
                (EXTRACT(EPOCH FROM announced_at) * 1000)::bigint, \
                (EXTRACT(EPOCH FROM withdrawn_at) * 1000)::bigint \
             FROM flowspec_rules WHERE withdrawn_at IS NULL ORDER BY dst, proto, dst_port",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (dst, proto, dst_port, rate, origin, announced_at_ms, withdrawn_at_ms) in rows {
            let announced_at_ms = u64::try_from(announced_at_ms).map_err(|_| {
                StateError::Db(sqlx::Error::Decode(
                    format!("announced_at_ms {announced_at_ms} out of u64 range").into(),
                ))
            })?;
            let withdrawn_at_ms = withdrawn_at_ms
                .map(u64::try_from)
                .transpose()
                .map_err(|_| {
                    StateError::Db(sqlx::Error::Decode(
                        "withdrawn_at_ms out of u64 range".into(),
                    ))
                })?;
            out.push(FlowSpecRuleRow {
                dst: dst.ip(),
                proto: narrow_proto(proto)?,
                dst_port: narrow_port(dst_port)?,
                rate,
                origin,
                announced_at_ms,
                withdrawn_at_ms,
            });
        }
        Ok(out)
    }

    /// Append an operator intent row to `flowspec_requests` (`status =
    /// 'pending'` by default). Returns the new row's id.
    pub async fn enqueue_flowspec_request(
        &self,
        dst: IpAddr,
        proto: u8,
        dst_port: u16,
        rate: f32,
        action: &str,
        created_by: &str,
    ) -> Result<i64, StateError> {
        let dst = ipnetwork_addr(dst);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO flowspec_requests (dst, proto, dst_port, rate, action, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(dst)
        .bind(i32::from(proto))
        .bind(i32::from(dst_port))
        .bind(f64::from(rate))
        .bind(action)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Fetch all FlowSpec requests with `status = 'pending'`, ordered by id.
    ///
    /// Status-driven (not a watermark): every tick re-reads the genuinely
    /// pending set, so a capacity-deferred add is naturally retried (it's still
    /// `pending`) and a restart never replays already-`applied`/`rejected`
    /// history.
    pub async fn pending_flowspec_requests(&self) -> Result<Vec<FlowSpecRequestRow>, StateError> {
        let rows: Vec<FlowSpecRequestTuple> = sqlx::query_as(
            "SELECT id, dst, proto, dst_port, rate::real, action, created_by, status, note \
             FROM flowspec_requests WHERE status = 'pending' ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows_to_flowspec_requests(rows)
    }

    /// Mark any still-`pending` `add` request for the `(dst, proto, dst_port)`
    /// flow key with `id < before_id` as `applied` (with a `"superseded by
    /// remove"` note), so a later remove cancels an earlier not-yet-applied add
    /// for the same flow instead of letting it re-announce once capacity frees.
    ///
    /// Scoped to `before_id` (the remove request's own id) so a re-add that
    /// races in after the remove was snapshotted — i.e. has a higher id than
    /// the remove — is never superseded by it.
    pub async fn supersede_pending_flowspec_adds(
        &self,
        dst: IpAddr,
        proto: u8,
        dst_port: u16,
        before_id: i64,
    ) -> Result<(), StateError> {
        let dst = ipnetwork_addr(dst);
        sqlx::query(
            "UPDATE flowspec_requests SET status = 'applied', note = 'superseded by remove', \
             applied_at = now() WHERE action = 'add' AND dst = $1 AND proto = $2 AND dst_port = $3 \
             AND status = 'pending' AND id < $4",
        )
        .bind(dst)
        .bind(i32::from(proto))
        .bind(i32::from(dst_port))
        .bind(before_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update a FlowSpec request's status (and optional note), stamping
    /// `applied_at`.
    pub async fn set_flowspec_request_status(
        &self,
        id: i64,
        status: &str,
        note: Option<&str>,
    ) -> Result<(), StateError> {
        sqlx::query(
            "UPDATE flowspec_requests SET status = $2, note = $3, applied_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List FlowSpec requests, optionally filtered to a single `status`.
    pub async fn list_flowspec_requests(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<FlowSpecRequestRow>, StateError> {
        let rows: Vec<FlowSpecRequestTuple> = match status_filter {
            Some(status) => sqlx::query_as(
                "SELECT id, dst, proto, dst_port, rate::real, action, created_by, status, note \
                     FROM flowspec_requests WHERE status = $1 ORDER BY id",
            )
            .bind(status)
            .fetch_all(&self.pool)
            .await?,
            None => sqlx::query_as(
                "SELECT id, dst, proto, dst_port, rate::real, action, created_by, status, note \
                     FROM flowspec_requests ORDER BY id",
            )
            .fetch_all(&self.pool)
            .await?,
        };
        rows_to_flowspec_requests(rows)
    }
}

/// Narrow a Postgres `INTEGER` (`i32`) protocol column to `u8`, mapping an
/// out-of-range value to a decode error rather than a silent `as` truncation.
fn narrow_proto(v: i32) -> Result<u8, StateError> {
    u8::try_from(v).map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))
}

/// Narrow a Postgres `INTEGER` (`i32`) port column to `u16`, mapping an
/// out-of-range value to a decode error rather than a silent `as` truncation.
fn narrow_port(v: i32) -> Result<u16, StateError> {
    u16::try_from(v).map_err(|e| StateError::Db(sqlx::Error::Decode(Box::new(e))))
}

/// Map raw `flowspec_requests` rows into [`FlowSpecRequestRow`]s, narrowing the
/// `INTEGER` proto/port columns to `u8`/`u16` (`rate` is already decoded as
/// `f32` via a `::real` cast in the SELECT).
fn rows_to_flowspec_requests(
    rows: Vec<FlowSpecRequestTuple>,
) -> Result<Vec<FlowSpecRequestRow>, StateError> {
    let mut out = Vec::with_capacity(rows.len());
    for (id, dst, proto, dst_port, rate, action, created_by, status, note) in rows {
        out.push(FlowSpecRequestRow {
            id,
            dst: dst.ip(),
            proto: narrow_proto(proto)?,
            dst_port: narrow_port(dst_port)?,
            rate,
            action,
            created_by,
            status,
            note,
        });
    }
    Ok(out)
}

#[async_trait::async_trait]
impl blackwall_rtbh::FlowSpecJournal for Store {
    async fn record_announce(
        &self,
        rule: blackwall_bgp::FlowSpecRule,
        origin: blackwall_rtbh::BlackholeOrigin,
        at_ms: u64,
    ) -> Result<(), blackwall_rtbh::JournalError> {
        let (dst, proto, port, rate) = flatten_flowspec(&rule);
        let o = match origin {
            blackwall_rtbh::BlackholeOrigin::Auto => "auto",
            blackwall_rtbh::BlackholeOrigin::Manual => "manual",
        };
        self.record_flowspec(dst, proto, port, rate, o, at_ms)
            .await
            .map_err(|e| blackwall_rtbh::JournalError(e.to_string()))
    }

    async fn record_withdraw(
        &self,
        rule: blackwall_bgp::FlowSpecRule,
        at_ms: u64,
    ) -> Result<(), blackwall_rtbh::JournalError> {
        let (dst, proto, port, _rate) = flatten_flowspec(&rule);
        // `only_auto = false` here is safe: the auto-vs-manual guard (never let
        // an auto-clear withdraw a manual rule) is enforced upstream in
        // `FlowSpecController` before this ever runs (mirrors the RTBH journal).
        self.clear_flowspec(dst, proto, port, at_ms, false)
            .await
            .map_err(|e| blackwall_rtbh::JournalError(e.to_string()))
    }
}

/// Flatten a [`blackwall_bgp::FlowSpecRule`] to the Store's `(dst, proto,
/// dst_port, rate)` scalar columns. The auto-mitigation path always sets
/// `protocol`/`dst_port` (a concentrated flow has both); absent components
/// default to `0`, matching how the mirror keys rows.
fn flatten_flowspec(rule: &blackwall_bgp::FlowSpecRule) -> (IpAddr, u8, u16, f32) {
    let dst = rule.dst.addr();
    let proto = rule.protocol.unwrap_or(0);
    let port = rule.dst_port.unwrap_or(0);
    let blackwall_bgp::FlowAction::TrafficRate(rate) = rule.action;
    (dst, proto, port, rate)
}

/// Map raw `rtbh_requests` rows into [`RtbhRequestRow`]s.
fn rows_to_requests(
    rows: Vec<(
        i64,
        sqlx::types::ipnetwork::IpNetwork,
        String,
        String,
        String,
        Option<String>,
    )>,
) -> Vec<RtbhRequestRow> {
    rows.into_iter()
        .map(
            |(id, target, action, created_by, status, note)| RtbhRequestRow {
                id,
                target: target.ip(),
                action,
                created_by,
                status,
                note,
            },
        )
        .collect()
}

#[async_trait::async_trait]
impl blackwall_rtbh::BlackholeJournal for Store {
    async fn record_announce(
        &self,
        target: IpAddr,
        origin: blackwall_rtbh::BlackholeOrigin,
        at_ms: u64,
    ) -> Result<(), blackwall_rtbh::JournalError> {
        let o = match origin {
            blackwall_rtbh::BlackholeOrigin::Auto => "auto",
            blackwall_rtbh::BlackholeOrigin::Manual => "manual",
        };
        self.record_blackhole(target, o, at_ms)
            .await
            .map_err(|e| blackwall_rtbh::JournalError(e.to_string()))
    }

    async fn record_withdraw(
        &self,
        target: IpAddr,
        at_ms: u64,
    ) -> Result<(), blackwall_rtbh::JournalError> {
        // `only_auto = false` here is safe: the auto-vs-manual guard (never
        // let an auto-clear withdraw a manually-added blackhole) is enforced
        // upstream, in `RtbhController::request_clear`, before this ever runs.
        self.clear_blackhole(target, at_ms, false)
            .await
            .map_err(|e| blackwall_rtbh::JournalError(e.to_string()))
    }
}

/// Convert an [`IpAddr`] into the `sqlx` INET wire type as a /32 or /128 host.
fn ipnetwork_addr(addr: IpAddr) -> sqlx::types::ipnetwork::IpNetwork {
    sqlx::types::ipnetwork::IpNetwork::from_str(&addr.to_string()).expect("host address is valid")
}

/// Map a [`Severity`] to its database text representation.
fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Warning => "warning",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// A [`MitigationSink`] that persists detection events to Postgres.
pub struct PgMitigationSink {
    store: Arc<Store>,
}

impl PgMitigationSink {
    /// Create a new sink wrapping `store`.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl MitigationSink for PgMitigationSink {
    async fn handle(&self, event: &DetectionEvent) {
        let res = match event {
            DetectionEvent::Opened(d) => self.store.open_detection(d).await,
            DetectionEvent::Updated(d) => {
                self.store
                    .update_detection(d.target, d.observed_pps, d.observed_bps, d.last_seen_ms)
                    .await
            }
            DetectionEvent::Cleared { target, at_ms } => {
                self.store.clear_detection(*target, *at_ms).await
            }
        };
        if let Err(err) = res {
            tracing::warn!(%err, "failed to persist detection event");
        } else if let DetectionEvent::Opened(d) = event {
            tracing::warn!(
                target = %d.target,
                pps = d.observed_pps,
                severity = ?d.severity,
                "attack detected"
            );
        }
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

    #[tokio::test]
    async fn apply_policy_persists_services_and_audit() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        let policy = blackwall_config_sample();
        let written = store.apply_policy(&policy, "test").await.expect("apply");
        assert_eq!(written, 2); // TCP-443 + UDP-53

        let services = store.list_services().await.expect("list");
        let tcp_svc = services
            .iter()
            .find(|s| s.port == 443)
            .expect("port 443 service");
        assert_eq!(tcp_svc.tenant, "acme");
        assert_eq!(tcp_svc.proto, L4Proto::Tcp);
        let udp_svc = services
            .iter()
            .find(|s| s.port == 53)
            .expect("port 53 service");
        assert_eq!(udp_svc.proto, L4Proto::Udp);

        let audit_after_first = store.audit_count().await.expect("count");
        assert!(audit_after_first >= 1);

        // Second apply: TRUNCATE replaced, not duplicated.
        let written2 = store.apply_policy(&policy, "test").await.expect("apply2");
        assert_eq!(written2, 2);
        let services2 = store.list_services().await.expect("list2");
        // After our second apply both services are present (TRUNCATE replaced all).
        let svc2 = services2
            .iter()
            .find(|s| s.port == 443)
            .expect("port 443 still present after second apply");
        assert_eq!(svc2.tenant, "acme");
        let audit_after_second = store.audit_count().await.expect("count2");
        assert!(
            audit_after_second > audit_after_first,
            "audit count must have grown by at least 1"
        );
    }

    #[tokio::test]
    async fn pool_accessor_returns_pool() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        // Just verify pool() doesn't panic; audit_count uses the pool.
        let _count = store.audit_count().await.expect("audit_count via pool()");
    }

    #[tokio::test]
    async fn detection_open_update_clear_roundtrip() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let t: IpAddr = "203.0.113.20".parse().unwrap();
        let d = sample_detection(t, 1_000, 1_000);
        store.open_detection(&d).await.unwrap();

        let row: (f64, f64, bool) = sqlx::query_as(
            "SELECT observed_pps, observed_bps, cleared_at IS NOT NULL FROM detections \
             WHERE target = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(ipnetwork_addr(t))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row.0, d.observed_pps);
        assert_eq!(row.1, d.observed_bps);
        assert!(!row.2, "freshly opened detection must not be cleared");

        store
            .update_detection(t, 90_000.0, 700_000_000.0, 2_000)
            .await
            .unwrap();
        let row: (f64, f64) = sqlx::query_as(
            "SELECT observed_pps, observed_bps FROM detections \
             WHERE target = $1 AND cleared_at IS NULL",
        )
        .bind(ipnetwork_addr(t))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row.0, 90_000.0);
        assert_eq!(row.1, 700_000_000.0);

        store.clear_detection(t, 3_000).await.unwrap();
        let cleared: (bool,) = sqlx::query_as(
            "SELECT cleared_at IS NOT NULL FROM detections \
             WHERE target = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(ipnetwork_addr(t))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(cleared.0, "detection must be cleared after clear_detection");

        // A second clear_detection is a harmless no-op: the WHERE clause
        // (cleared_at IS NULL) no longer matches any row for this target.
        store.clear_detection(t, 4_000).await.unwrap();
    }

    #[tokio::test]
    async fn pg_mitigation_sink_handles_opened_updated_cleared() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Arc::new(Store::connect(&url).await.unwrap());
        store.migrate().await.unwrap();
        let sink = PgMitigationSink::new(store.clone());
        let t: IpAddr = "203.0.113.21".parse().unwrap();

        let opened = sample_detection(t, 5_000, 5_000);
        sink.handle(&DetectionEvent::Opened(opened.clone())).await;
        let row: (f64, bool) = sqlx::query_as(
            "SELECT observed_pps, cleared_at IS NOT NULL FROM detections \
             WHERE target = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(ipnetwork_addr(t))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row.0, opened.observed_pps);
        assert!(!row.1, "Opened must insert an uncleared row");

        let mut updated = opened.clone();
        updated.observed_pps = 123_456.0;
        updated.observed_bps = 987_654.0;
        updated.last_seen_ms = 6_000;
        sink.handle(&DetectionEvent::Updated(updated.clone())).await;
        let row: (f64, f64) = sqlx::query_as(
            "SELECT observed_pps, observed_bps FROM detections \
             WHERE target = $1 AND cleared_at IS NULL",
        )
        .bind(ipnetwork_addr(t))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row.0, updated.observed_pps);
        assert_eq!(row.1, updated.observed_bps);

        sink.handle(&DetectionEvent::Cleared {
            target: t,
            at_ms: 7_000,
        })
        .await;
        let cleared: (bool,) = sqlx::query_as(
            "SELECT cleared_at IS NOT NULL FROM detections \
             WHERE target = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(ipnetwork_addr(t))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(cleared.0, "Cleared must mark the row cleared");
    }

    #[tokio::test]
    async fn records_and_counts_sessions() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let before = store.session_count().await.expect("count");
        store
            .record_session(&SessionRow {
                local_addr: "203.0.113.5".parse().unwrap(),
                local_port: 80,
                peer_addr: "198.51.100.9".parse().unwrap(),
                proto: "tcp".to_owned(),
                emulator: "http".to_owned(),
                bytes_in: 30,
                bytes_out: 200,
                note: Some("GET / HTTP/1.1".to_owned()),
            })
            .await
            .expect("record");
        assert_eq!(store.session_count().await.expect("count"), before + 1);
    }

    #[tokio::test]
    async fn records_and_counts_detections() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let before = store.detection_count().await.expect("count");
        let t: IpAddr = "203.0.113.21".parse().unwrap();
        store
            .open_detection(&sample_detection(t, 1_000, 1_000))
            .await
            .expect("open");
        assert_eq!(store.detection_count().await.expect("count"), before + 1);
    }

    #[tokio::test]
    async fn rtbh_blackhole_roundtrip() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let t: IpAddr = "203.0.113.7".parse().unwrap();
        store.record_blackhole(t, "auto", 1_000).await.unwrap();
        let active = store.list_active_blackholes().await.unwrap();
        assert!(active.iter().any(|r| r.target == t && r.origin == "auto"));
        // manual upsert must not downgrade origin:
        store.record_blackhole(t, "manual", 2_000).await.unwrap();
        store.record_blackhole(t, "auto", 3_000).await.unwrap(); // must NOT downgrade
        let active = store.list_active_blackholes().await.unwrap();
        assert_eq!(
            active.iter().find(|r| r.target == t).unwrap().origin,
            "manual"
        );
        store.clear_blackhole(t, 4_000, false).await.unwrap();
        assert!(!store
            .list_active_blackholes()
            .await
            .unwrap()
            .iter()
            .any(|r| r.target == t));
    }

    #[tokio::test]
    async fn rtbh_clear_only_auto_guards_manual() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let t: IpAddr = "203.0.113.70".parse().unwrap();
        store.record_blackhole(t, "manual", 1_000).await.unwrap();
        // only_auto=true must not clear a manual entry.
        store.clear_blackhole(t, 2_000, true).await.unwrap();
        assert!(store
            .list_active_blackholes()
            .await
            .unwrap()
            .iter()
            .any(|r| r.target == t));
        // only_auto=true does clear an auto entry.
        let t2: IpAddr = "203.0.113.71".parse().unwrap();
        store.record_blackhole(t2, "auto", 1_000).await.unwrap();
        store.clear_blackhole(t2, 2_000, true).await.unwrap();
        assert!(!store
            .list_active_blackholes()
            .await
            .unwrap()
            .iter()
            .any(|r| r.target == t2));
    }

    #[tokio::test]
    async fn rtbh_request_queue_roundtrip() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let id = store
            .enqueue_request("203.0.113.8".parse().unwrap(), "add", "op@host")
            .await
            .unwrap();
        let pending = store.pending_requests().await.unwrap();
        assert!(pending.iter().any(|r| r.id == id && r.action == "add"));
        store.set_request_status(id, "applied", None).await.unwrap();
        assert_eq!(
            store
                .list_requests(Some("applied"))
                .await
                .unwrap()
                .iter()
                .find(|r| r.id == id)
                .unwrap()
                .status,
            "applied"
        );
        assert!(
            !store
                .pending_requests()
                .await
                .unwrap()
                .iter()
                .any(|r| r.id == id),
            "an applied request must no longer appear in pending_requests"
        );
    }

    #[tokio::test]
    async fn rtbh_supersede_pending_adds() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let t: IpAddr = "203.0.113.11".parse().unwrap();
        let id = store.enqueue_request(t, "add", "op@host").await.unwrap();
        assert!(store
            .pending_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == id));

        let remove_id = store.enqueue_request(t, "remove", "op@host").await.unwrap();
        store.supersede_pending_adds(t, remove_id).await.unwrap();

        let row = store
            .list_requests(None)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.id == id)
            .unwrap();
        assert_eq!(row.status, "applied");
        assert_eq!(row.note.as_deref(), Some("superseded by remove"));
        assert!(
            !store
                .pending_requests()
                .await
                .unwrap()
                .iter()
                .any(|r| r.id == id),
            "superseded add must no longer be pending"
        );
    }

    /// A race: an operator re-adds a target in the window between a tick's
    /// `pending_requests()` snapshot and that tick processing an earlier
    /// `remove` for the same target. The newer add (id >= the remove's id)
    /// must survive; only adds strictly older than the remove are
    /// superseded.
    #[tokio::test]
    async fn rtbh_supersede_pending_adds_scoped_to_before_id() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let t: IpAddr = "203.0.113.12".parse().unwrap();

        let old_add_id = store.enqueue_request(t, "add", "op@host").await.unwrap();
        let remove_id = store.enqueue_request(t, "remove", "op@host").await.unwrap();
        // Simulates a re-add racing in after the remove's id was captured
        // (e.g. after a tick's pending_requests() snapshot already read the
        // remove) but before supersede_pending_adds runs.
        let new_add_id = store.enqueue_request(t, "add", "op@host").await.unwrap();

        store.supersede_pending_adds(t, remove_id).await.unwrap();

        let all = store.list_requests(None).await.unwrap();
        let old_add = all.iter().find(|r| r.id == old_add_id).unwrap();
        assert_eq!(
            old_add.status, "applied",
            "add before the remove's id must be superseded"
        );
        assert_eq!(old_add.note.as_deref(), Some("superseded by remove"));

        let new_add = all.iter().find(|r| r.id == new_add_id).unwrap();
        assert_eq!(
            new_add.status, "pending",
            "add with id >= before_id must NOT be superseded (it raced in after the remove)"
        );
    }

    #[tokio::test]
    async fn rtbh_request_status_note_and_unfiltered_list() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let id = store
            .enqueue_request("203.0.113.9".parse().unwrap(), "remove", "op2@host")
            .await
            .unwrap();
        store
            .set_request_status(id, "rejected", Some("out of prefix"))
            .await
            .unwrap();
        let all = store.list_requests(None).await.unwrap();
        let row = all.iter().find(|r| r.id == id).unwrap();
        assert_eq!(row.status, "rejected");
        assert_eq!(row.note.as_deref(), Some("out of prefix"));
        assert_eq!(row.action, "remove");
        assert_eq!(row.created_by, "op2@host");
    }

    #[tokio::test]
    async fn rtbh_blackhole_journal_impl() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        use blackwall_rtbh::BlackholeJournal;
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let t: IpAddr = "203.0.113.10".parse().unwrap();
        store
            .record_announce(t, blackwall_rtbh::BlackholeOrigin::Auto, 1_000)
            .await
            .unwrap();
        assert!(store
            .list_active_blackholes()
            .await
            .unwrap()
            .iter()
            .any(|r| r.target == t && r.origin == "auto"));
        store
            .record_announce(t, blackwall_rtbh::BlackholeOrigin::Manual, 2_000)
            .await
            .unwrap();
        assert_eq!(
            store
                .list_active_blackholes()
                .await
                .unwrap()
                .iter()
                .find(|r| r.target == t)
                .unwrap()
                .origin,
            "manual"
        );
        store.record_withdraw(t, 3_000).await.unwrap();
        assert!(!store
            .list_active_blackholes()
            .await
            .unwrap()
            .iter()
            .any(|r| r.target == t));
    }

    #[tokio::test]
    async fn flowspec_record_list_clear_roundtrip() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let dst: IpAddr = "203.0.113.7".parse().unwrap();
        store
            .record_flowspec(dst, 17, 53, 0.0, "auto", 1_000)
            .await
            .unwrap();
        let active = store.list_active_flowspec().await.unwrap();
        let row = active.iter().find(|r| r.dst == dst).expect("row present");
        assert_eq!(row.proto, 17);
        assert_eq!(row.dst_port, 53);
        assert_eq!(row.rate, 0.0);
        assert_eq!(row.origin, "auto");
        store
            .clear_flowspec(dst, 17, 53, 2_000, false)
            .await
            .unwrap();
        assert!(!store
            .list_active_flowspec()
            .await
            .unwrap()
            .iter()
            .any(|r| r.dst == dst));
    }

    #[tokio::test]
    async fn flowspec_no_downgrade_manual_to_auto() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let dst: IpAddr = "203.0.113.8".parse().unwrap();
        store
            .record_flowspec(dst, 6, 443, 0.0, "manual", 1_000)
            .await
            .unwrap();
        // Re-announcing as auto must NOT downgrade the manual origin.
        store
            .record_flowspec(dst, 6, 443, 0.0, "auto", 1_500)
            .await
            .unwrap();
        let active = store.list_active_flowspec().await.unwrap();
        assert_eq!(
            active.iter().find(|r| r.dst == dst).unwrap().origin,
            "manual"
        );
    }

    #[tokio::test]
    async fn flowspec_clear_only_auto_keeps_manual() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let dst: IpAddr = "203.0.113.9".parse().unwrap();
        store
            .record_flowspec(dst, 6, 80, 0.0, "manual", 1_000)
            .await
            .unwrap();
        // only_auto=true must not clear a manual entry.
        store.clear_flowspec(dst, 6, 80, 2_000, true).await.unwrap();
        assert!(store
            .list_active_flowspec()
            .await
            .unwrap()
            .iter()
            .any(|r| r.dst == dst));
    }

    #[tokio::test]
    async fn flowspec_request_queue_and_supersede() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let dst: IpAddr = "203.0.113.10".parse().unwrap();
        let add_id = store
            .enqueue_flowspec_request(dst, 17, 53, 0.0, "add", "op")
            .await
            .unwrap();
        let rm_id = store
            .enqueue_flowspec_request(dst, 17, 53, 0.0, "remove", "op")
            .await
            .unwrap();
        let pending = store.pending_flowspec_requests().await.unwrap();
        assert!(pending.iter().any(|r| r.id == add_id && r.action == "add"));
        assert!(pending
            .iter()
            .any(|r| r.id == rm_id && r.action == "remove"));

        store
            .supersede_pending_flowspec_adds(dst, 17, 53, rm_id)
            .await
            .unwrap();
        // The earlier add is now 'applied'; only the remove stays pending.
        let pending = store.pending_flowspec_requests().await.unwrap();
        assert!(
            !pending.iter().any(|r| r.id == add_id),
            "superseded add must no longer be pending"
        );
        assert!(pending.iter().any(|r| r.id == rm_id));
        let superseded = store
            .list_flowspec_requests(None)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.id == add_id)
            .unwrap();
        assert_eq!(superseded.status, "applied");
        assert_eq!(superseded.note.as_deref(), Some("superseded by remove"));

        store
            .set_flowspec_request_status(rm_id, "applied", None)
            .await
            .unwrap();
        assert!(!store
            .pending_flowspec_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == rm_id));
    }

    #[tokio::test]
    async fn flowspec_journal_impl() {
        let Some(url) = test_url() else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        use blackwall_rtbh::FlowSpecJournal;
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let dst: IpAddr = "203.0.113.13".parse().unwrap();
        let rule = blackwall_bgp::FlowSpecRule {
            dst: "203.0.113.13/32".parse().unwrap(),
            protocol: Some(17),
            dst_port: Some(53),
            action: blackwall_bgp::FlowAction::TrafficRate(0.0),
        };
        store
            .record_announce(rule.clone(), blackwall_rtbh::BlackholeOrigin::Auto, 1_000)
            .await
            .unwrap();
        assert!(store
            .list_active_flowspec()
            .await
            .unwrap()
            .iter()
            .any(|r| r.dst == dst && r.proto == 17 && r.dst_port == 53 && r.origin == "auto"));
        store
            .record_announce(rule.clone(), blackwall_rtbh::BlackholeOrigin::Manual, 2_000)
            .await
            .unwrap();
        assert_eq!(
            store
                .list_active_flowspec()
                .await
                .unwrap()
                .iter()
                .find(|r| r.dst == dst)
                .unwrap()
                .origin,
            "manual"
        );
        store.record_withdraw(rule, 3_000).await.unwrap();
        assert!(!store
            .list_active_flowspec()
            .await
            .unwrap()
            .iter()
            .any(|r| r.dst == dst));
    }

    #[test]
    fn state_error_display_policy() {
        use blackwall_core::PolicyError;
        let inner = PolicyError::AddressOutsidePrefixes("10.0.0.1".parse().unwrap());
        let e = StateError::Policy(inner);
        assert!(e.to_string().contains("invalid policy"));
    }

    #[test]
    fn state_error_display_db() {
        let inner = sqlx::Error::RowNotFound;
        let e = StateError::Db(inner);
        let s = e.to_string();
        assert!(s.contains("database error"), "got: {s}");
    }

    #[test]
    fn session_row_clone_and_eq() {
        let row = SessionRow {
            local_addr: "203.0.113.1".parse().unwrap(),
            local_port: 22,
            peer_addr: "198.51.100.1".parse().unwrap(),
            proto: "tcp".to_owned(),
            emulator: "generic".to_owned(),
            bytes_in: 0,
            bytes_out: 42,
            note: None,
        };
        let row2 = row.clone();
        assert_eq!(row, row2);
    }

    /// Build a sample [`Detection`] for `target`, with fixed source/port
    /// breakdowns and `Critical` severity — enough to exercise the
    /// `top_sources`/`top_ports` JSON encoding on insert.
    fn sample_detection(target: IpAddr, first_seen_ms: u64, last_seen_ms: u64) -> Detection {
        Detection {
            target,
            kind: blackwall_flow::AttackKind::Volumetric,
            observed_pps: 50_000.0,
            observed_bps: 400_000_000.0,
            proto: 17,
            top_sources: vec![("198.51.100.5".parse().unwrap(), 40_000.0)],
            top_ports: vec![(53, 40_000.0)],
            severity: Severity::Critical,
            first_seen_ms,
            last_seen_ms,
        }
    }

    fn blackwall_config_sample() -> Policy {
        use blackwall_core::{AllowRule, ServiceTarget, Tenant};
        Policy {
            interface: "eth0".to_owned(),
            prefixes: vec!["203.0.113.0/24".parse().expect("prefix")],
            default_state: blackwall_core::PortState::Deception,
            tenants: vec![Tenant {
                name: "acme".to_owned(),
                owned: vec!["203.0.113.5".parse().expect("ip")],
                allows: vec![
                    AllowRule {
                        proto: L4Proto::Tcp,
                        port: 443,
                        target: ServiceTarget::Host,
                    },
                    AllowRule {
                        proto: L4Proto::Udp,
                        port: 53,
                        target: ServiceTarget::Host,
                    },
                ],
            }],
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
            rtbh: None,
            flowspec: None,
            metrics_listen: None,
        }
    }
}
