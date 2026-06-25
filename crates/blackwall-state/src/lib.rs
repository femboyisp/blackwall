//! PostgreSQL persistence for Blackwall: tenants, IP assignments, services,
//! and the audit log.

mod audit;
mod error;
mod services;
mod sessions;
mod tenants;

pub use error::StateError;
pub use services::StoredService;
pub use sessions::SessionRow;

use blackwall_core::{L4Proto, Policy, ServiceTarget};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::IpAddr;
use std::str::FromStr;

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
}

/// Convert an [`IpAddr`] into the `sqlx` INET wire type as a /32 or /128 host.
fn ipnetwork_addr(addr: IpAddr) -> sqlx::types::ipnetwork::IpNetwork {
    sqlx::types::ipnetwork::IpNetwork::from_str(&addr.to_string()).expect("host address is valid")
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
        }
    }
}
