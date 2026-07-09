//! Concrete `AppState` backed by the shared `Store`, plus the API bind loop.
//! I/O glue — excluded from coverage like `metrics.rs`.

use blackwall_api::error::ApiError;
use blackwall_api::state::*;
use blackwall_api::{router, AppState, AuthConfig};
use blackwall_core::{ApiConfig, ServiceTarget};
use blackwall_state::Store;
use std::sync::Arc;

/// Concrete [`AppState`] backed by the shared Postgres-backed [`Store`].
///
/// Every method is a thin field-by-field mapping from a `Store` read method's
/// row type to the corresponding `*View` the API handlers serialize.
pub struct StoreAppState {
    store: Arc<Store>,
}

impl StoreAppState {
    /// Wrap a shared `Store` handle as an `AppState`.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

/// Map any `Store` read failure to [`ApiError::Internal`]; the detail is
/// logged by the error's `IntoResponse` impl but never returned to the client.
fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// Render a [`ServiceTarget`] using the same syntax the config parser accepts
/// (see `blackwall_config::parser::parse_target`): `"host"`, `"incus:NAME"`,
/// or `"nat:IP:PORT"`.
fn render_target(target: &ServiceTarget) -> String {
    match target {
        ServiceTarget::Host => "host".to_owned(),
        ServiceTarget::Incus(name) => format!("incus:{name}"),
        ServiceTarget::Nat(addr) => format!("nat:{addr}"),
    }
}

#[async_trait::async_trait]
impl AppState for StoreAppState {
    async fn tenants(&self) -> Result<Vec<TenantView>, ApiError> {
        let rows = self.store.list_tenants().await.map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|(name, owned)| TenantView { name, owned })
            .collect())
    }

    async fn services(&self) -> Result<Vec<ServiceView>, ApiError> {
        let rows = self.store.list_services().await.map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|svc| ServiceView {
                tenant: svc.tenant,
                address: svc.address,
                proto: svc.proto.to_string(),
                port: svc.port,
                target: render_target(&svc.target),
            })
            .collect())
    }

    async fn ip_assignments(&self) -> Result<Vec<IpAssignmentView>, ApiError> {
        let rows = self.store.list_ip_assignments().await.map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|(tenant, address)| IpAssignmentView { tenant, address })
            .collect())
    }

    async fn rtbh(&self) -> Result<Vec<RtbhView>, ApiError> {
        let rows = self
            .store
            .list_active_blackholes()
            .await
            .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| RtbhView {
                target: row.target,
                origin: row.origin,
                announced_at_ms: row.announced_at_ms,
                withdrawn_at_ms: row.withdrawn_at_ms,
            })
            .collect())
    }

    async fn flowspec(&self) -> Result<Vec<FlowSpecView>, ApiError> {
        let rows = self.store.list_active_flowspec().await.map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| FlowSpecView {
                dst: row.dst,
                proto: row.proto,
                dst_port: row.dst_port,
                rate: row.rate,
                origin: row.origin,
                announced_at_ms: row.announced_at_ms,
                withdrawn_at_ms: row.withdrawn_at_ms,
            })
            .collect())
    }

    async fn xdp(&self) -> Result<Vec<XdpView>, ApiError> {
        let rows = self.store.xdp_active().await.map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| XdpView {
                kind: row.kind,
                target: row.target,
                prefixlen: row.prefixlen,
                rate_pps: row.rate_pps,
                burst: row.burst,
                origin: row.origin,
                victim: row.victim,
            })
            .collect())
    }

    async fn detections(&self) -> Result<Vec<DetectionView>, ApiError> {
        let rows = self
            .store
            .list_active_detections()
            .await
            .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| DetectionView {
                target: row.target,
                observed_pps: row.observed_pps,
                observed_bps: row.observed_bps,
                severity: row.severity,
                first_seen_ms: row.first_seen_ms,
                last_seen_ms: row.last_seen_ms,
            })
            .collect())
    }

    async fn sessions(&self, limit: i64) -> Result<Vec<SessionView>, ApiError> {
        let rows = self
            .store
            .list_recent_sessions(limit)
            .await
            .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| SessionView {
                local_addr: row.local_addr,
                local_port: row.local_port,
                peer_addr: row.peer_addr,
                proto: row.proto,
                emulator: row.emulator,
                bytes_in: row.bytes_in,
                bytes_out: row.bytes_out,
                note: row.note,
            })
            .collect())
    }

    async fn audit(&self, limit: i64) -> Result<Vec<AuditView>, ApiError> {
        let rows = self
            .store
            .list_recent_audit(limit)
            .await
            .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| AuditView {
                at_ms: row.at_ms,
                actor: row.actor,
                action: row.action,
                detail: row.detail,
            })
            .collect())
    }
}

/// Load the bearer token (first line of the token file), build the router, and
/// serve until the process exits. A bind failure disables the API and is logged.
pub async fn serve_api(cfg: ApiConfig, store: Arc<Store>) {
    let token = match std::fs::read_to_string(&cfg.token_file) {
        Ok(s) => s.lines().next().unwrap_or_default().trim().to_owned(),
        Err(e) => {
            tracing::error!(%e, path = %cfg.token_file.display(), "api: token file unreadable; API disabled");
            return;
        }
    };
    if token.is_empty() {
        tracing::error!("api: token file empty; API disabled");
        return;
    }
    let auth = Arc::new(AuthConfig::new("admin", &token));
    let state: Arc<dyn AppState> = Arc::new(StoreAppState::new(store));
    let app = router(state, auth);
    let listener = match tokio::net::TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%e, listen = %cfg.listen, "api: bind failed; API disabled");
            return;
        }
    };
    tracing::info!(listen = %cfg.listen, "control API listening");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "api: server exited");
    }
}
