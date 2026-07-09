//! Blackwall operations control API (axum). Phase 1: read-only endpoints.
#![forbid(unsafe_code)]

pub mod auth;
pub mod dto;
pub mod error;
pub mod handlers;
pub mod state;
#[cfg(any(test, feature = "testutil"))]
pub mod testutil;

use std::sync::Arc;

pub use auth::{require_bearer, AuthConfig};
pub use error::{ApiError, ApiResult};
pub use state::AppState;

use axum::routing::get;
use axum::Router;

/// Build the fully-wired, auth-guarded read-only API router.
pub fn router(state: Arc<dyn AppState>, auth: Arc<AuthConfig>) -> Router {
    Router::new()
        .route("/v1/tenants", get(handlers::list_tenants))
        .route("/v1/tenants/{name}", get(handlers::get_tenant))
        .route(
            "/v1/tenants/{name}/services",
            get(handlers::tenant_services),
        )
        .route(
            "/v1/tenants/{name}/ip-assignments",
            get(handlers::tenant_ip_assignments),
        )
        .route("/v1/mitigations/rtbh", get(handlers::list_rtbh))
        .route("/v1/mitigations/flowspec", get(handlers::list_flowspec))
        .route("/v1/mitigations/xdp", get(handlers::list_xdp))
        .route("/v1/detections", get(handlers::list_detections))
        .route("/v1/sessions", get(handlers::list_sessions))
        .route("/v1/audit", get(handlers::list_audit))
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            require_bearer,
        ))
        .with_state(state)
}
