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
use utoipa::OpenApi;

/// Registers the `bearer` HTTP security scheme referenced by every path.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
            );
        }
    }
}

/// The generated OpenAPI 3.1 document for the control API.
#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    paths(
        handlers::list_tenants,
        handlers::get_tenant,
        handlers::tenant_services,
        handlers::tenant_ip_assignments,
        handlers::list_rtbh,
        handlers::list_flowspec,
        handlers::list_xdp,
        handlers::list_detections,
        handlers::list_sessions,
        handlers::list_audit
    ),
    components(schemas(
        dto::TenantDto,
        dto::ServiceDto,
        dto::IpAssignmentDto,
        dto::RtbhDto,
        dto::FlowSpecDto,
        dto::XdpDto,
        dto::DetectionDto,
        dto::SessionDto,
        dto::AuditDto
    )),
    info(title = "Blackwall Control API", version = "1.0.0")
)]
pub struct ApiDoc;

/// Serves the generated OpenAPI document as JSON.
async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

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
        .route("/v1/openapi.json", get(openapi_json))
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            require_bearer,
        ))
        .with_state(state)
}
