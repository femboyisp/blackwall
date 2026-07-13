//! Read-only axum handlers, generic over `AppState`.

use crate::dto::{
    AuditDto, DetectionDto, FlowSpecDto, IpAssignmentDto, RtbhDto, ServiceDto, SessionDto,
    TenantDto, XdpDto,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

/// Default row cap for the `sessions`/`audit` feeds.
const DEFAULT_LIMIT: i64 = 100;

/// Upper bound on the `sessions`/`audit` feed `?limit=`, regardless of what
/// the caller requests.
const MAX_LIMIT: i64 = 1000;

/// Clamp a requested feed `limit` to `[1, MAX_LIMIT]`, defaulting to
/// `DEFAULT_LIMIT` when absent.
///
/// Guards the `LIMIT $1` bind in the feed queries: a negative or zero value
/// would otherwise reach Postgres and error out, and an unbounded value
/// would dump the entire table.
fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// `?limit=` query for the capped feeds.
#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    /// Maximum number of rows to return; defaults to `DEFAULT_LIMIT` (100).
    limit: Option<i64>,
}

/// Shorthand for the `AppState` extractor shared by every handler.
type St = State<Arc<dyn AppState>>;

/// `GET /v1/tenants` — every tenant and the addresses it owns.
#[utoipa::path(
    get, path = "/v1/tenants",
    responses((status = 200, description = "All tenants", body = [TenantDto])),
    security(("bearer" = []))
)]
pub async fn list_tenants(State(s): St) -> ApiResult<Json<Vec<TenantDto>>> {
    Ok(Json(
        s.tenants()
            .await?
            .into_iter()
            .map(TenantDto::from)
            .collect(),
    ))
}

/// `GET /v1/tenants/{name}` — a single tenant; 404 if unknown.
#[utoipa::path(
    get, path = "/v1/tenants/{name}",
    params(("name" = String, Path, description = "Tenant name")),
    responses(
        (status = 200, description = "The tenant", body = TenantDto),
        (status = 404, description = "Unknown tenant")
    ),
    security(("bearer" = []))
)]
pub async fn get_tenant(State(s): St, Path(name): Path<String>) -> ApiResult<Json<TenantDto>> {
    let t = s.tenants().await?.into_iter().find(|t| t.name == name);
    t.map(|t| Json(TenantDto::from(t)))
        .ok_or(ApiError::NotFound(name))
}

/// `GET /v1/tenants/{name}/services` — services owned by the tenant; 404 if
/// the tenant is unknown.
#[utoipa::path(
    get, path = "/v1/tenants/{name}/services",
    params(("name" = String, Path, description = "Tenant name")),
    responses(
        (status = 200, description = "Services owned by the tenant", body = [ServiceDto]),
        (status = 404, description = "Unknown tenant")
    ),
    security(("bearer" = []))
)]
pub async fn tenant_services(
    State(s): St,
    Path(name): Path<String>,
) -> ApiResult<Json<Vec<ServiceDto>>> {
    if !s.tenants().await?.iter().any(|t| t.name == name) {
        return Err(ApiError::NotFound(name));
    }
    let out = s
        .services()
        .await?
        .into_iter()
        .filter(|svc| svc.tenant == name)
        .map(ServiceDto::from)
        .collect();
    Ok(Json(out))
}

/// `GET /v1/tenants/{name}/ip-assignments` — addresses assigned to the
/// tenant; 404 if the tenant is unknown.
#[utoipa::path(
    get, path = "/v1/tenants/{name}/ip-assignments",
    params(("name" = String, Path, description = "Tenant name")),
    responses(
        (status = 200, description = "Addresses assigned to the tenant", body = [IpAssignmentDto]),
        (status = 404, description = "Unknown tenant")
    ),
    security(("bearer" = []))
)]
pub async fn tenant_ip_assignments(
    State(s): St,
    Path(name): Path<String>,
) -> ApiResult<Json<Vec<IpAssignmentDto>>> {
    if !s.tenants().await?.iter().any(|t| t.name == name) {
        return Err(ApiError::NotFound(name));
    }
    let out = s
        .ip_assignments()
        .await?
        .into_iter()
        .filter(|a| a.tenant == name)
        .map(IpAssignmentDto::from)
        .collect();
    Ok(Json(out))
}

/// `GET /v1/mitigations/rtbh` — active RTBH blackholes.
#[utoipa::path(
    get, path = "/v1/mitigations/rtbh",
    responses((status = 200, description = "Active RTBH blackholes", body = [RtbhDto])),
    security(("bearer" = []))
)]
pub async fn list_rtbh(State(s): St) -> ApiResult<Json<Vec<RtbhDto>>> {
    Ok(Json(
        s.rtbh().await?.into_iter().map(RtbhDto::from).collect(),
    ))
}

/// `GET /v1/mitigations/flowspec` — active FlowSpec rules.
#[utoipa::path(
    get, path = "/v1/mitigations/flowspec",
    responses((status = 200, description = "Active FlowSpec rules", body = [FlowSpecDto])),
    security(("bearer" = []))
)]
pub async fn list_flowspec(State(s): St) -> ApiResult<Json<Vec<FlowSpecDto>>> {
    Ok(Json(
        s.flowspec()
            .await?
            .into_iter()
            .map(FlowSpecDto::from)
            .collect(),
    ))
}

/// `GET /v1/mitigations/xdp` — active XDP block / rate-limit entries.
#[utoipa::path(
    get, path = "/v1/mitigations/xdp",
    responses((status = 200, description = "Active XDP block / rate-limit entries", body = [XdpDto])),
    security(("bearer" = []))
)]
pub async fn list_xdp(State(s): St) -> ApiResult<Json<Vec<XdpDto>>> {
    Ok(Json(s.xdp().await?.into_iter().map(XdpDto::from).collect()))
}

/// `GET /v1/detections` — active volumetric detections.
#[utoipa::path(
    get, path = "/v1/detections",
    responses((status = 200, description = "Active volumetric detections", body = [DetectionDto])),
    security(("bearer" = []))
)]
pub async fn list_detections(State(s): St) -> ApiResult<Json<Vec<DetectionDto>>> {
    Ok(Json(
        s.detections()
            .await?
            .into_iter()
            .map(DetectionDto::from)
            .collect(),
    ))
}

/// `GET /v1/sessions?limit=` — most-recent deception sessions, capped at
/// `limit` (default `DEFAULT_LIMIT`, currently 100).
#[utoipa::path(
    get, path = "/v1/sessions",
    params(("limit" = Option<i64>, Query, description = "Maximum rows to return (default 100)")),
    responses((status = 200, description = "Most-recent deception sessions", body = [SessionDto])),
    security(("bearer" = []))
)]
pub async fn list_sessions(
    State(s): St,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<SessionDto>>> {
    let limit = clamp_limit(q.limit);
    Ok(Json(
        s.sessions(limit)
            .await?
            .into_iter()
            .map(SessionDto::from)
            .collect(),
    ))
}

/// `GET /v1/audit?limit=` — most-recent audit-log entries, capped at `limit`
/// (default `DEFAULT_LIMIT`, currently 100).
#[utoipa::path(
    get, path = "/v1/audit",
    params(("limit" = Option<i64>, Query, description = "Maximum rows to return (default 100)")),
    responses((status = 200, description = "Most-recent audit-log entries", body = [AuditDto])),
    security(("bearer" = []))
)]
pub async fn list_audit(
    State(s): St,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<AuditDto>>> {
    let limit = clamp_limit(q.limit);
    Ok(Json(
        s.audit(limit)
            .await?
            .into_iter()
            .map(AuditDto::from)
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_clamped() {
        assert_eq!(clamp_limit(Some(-1)), 1);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(i64::MAX)), MAX_LIMIT);
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(50)), 50);
    }
}
