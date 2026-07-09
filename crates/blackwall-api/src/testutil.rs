//! In-memory `AppState` for handler tests — no database, no kernel.

use crate::error::ApiResult;
use crate::state::*;
use async_trait::async_trait;

/// A fake `AppState` returning fixed vectors. Fields are public so each test
/// sets exactly the rows it needs.
#[derive(Default)]
pub struct FakeState {
    /// Rows returned by `tenants()`.
    pub tenants: Vec<TenantView>,
    /// Rows returned by `services()`.
    pub services: Vec<ServiceView>,
    /// Rows returned by `ip_assignments()`.
    pub ip_assignments: Vec<IpAssignmentView>,
    /// Rows returned by `rtbh()`.
    pub rtbh: Vec<RtbhView>,
    /// Rows returned by `flowspec()`.
    pub flowspec: Vec<FlowSpecView>,
    /// Rows returned by `xdp()`.
    pub xdp: Vec<XdpView>,
    /// Rows returned by `detections()`.
    pub detections: Vec<DetectionView>,
    /// Rows returned by `sessions()`, truncated to the requested limit.
    pub sessions: Vec<SessionView>,
    /// Rows returned by `audit()`, truncated to the requested limit.
    pub audit: Vec<AuditView>,
}

#[async_trait]
impl AppState for FakeState {
    async fn tenants(&self) -> ApiResult<Vec<TenantView>> {
        Ok(self.tenants.clone())
    }

    async fn services(&self) -> ApiResult<Vec<ServiceView>> {
        Ok(self.services.clone())
    }

    async fn ip_assignments(&self) -> ApiResult<Vec<IpAssignmentView>> {
        Ok(self.ip_assignments.clone())
    }

    async fn rtbh(&self) -> ApiResult<Vec<RtbhView>> {
        Ok(self.rtbh.clone())
    }

    async fn flowspec(&self) -> ApiResult<Vec<FlowSpecView>> {
        Ok(self.flowspec.clone())
    }

    async fn xdp(&self) -> ApiResult<Vec<XdpView>> {
        Ok(self.xdp.clone())
    }

    async fn detections(&self) -> ApiResult<Vec<DetectionView>> {
        Ok(self.detections.clone())
    }

    async fn sessions(&self, limit: i64) -> ApiResult<Vec<SessionView>> {
        let n = usize::try_from(limit.max(0)).unwrap_or(0);
        Ok(self.sessions.iter().take(n).cloned().collect())
    }

    async fn audit(&self, limit: i64) -> ApiResult<Vec<AuditView>> {
        let n = usize::try_from(limit.max(0)).unwrap_or(0);
        Ok(self.audit.iter().take(n).cloned().collect())
    }
}
