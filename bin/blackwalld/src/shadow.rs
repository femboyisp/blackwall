//! Concrete shadow recorder: logs, meters, and audit-logs intended mitigations.
//! I/O glue — coverage-excluded.

use blackwall_rtbh::{ShadowAction, ShadowRecorder};
use blackwall_xdp::{XdpAction, XdpExecError, XdpExecutor};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Per-(plane, action) counters backing the `blackwall_shadow_would_mitigate_total`
/// metric. Shared (behind an `Arc`) across the RTBH manager, the FlowSpec
/// manager, the XDP shadow gate, and the `/metrics` endpoint.
#[derive(Default)]
pub struct ShadowMetrics {
    /// RTBH blackhole announcements that would have been sent.
    pub rtbh_announce: AtomicU64,
    /// RTBH blackhole withdrawals that would have been sent.
    pub rtbh_withdraw: AtomicU64,
    /// FlowSpec rule announcements that would have been sent.
    pub flowspec_announce: AtomicU64,
    /// FlowSpec rule withdrawals that would have been sent.
    pub flowspec_withdraw: AtomicU64,
    /// XDP blocks that would have been installed.
    pub xdp_block: AtomicU64,
    /// XDP rate limits that would have been installed.
    pub xdp_rate_limit: AtomicU64,
}

/// Records shadow actions to the audit log + metrics + INFO log.
///
/// Wired in place of a real `BgpExecutor`/journal pair (via
/// [`blackwall_rtbh::ShadowBgpExecutor`]) when the `shadow` config directive
/// is set: every mitigation the manager would have applied is logged,
/// counted, and durably audited instead of reaching a real BGP session.
pub struct AuditShadowRecorder {
    store: Arc<blackwall_state::Store>,
    metrics: Arc<ShadowMetrics>,
}

impl AuditShadowRecorder {
    /// Build a recorder that audits to `store` and meters into `metrics`.
    pub fn new(store: Arc<blackwall_state::Store>, metrics: Arc<ShadowMetrics>) -> Self {
        Self { store, metrics }
    }
}

#[async_trait::async_trait]
impl ShadowRecorder for AuditShadowRecorder {
    async fn record(&self, action: ShadowAction) {
        let (plane, verb, target, counter): (&str, &str, String, &AtomicU64) = match &action {
            ShadowAction::RtbhAnnounce(r) => (
                "rtbh",
                "announce",
                format!("{r:?}"),
                &self.metrics.rtbh_announce,
            ),
            ShadowAction::RtbhWithdraw(p) => (
                "rtbh",
                "withdraw",
                p.to_string(),
                &self.metrics.rtbh_withdraw,
            ),
            ShadowAction::FlowSpecAnnounce(r) => (
                "flowspec",
                "announce",
                format!("{r:?}"),
                &self.metrics.flowspec_announce,
            ),
            ShadowAction::FlowSpecWithdraw(r) => (
                "flowspec",
                "withdraw",
                format!("{r:?}"),
                &self.metrics.flowspec_withdraw,
            ),
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            plane,
            verb,
            target = %target,
            "shadow: would mitigate (logged, not applied)"
        );
        let detail = serde_json::json!({ "plane": plane, "verb": verb, "target": target });
        if let Err(err) = self
            .store
            .record_audit("shadow", &format!("shadow.{plane}.{verb}"), &detail)
            .await
        {
            tracing::warn!(%err, "shadow: audit write failed (mitigation still suppressed)");
        }
    }
}

/// [`XdpExecutor`] used in place of the live eBPF map writer when the
/// `shadow` config directive is set: install actions (`Block`/`RateLimit`)
/// are logged, metered into [`ShadowMetrics`], and audit-logged instead of
/// touching a map; removal actions (`Unblock`/`ClearRate`) are pure no-ops,
/// since shadow mode never installed anything for them to remove.
pub struct ShadowXdpExecutor {
    store: Arc<blackwall_state::Store>,
    metrics: Arc<ShadowMetrics>,
}

impl ShadowXdpExecutor {
    /// Build an executor that audits to `store` and meters into `metrics`.
    pub fn new(store: Arc<blackwall_state::Store>, metrics: Arc<ShadowMetrics>) -> Self {
        Self { store, metrics }
    }
}

#[async_trait::async_trait]
impl XdpExecutor for ShadowXdpExecutor {
    async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError> {
        match action {
            XdpAction::Block { net } => {
                self.metrics.xdp_block.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    plane = "xdp",
                    verb = "block",
                    target = %net,
                    "shadow: would mitigate (not applied)"
                );
                let detail =
                    serde_json::json!({"plane": "xdp", "verb": "block", "target": net.to_string()});
                if let Err(err) = self
                    .store
                    .record_audit("shadow", "shadow.xdp.block", &detail)
                    .await
                {
                    tracing::warn!(%err, "shadow: audit write failed (mitigation still suppressed)");
                }
            }
            XdpAction::RateLimit {
                src,
                pps,
                burst,
                victim,
            } => {
                self.metrics.xdp_rate_limit.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    plane = "xdp",
                    verb = "rate_limit",
                    target = %src,
                    pps,
                    burst,
                    victim = victim.map(|v| v.to_string()),
                    "shadow: would mitigate (not applied)"
                );
                let detail = serde_json::json!({
                    "plane": "xdp",
                    "verb": "rate_limit",
                    "target": src.to_string(),
                    "pps": pps,
                    "burst": burst,
                    "victim": victim.map(|v| v.to_string()),
                });
                if let Err(err) = self
                    .store
                    .record_audit("shadow", "shadow.xdp.rate_limit", &detail)
                    .await
                {
                    tracing::warn!(%err, "shadow: audit write failed (mitigation still suppressed)");
                }
            }
            XdpAction::Unblock { net } => {
                tracing::debug!(
                    plane = "xdp",
                    verb = "unblock",
                    target = %net,
                    "shadow: no-op (nothing was ever installed)"
                );
            }
            XdpAction::ClearRate { src } => {
                tracing::debug!(
                    plane = "xdp",
                    verb = "clear_rate",
                    target = %src,
                    "shadow: no-op (nothing was ever installed)"
                );
            }
        }
        Ok(())
    }
}

/// Selects between the live eBPF map writer and [`ShadowXdpExecutor`] at
/// construction time, so [`crate::DaemonXdpManager`]'s single `XdpManager`
/// type serves both live and shadow sessions — every apply call site
/// (detections, manual CLI requests, restart rehydration) is gated by
/// whichever variant is installed, with no per-call-site branching.
pub enum XdpExec {
    /// Writes straight to the live eBPF maps.
    Live(Arc<blackwall_xdp::XdpDataplane>),
    /// Shadow mode: records + meters, never touches a map.
    Shadow(ShadowXdpExecutor),
}

#[async_trait::async_trait]
impl XdpExecutor for XdpExec {
    async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError> {
        match self {
            Self::Live(dataplane) => dataplane.apply(action).await,
            Self::Shadow(shadow) => shadow.apply(action).await,
        }
    }
}
