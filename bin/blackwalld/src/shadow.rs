//! Concrete shadow recorder: logs, meters, and audit-logs intended mitigations.
//! I/O glue — coverage-excluded.

use blackwall_rtbh::{ShadowAction, ShadowRecorder};
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
