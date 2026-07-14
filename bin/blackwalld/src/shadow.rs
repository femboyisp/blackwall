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

/// Per-plane counters backing the `blackwall_mitigations_protected_skipped_total`
/// metric (C1 anycast self-protection: RTBH/FlowSpec/XDP each skip a target
/// that falls inside a configured `protected_prefixes` entry, own VIP,
/// before ever reaching eligibility). Unlike [`ShadowMetrics`], this fires in
/// BOTH shadow and live sessions — the guard runs inside each pure
/// controller itself, so it applies regardless of mode. Built unconditionally
/// (harmless all-zero counters when RTBH/FlowSpec/XDP aren't configured);
/// each manager task copies its controller's `protected_skipped()` counter in
/// here on every tick, mirroring how `CollectorMetrics::set_min_sample_suppressed`
/// is kept in sync from the flow detector.
#[derive(Default)]
pub struct ProtectedSkippedMetrics {
    /// RTBH targets skipped because they were in a protected prefix.
    pub rtbh: AtomicU64,
    /// FlowSpec targets skipped because they were in a protected prefix.
    pub flowspec: AtomicU64,
    /// XDP detections skipped because the victim was in a protected prefix.
    pub xdp: AtomicU64,
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
        // `target` is a short display string for the INFO log only; `detail`
        // is the structured JSON persisted to `audit_log` so `/v1/audit`
        // consumers read fields (prefix/next_hop/dst/proto/…) rather than
        // regex over a Debug blob.
        let (plane, verb, target, detail, counter): (
            &str,
            &str,
            String,
            serde_json::Value,
            &AtomicU64,
        ) = match &action {
            ShadowAction::RtbhAnnounce(r) => (
                "rtbh",
                "announce",
                r.prefix.to_string(),
                route_detail("rtbh", "announce", r),
                &self.metrics.rtbh_announce,
            ),
            ShadowAction::RtbhWithdraw(p) => (
                "rtbh",
                "withdraw",
                p.to_string(),
                serde_json::json!({ "plane": "rtbh", "verb": "withdraw", "prefix": p.to_string() }),
                &self.metrics.rtbh_withdraw,
            ),
            ShadowAction::FlowSpecAnnounce(r) => (
                "flowspec",
                "announce",
                r.dst.to_string(),
                flowspec_detail("flowspec", "announce", r),
                &self.metrics.flowspec_announce,
            ),
            ShadowAction::FlowSpecWithdraw(r) => (
                "flowspec",
                "withdraw",
                r.dst.to_string(),
                flowspec_detail("flowspec", "withdraw", r),
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
        if let Err(err) = self
            .store
            .record_audit("shadow", &format!("shadow.{plane}.{verb}"), &detail)
            .await
        {
            tracing::warn!(%err, "shadow: audit write failed (mitigation still suppressed)");
        }
    }
}

/// Structured audit detail for an RTBH route: its prefix, next hop, and
/// communities (as `asn:value` strings) as their own JSON fields, so audit
/// consumers read fields rather than a Debug blob.
fn route_detail(plane: &str, verb: &str, r: &blackwall_bgp::Route) -> serde_json::Value {
    let communities: Vec<String> = r
        .communities
        .iter()
        .map(|(asn, value)| format!("{asn}:{value}"))
        .collect();
    serde_json::json!({
        "plane": plane,
        "verb": verb,
        "prefix": r.prefix.to_string(),
        "next_hop": r.next_hop.to_string(),
        "communities": communities,
    })
}

/// Structured audit detail for a FlowSpec rule: destination, protocol,
/// destination port, and rate (bytes/sec) as their own JSON fields.
fn flowspec_detail(plane: &str, verb: &str, r: &blackwall_bgp::FlowSpecRule) -> serde_json::Value {
    let rate = match &r.action {
        blackwall_bgp::FlowAction::TrafficRate(rate) => *rate,
    };
    serde_json::json!({
        "plane": plane,
        "verb": verb,
        "dst": r.dst.to_string(),
        "protocol": r.protocol,
        "dst_port": r.dst_port,
        "rate": rate,
    })
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
