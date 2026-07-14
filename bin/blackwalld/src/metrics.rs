//! Minimal Prometheus `/metrics` endpoint, hand-rolled over `TcpListener` (no
//! HTTP framework). Single-purpose: any `GET` returns the current exposition;
//! everything else is `405`. Bind to localhost or a trusted management net —
//! there is no auth or TLS. Enabled by the `metrics listen=<ip:port>` directive.

use blackwall_metrics::{render_prometheus, render_xdp_metrics, Metric, MetricKind, XdpMetrics};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Everything the scrape handler reads at request time. Cheap to clone (an
/// `Arc<Store>`, a cloneable `BgpHandle`, an `Arc<CollectorMetrics>`).
#[derive(Clone)]
pub(crate) struct MetricsSources {
    pub store: Arc<blackwall_state::Store>,
    /// `None` when no `rtbh` block is configured (no BGP session to report).
    pub bgp: Option<blackwall_bgp::BgpHandle>,
    /// `None` for the deception engine (no sFlow collector).
    pub collector: Option<Arc<blackwall_flow::CollectorMetrics>>,
    /// Live in-flight deception sessions; `None` outside the deception engine.
    pub inflight: Option<Arc<std::sync::atomic::AtomicUsize>>,
    /// A shared handle to the attached XDP data plane, for per-CPU counter and
    /// map-occupancy gauges; `None` when XDP is disabled or failed to attach.
    pub xdp: Option<Arc<blackwall_xdp::XdpDataplane>>,
    /// Stateless SYN-cookie / UDP responder counters; `None` outside the
    /// deception engine (e.g. the `flow` daemon, which has no responder).
    pub stateless: Option<Arc<blackwall_deception::transport::StatelessMetrics>>,
    /// AF_XDP UDP responder replies-sent counter (sub-project B3.2); `None`
    /// when the AF_XDP UDP responder is disabled (`afxdp-udp-ports` empty).
    pub afxdp_udp_responses: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// Per-POP agent telemetry snapshot, refreshed once per collector tick;
    /// `None` outside the flow daemon (no sFlow collector, no agents).
    pub agent_stats: Option<Arc<std::sync::Mutex<Vec<blackwall_flow::AgentStat>>>>,
    /// Shadow-mode "would mitigate" counters (RTBH/FlowSpec/XDP); `None`
    /// outside the flow daemon (no RTBH/FlowSpec/XDP managers to shadow).
    pub shadow: Option<Arc<crate::shadow::ShadowMetrics>>,
    /// Per-plane anycast self-protection skip counters (C1); `None` outside
    /// the flow daemon (no RTBH/FlowSpec/XDP managers to guard). Unlike
    /// `shadow`, populated in both shadow AND live sessions.
    pub protected_skipped: Option<Arc<crate::shadow::ProtectedSkippedMetrics>>,
}

/// Correctly-rounded `u64 -> f64` without an `as` cast: `u32 -> f64` is exact
/// (32 bits fit the 52-bit mantissa), so split the value into high/low halves.
fn u64_to_f64(v: u64) -> f64 {
    let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi) * 4_294_967_296.0 + f64::from(lo)
}

/// A non-negative count (`i64`/`usize`) as an `f64`; negatives/overflow clamp to 0.
fn count_to_f64(v: impl TryInto<u64>) -> f64 {
    v.try_into().map(u64_to_f64).unwrap_or(0.0)
}

/// Build the current metric set. DB-backed gauges are read here at scrape time;
/// a failing query is logged and its metric omitted rather than failing the scrape.
async fn gather(sources: &MetricsSources) -> Vec<Metric> {
    let mut m: Vec<Metric> = Vec::new();

    if let Some(bgp) = &sources.bgp {
        let state = match bgp.state() {
            blackwall_bgp::SessionState::Idle => 0.0,
            blackwall_bgp::SessionState::Connecting => 1.0,
            blackwall_bgp::SessionState::Established => 2.0,
        };
        m.push(Metric {
            name: "blackwall_bgp_session_state",
            help: "BGP session state (0 idle, 1 connecting, 2 established)",
            kind: MetricKind::Gauge,
            value: state,
        });
        m.push(Metric {
            name: "blackwall_bgp_reconnects_total",
            help: "BGP session reconnect attempts since start",
            kind: MetricKind::Counter,
            value: u64_to_f64(bgp.reconnects()),
        });
    }

    if let Some(collector) = &sources.collector {
        m.push(Metric {
            name: "blackwall_flow_datagrams_total",
            help: "sFlow datagrams received by the collector",
            kind: MetricKind::Counter,
            value: u64_to_f64(collector.datagrams()),
        });
        m.push(Metric {
            name: "blackwall_flow_decode_errors_total",
            help: "sFlow datagrams that failed to decode",
            kind: MetricKind::Counter,
            value: u64_to_f64(collector.decode_errors()),
        });
        m.push(Metric {
            name: "blackwall_flow_sample_decode_errors_total",
            help: "sFlow samples that failed to decode within an otherwise-valid datagram",
            kind: MetricKind::Counter,
            value: u64_to_f64(collector.sample_decode_errors()),
        });
    }
    if let Some(inflight) = &sources.inflight {
        m.push(Metric {
            name: "blackwall_deception_sessions_active",
            help: "Deception honeypot sessions currently in flight",
            kind: MetricKind::Gauge,
            value: count_to_f64(inflight.load(std::sync::atomic::Ordering::Relaxed)),
        });
    }
    if let Some(stateless) = &sources.stateless {
        m.extend(stateless_metrics(stateless));
    }
    if let Some(afxdp_udp) = &sources.afxdp_udp_responses {
        m.push(Metric {
            name: "blackwall_xdp_udp_responses_total",
            help: "AF_XDP UDP responder replies sent (reflection-safe, B3.2)",
            kind: MetricKind::Counter,
            value: u64_to_f64(afxdp_udp.load(std::sync::atomic::Ordering::Relaxed)),
        });
    }

    let s = &sources.store;
    match s.list_active_blackholes().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_rtbh_active",
            help: "Active RTBH blackholes",
            kind: MetricKind::Gauge,
            value: count_to_f64(v.len()),
        }),
        Err(e) => tracing::warn!(%e, "metrics: rtbh_active query failed"),
    }
    match s.list_active_flowspec().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_flowspec_active",
            help: "Active FlowSpec rules",
            kind: MetricKind::Gauge,
            value: count_to_f64(v.len()),
        }),
        Err(e) => tracing::warn!(%e, "metrics: flowspec_active query failed"),
    }
    match s.pending_requests().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_rtbh_requests_pending",
            help: "Pending RTBH operator-intent requests",
            kind: MetricKind::Gauge,
            value: count_to_f64(v.len()),
        }),
        Err(e) => tracing::warn!(%e, "metrics: rtbh_requests_pending query failed"),
    }
    match s.pending_flowspec_requests().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_flowspec_requests_pending",
            help: "Pending FlowSpec operator-intent requests",
            kind: MetricKind::Gauge,
            value: count_to_f64(v.len()),
        }),
        Err(e) => tracing::warn!(%e, "metrics: flowspec_requests_pending query failed"),
    }
    match s.detection_count().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_detections_total",
            help: "Attack detections recorded",
            kind: MetricKind::Counter,
            value: count_to_f64(v),
        }),
        Err(e) => tracing::warn!(%e, "metrics: detections_total query failed"),
    }
    match s.session_count().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_deception_sessions_total",
            help: "Deception sessions captured",
            kind: MetricKind::Counter,
            value: count_to_f64(v),
        }),
        Err(e) => tracing::warn!(%e, "metrics: deception_sessions_total query failed"),
    }
    match s.audit_count().await {
        Ok(v) => m.push(Metric {
            name: "blackwall_audit_total",
            help: "Audit-log entries",
            kind: MetricKind::Counter,
            value: count_to_f64(v),
        }),
        Err(e) => tracing::warn!(%e, "metrics: audit_total query failed"),
    }

    m
}

/// Render the four stateless SYN-cookie / UDP responder counters from a live
/// [`blackwall_deception::transport::StatelessMetrics`] snapshot.
///
/// Pure and side-effect free (unlike [`gather`], which also awaits DB
/// queries), so it is unit-tested directly without a live `Store`.
fn stateless_metrics(stateless: &blackwall_deception::transport::StatelessMetrics) -> Vec<Metric> {
    vec![
        Metric {
            name: "blackwall_stateless_syn_cookies_sent_total",
            help: "Stateless SYN-cookie SYN-ACKs sent",
            kind: MetricKind::Counter,
            value: u64_to_f64(stateless.syn_cookies_sent()),
        },
        Metric {
            name: "blackwall_stateless_acks_validated_total",
            help: "Stateless-tier completing ACKs whose SYN-cookie validated",
            kind: MetricKind::Counter,
            value: u64_to_f64(stateless.acks_validated()),
        },
        Metric {
            name: "blackwall_stateless_acks_rejected_total",
            help: "Stateless-tier ACKs whose SYN-cookie failed validation",
            kind: MetricKind::Counter,
            value: u64_to_f64(stateless.acks_rejected()),
        },
        Metric {
            name: "blackwall_stateless_udp_responses_total",
            help: "Stateless UDP responses sent",
            kind: MetricKind::Counter,
            value: u64_to_f64(stateless.udp_responses()),
        },
    ]
}

/// Render the labelled XDP data-plane block from a live `stats()` snapshot, or
/// `None` when XDP is not attached. Per-CPU counters expose the *packet*
/// dimension of each [`blackwall_xdp::XdpStats`] `Stat`.
fn xdp_block(sources: &MetricsSources) -> Option<String> {
    let dp = sources.xdp.as_ref()?;
    let s = dp.stats();
    Some(render_xdp_metrics(&XdpMetrics {
        passed_packets: u64_to_f64(s.passed.packets),
        dropped_blocklist_packets: u64_to_f64(s.dropped_blocklist.packets),
        dropped_ratelimit_packets: u64_to_f64(s.dropped_ratelimit.packets),
        syn_cookies_sent_packets: u64_to_f64(s.syn_cookies_sent.packets),
        blocked_entries: u64_to_f64(s.blocked_entries),
        ratelimit_entries: u64_to_f64(s.ratelimit_entries),
    }))
}

/// Render only the per-POP telemetry blocks (`blackwall_flow_pop_last_seen_seconds`,
/// `blackwall_flow_agent_sampling_mismatch_total`,
/// `blackwall_flow_sampling_near_ceiling_total`) from an already-sorted `stats`
/// slice. Pure and DB-free (so it is unit-testable). `now_ms` must be the same
/// monotonic clock as `AgentStat.last_seen_ms` — see [`agent_stats_block`].
fn render_agent_pop_stats(stats: &[blackwall_flow::AgentStat], now_ms: u64) -> String {
    let mut out = String::new();
    if stats.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "# HELP blackwall_flow_pop_last_seen_seconds Seconds since this POP's sFlow agent was last observed"
    );
    let _ = writeln!(out, "# TYPE blackwall_flow_pop_last_seen_seconds gauge");
    for s in stats {
        let age_secs = now_ms.saturating_sub(s.last_seen_ms) / 1000;
        let _ = writeln!(
            out,
            "blackwall_flow_pop_last_seen_seconds{{pop=\"{}\"}} {age_secs}",
            s.pop
        );
    }
    let _ = writeln!(
        out,
        "\n# HELP blackwall_flow_agent_sampling_mismatch_total Sampling-rate mismatches clamped per POP"
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_flow_agent_sampling_mismatch_total counter"
    );
    for s in stats {
        let _ = writeln!(
            out,
            "blackwall_flow_agent_sampling_mismatch_total{{pop=\"{}\"}} {}",
            s.pop, s.mismatches
        );
    }
    let _ = writeln!(
        out,
        "\n# HELP blackwall_flow_sampling_near_ceiling_total Samples per POP whose trusted sampling rate landed at or above half the max-sampling-factor ceiling"
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_flow_sampling_near_ceiling_total counter"
    );
    for s in stats {
        let _ = writeln!(
            out,
            "blackwall_flow_sampling_near_ceiling_total{{pop=\"{}\"}} {}",
            s.pop, s.near_ceiling
        );
    }
    out
}

/// Render the per-POP telemetry blocks (`blackwall_flow_pop_last_seen_seconds`,
/// `blackwall_flow_agent_sampling_mismatch_total`,
/// `blackwall_flow_sampling_near_ceiling_total`) plus the
/// `blackwall_flow_unknown_agent_observations_total` and
/// `blackwall_flow_min_sample_suppressed_total` scalars, or `None` when the
/// flow daemon has no per-agent snapshot wired up (`sources.agent_stats` is
/// `None` — the deception engine, which has no sFlow collector).
///
/// POP names are dynamic labels unknown at compile time, so — like
/// [`xdp_block`]'s `reason` label — this hand-writes the exposition text
/// directly rather than going through [`Metric`], which only carries a
/// `&'static str` name. `now_ms` MUST be [`blackwall_flow::monotonic_now_ms`]
/// (the same monotonic clock the collector stamps `AgentStat.last_seen_ms`
/// with), so the per-POP last-seen age is real seconds — NOT wall-clock epoch,
/// which would make every age a nonsense ~epoch-sized value.
fn agent_stats_block(sources: &MetricsSources, now_ms: u64) -> Option<String> {
    let snapshot = sources.agent_stats.as_ref()?;
    let mut stats: Vec<blackwall_flow::AgentStat> = match snapshot.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    // Deterministic scrape output regardless of HashMap iteration order.
    stats.sort_by(|a, b| a.pop.cmp(&b.pop));

    let mut out = render_agent_pop_stats(&stats, now_ms);

    // Always emitted (a single scalar, not per-label) so the series exists
    // even before any known agent has been observed.
    let unknown = sources
        .collector
        .as_ref()
        .map_or(0, |c| c.unknown_agent_observations());
    if !out.is_empty() {
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "# HELP blackwall_flow_unknown_agent_observations_total sFlow sample observations from agents not in the POP map."
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_flow_unknown_agent_observations_total counter"
    );
    let _ = writeln!(
        out,
        "blackwall_flow_unknown_agent_observations_total {unknown}"
    );

    // Always emitted alongside `unknown_agent_observations_total`, same reasoning.
    let min_sample_suppressed = sources
        .collector
        .as_ref()
        .map_or(0, |c| c.min_sample_suppressed());
    out.push('\n');
    let _ = writeln!(
        out,
        "# HELP blackwall_flow_min_sample_suppressed_total Detections suppressed by the minimum-sample gate"
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_flow_min_sample_suppressed_total counter"
    );
    let _ = writeln!(
        out,
        "blackwall_flow_min_sample_suppressed_total {min_sample_suppressed}"
    );

    // Always emitted alongside the other scalars above, same reasoning:
    // distinguishes "quiet network" (both zero) from "POP silently dropping
    // samples" (decode/suppression counters moving but detections never open).
    let detections_opened = sources
        .collector
        .as_ref()
        .map_or(0, |c| c.detections_opened());
    out.push('\n');
    let _ = writeln!(
        out,
        "# HELP blackwall_flow_detections_opened_total Detections opened by the flow detector"
    );
    let _ = writeln!(out, "# TYPE blackwall_flow_detections_opened_total counter");
    let _ = writeln!(
        out,
        "blackwall_flow_detections_opened_total {detections_opened}"
    );

    let detections_cleared = sources
        .collector
        .as_ref()
        .map_or(0, |c| c.detections_cleared());
    out.push('\n');
    let _ = writeln!(
        out,
        "# HELP blackwall_flow_detections_cleared_total Detections cleared by the flow detector"
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_flow_detections_cleared_total counter"
    );
    let _ = writeln!(
        out,
        "blackwall_flow_detections_cleared_total {detections_cleared}"
    );

    Some(out)
}

/// Render `blackwall_shadow_would_mitigate_total{plane,action}` from the
/// shared shadow counters, or `None` when shadow counters aren't wired up
/// (outside the flow daemon). Labels are a fixed, known-at-compile-time set
/// (unlike [`agent_stats_block`]'s dynamic POP names), but still hand-written
/// since [`Metric`] only carries unlabelled series.
fn shadow_block(sources: &MetricsSources) -> Option<String> {
    use std::sync::atomic::Ordering;

    let shadow = sources.shadow.as_ref()?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP blackwall_shadow_would_mitigate_total Mitigations that would have been applied under shadow mode, by plane and action"
    );
    let _ = writeln!(out, "# TYPE blackwall_shadow_would_mitigate_total counter");
    for (plane, action, counter) in [
        ("rtbh", "announce", &shadow.rtbh_announce),
        ("rtbh", "withdraw", &shadow.rtbh_withdraw),
        ("flowspec", "announce", &shadow.flowspec_announce),
        ("flowspec", "withdraw", &shadow.flowspec_withdraw),
        ("xdp", "block", &shadow.xdp_block),
        ("xdp", "rate_limit", &shadow.xdp_rate_limit),
    ] {
        let _ = writeln!(
            out,
            "blackwall_shadow_would_mitigate_total{{plane=\"{plane}\",action=\"{action}\"}} {}",
            counter.load(Ordering::Relaxed)
        );
    }
    Some(out)
}

/// Render `blackwall_mitigations_protected_skipped_total{plane}` from the
/// shared per-plane counters, or `None` when they aren't wired up (outside
/// the flow daemon). Labels are a fixed, known-at-compile-time set, but still
/// hand-written since [`Metric`] only carries unlabelled series — mirrors
/// [`shadow_block`].
fn protected_skipped_block(sources: &MetricsSources) -> Option<String> {
    use std::sync::atomic::Ordering;

    let counters = sources.protected_skipped.as_ref()?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP blackwall_mitigations_protected_skipped_total Targets skipped because they fell inside a configured protected prefix (own VIP), by plane"
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_mitigations_protected_skipped_total counter"
    );
    for (plane, counter) in [
        ("rtbh", &counters.rtbh),
        ("flowspec", &counters.flowspec),
        ("xdp", &counters.xdp),
    ] {
        let _ = writeln!(
            out,
            "blackwall_mitigations_protected_skipped_total{{plane=\"{plane}\"}} {}",
            counter.load(Ordering::Relaxed)
        );
    }
    Some(out)
}

/// Serve `/metrics` forever. Each connection is handled on its own task so a
/// slow client cannot block scrapes; a bind failure disables the endpoint (and
/// is logged) without taking down the daemon.
pub(crate) async fn metrics_server(listen: SocketAddr, sources: MetricsSources) {
    let listener = match TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%e, %listen, "metrics: bind failed; endpoint disabled");
            return;
        }
    };
    tracing::info!(%listen, "metrics endpoint listening");
    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(%e, "metrics: accept failed");
                continue;
            }
        };
        let sources = sources.clone();
        tokio::spawn(async move {
            handle_conn(sock, &sources).await;
        });
    }
}

async fn handle_conn(mut sock: tokio::net::TcpStream, sources: &MetricsSources) {
    // Read only enough to see the request method; ignore the rest.
    let mut buf = [0u8; 1024];
    let _ = sock.read(&mut buf).await;
    let response = if buf.starts_with(b"GET ") {
        let mut body = render_prometheus(&gather(sources).await);
        if let Some(xdp) = xdp_block(sources) {
            // Both blocks are trailing-newline-terminated with no blank tail, so
            // a single '\n' separates them exactly like adjacent metric blocks.
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(&xdp);
        }
        if let Some(agent) = agent_stats_block(sources, blackwall_flow::monotonic_now_ms()) {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(&agent);
        }
        if let Some(shadow) = shadow_block(sources) {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(&shadow);
        }
        if let Some(protected) = protected_skipped_block(sources) {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(&protected);
        }
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_owned()
    };
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::{render_agent_pop_stats, stateless_metrics};
    use blackwall_deception::transport::StatelessMetrics;
    use blackwall_metrics::render_prometheus;

    #[test]
    fn pop_last_seen_age_uses_monotonic_clock_not_epoch() {
        // Regression for the clock-domain bug: the collector stamps
        // `AgentStat.last_seen_ms` from the monotonic clock, so the renderer must
        // compute the age against the SAME clock. A just-seen agent must read
        // ~0 s, not ~epoch (the old bug rendered ~1.78e9 by subtracting a
        // monotonic timestamp from an epoch "now").
        let stats = vec![blackwall_flow::AgentStat {
            pop: "kc".to_string(),
            last_seen_ms: blackwall_flow::monotonic_now_ms(), // just observed
            mismatches: 0,
            near_ceiling: 0,
        }];
        let body = render_agent_pop_stats(&stats, blackwall_flow::monotonic_now_ms());
        let line = body
            .lines()
            .find(|l| l.starts_with("blackwall_flow_pop_last_seen_seconds{pop=\"kc\"}"))
            .expect("pop_last_seen line present");
        let age: u64 = line
            .rsplit(' ')
            .next()
            .and_then(|v| v.parse().ok())
            .expect("age value parses");
        assert!(
            age < 5,
            "a just-seen agent's last-seen age must be ~0s, got {age} (clock-domain regression)"
        );
    }

    #[test]
    fn stateless_metrics_renders_all_four_counters_with_expected_values() {
        let stateless = StatelessMetrics::new();
        stateless.record_syn_cookie_sent();
        stateless.record_syn_cookie_sent();
        stateless.record_ack_validated();
        stateless.record_ack_rejected();
        stateless.record_ack_rejected();
        stateless.record_ack_rejected();
        stateless.record_udp_response();

        let body = render_prometheus(&stateless_metrics(&stateless));

        assert!(body.contains("# TYPE blackwall_stateless_syn_cookies_sent_total counter"));
        assert!(body.contains("blackwall_stateless_syn_cookies_sent_total 2\n"));
        assert!(body.contains("# TYPE blackwall_stateless_acks_validated_total counter"));
        assert!(body.contains("blackwall_stateless_acks_validated_total 1\n"));
        assert!(body.contains("# TYPE blackwall_stateless_acks_rejected_total counter"));
        assert!(body.contains("blackwall_stateless_acks_rejected_total 3\n"));
        assert!(body.contains("# TYPE blackwall_stateless_udp_responses_total counter"));
        assert!(body.contains("blackwall_stateless_udp_responses_total 1\n"));
    }

    #[test]
    fn stateless_metrics_renders_zeros_for_a_fresh_counter_set() {
        let stateless = StatelessMetrics::new();
        let body = render_prometheus(&stateless_metrics(&stateless));
        assert!(body.contains("blackwall_stateless_syn_cookies_sent_total 0\n"));
        assert!(body.contains("blackwall_stateless_acks_validated_total 0\n"));
        assert!(body.contains("blackwall_stateless_acks_rejected_total 0\n"));
        assert!(body.contains("blackwall_stateless_udp_responses_total 0\n"));
    }
}
