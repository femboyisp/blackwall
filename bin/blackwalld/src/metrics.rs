//! Minimal Prometheus `/metrics` endpoint, hand-rolled over `TcpListener` (no
//! HTTP framework). Single-purpose: any `GET` returns the current exposition;
//! everything else is `405`. Bind to localhost or a trusted management net —
//! there is no auth or TLS. Enabled by the `metrics listen=<ip:port>` directive.

use blackwall_metrics::{render_prometheus, render_xdp_metrics, Metric, MetricKind, XdpMetrics};
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
    }
    if let Some(inflight) = &sources.inflight {
        m.push(Metric {
            name: "blackwall_deception_sessions_active",
            help: "Deception honeypot sessions currently in flight",
            kind: MetricKind::Gauge,
            value: count_to_f64(inflight.load(std::sync::atomic::Ordering::Relaxed)),
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
        blocked_entries: u64_to_f64(s.blocked_entries),
        ratelimit_entries: u64_to_f64(s.ratelimit_entries),
    }))
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
