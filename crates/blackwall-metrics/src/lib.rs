//! Pure Prometheus text exposition rendering for Blackwall.
//!
//! This crate holds the one covered, dependency-free piece of the metrics
//! endpoint: turning a slice of [`Metric`] values into the Prometheus text
//! exposition format (version 0.0.4). All I/O — the `TcpListener` accept loop
//! and the scrape-time database queries — lives in the coverage-excluded
//! `blackwalld` glue, so this module can be exhaustively unit-tested.

use std::fmt::Write as _;

/// The Prometheus metric type of a [`Metric`].
///
/// Only the two kinds Blackwall currently exports are modelled; histograms and
/// summaries are intentionally out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// A value that can go up or down (e.g. active mitigations).
    Gauge,
    /// A monotonically increasing total (e.g. datagrams received).
    Counter,
}

impl MetricKind {
    /// The token used on the `# TYPE` line for this kind.
    #[must_use]
    fn as_type_str(self) -> &'static str {
        match self {
            MetricKind::Gauge => "gauge",
            MetricKind::Counter => "counter",
        }
    }
}

/// A single metric sample to be rendered.
///
/// The `name` and `help` are static because the metric set is fixed at compile
/// time; only `value` varies per scrape.
#[derive(Debug, Clone, Copy)]
pub struct Metric {
    /// The metric name, e.g. `blackwall_rtbh_active`.
    pub name: &'static str,
    /// Human-readable help text for the `# HELP` line.
    pub help: &'static str,
    /// Whether this metric is a gauge or a counter.
    pub kind: MetricKind,
    /// The current sample value.
    pub value: f64,
}

/// Format a metric value the way Prometheus text exposition prefers: an
/// integer-valued, finite `f64` is rendered without a decimal point (`5`, not
/// `5.0`), while any fractional or non-finite value uses the default float
/// formatting.
///
/// The integer case uses `{:.0}` fixed-precision formatting, which prints a
/// whole-number `f64` with no fractional digits and no rounding (the value is
/// already integral) — sidestepping any `f64`-to-integer `as` cast.
fn format_value(value: f64) -> String {
    if value.fract() == 0.0 && value.is_finite() {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

/// Render a slice of [`Metric`]s into Prometheus text exposition format 0.0.4.
///
/// For each metric this emits a `# HELP <name> <help>` line, a
/// `# TYPE <name> gauge|counter` line, then a `<name> <value>` sample line.
/// Metric blocks are emitted in the given order (deterministic) and separated
/// by a blank line. An empty slice renders the empty string.
#[must_use]
pub fn render_prometheus(metrics: &[Metric]) -> String {
    let mut out = String::new();
    for (i, metric) in metrics.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // Writes to a String are infallible; the Result is discarded.
        let _ = writeln!(out, "# HELP {} {}", metric.name, metric.help);
        let _ = writeln!(out, "# TYPE {} {}", metric.name, metric.kind.as_type_str());
        let _ = writeln!(out, "{} {}", metric.name, format_value(metric.value));
    }
    out
}

/// A snapshot of the XDP data plane's counters for Prometheus rendering.
///
/// Values are `f64` (already widened from the data plane's `u64` per-CPU
/// counters and map occupancies by the caller) so this stays a pure,
/// dependency-free renderer with no integer `as` casts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct XdpMetrics {
    /// Packets passed by the filter (`REASON_PASS`).
    pub passed_packets: f64,
    /// Packets dropped by the source blocklist (`REASON_BLOCKLIST`).
    pub dropped_blocklist_packets: f64,
    /// Packets dropped by the rate limiter (`REASON_RATELIMIT`).
    pub dropped_ratelimit_packets: f64,
    /// Packets answered in-kernel with a SipHash-cookie SYN-ACK via `XDP_TX`
    /// (`REASON_SYNCOOKIE`, B2.3c).
    pub syn_cookies_sent_packets: f64,
    /// SYNs that cleared every SYN-cookie gate but were denied a SYN-ACK
    /// because the global `TX_BUDGET` mint-rate cap was exhausted
    /// (`REASON_SYNCOOKIE_TXCAPPED`, sub-project X3).
    pub syn_cookies_txcapped_packets: f64,
    /// Number of active blocklist entries (`BLOCK_V4` + `BLOCK_V6`).
    pub blocked_entries: f64,
    /// Number of active rate-limit entries (`RATE`).
    pub ratelimit_entries: f64,
}

/// Render the XDP data-plane metrics block as Prometheus text exposition 0.0.4.
///
/// Unlike [`render_prometheus`], this emits a single labelled counter
/// (`blackwall_xdp_packets_dropped_total{reason="blocklist"|"ratelimit"}`)
/// whose two series share one `# HELP`/`# TYPE` header, alongside the passed
/// counter and the two occupancy gauges. Blocks are separated by a blank line
/// and there is no trailing blank line, matching [`render_prometheus`] so the
/// two outputs concatenate cleanly.
#[must_use]
pub fn render_xdp_metrics(m: &XdpMetrics) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP blackwall_xdp_packets_dropped_total Packets dropped by the XDP data plane, by reason"
    );
    let _ = writeln!(out, "# TYPE blackwall_xdp_packets_dropped_total counter");
    let _ = writeln!(
        out,
        "blackwall_xdp_packets_dropped_total{{reason=\"blocklist\"}} {}",
        format_value(m.dropped_blocklist_packets)
    );
    let _ = writeln!(
        out,
        "blackwall_xdp_packets_dropped_total{{reason=\"ratelimit\"}} {}",
        format_value(m.dropped_ratelimit_packets)
    );
    let _ = writeln!(
        out,
        "\n# HELP blackwall_xdp_packets_passed_total Packets passed by the XDP data plane"
    );
    let _ = writeln!(out, "# TYPE blackwall_xdp_packets_passed_total counter");
    let _ = writeln!(
        out,
        "blackwall_xdp_packets_passed_total {}",
        format_value(m.passed_packets)
    );
    let _ = writeln!(
        out,
        "\n# HELP blackwall_xdp_syn_cookies_sent_total SYN-ACKs answered in-kernel with a \
         SipHash SYN cookie"
    );
    let _ = writeln!(out, "# TYPE blackwall_xdp_syn_cookies_sent_total counter");
    let _ = writeln!(
        out,
        "blackwall_xdp_syn_cookies_sent_total {}",
        format_value(m.syn_cookies_sent_packets)
    );
    let _ = writeln!(
        out,
        "\n# HELP blackwall_xdp_syn_cookies_txcapped_total SYNs that cleared every \
         SYN-cookie gate but were denied a SYN-ACK because the global XDP_TX mint-rate cap \
         was exhausted"
    );
    let _ = writeln!(
        out,
        "# TYPE blackwall_xdp_syn_cookies_txcapped_total counter"
    );
    let _ = writeln!(
        out,
        "blackwall_xdp_syn_cookies_txcapped_total {}",
        format_value(m.syn_cookies_txcapped_packets)
    );
    let _ = writeln!(
        out,
        "\n# HELP blackwall_xdp_blocked_entries Active XDP source-blocklist entries"
    );
    let _ = writeln!(out, "# TYPE blackwall_xdp_blocked_entries gauge");
    let _ = writeln!(
        out,
        "blackwall_xdp_blocked_entries {}",
        format_value(m.blocked_entries)
    );
    let _ = writeln!(
        out,
        "\n# HELP blackwall_xdp_ratelimit_entries Active XDP rate-limit entries"
    );
    let _ = writeln!(out, "# TYPE blackwall_xdp_ratelimit_entries gauge");
    let _ = writeln!(
        out,
        "blackwall_xdp_ratelimit_entries {}",
        format_value(m.ratelimit_entries)
    );
    out
}

#[cfg(test)]
mod tests {
    use super::{render_prometheus, render_xdp_metrics, Metric, MetricKind, XdpMetrics};

    #[test]
    fn renders_golden_multi_metric() {
        let metrics = [
            Metric {
                name: "blackwall_rtbh_active",
                help: "Active RTBH blackholes",
                kind: MetricKind::Gauge,
                value: 3.0,
            },
            Metric {
                name: "blackwall_flow_datagrams_total",
                help: "sFlow datagrams received",
                kind: MetricKind::Counter,
                value: 42.0,
            },
            Metric {
                name: "blackwall_flow_loss_ratio",
                help: "Fraction of datagrams dropped",
                kind: MetricKind::Gauge,
                value: 0.25,
            },
        ];
        let expected = "\
# HELP blackwall_rtbh_active Active RTBH blackholes
# TYPE blackwall_rtbh_active gauge
blackwall_rtbh_active 3

# HELP blackwall_flow_datagrams_total sFlow datagrams received
# TYPE blackwall_flow_datagrams_total counter
blackwall_flow_datagrams_total 42

# HELP blackwall_flow_loss_ratio Fraction of datagrams dropped
# TYPE blackwall_flow_loss_ratio gauge
blackwall_flow_loss_ratio 0.25
";
        assert_eq!(render_prometheus(&metrics), expected);
    }

    #[test]
    fn empty_slice_renders_empty_string() {
        assert_eq!(render_prometheus(&[]), "");
    }

    #[test]
    fn single_metric_has_no_trailing_blank_line() {
        let metrics = [Metric {
            name: "blackwall_bgp_reconnects_total",
            help: "BGP session reconnects",
            kind: MetricKind::Counter,
            value: 0.0,
        }];
        let expected = "\
# HELP blackwall_bgp_reconnects_total BGP session reconnects
# TYPE blackwall_bgp_reconnects_total counter
blackwall_bgp_reconnects_total 0
";
        assert_eq!(render_prometheus(&metrics), expected);
    }

    #[test]
    fn integer_valued_float_drops_decimal_point() {
        let metrics = [Metric {
            name: "big",
            help: "large integer value",
            kind: MetricKind::Counter,
            value: 1_000_000.0,
        }];
        assert!(render_prometheus(&metrics).contains("big 1000000\n"));
    }

    #[test]
    fn fractional_value_keeps_decimal() {
        let metrics = [Metric {
            name: "frac",
            help: "fractional value",
            kind: MetricKind::Gauge,
            value: 1.5,
        }];
        assert!(render_prometheus(&metrics).contains("frac 1.5\n"));
    }

    #[test]
    fn non_finite_value_uses_default_float_formatting() {
        let metrics = [Metric {
            name: "inf",
            help: "non-finite value",
            kind: MetricKind::Gauge,
            value: f64::INFINITY,
        }];
        assert!(render_prometheus(&metrics).contains("inf inf\n"));
    }

    #[test]
    fn metric_kind_type_tokens() {
        assert_eq!(MetricKind::Gauge.as_type_str(), "gauge");
        assert_eq!(MetricKind::Counter.as_type_str(), "counter");
    }

    #[test]
    fn renders_golden_xdp_block() {
        let m = XdpMetrics {
            passed_packets: 1000.0,
            dropped_blocklist_packets: 42.0,
            dropped_ratelimit_packets: 7.0,
            syn_cookies_sent_packets: 9.0,
            syn_cookies_txcapped_packets: 2.0,
            blocked_entries: 3.0,
            ratelimit_entries: 5.0,
        };
        let expected = "\
# HELP blackwall_xdp_packets_dropped_total Packets dropped by the XDP data plane, by reason
# TYPE blackwall_xdp_packets_dropped_total counter
blackwall_xdp_packets_dropped_total{reason=\"blocklist\"} 42
blackwall_xdp_packets_dropped_total{reason=\"ratelimit\"} 7

# HELP blackwall_xdp_packets_passed_total Packets passed by the XDP data plane
# TYPE blackwall_xdp_packets_passed_total counter
blackwall_xdp_packets_passed_total 1000

# HELP blackwall_xdp_syn_cookies_sent_total SYN-ACKs answered in-kernel with a SipHash SYN cookie
# TYPE blackwall_xdp_syn_cookies_sent_total counter
blackwall_xdp_syn_cookies_sent_total 9

# HELP blackwall_xdp_syn_cookies_txcapped_total SYNs that cleared every SYN-cookie gate but were denied a SYN-ACK because the global XDP_TX mint-rate cap was exhausted
# TYPE blackwall_xdp_syn_cookies_txcapped_total counter
blackwall_xdp_syn_cookies_txcapped_total 2

# HELP blackwall_xdp_blocked_entries Active XDP source-blocklist entries
# TYPE blackwall_xdp_blocked_entries gauge
blackwall_xdp_blocked_entries 3

# HELP blackwall_xdp_ratelimit_entries Active XDP rate-limit entries
# TYPE blackwall_xdp_ratelimit_entries gauge
blackwall_xdp_ratelimit_entries 5
";
        assert_eq!(render_xdp_metrics(&m), expected);
    }

    #[test]
    fn xdp_block_concatenates_cleanly_after_render_prometheus() {
        // No trailing blank line on either block, so a single '\n' joins them.
        let head = render_prometheus(&[Metric {
            name: "blackwall_rtbh_active",
            help: "Active RTBH blackholes",
            kind: MetricKind::Gauge,
            value: 1.0,
        }]);
        let xdp = render_xdp_metrics(&XdpMetrics {
            passed_packets: 0.0,
            dropped_blocklist_packets: 0.0,
            dropped_ratelimit_packets: 0.0,
            syn_cookies_sent_packets: 0.0,
            syn_cookies_txcapped_packets: 0.0,
            blocked_entries: 0.0,
            ratelimit_entries: 0.0,
        });
        let combined = format!("{head}\n{xdp}");
        assert!(combined
            .contains("blackwall_rtbh_active 1\n\n# HELP blackwall_xdp_packets_dropped_total"));
        assert!(
            !combined.contains("\n\n\n"),
            "no triple newline between blocks"
        );
    }
}
