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

#[cfg(test)]
mod tests {
    use super::{render_prometheus, Metric, MetricKind};

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
}
