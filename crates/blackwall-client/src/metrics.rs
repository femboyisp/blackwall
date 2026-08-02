//! Prometheus text-exposition parser + typed snapshot.
//!
//! Blackwall's `/metrics` endpoint (`bin/blackwalld/src/metrics.rs`) is a
//! hand-rolled Prometheus text renderer with no label support today (every
//! `Metric` is a bare `name value` line — see `blackwall_metrics::Metric`).
//! This parser is nonetheless written to also accept the labeled form
//! (`name{k="v",...} value`) per the dashboard's forward-compatible
//! `MetricsSnapshot`/`Sample` shape, so a future labeled exporter needs no
//! client-side change.

use std::collections::{BTreeMap, HashMap};

/// One parsed sample: its label set (empty for a bare `name value` line) and
/// numeric value.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Label name -> value, in sorted (`BTreeMap`) order for stable display.
    pub labels: BTreeMap<String, String>,
    /// The sample's numeric value.
    pub value: f64,
}

/// A parsed Prometheus text exposition: every family name maps to the
/// samples observed for it, in the order they appeared in the text.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetricsSnapshot {
    /// Metric family name -> its samples.
    pub families: HashMap<String, Vec<Sample>>,
}

impl MetricsSnapshot {
    /// The value of the first sample for `name`, if the family is present.
    /// Convenience for single-valued (unlabeled) gauges/counters.
    #[must_use]
    pub fn gauge(&self, name: &str) -> Option<f64> {
        self.families.get(name)?.first().map(|s| s.value)
    }

    /// All samples for `name`, or an empty slice if the family is absent.
    #[must_use]
    pub fn samples(&self, name: &str) -> &[Sample] {
        self.families
            .get(name)
            .map_or(&[] as &[Sample], Vec::as_slice)
    }
}

/// Split a `key="value"` label list (the text between `{` and `}`, exclusive)
/// on top-level commas, returning `(key, value)` pairs with the value's
/// surrounding quotes stripped. Malformed segments (no `=`, unterminated
/// quotes) are skipped rather than causing a panic.
fn parse_labels(raw: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    for segment in split_top_level_commas(raw) {
        let Some((key, val)) = segment.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        let val = val.strip_prefix('"').unwrap_or(val);
        let val = val.strip_suffix('"').unwrap_or(val);
        if key.is_empty() {
            continue;
        }
        labels.insert(key.to_string(), val.to_string());
    }
    labels
}

/// Split `raw` on commas that are not inside a `"..."` quoted value (a label
/// value could in principle contain a comma).
fn split_top_level_commas(raw: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in raw.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(&raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = &raw[start..];
    if !tail.trim().is_empty() || !parts.is_empty() {
        parts.push(tail);
    }
    parts
}

/// Parse one non-comment, non-blank exposition line into `(name, labels,
/// value)`. Returns `None` for a line that doesn't match either the labeled
/// or bare sample form (malformed lines are skipped, never panicked on).
fn parse_line(line: &str) -> Option<(String, BTreeMap<String, String>, f64)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Some(brace) = line.find('{') {
        let name = line[..brace].trim();
        let close = line.find('}')?;
        if close < brace {
            return None;
        }
        let labels = parse_labels(&line[brace + 1..close]);
        let value_str = line[close + 1..].trim();
        let value: f64 = value_str.parse().ok()?;
        if name.is_empty() {
            return None;
        }
        Some((name.to_string(), labels, value))
    } else {
        let mut parts = line.splitn(2, char::is_whitespace);
        let name = parts.next()?.trim();
        let value_str = parts.next()?.trim();
        let value: f64 = value_str.parse().ok()?;
        if name.is_empty() {
            return None;
        }
        Some((name.to_string(), BTreeMap::new(), value))
    }
}

/// Parse a Prometheus text exposition (version 0.0.4) into a
/// [`MetricsSnapshot`]. `# HELP`/`# TYPE`/comment lines and blank lines are
/// ignored; a line that fails to parse is skipped rather than aborting the
/// whole parse (a partial/corrupt scrape still yields whatever decoded).
#[must_use]
pub fn parse_prometheus(text: &str) -> MetricsSnapshot {
    let mut families: HashMap<String, Vec<Sample>> = HashMap::new();
    for line in text.lines() {
        if let Some((name, labels, value)) = parse_line(line) {
            families
                .entry(name)
                .or_default()
                .push(Sample { labels, value });
        }
    }
    MetricsSnapshot { families }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_labeled_and_bare_families() {
        let txt = "\
# HELP blackwall_armed armed
# TYPE blackwall_armed gauge
blackwall_armed 1
blackwall_bgp_session_state{peer=\"10.0.0.1\"} 6
blackwall_bgp_session_state{peer=\"10.0.0.2\"} 2
blackwall_flow_sampled_bytes_total 500064
";
        let s = parse_prometheus(txt);
        assert_eq!(s.gauge("blackwall_armed"), Some(1.0));
        assert_eq!(s.samples("blackwall_bgp_session_state").len(), 2);
        assert_eq!(
            s.gauge("blackwall_flow_sampled_bytes_total"),
            Some(500064.0)
        );
        assert_eq!(s.gauge("nonexistent"), None);
    }

    #[test]
    fn parses_labels_into_sorted_map() {
        let txt = "blackwall_bgp_session_state{peer=\"10.0.0.1\",extra=\"x\"} 2\n";
        let s = parse_prometheus(txt);
        let sample = &s.samples("blackwall_bgp_session_state")[0];
        assert_eq!(sample.labels.get("peer"), Some(&"10.0.0.1".to_string()));
        assert_eq!(sample.labels.get("extra"), Some(&"x".to_string()));
        assert_eq!(sample.value, 2.0);
    }

    #[test]
    fn skips_malformed_and_blank_lines_without_panicking() {
        let txt = "\
not a metric line at all
blackwall_ok 3

blackwall_bad_value abc
{malformed} 1
";
        let s = parse_prometheus(txt);
        assert_eq!(s.gauge("blackwall_ok"), Some(3.0));
        assert_eq!(s.families.len(), 1);
    }

    #[test]
    fn empty_text_yields_empty_snapshot() {
        let s = parse_prometheus("");
        assert!(s.families.is_empty());
        assert_eq!(s.gauge("anything"), None);
        assert!(s.samples("anything").is_empty());
    }
}
