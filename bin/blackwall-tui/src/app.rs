//! `AppState`: the latest data each panel renders from, plus per-source
//! staleness. Pure data + pure methods — no I/O lives here (the terminal
//! setup and the tokio refresh loop that feeds this state live in
//! `main.rs`, which is coverage-excluded).

use blackwall_api::dto::{RtbhDto, SessionDto};
use blackwall_client::views::{self, BgpPeer, Throughput};
use blackwall_client::MetricsSnapshot;
use std::time::Duration;

/// A source is drawn dim with a stale badge once its last successful
/// refresh is older than this.
pub const STALE_AFTER: Duration = Duration::from_secs(10);

/// Everything the panels render from. Populated by the refresh loop in
/// `main.rs` via [`AppState::apply_metrics`]/[`AppState::apply_api`], with
/// [`AppState::tick_ages`] advancing the staleness clock between refreshes.
/// `Default` is the dashboard's pre-first-scrape state (empty, unarmed, zero
/// age, so nothing renders stale until a source has actually had a chance
/// to report in).
#[derive(Debug, Clone, Default)]
pub struct AppState {
    /// Computed from the two most recent metrics scrapes; `None` until a
    /// second scrape has landed.
    pub throughput: Option<Throughput>,
    /// Decoded BGP session rows from the most recent metrics scrape.
    pub peers: Vec<BgpPeer>,
    /// Active RTBH blackholes from the most recent `/v1/mitigations/rtbh` fetch.
    pub rtbh: Vec<RtbhDto>,
    /// Recent deception sessions from the most recent `/v1/sessions` fetch.
    pub sessions: Vec<SessionDto>,
    /// Whether mitigations are live (`blackwall_armed`, from the metrics scrape).
    pub armed: bool,
    /// Time since the metrics endpoint last answered successfully.
    pub metrics_age: Duration,
    /// Time since the control API last answered successfully.
    pub api_age: Duration,

    /// The previous metrics snapshot, kept to compute [`Throughput`] as a
    /// delta against the next one. `pub(crate)`, not `pub`: internal
    /// bookkeeping that panel test modules need for `AppState { .. }`
    /// struct-update literals, but no other crate should read.
    pub(crate) prev_metrics: Option<MetricsSnapshot>,
    /// The `t_secs` timestamp `prev_metrics` was captured at.
    pub(crate) prev_metrics_t: f64,
    /// The `t_secs` timestamp of the last successful metrics scrape, or
    /// `None` before the first one; drives `metrics_age` via `tick_ages`.
    pub(crate) last_metrics_t: Option<f64>,
    /// The `t_secs` timestamp of the last successful API entity fetch, or
    /// `None` before the first one; drives `api_age` via `tick_ages`.
    pub(crate) last_api_t: Option<f64>,
}

impl AppState {
    /// Whether the metrics-derived panels (throughput, peerings) should
    /// render dim with a stale badge.
    #[must_use]
    pub fn metrics_stale(&self) -> bool {
        self.metrics_age > STALE_AFTER
    }

    /// Whether the API-derived panels (rtbh, sessions) should render dim
    /// with a stale badge.
    #[must_use]
    pub fn api_stale(&self) -> bool {
        self.api_age > STALE_AFTER
    }

    /// Apply a freshly-scraped metrics snapshot at process-elapsed time
    /// `t_secs`: recomputes `armed`/`peers` from it directly, and — once a
    /// second snapshot has landed — `throughput` as the delta against the
    /// previous one (see [`views::throughput`]; a non-positive `dt`, e.g. a
    /// repeated or out-of-order timestamp, is skipped rather than dividing
    /// by zero/negative). Resets `metrics_age` to zero: this is, by
    /// definition, the moment of a successful refresh.
    pub fn apply_metrics(&mut self, snapshot: MetricsSnapshot, t_secs: f64) {
        self.armed = views::armed(&snapshot);
        self.peers = views::bgp_peers(&snapshot);

        if let Some(prev) = &self.prev_metrics {
            let dt = t_secs - self.prev_metrics_t;
            if dt > 0.0 {
                self.throughput = Some(views::throughput(prev, &snapshot, dt));
            }
        }

        self.prev_metrics_t = t_secs;
        self.last_metrics_t = Some(t_secs);
        self.metrics_age = Duration::ZERO;
        self.prev_metrics = Some(snapshot);
    }

    /// Apply freshly-fetched control-API entities at process-elapsed time
    /// `t_secs`. Resets `api_age` to zero.
    pub fn apply_api(&mut self, rtbh: Vec<RtbhDto>, sessions: Vec<SessionDto>, t_secs: f64) {
        self.rtbh = rtbh;
        self.sessions = sessions;
        self.last_api_t = Some(t_secs);
        self.api_age = Duration::ZERO;
    }

    /// Advance `metrics_age`/`api_age` to reflect `now_elapsed` (process
    /// uptime) against the last successful refresh of each source, without
    /// requiring a new scrape. Called on the refresh loop's fast idle tick
    /// so the stale badge counts up smoothly between scrapes rather than
    /// jumping only when a new one lands. A source that has never
    /// successfully refreshed is left at its current age (Phase 1 has no
    /// distinct "never seen" badge beyond the existing `OFFLINE` cutoff).
    pub fn tick_ages(&mut self, now_elapsed: Duration) {
        if let Some(last) = self.last_metrics_t {
            self.metrics_age = now_elapsed.saturating_sub(secs_to_duration(last));
        }
        if let Some(last) = self.last_api_t {
            self.api_age = now_elapsed.saturating_sub(secs_to_duration(last));
        }
    }
}

/// A non-negative `f64` seconds value as a `Duration`; negative input
/// clamps to zero.
fn secs_to_duration(secs: f64) -> Duration {
    Duration::from_secs_f64(secs.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_client::parse_prometheus;

    #[test]
    fn applying_two_metric_snapshots_yields_throughput() {
        let mut app = AppState::default();
        app.apply_metrics(
            parse_prometheus(
                "blackwall_flow_sampled_bytes_total 0\nblackwall_flow_sampled_packets_total 0\n",
            ),
            0.0,
        );
        app.apply_metrics(
            parse_prometheus(
                "blackwall_flow_sampled_bytes_total 1000\nblackwall_flow_sampled_packets_total 10\n",
            ),
            1.0,
        );
        assert_eq!(app.throughput.unwrap().bps, 8000.0);
        assert_eq!(app.throughput.unwrap().pps, 10.0);
    }

    #[test]
    fn a_single_snapshot_leaves_throughput_none() {
        let mut app = AppState::default();
        app.apply_metrics(
            parse_prometheus("blackwall_flow_sampled_bytes_total 0\n"),
            0.0,
        );
        assert!(app.throughput.is_none());
    }

    #[test]
    fn apply_metrics_updates_armed_and_peers_and_resets_age() {
        let mut app = AppState {
            metrics_age: Duration::from_secs(30),
            ..Default::default()
        };
        app.apply_metrics(
            parse_prometheus("blackwall_armed 1\nblackwall_bgp_session_state 2\n"),
            0.0,
        );
        assert!(app.armed);
        assert_eq!(app.peers.len(), 1);
        assert_eq!(app.metrics_age, Duration::ZERO);
    }

    #[test]
    fn apply_api_replaces_entities_and_resets_age() {
        let mut app = AppState {
            api_age: Duration::from_secs(30),
            ..Default::default()
        };
        app.apply_api(vec![], vec![], 0.0);
        assert_eq!(app.api_age, Duration::ZERO);
        assert!(app.rtbh.is_empty());
        assert!(app.sessions.is_empty());
    }

    #[test]
    fn tick_ages_advances_age_since_last_successful_refresh() {
        let mut app = AppState::default();
        app.apply_metrics(parse_prometheus("blackwall_armed 1\n"), 2.0);
        app.apply_api(vec![], vec![], 2.0);
        app.tick_ages(Duration::from_secs_f64(9.0));
        assert_eq!(app.metrics_age, Duration::from_secs(7));
        assert_eq!(app.api_age, Duration::from_secs(7));
    }

    #[test]
    fn tick_ages_before_any_refresh_leaves_zero_age() {
        let mut app = AppState::default();
        app.tick_ages(Duration::from_secs(100));
        assert_eq!(app.metrics_age, Duration::ZERO);
        assert_eq!(app.api_age, Duration::ZERO);
    }

    #[test]
    fn out_of_order_timestamp_does_not_produce_negative_dt_throughput() {
        let mut app = AppState::default();
        app.apply_metrics(
            parse_prometheus("blackwall_flow_sampled_bytes_total 1000\n"),
            5.0,
        );
        // A repeated/earlier timestamp: dt <= 0, so throughput is left
        // untouched rather than computed from a non-positive interval.
        app.apply_metrics(
            parse_prometheus("blackwall_flow_sampled_bytes_total 2000\n"),
            5.0,
        );
        assert!(app.throughput.is_none());
    }

    #[test]
    fn stale_helpers_reflect_the_threshold() {
        let mut app = AppState::default();
        assert!(!app.metrics_stale());
        assert!(!app.api_stale());
        app.metrics_age = STALE_AFTER + Duration::from_secs(1);
        app.api_age = STALE_AFTER + Duration::from_secs(1);
        assert!(app.metrics_stale());
        assert!(app.api_stale());
    }
}
