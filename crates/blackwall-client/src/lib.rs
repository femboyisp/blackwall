//! Read-only data layer shared by the Blackwall TUI (Phase 1) and, later, the
//! web GUI (Phase 2): an [`api::ApiClient`] over the read control API's
//! `/v1/*` routes (reusing `blackwall_api::dto` types directly — no
//! redefined DTOs) and a [`http::MetricsClient`] that scrapes and parses the
//! Prometheus text endpoint. No mutating/write call lives anywhere in this
//! crate.

pub mod metrics;

pub use metrics::{parse_prometheus, MetricsSnapshot, Sample};
