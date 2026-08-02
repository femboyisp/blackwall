//! `MetricsClient`: scrapes the Prometheus text endpoint (`:9100` by
//! default) and parses it with [`crate::parse_prometheus`]. I/O glue —
//! excluded from coverage like `api.rs`/`bin/blackwalld/src/api.rs`; needs a
//! live metrics endpoint to exercise. `parse_prometheus` itself is fully
//! unit-tested in `metrics.rs`.

use crate::api::ClientError;
use crate::{parse_prometheus, MetricsSnapshot};
use reqwest::Url;

/// Read-only client for the Prometheus text-exposition endpoint.
#[derive(Debug, Clone)]
pub struct MetricsClient {
    url: Url,
    http: reqwest::Client,
}

impl MetricsClient {
    /// Build a client against `url` (the full `/metrics` endpoint URL).
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self {
            url,
            http: reqwest::Client::new(),
        }
    }

    /// Scrape and parse the current exposition. A non-2xx status maps to
    /// [`ClientError::Status`].
    pub async fn fetch(&self) -> Result<MetricsSnapshot, ClientError> {
        let resp = self.http.get(self.url.clone()).send().await?;
        if !resp.status().is_success() {
            return Err(ClientError::Status(resp.status().as_u16()));
        }
        let body = resp.text().await?;
        Ok(parse_prometheus(&body))
    }
}
