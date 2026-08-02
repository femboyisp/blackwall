//! `ApiClient`: read-only HTTP access to the control API's `/v1/*` entity
//! routes, decoding straight into `blackwall_api::dto` types (no redefined
//! DTOs — see that crate's `RtbhDto`/`DetectionDto`/`SessionDto` doc for why
//! they're `Deserialize`). Only `GET` requests: this client has no
//! write/mutating method, matching the dashboard's read-only constraint.
//!
//! The real network request functions are excluded from the coverage gate
//! (`scripts/coverage.sh`), matching the repo's existing `*_net.rs`/`api.rs`
//! convention (e.g. `bin/blackwalld/src/api.rs`, `flow/src/collector_net.rs`)
//! — they need a live control API to exercise. The DTO wire-contract is
//! covered by the fixture-based decode test below, which needs no network.

use blackwall_api::dto::{DetectionDto, RtbhDto, SessionDto};
use reqwest::Url;

/// Errors an `ApiClient`/`MetricsClient` request can fail with.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The underlying HTTP request failed (connect/timeout/TLS/etc).
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The response body failed to decode into the expected type.
    #[error("failed to decode response body: {0}")]
    Decode(#[from] serde_json::Error),
    /// The server returned a non-2xx status.
    #[error("server returned status {0}")]
    Status(u16),
}

/// Read-only client for the control API's `/v1/*` entity routes.
#[derive(Debug, Clone)]
pub struct ApiClient {
    base: Url,
    token: Option<String>,
    http: reqwest::Client,
}

impl ApiClient {
    /// Build a client against `base` (e.g. `http://127.0.0.1:8080`),
    /// optionally authenticating every request with `token` as a `Bearer`
    /// `Authorization` header.
    #[must_use]
    pub fn new(base: Url, token: Option<String>) -> Self {
        Self {
            base,
            token,
            http: reqwest::Client::new(),
        }
    }

    /// `GET` a `/v1/*` JSON array route and decode it, applying the bearer
    /// token (if configured) and mapping a non-2xx status to
    /// [`ClientError::Status`]. I/O glue — excluded from coverage like
    /// `bin/blackwalld/src/api.rs`; needs a live control API to exercise.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = self.base.join(path).map_err(|_| ClientError::Status(0))?;
        let mut req = self.http.get(url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(ClientError::Status(resp.status().as_u16()));
        }
        let body = resp.text().await?;
        let decoded = serde_json::from_str(&body)?;
        Ok(decoded)
    }

    /// `GET /v1/mitigations/rtbh` — active RTBH blackholes.
    pub async fn rtbh(&self) -> Result<Vec<RtbhDto>, ClientError> {
        self.get_json("/v1/mitigations/rtbh").await
    }

    /// `GET /v1/sessions` — most-recent deception sessions.
    pub async fn sessions(&self) -> Result<Vec<SessionDto>, ClientError> {
        self.get_json("/v1/sessions").await
    }

    /// `GET /v1/detections` — active volumetric detections.
    pub async fn detections(&self) -> Result<Vec<DetectionDto>, ClientError> {
        self.get_json("/v1/detections").await
    }
}

#[cfg(test)]
mod tests {
    use blackwall_api::dto::RtbhDto;

    /// The shape mirrors `GET /v1/mitigations/rtbh`'s JSON body, one
    /// `RtbhDto` (`crates/blackwall-api/src/dto.rs`): `target` (IP string),
    /// `origin` (string), `announced_at_ms` (u64), `withdrawn_at_ms`
    /// (nullable u64). Decoding straight into the shared DTO — not a
    /// redefined client-side type — makes schema drift a compile error.
    #[test]
    fn rtbh_response_decodes_into_dto() {
        let json = r#"[
            {
                "target": "203.0.113.5",
                "origin": "api:admin",
                "announced_at_ms": 1735689600000,
                "withdrawn_at_ms": null
            },
            {
                "target": "2001:db8::1",
                "origin": "detector:auto",
                "announced_at_ms": 1735689700000,
                "withdrawn_at_ms": 1735689800000
            }
        ]"#;
        let v: Vec<RtbhDto> = serde_json::from_str(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].origin, "api:admin");
        assert_eq!(v[0].announced_at_ms, 1_735_689_600_000);
        assert_eq!(v[0].withdrawn_at_ms, None);
        assert_eq!(v[1].withdrawn_at_ms, Some(1_735_689_800_000));
    }

    #[test]
    fn malformed_rtbh_response_fails_to_decode() {
        let json = r#"[{"target": "not-an-ip", "origin": "x"}]"#;
        let result: Result<Vec<RtbhDto>, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
