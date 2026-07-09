//! Bearer-token authentication: a static admin token, stored hashed, compared
//! in constant time on every request.

use crate::error::ApiError;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// The configured admin credential: a short non-secret id (for audit
/// attribution) plus the SHA-256 of the secret token.
#[derive(Clone)]
pub struct AuthConfig {
    token_id: String,
    token_sha256: [u8; 32],
}

impl AuthConfig {
    /// Build from a label and the plaintext token (which is hashed, not stored).
    pub fn new(token_id: impl Into<String>, plaintext_token: &str) -> Self {
        let digest = Sha256::digest(plaintext_token.as_bytes());
        let mut token_sha256 = [0u8; 32];
        token_sha256.copy_from_slice(&digest);
        Self {
            token_id: token_id.into(),
            token_sha256,
        }
    }

    /// The non-secret label used to attribute audited actions.
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Constant-time check of a presented plaintext token.
    fn accepts(&self, presented: &str) -> bool {
        let digest = Sha256::digest(presented.as_bytes());
        digest.ct_eq(&self.token_sha256).into()
    }
}

/// axum middleware: require a valid `Authorization: Bearer <token>` header.
pub async fn require_bearer(
    State(auth): State<Arc<AuthConfig>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match presented {
        Some(token) if auth.accepts(token) => Ok(next.run(req).await),
        _ => Err(ApiError::Unauthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt as _; // for `oneshot`

    #[test]
    fn accepts_correct_token_only() {
        let auth = AuthConfig::new("admin", "s3cret");
        assert!(auth.accepts("s3cret"));
        assert!(!auth.accepts("wrong"));
        assert!(!auth.accepts("s3cre")); // prefix must not pass
        assert!(!auth.accepts(""));
        assert_eq!(auth.token_id(), "admin");
    }

    fn guarded_router() -> Router {
        let auth = Arc::new(AuthConfig::new("admin", "s3cret"));
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn_with_state(
                auth.clone(),
                require_bearer,
            ))
            .with_state(auth)
    }

    #[tokio::test]
    async fn rejects_missing_and_accepts_valid_bearer() {
        // Missing header → 401.
        let resp = guarded_router()
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);

        // Valid bearer → 200.
        let resp = guarded_router()
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("authorization", "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
