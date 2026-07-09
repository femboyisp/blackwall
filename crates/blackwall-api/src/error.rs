//! The API's single error type and its HTTP representation.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Every failure an API handler can return, mapped to one HTTP status.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Missing or invalid bearer token.
    #[error("unauthorized")]
    Unauthorized,
    /// A named tenant or resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// Input failed structural or semantic validation.
    #[error("validation failed: {0}")]
    Validation(String),
    /// A uniqueness constraint was violated.
    #[error("conflict: {0}")]
    Conflict(String),
    /// The kernel apply (nft/XDP) failed after the database commit.
    #[error("apply failed: {0}")]
    ApplyFailed(String),
    /// An internal failure whose detail is logged, never returned to the client.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::ApplyFailed(_) | ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::Unauthorized => "unauthorized",
            ApiError::NotFound(_) => "not_found",
            ApiError::Validation(_) => "validation_failed",
            ApiError::Conflict(_) => "conflict",
            ApiError::ApplyFailed(_) => "apply_failed",
            ApiError::Internal(_) => "internal",
        }
    }

    /// The client-safe message. `Internal` never leaks its detail.
    fn public_message(&self) -> String {
        match self {
            ApiError::Internal(_) => "internal error".to_owned(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(detail) = &self {
            tracing::error!(%detail, "api internal error");
        }
        let body = serde_json::json!({
            "error": { "code": self.code(), "message": self.public_message() }
        });
        (self.status(), Json(body)).into_response()
    }
}

/// Shorthand for handler results.
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn status_and_code_mapping() {
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ApiError::NotFound("t".into()).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::Validation("v".into()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Conflict("c".into()).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::ApplyFailed("a".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(ApiError::Unauthorized.code(), "unauthorized");
    }

    #[test]
    fn internal_detail_is_not_leaked() {
        assert_eq!(
            ApiError::Internal("secret db url".into()).public_message(),
            "internal error"
        );
        // Non-internal errors keep their message.
        assert_eq!(
            ApiError::NotFound("acme".into()).public_message(),
            "not found: acme"
        );
    }
}
