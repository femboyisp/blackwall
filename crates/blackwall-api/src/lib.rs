//! Blackwall operations control API (axum). Phase 1: read-only endpoints.
#![forbid(unsafe_code)]

pub mod error;
pub mod state;

pub use error::{ApiError, ApiResult};
pub use state::AppState;
