# Blackwall A·M4 — Phase 1: Read-Only Control API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `blackwall-api` crate — an authenticated, tenant-aware, read-only HTTP control API (axum) with a generated OpenAPI document — mounted inside `blackwalld run` behind a new `api listen=… token-file=…` config directive.

**Architecture:** A new library crate `blackwall-api` holds the entire HTTP surface (router, DTOs, auth layer, handlers) and depends only on an `AppState` trait — so every handler unit-tests against an in-memory fake with no database. The concrete `AppState` (backed by `blackwall_state::Store`) and the `TcpListener`/`axum::serve` bind loop live in thin, coverage-excluded `blackwalld` glue, exactly like the existing `/metrics` endpoint. Phase 1 is read-only; the `AppState` trait and DTOs are shaped so Phase 2 mutation methods are additive, not a rewrite.

**Tech Stack:** Rust 2021, axum, tower/tower-http, utoipa (code-first OpenAPI), subtle (constant-time compare), sha2 (token hashing), sqlx→PostgreSQL, async-trait, serde.

## Global Constraints

Copied verbatim from `docs/superpowers/specs/2026-07-09-blackwall-am4-api-ops-design.md`. Every task inherits these:

- **No `as` casts.** Use `TryFrom`/`try_from`, `to_be_bytes`, etc.
- **`#[expect(lint, reason = "…")]`, never bare `#[allow]`.**
- **Exact version pins** for every new dependency (`=x.y.z`), no caret ranges.
- **Rustdoc on all public items.**
- **≥90% line coverage** (`scripts/coverage.sh`).
- **`cargo clippy --workspace --all-targets -- --deny warnings` clean; `cargo fmt --all -- --check` clean.**
- **No `Co-Authored-By` / `Claude-Session` commit trailers.**
- `DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall` (PostgreSQL on port 5433).
- Work in this worktree: `/home/zoa/projects/femboy/blackwall/blackwall-am4-wt`, branch `sp-am4-spec` (off `origin/main`).

## Exact-Pinned Dependencies (add to `[workspace.dependencies]` in root `Cargo.toml`)

Confirm the latest patch of each at implementation time with `cargo search <name>` and pin exactly:

```toml
axum = "=0.8.1"
tower = "=0.5.2"
tower-http = { version = "=0.6.2", features = ["trace"] }
utoipa = { version = "=5.3.1", features = ["axum_extras"] }
subtle = "=2.6.1"
sha2 = "=0.10.8"
```

`serde`, `serde_json`, `async-trait`, `thiserror`, `tokio`, `tracing` already exist in `[workspace.dependencies]` — reuse via `.workspace = true`.

## File Structure

```
crates/blackwall-api/
  Cargo.toml                — new crate manifest
  src/lib.rs                — crate root: re-exports, router() builder, OpenApi doc
  src/error.rs              — ApiError enum + IntoResponse
  src/auth.rs               — AuthConfig + bearer-token middleware
  src/state.rs              — AppState trait + the *View DTOs it returns
  src/dto.rs                — HTTP response DTOs (utoipa::ToSchema) + From<*View>
  src/handlers.rs           — axum handlers (generic over AppState)
  src/testutil.rs           — #[cfg(test)] in-memory FakeState
crates/blackwall-state/src/lib.rs   — MODIFY: add 5 thin read methods
crates/blackwall-core/src/policy.rs — MODIFY: add `api: Option<ApiConfig>` field
crates/blackwall-core/src/lib.rs    — MODIFY: define ApiConfig struct + re-export
crates/blackwall-config/src/parser.rs — MODIFY: parse `api` directive
bin/blackwalld/Cargo.toml           — MODIFY: depend on blackwall-api
bin/blackwalld/src/api.rs           — new: concrete StoreAppState + serve glue (coverage-excluded)
bin/blackwalld/src/main.rs          — MODIFY: mount API in run
```

---

### Task 1: Scaffold `blackwall-api` crate — error type + AppState trait + View DTOs

**Files:**
- Create: `crates/blackwall-api/Cargo.toml`
- Create: `crates/blackwall-api/src/lib.rs`
- Create: `crates/blackwall-api/src/error.rs`
- Create: `crates/blackwall-api/src/state.rs`

**Interfaces:**
- Produces:
  - `pub enum ApiError { Unauthorized, NotFound(String), Validation(String), Conflict(String), ApplyFailed(String), Internal(String) }` with `impl IntoResponse` and `impl std::error::Error`.
  - `pub type ApiResult<T> = Result<T, ApiError>;`
  - `#[async_trait] pub trait AppState: Send + Sync + 'static` with read methods (listed below) all returning `ApiResult<…>`.
  - View structs in `state.rs`: `TenantView { name: String, owned: Vec<IpAddr> }`, `ServiceView { tenant: String, address: IpAddr, proto: String, port: u16, target: String }`, `IpAssignmentView { tenant: String, address: IpAddr }`, `RtbhView { target: IpAddr, origin: String, announced_at_ms: u64, withdrawn_at_ms: Option<u64> }`, `FlowSpecView { dst: IpAddr, proto: u8, dst_port: u16, rate: f32, origin: String, announced_at_ms: u64, withdrawn_at_ms: Option<u64> }`, `XdpView { kind: String, target: IpAddr, prefixlen: Option<u8>, rate_pps: Option<u64>, burst: Option<u64>, origin: String, victim: Option<IpAddr> }`, `DetectionView { target: IpAddr, observed_pps: f64, observed_bps: f64, severity: String, first_seen_ms: u64, last_seen_ms: u64 }`, `SessionView { local_addr: IpAddr, local_port: u16, peer_addr: IpAddr, proto: String, emulator: String, bytes_in: i64, bytes_out: i64, note: Option<String> }`, `AuditView { at_ms: u64, actor: String, action: String, detail: serde_json::Value }`.

- [ ] **Step 1: Create the crate manifest**

`crates/blackwall-api/Cargo.toml`:

```toml
[package]
name = "blackwall-api"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
axum = "=0.8.1"
tower = "=0.5.2"
tower-http = { version = "=0.6.2", features = ["trace"] }
utoipa = { version = "=5.3.1", features = ["axum_extras"] }
subtle = "=2.6.1"
sha2 = "=0.10.8"
serde = { workspace = true }
serde_json = { workspace = true }
async-trait = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tokio = { workspace = true }
```

- [ ] **Step 2: Write the failing test for `ApiError` → HTTP status mapping**

Create `crates/blackwall-api/src/error.rs`:

```rust
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
            ApiError::ApplyFailed(_) | ApiError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
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
        assert_eq!(ApiError::NotFound("t".into()).status(), StatusCode::NOT_FOUND);
        assert_eq!(ApiError::Validation("v".into()).status(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::Conflict("c".into()).status(), StatusCode::CONFLICT);
        assert_eq!(
            ApiError::ApplyFailed("a".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(ApiError::Unauthorized.code(), "unauthorized");
    }

    #[test]
    fn internal_detail_is_not_leaked() {
        assert_eq!(ApiError::Internal("secret db url".into()).public_message(), "internal error");
        // Non-internal errors keep their message.
        assert_eq!(ApiError::NotFound("acme".into()).public_message(), "not found: acme");
    }
}
```

- [ ] **Step 3: Create `state.rs` with the View DTOs and the `AppState` trait**

Create `crates/blackwall-api/src/state.rs`:

```rust
//! The `AppState` seam: what handlers need from the daemon, and the plain
//! data views they return. Phase 1 is read-only; Phase 2 adds mutation methods.

use crate::error::ApiResult;
use async_trait::async_trait;
use std::net::IpAddr;

/// A tenant and the addresses it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantView {
    /// Unique tenant name.
    pub name: String,
    /// Addresses assigned to the tenant.
    pub owned: Vec<IpAddr>,
}

/// A real service exposed by a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    /// Owning tenant name.
    pub tenant: String,
    /// Frontend address.
    pub address: IpAddr,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Frontend port.
    pub port: u16,
    /// Rendered target (e.g. `"accept"` or `"nat:203.0.113.9:8080"`).
    pub target: String,
}

/// One tenant↔address assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAssignmentView {
    /// Owning tenant name.
    pub tenant: String,
    /// Assigned address.
    pub address: IpAddr,
}

/// An RTBH blackhole (announced mirror).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtbhView {
    /// Null-routed target.
    pub target: IpAddr,
    /// Who requested it.
    pub origin: String,
    /// Announce time (ms since epoch).
    pub announced_at_ms: u64,
    /// Withdraw time, if withdrawn.
    pub withdrawn_at_ms: Option<u64>,
}

/// A FlowSpec rule (announced mirror).
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpecView {
    /// Victim destination.
    pub dst: IpAddr,
    /// IP protocol number.
    pub proto: u8,
    /// Destination port.
    pub dst_port: u16,
    /// Rate-limit (bytes/s; 0 = drop).
    pub rate: f32,
    /// Who requested it.
    pub origin: String,
    /// Announce time (ms).
    pub announced_at_ms: u64,
    /// Withdraw time, if withdrawn.
    pub withdrawn_at_ms: Option<u64>,
}

/// An active XDP block / rate-limit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpView {
    /// `"block"` or `"rate_limit"`.
    pub kind: String,
    /// Source or victim target.
    pub target: IpAddr,
    /// LPM prefix length, if a prefix.
    pub prefixlen: Option<u8>,
    /// Rate limit (pps), if a rate-limit entry.
    pub rate_pps: Option<u64>,
    /// Token-bucket burst, if a rate-limit entry.
    pub burst: Option<u64>,
    /// Who requested it.
    pub origin: String,
    /// Victim address, if source-keyed to a victim.
    pub victim: Option<IpAddr>,
}

/// An active volumetric detection.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionView {
    /// Detected target.
    pub target: IpAddr,
    /// Observed packets/s.
    pub observed_pps: f64,
    /// Observed bits/s.
    pub observed_bps: f64,
    /// Severity label.
    pub severity: String,
    /// First-seen time (ms).
    pub first_seen_ms: u64,
    /// Last-seen time (ms).
    pub last_seen_ms: u64,
}

/// A recorded deception session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    /// Local (honeypot) address.
    pub local_addr: IpAddr,
    /// Local port.
    pub local_port: u16,
    /// Peer (attacker) address.
    pub peer_addr: IpAddr,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Emulator that handled it.
    pub emulator: String,
    /// Bytes received.
    pub bytes_in: i64,
    /// Bytes sent.
    pub bytes_out: i64,
    /// Captured detail (request line / attempted creds).
    pub note: Option<String>,
}

/// One audit-log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditView {
    /// Event time (ms).
    pub at_ms: u64,
    /// Who acted (e.g. `"api:admin"`).
    pub actor: String,
    /// What happened (e.g. `"service.create"`).
    pub action: String,
    /// Structured detail.
    pub detail: serde_json::Value,
}

/// Everything the read-only handlers need from the daemon. The concrete impl
/// lives in `blackwalld`; tests use an in-memory fake.
#[async_trait]
pub trait AppState: Send + Sync + 'static {
    /// All tenants.
    async fn tenants(&self) -> ApiResult<Vec<TenantView>>;
    /// All exposed services.
    async fn services(&self) -> ApiResult<Vec<ServiceView>>;
    /// All tenant↔address assignments.
    async fn ip_assignments(&self) -> ApiResult<Vec<IpAssignmentView>>;
    /// Active RTBH blackholes.
    async fn rtbh(&self) -> ApiResult<Vec<RtbhView>>;
    /// Active FlowSpec rules.
    async fn flowspec(&self) -> ApiResult<Vec<FlowSpecView>>;
    /// Active XDP entries.
    async fn xdp(&self) -> ApiResult<Vec<XdpView>>;
    /// Active detections.
    async fn detections(&self) -> ApiResult<Vec<DetectionView>>;
    /// Most-recent sessions, newest first, capped at `limit`.
    async fn sessions(&self, limit: i64) -> ApiResult<Vec<SessionView>>;
    /// Most-recent audit entries, newest first, capped at `limit`.
    async fn audit(&self, limit: i64) -> ApiResult<Vec<AuditView>>;
}
```

- [ ] **Step 4: Create `lib.rs` wiring the modules**

Create `crates/blackwall-api/src/lib.rs`:

```rust
//! Blackwall operations control API (axum). Phase 1: read-only endpoints.
#![forbid(unsafe_code)]

pub mod error;
pub mod state;

pub use error::{ApiError, ApiResult};
pub use state::AppState;
```

- [ ] **Step 5: Add the crate to the workspace and verify it compiles + error tests pass**

Add the six new deps to `[workspace.dependencies]` in the root `Cargo.toml` (see the pinned-deps block above). The crate is picked up automatically by the `members = ["crates/*"]` glob.

Run:
```bash
cd /home/zoa/projects/femboy/blackwall/blackwall-am4-wt
cargo test -p blackwall-api 2>&1 | grep -E "test result|error\["
```
Expected: `test result: ok. 2 passed` (the two `error.rs` tests), no compile errors.

- [ ] **Step 6: Commit**

```bash
git add crates/blackwall-api Cargo.toml
git commit -m "feat(api): scaffold blackwall-api crate — ApiError + AppState trait + views"
```

---

### Task 2: Bearer-token auth middleware

**Files:**
- Create: `crates/blackwall-api/src/auth.rs`
- Modify: `crates/blackwall-api/src/lib.rs` (add `pub mod auth;`)

**Interfaces:**
- Consumes: `ApiError` (Task 1).
- Produces:
  - `pub struct AuthConfig { token_id: String, token_sha256: [u8; 32] }` with `pub fn new(token_id: impl Into<String>, plaintext_token: &str) -> Self` (hashes with SHA-256) and `pub fn token_id(&self) -> &str`.
  - `pub async fn require_bearer(State(auth): State<Arc<AuthConfig>>, req: Request, next: Next) -> Result<Response, ApiError>` — an axum middleware that 401s unless `Authorization: Bearer <t>` hashes equal to the configured hash (constant-time via `subtle`).

- [ ] **Step 1: Write the failing test for token hashing + constant-time check**

Create `crates/blackwall-api/src/auth.rs`:

```rust
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
        Self { token_id: token_id.into(), token_sha256 }
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

    #[test]
    fn accepts_correct_token_only() {
        let auth = AuthConfig::new("admin", "s3cret");
        assert!(auth.accepts("s3cret"));
        assert!(!auth.accepts("wrong"));
        assert!(!auth.accepts("s3cre")); // prefix must not pass
        assert!(!auth.accepts(""));
        assert_eq!(auth.token_id(), "admin");
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/blackwall-api/src/lib.rs` add after `pub mod error;`:

```rust
pub mod auth;
```
and to the re-exports:
```rust
pub use auth::{AuthConfig, require_bearer};
```

- [ ] **Step 3: Run the unit test**

```bash
cargo test -p blackwall-api auth 2>&1 | grep -E "test result|error\["
```
Expected: `test result: ok. 1 passed`.

- [ ] **Step 4: Write an integration test that the middleware 401s / 200s over a real router**

Append to `crates/blackwall-api/src/auth.rs` `mod tests`:

```rust
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt as _; // from tower/axum dev tree
    use tower::ServiceExt as _; // for `oneshot`

    fn guarded_router() -> Router {
        let auth = Arc::new(AuthConfig::new("admin", "s3cret"));
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn_with_state(auth.clone(), require_bearer))
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
```

Add dev-deps to `crates/blackwall-api/Cargo.toml` `[dev-dependencies]`:
```toml
tower = "=0.5.2"
http-body-util = "=0.1.2"
```
(`tower` is already a normal dep; adding it under dev-deps is harmless but you may instead rely on the normal dep — keep the normal dep and add only `http-body-util` if duplication warns.)

- [ ] **Step 5: Run and commit**

```bash
cargo test -p blackwall-api auth 2>&1 | grep -E "test result|error\["
git add crates/blackwall-api
git commit -m "feat(api): bearer-token auth middleware (SHA-256, constant-time)"
```
Expected: `test result: ok. 2 passed`.

---

### Task 3: Read DTOs, handlers, and the router

**Files:**
- Create: `crates/blackwall-api/src/dto.rs`
- Create: `crates/blackwall-api/src/handlers.rs`
- Create: `crates/blackwall-api/src/testutil.rs`
- Modify: `crates/blackwall-api/src/lib.rs` (modules + `router()` builder)

**Interfaces:**
- Consumes: `AppState` + all `*View` types (Task 1), `AuthConfig` + `require_bearer` (Task 2).
- Produces:
  - `pub fn router(state: Arc<dyn AppState>, auth: Arc<AuthConfig>) -> axum::Router` — the fully-wired, auth-guarded router.
  - Response DTOs in `dto.rs` deriving `serde::Serialize` + `utoipa::ToSchema`, each with `From<*View>`.
  - `#[cfg(test)] pub struct FakeState { … }` in `testutil.rs` implementing `AppState` from in-memory vectors.

- [ ] **Step 1: Write the DTOs with `From<*View>` conversions**

Create `crates/blackwall-api/src/dto.rs`. One DTO per view; they are 1:1 in Phase 1 but kept separate so the wire contract can diverge later. Show two fully; the rest follow the identical field-copy pattern:

```rust
//! HTTP response bodies. Separate from the internal `*View` types so the wire
//! contract is decoupled from the daemon's data model.

use crate::state::{
    AuditView, DetectionView, FlowSpecView, IpAssignmentView, RtbhView, ServiceView,
    SessionView, TenantView, XdpView,
};
use serde::Serialize;
use std::net::IpAddr;
use utoipa::ToSchema;

/// A tenant and its owned addresses.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantDto {
    /// Unique tenant name.
    pub name: String,
    /// Addresses assigned to the tenant.
    pub owned: Vec<IpAddr>,
}

impl From<TenantView> for TenantDto {
    fn from(v: TenantView) -> Self {
        Self { name: v.name, owned: v.owned }
    }
}

/// A real service exposed by a tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceDto {
    /// Owning tenant.
    pub tenant: String,
    /// Frontend address.
    pub address: IpAddr,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Frontend port.
    pub port: u16,
    /// Rendered target.
    pub target: String,
}

impl From<ServiceView> for ServiceDto {
    fn from(v: ServiceView) -> Self {
        Self { tenant: v.tenant, address: v.address, proto: v.proto, port: v.port, target: v.target }
    }
}

// Repeat the identical pattern for: IpAssignmentDto(IpAssignmentView),
// RtbhDto(RtbhView), FlowSpecDto(FlowSpecView), XdpDto(XdpView),
// DetectionDto(DetectionView), SessionDto(SessionView), AuditDto(AuditView).
// Each derives (Debug, Serialize, ToSchema), has the SAME fields as its View,
// and a From<View> that moves every field across. Full field lists are in
// state.rs (Task 1). Every public field carries a one-line rustdoc.
```

Write out all nine DTOs (do not leave the comment as-is — the comment names exactly which structs to produce and their fields live in `state.rs`).

- [ ] **Step 2: Write the `FakeState` test helper**

Create `crates/blackwall-api/src/testutil.rs`:

```rust
//! In-memory `AppState` for handler tests — no database, no kernel.

use crate::error::ApiResult;
use crate::state::*;
use async_trait::async_trait;

/// A fake `AppState` returning fixed vectors. Fields are public so each test
/// sets exactly the rows it needs.
#[derive(Default)]
pub struct FakeState {
    pub tenants: Vec<TenantView>,
    pub services: Vec<ServiceView>,
    pub ip_assignments: Vec<IpAssignmentView>,
    pub rtbh: Vec<RtbhView>,
    pub flowspec: Vec<FlowSpecView>,
    pub xdp: Vec<XdpView>,
    pub detections: Vec<DetectionView>,
    pub sessions: Vec<SessionView>,
    pub audit: Vec<AuditView>,
}

#[async_trait]
impl AppState for FakeState {
    async fn tenants(&self) -> ApiResult<Vec<TenantView>> { Ok(self.tenants.clone()) }
    async fn services(&self) -> ApiResult<Vec<ServiceView>> { Ok(self.services.clone()) }
    async fn ip_assignments(&self) -> ApiResult<Vec<IpAssignmentView>> { Ok(self.ip_assignments.clone()) }
    async fn rtbh(&self) -> ApiResult<Vec<RtbhView>> { Ok(self.rtbh.clone()) }
    async fn flowspec(&self) -> ApiResult<Vec<FlowSpecView>> { Ok(self.flowspec.clone()) }
    async fn xdp(&self) -> ApiResult<Vec<XdpView>> { Ok(self.xdp.clone()) }
    async fn detections(&self) -> ApiResult<Vec<DetectionView>> { Ok(self.detections.clone()) }
    async fn sessions(&self, limit: i64) -> ApiResult<Vec<SessionView>> {
        Ok(self.sessions.iter().take(limit.max(0) as usize).cloned().collect())
    }
    async fn audit(&self, limit: i64) -> ApiResult<Vec<AuditView>> {
        Ok(self.audit.iter().take(limit.max(0) as usize).cloned().collect())
    }
}
```

Note: the `as usize` here is in **test-only** code. To honor the no-`as` rule even in tests, replace with `usize::try_from(limit.max(0)).unwrap_or(0)`. Use that form.

- [ ] **Step 3: Write the handlers**

Create `crates/blackwall-api/src/handlers.rs`. Handlers are generic over `Arc<dyn AppState>` via `State`. Global list endpoints and tenant-scoped endpoints (which resolve + 404 on unknown tenant, then filter):

```rust
//! Read-only axum handlers, generic over `AppState`.

use crate::dto::*;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

/// Default row cap for the `sessions`/`audit` feeds.
const DEFAULT_LIMIT: i64 = 100;

/// `?limit=` query for the capped feeds.
#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    limit: Option<i64>,
}

type St = State<Arc<dyn AppState>>;

/// `GET /v1/tenants`
pub async fn list_tenants(State(s): St) -> ApiResult<Json<Vec<TenantDto>>> {
    Ok(Json(s.tenants().await?.into_iter().map(TenantDto::from).collect()))
}

/// `GET /v1/tenants/{name}` — 404 if unknown.
pub async fn get_tenant(State(s): St, Path(name): Path<String>) -> ApiResult<Json<TenantDto>> {
    let t = s.tenants().await?.into_iter().find(|t| t.name == name);
    t.map(|t| Json(TenantDto::from(t))).ok_or(ApiError::NotFound(name))
}

/// `GET /v1/tenants/{name}/services` — 404 if the tenant is unknown.
pub async fn tenant_services(
    State(s): St,
    Path(name): Path<String>,
) -> ApiResult<Json<Vec<ServiceDto>>> {
    if !s.tenants().await?.iter().any(|t| t.name == name) {
        return Err(ApiError::NotFound(name));
    }
    let out = s
        .services()
        .await?
        .into_iter()
        .filter(|svc| svc.tenant == name)
        .map(ServiceDto::from)
        .collect();
    Ok(Json(out))
}

/// `GET /v1/tenants/{name}/ip-assignments` — 404 if the tenant is unknown.
pub async fn tenant_ip_assignments(
    State(s): St,
    Path(name): Path<String>,
) -> ApiResult<Json<Vec<IpAssignmentDto>>> {
    if !s.tenants().await?.iter().any(|t| t.name == name) {
        return Err(ApiError::NotFound(name));
    }
    let out = s
        .ip_assignments()
        .await?
        .into_iter()
        .filter(|a| a.tenant == name)
        .map(IpAssignmentDto::from)
        .collect();
    Ok(Json(out))
}

/// `GET /v1/mitigations/rtbh`
pub async fn list_rtbh(State(s): St) -> ApiResult<Json<Vec<RtbhDto>>> {
    Ok(Json(s.rtbh().await?.into_iter().map(RtbhDto::from).collect()))
}

/// `GET /v1/mitigations/flowspec`
pub async fn list_flowspec(State(s): St) -> ApiResult<Json<Vec<FlowSpecDto>>> {
    Ok(Json(s.flowspec().await?.into_iter().map(FlowSpecDto::from).collect()))
}

/// `GET /v1/mitigations/xdp`
pub async fn list_xdp(State(s): St) -> ApiResult<Json<Vec<XdpDto>>> {
    Ok(Json(s.xdp().await?.into_iter().map(XdpDto::from).collect()))
}

/// `GET /v1/detections`
pub async fn list_detections(State(s): St) -> ApiResult<Json<Vec<DetectionDto>>> {
    Ok(Json(s.detections().await?.into_iter().map(DetectionDto::from).collect()))
}

/// `GET /v1/sessions?limit=`
pub async fn list_sessions(
    State(s): St,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<SessionDto>>> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    Ok(Json(s.sessions(limit).await?.into_iter().map(SessionDto::from).collect()))
}

/// `GET /v1/audit?limit=`
pub async fn list_audit(
    State(s): St,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<Vec<AuditDto>>> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    Ok(Json(s.audit(limit).await?.into_iter().map(AuditDto::from).collect()))
}
```

- [ ] **Step 4: Write the `router()` builder in `lib.rs`**

Replace `crates/blackwall-api/src/lib.rs` body with:

```rust
//! Blackwall operations control API (axum). Phase 1: read-only endpoints.
#![forbid(unsafe_code)]

pub mod auth;
pub mod dto;
pub mod error;
pub mod handlers;
pub mod state;
#[cfg(test)]
pub mod testutil;

use std::sync::Arc;

pub use auth::{require_bearer, AuthConfig};
pub use error::{ApiError, ApiResult};
pub use state::AppState;

use axum::routing::get;
use axum::Router;

/// Build the fully-wired, auth-guarded read-only API router.
pub fn router(state: Arc<dyn AppState>, auth: Arc<AuthConfig>) -> Router {
    Router::new()
        .route("/v1/tenants", get(handlers::list_tenants))
        .route("/v1/tenants/{name}", get(handlers::get_tenant))
        .route("/v1/tenants/{name}/services", get(handlers::tenant_services))
        .route("/v1/tenants/{name}/ip-assignments", get(handlers::tenant_ip_assignments))
        .route("/v1/mitigations/rtbh", get(handlers::list_rtbh))
        .route("/v1/mitigations/flowspec", get(handlers::list_flowspec))
        .route("/v1/mitigations/xdp", get(handlers::list_xdp))
        .route("/v1/detections", get(handlers::list_detections))
        .route("/v1/sessions", get(handlers::list_sessions))
        .route("/v1/audit", get(handlers::list_audit))
        .layer(axum::middleware::from_fn_with_state(auth.clone(), require_bearer))
        .with_state(state)
}
```

Note the axum 0.8 path-param syntax is `{name}` (not `:name`).

- [ ] **Step 5: Write handler tests against `FakeState` (happy path, tenant 404, tenant scoping)**

Create `crates/blackwall-api/tests/read_endpoints.rs`:

```rust
use blackwall_api::testutil::FakeState;
use blackwall_api::{router, AuthConfig};
use blackwall_api::state::{ServiceView, TenantView};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt as _;

fn addr(s: &str) -> IpAddr { s.parse().unwrap() }

fn app(state: FakeState) -> axum::Router {
    let auth = Arc::new(AuthConfig::new("admin", "s3cret"));
    router(Arc::new(state), auth)
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", "Bearer s3cret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() { serde_json::Value::Null }
               else { serde_json::from_slice(&bytes).unwrap() };
    (status, json)
}

#[tokio::test]
async fn lists_tenants() {
    let state = FakeState {
        tenants: vec![TenantView { name: "acme".into(), owned: vec![addr("203.0.113.1")] }],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["name"], "acme");
    assert_eq!(body[0]["owned"][0], "203.0.113.1");
}

#[tokio::test]
async fn unknown_tenant_is_404() {
    let (status, body) = get_json(app(FakeState::default()), "/v1/tenants/ghost").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn tenant_services_are_scoped() {
    let state = FakeState {
        tenants: vec![
            TenantView { name: "acme".into(), owned: vec![] },
            TenantView { name: "other".into(), owned: vec![] },
        ],
        services: vec![
            ServiceView { tenant: "acme".into(), address: addr("203.0.113.1"), proto: "tcp".into(), port: 443, target: "accept".into() },
            ServiceView { tenant: "other".into(), address: addr("203.0.113.2"), proto: "tcp".into(), port: 80, target: "accept".into() },
        ],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/tenants/acme/services").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["port"], 443);
}

#[tokio::test]
async fn missing_auth_is_401() {
    let resp = app(FakeState::default())
        .oneshot(Request::builder().uri("/v1/tenants").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
```

Add `http-body-util = "=0.1.2"` to `[dev-dependencies]` if not already present from Task 2.

- [ ] **Step 6: Run all tests + clippy + fmt, then commit**

```bash
cargo test -p blackwall-api 2>&1 | grep -E "test result|error\["
cargo clippy -p blackwall-api --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates/blackwall-api Cargo.toml
git commit -m "feat(api): read-only DTOs, handlers, and auth-guarded router"
```
Expected: all tests pass; clippy clean.

---

### Task 4: Generated OpenAPI document + contract test

**Files:**
- Modify: `crates/blackwall-api/src/lib.rs` (add `ApiDoc` + `/v1/openapi.json` route)
- Modify: `crates/blackwall-api/src/handlers.rs` (add `#[utoipa::path]` to each handler)

**Interfaces:**
- Produces: `pub struct ApiDoc` deriving `utoipa::OpenApi`; a `GET /v1/openapi.json` route returning the doc as JSON.

- [ ] **Step 1: Annotate each handler with `#[utoipa::path]`**

Above each handler in `handlers.rs`, add its path annotation. Example for two; apply the analogous annotation to all ten:

```rust
#[utoipa::path(
    get, path = "/v1/tenants",
    responses((status = 200, description = "All tenants", body = [TenantDto])),
    security(("bearer" = []))
)]
pub async fn list_tenants(State(s): St) -> ApiResult<Json<Vec<TenantDto>>> { /* unchanged */ }

#[utoipa::path(
    get, path = "/v1/tenants/{name}",
    params(("name" = String, Path, description = "Tenant name")),
    responses(
        (status = 200, description = "The tenant", body = TenantDto),
        (status = 404, description = "Unknown tenant")
    ),
    security(("bearer" = []))
)]
pub async fn get_tenant(/* unchanged */) { /* unchanged */ }
```

- [ ] **Step 2: Define `ApiDoc` and serve it**

In `lib.rs` add:

```rust
use utoipa::OpenApi;

/// The generated OpenAPI 3.1 document for the control API.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::list_tenants, handlers::get_tenant, handlers::tenant_services,
        handlers::tenant_ip_assignments, handlers::list_rtbh, handlers::list_flowspec,
        handlers::list_xdp, handlers::list_detections, handlers::list_sessions,
        handlers::list_audit
    ),
    components(schemas(
        dto::TenantDto, dto::ServiceDto, dto::IpAssignmentDto, dto::RtbhDto,
        dto::FlowSpecDto, dto::XdpDto, dto::DetectionDto, dto::SessionDto, dto::AuditDto
    )),
    info(title = "Blackwall Control API", version = "1.0.0")
)]
pub struct ApiDoc;

async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}
```

Add the route to `router()` (before the auth layer so the schema is fetchable without a token, or after it to require auth — Phase 1 choice: keep it **behind** auth for parity with every other endpoint):

```rust
        .route("/v1/openapi.json", get(openapi_json))
```
(place this line among the other `.route(...)` calls, above the `.layer(...)`.)

- [ ] **Step 3: Write the contract test — every mounted route appears in the doc**

Create `crates/blackwall-api/tests/openapi_contract.rs`:

```rust
use blackwall_api::ApiDoc;
use utoipa::OpenApi;

#[test]
fn openapi_lists_every_route() {
    let doc = ApiDoc::openapi();
    let paths = &doc.paths.paths;
    for expected in [
        "/v1/tenants",
        "/v1/tenants/{name}",
        "/v1/tenants/{name}/services",
        "/v1/tenants/{name}/ip-assignments",
        "/v1/mitigations/rtbh",
        "/v1/mitigations/flowspec",
        "/v1/mitigations/xdp",
        "/v1/detections",
        "/v1/sessions",
        "/v1/audit",
    ] {
        assert!(paths.contains_key(expected), "missing {expected} in OpenAPI doc");
    }
}
```

- [ ] **Step 4: Run + commit**

```bash
cargo test -p blackwall-api 2>&1 | grep -E "test result|error\["
cargo clippy -p blackwall-api --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates/blackwall-api
git commit -m "feat(api): generated OpenAPI document + route-coverage contract test"
```
Expected: contract test passes; all handlers annotated.

---

### Task 5: `api` config directive

**Files:**
- Modify: `crates/blackwall-core/src/lib.rs` (define `ApiConfig`, re-export)
- Modify: `crates/blackwall-core/src/policy.rs` (add `pub api: Option<ApiConfig>`)
- Modify: `crates/blackwall-core/src/resolve.rs` (default `api: None` at the two construction sites near lines 135, 298)
- Modify: `crates/blackwall-config/src/parser.rs` (parse `api listen=… token-file=…`)

**Interfaces:**
- Produces: `pub struct ApiConfig { pub listen: std::net::SocketAddr, pub token_file: std::path::PathBuf }`; `Policy.api: Option<ApiConfig>`.

- [ ] **Step 1: Define `ApiConfig` in `blackwall-core`**

In `crates/blackwall-core/src/lib.rs` (near the other config structs like `EngineConfig`):

```rust
/// Configuration for the operations control API (`api` directive); `None` on
/// [`Policy`] disables the API.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApiConfig {
    /// Address the API binds to (bind to localhost / a management interface;
    /// TLS is terminated by a reverse proxy).
    pub listen: std::net::SocketAddr,
    /// Path to a file whose first line is the admin bearer token.
    pub token_file: std::path::PathBuf,
}
```
Re-export it alongside the others (`pub use ...::ApiConfig;` if the module layout requires it — match how `EngineConfig` is exported).

- [ ] **Step 2: Add the field to `Policy` and default it in `resolve.rs`**

In `crates/blackwall-core/src/policy.rs`, after the `metrics_listen` field:

```rust
    /// Operations control API config; `None` disables it.
    pub api: Option<crate::ApiConfig>,
```

In `crates/blackwall-core/src/resolve.rs`, at each `Policy { … }` construction (the two sites that set `metrics_listen: None`), add:

```rust
            api: None,
```

- [ ] **Step 3: Write the failing parser test**

In `crates/blackwall-config/src/parser.rs` `mod tests` (near `parses_metrics_listen`):

```rust
    #[test]
    fn parses_api_directive() {
        let p = parse_text(
            "interface wan eth0\napi listen=127.0.0.1:8088 token-file=/etc/blackwall/api.token\n",
        )
        .unwrap();
        let api = p.api.expect("api set");
        assert_eq!(api.listen, "127.0.0.1:8088".parse().unwrap());
        assert_eq!(api.token_file, std::path::PathBuf::from("/etc/blackwall/api.token"));
    }

    #[test]
    fn api_requires_both_keys() {
        assert!(parse_text("interface wan eth0\napi listen=127.0.0.1:8088\n").is_err());
    }
```

- [ ] **Step 4: Run to verify it fails**

```bash
cargo test -p blackwall-config parses_api_directive 2>&1 | grep -E "test result|error\[|cannot find"
```
Expected: FAIL (field `api` does not exist / arm not handled).

- [ ] **Step 5: Implement the parser arm**

At the top of the parse fn add a local (near `let mut metrics_listen`):

```rust
    let mut api: Option<blackwall_core::ApiConfig> = None;
```

Add the directive arm (mirror the `"metrics"` arm at parser.rs:427):

```rust
            "api" => {
                let mut listen: Option<SocketAddr> = None;
                let mut token_file: Option<std::path::PathBuf> = None;
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "api",
                        value: tok.as_str().to_owned(),
                    })?;
                    match k {
                        "listen" => {
                            listen = Some(v.parse::<SocketAddr>().map_err(|_| {
                                ConfigError::BadValue { line: line.number, what: "api listen", value: v.to_owned() }
                            })?);
                        }
                        "token-file" => token_file = Some(std::path::PathBuf::from(v)),
                        _ => {
                            return Err(ConfigError::BadValue {
                                line: line.number, what: "api key", value: k.to_owned(),
                            });
                        }
                    }
                }
                let listen = listen.ok_or(ConfigError::MissingField { line: line.number, what: "api listen" })?;
                let token_file = token_file.ok_or(ConfigError::MissingField { line: line.number, what: "api token-file" })?;
                api = Some(blackwall_core::ApiConfig { listen, token_file });
            }
```

If `ConfigError` has no `MissingField` variant, use the existing `BadValue` with `value: "".into()` (check `crates/blackwall-config/src/error.rs` first and match an existing variant). Then set `api` in the returned `Policy { … }` struct literal (near `metrics_listen,`):

```rust
        api,
```

- [ ] **Step 6: Run tests + commit**

```bash
cargo test -p blackwall-config 2>&1 | grep -E "test result|error\["
cargo test -p blackwall-core 2>&1 | grep -E "test result|error\["
cargo fmt --all
git add crates/blackwall-core crates/blackwall-config
git commit -m "feat(config): api listen=/token-file= directive + Policy.api field"
```
Expected: both crates' tests pass, including the two new parser tests.

---

### Task 6: Thin `Store` read methods for tenants, assignments, detections, sessions, audit

**Files:**
- Modify: `crates/blackwall-state/src/lib.rs` (or the relevant sub-modules) — add 5 read methods
- Test: `crates/blackwall-state/tests/` (DB integration tests, gated on `DATABASE_URL`)

**Interfaces:**
- Produces (all on `impl Store`):
  - `pub async fn list_tenants(&self) -> Result<Vec<(String, Vec<IpAddr>)>, StateError>`
  - `pub async fn list_ip_assignments(&self) -> Result<Vec<(String, IpAddr)>, StateError>`
  - `pub async fn list_active_detections(&self) -> Result<Vec<DetectionRow>, StateError>` (define `DetectionRow { target, observed_pps, observed_bps, severity, first_seen_ms, last_seen_ms }` if none exists)
  - `pub async fn list_recent_sessions(&self, limit: i64) -> Result<Vec<SessionRow>, StateError>`
  - `pub async fn list_recent_audit(&self, limit: i64) -> Result<Vec<AuditRow>, StateError>` (define `AuditRow { at_ms, actor, action, detail: serde_json::Value }`)

**Interfaces (consumed by Task 7):** these exact signatures are what `StoreAppState` calls.

- [ ] **Step 1: Inspect the existing thin-query pattern**

Read `crates/blackwall-state/src/lib.rs:145` (`list_services`) and `:378` (`list_active_blackholes`) to copy their sqlx `query_as`/manual-map style, timestamp→ms conversion, and `StateError` handling. Match it exactly.

- [ ] **Step 2: Write the failing DB integration test**

Create `crates/blackwall-state/tests/read_methods.rs`:

```rust
// Gated on a reachable DATABASE_URL (port 5433). Mirrors existing state tests.
use blackwall_state::Store;

async fn store() -> Store {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    Store::connect(&url).await.expect("connect")
}

#[tokio::test]
async fn list_tenants_and_assignments_roundtrip() {
    let s = store().await;
    // Seed a tenant + assignment via the existing apply_policy path, then read.
    // (Use the same helper the existing apply_policy tests use; assert the
    // tenant name and its address appear in list_tenants / list_ip_assignments.)
    let tenants = s.list_tenants().await.expect("list_tenants");
    let _ = tenants; // presence-shaped assertion filled in with the seed helper
}
```

Follow the existing state-test seeding helper (grep `apply_policy` in `crates/blackwall-state/tests/`) so the test seeds deterministic rows and asserts them. Do **not** leave the placeholder assertion — seed a tenant `"t-read"` with address `203.0.113.7`, then assert `list_tenants()` contains `("t-read", vec![203.0.113.7])`.

- [ ] **Step 3: Run to verify it fails**

```bash
DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall \
  cargo test -p blackwall-state list_tenants 2>&1 | grep -E "test result|error\[|no method"
```
Expected: FAIL (`no method named list_tenants`).

- [ ] **Step 4: Implement the five read methods**

Add to `impl Store`, following the `list_services` style. Tenants + assignments:

```rust
    /// All tenants with their owned addresses.
    pub async fn list_tenants(&self) -> Result<Vec<(String, Vec<IpAddr>)>, StateError> {
        let rows = sqlx::query_as::<_, (String, ipnetwork::IpNetwork)>(
            "SELECT t.name, a.address FROM tenants t \
             LEFT JOIN ip_assignments a ON a.tenant_id = t.id \
             ORDER BY t.name",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<(String, Vec<IpAddr>)> = Vec::new();
        for (name, net) in rows {
            let addr = net.ip();
            match out.last_mut() {
                Some((n, addrs)) if *n == name => addrs.push(addr),
                _ => out.push((name, vec![addr])),
            }
        }
        Ok(out)
    }
```

(Handle the `LEFT JOIN` NULL address — a tenant with no assignments: use `Option<ipnetwork::IpNetwork>` in the tuple and skip `None`.) Implement `list_ip_assignments`, `list_active_detections`, `list_recent_sessions`, `list_recent_audit` in the same style; for the `_recent_` ones add `ORDER BY <time> DESC LIMIT $1` binding `limit`. Define `DetectionRow`/`AuditRow` next to the other row structs with `#[derive(Debug, Clone)]` and rustdoc on each field. Convert `TIMESTAMPTZ` to ms exactly as the existing rows do (grep an existing `_at_ms` mapping).

- [ ] **Step 5: Finish the test assertions, run, commit**

```bash
DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall \
  cargo test -p blackwall-state 2>&1 | grep -E "test result|error\["
cargo clippy -p blackwall-state --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates/blackwall-state
git commit -m "feat(state): thin read methods for tenants, assignments, detections, sessions, audit"
```
Expected: all state tests pass.

---

### Task 7: Concrete `StoreAppState` + mount in `blackwalld run`

**Files:**
- Modify: `bin/blackwalld/Cargo.toml` (add `blackwall-api` dep)
- Create: `bin/blackwalld/src/api.rs` (concrete `StoreAppState` + `serve` glue — coverage-excluded)
- Modify: `bin/blackwalld/src/main.rs` (declare `mod api;`, mount in `run`)

**Interfaces:**
- Consumes: `blackwall_api::{router, AppState, AuthConfig, ApiError}` and the Task-6 `Store` read methods; `blackwall_core::ApiConfig` (Task 5).
- Produces: `pub struct StoreAppState { store: Arc<Store> }` impl `AppState`; `pub async fn serve_api(cfg: ApiConfig, store: Arc<Store>)`.

- [ ] **Step 1: Add the dependency**

In `bin/blackwalld/Cargo.toml` `[dependencies]`:
```toml
blackwall-api = { path = "../../crates/blackwall-api" }
```

- [ ] **Step 2: Write the concrete `StoreAppState` glue**

Create `bin/blackwalld/src/api.rs`. This is I/O glue — exclude from coverage exactly as `metrics.rs` is (grep how `metrics.rs` is excluded — likely a `#![cfg_attr(coverage, ...)]` or a `scripts/coverage.sh` exclude path; replicate it). Map each `Store` read → `*View`, mapping `StateError` → `ApiError::Internal`:

```rust
//! Concrete `AppState` backed by the shared `Store`, plus the API bind loop.
//! I/O glue — excluded from coverage like `metrics.rs`.

use blackwall_api::error::ApiError;
use blackwall_api::state::*;
use blackwall_api::{router, AppState, AuthConfig};
use blackwall_core::ApiConfig;
use blackwall_state::Store;
use std::sync::Arc;

pub struct StoreAppState {
    store: Arc<Store>,
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

#[async_trait::async_trait]
impl AppState for StoreAppState {
    async fn tenants(&self) -> Result<Vec<TenantView>, ApiError> {
        let rows = self.store.list_tenants().await.map_err(internal)?;
        Ok(rows.into_iter().map(|(name, owned)| TenantView { name, owned }).collect())
    }
    // Implement services/ip_assignments/rtbh/flowspec/xdp/detections/sessions/audit
    // by calling the matching Store read method and mapping each row field-by-field
    // into its *View (field lists in blackwall-api::state). proto numbers/strings:
    // map L4Proto → "tcp"/"udp" via its Display/as_str; ServiceTarget → its rendered
    // string. Session/audit take the `limit` argument straight through.
}

/// Load the bearer token (first line of the token file), build the router, and
/// serve until the process exits. A bind failure disables the API and is logged.
pub async fn serve_api(cfg: ApiConfig, store: Arc<Store>) {
    let token = match std::fs::read_to_string(&cfg.token_file) {
        Ok(s) => s.lines().next().unwrap_or_default().trim().to_owned(),
        Err(e) => {
            tracing::error!(%e, path = %cfg.token_file.display(), "api: token file unreadable; API disabled");
            return;
        }
    };
    if token.is_empty() {
        tracing::error!("api: token file empty; API disabled");
        return;
    }
    let auth = Arc::new(AuthConfig::new("admin", &token));
    let state: Arc<dyn AppState> = Arc::new(StoreAppState { store });
    let app = router(state, auth);
    let listener = match tokio::net::TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%e, listen = %cfg.listen, "api: bind failed; API disabled");
            return;
        }
    };
    tracing::info!(listen = %cfg.listen, "control API listening");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "api: server exited");
    }
}
```

Fill in the elided `AppState` methods completely (no comment-only bodies).

- [ ] **Step 3: Mount it in `run`**

In `bin/blackwalld/src/main.rs`, add `mod api;` near the other module declarations. In the `run` path, next to where the metrics server is spawned (main.rs:1605 `if let Some(metrics_listen) = policy.metrics_listen`), add:

```rust
            if let Some(api_cfg) = policy.api.clone() {
                let store_for_api = store.clone();
                tokio::spawn(api::serve_api(api_cfg, store_for_api));
            }
```

- [ ] **Step 4: Build the whole workspace + a manual smoke check**

```bash
cargo build -p blackwalld 2>&1 | grep -E "error\[|Finished" | tail -1
```
Expected: `Finished`.

Manual smoke (optional, documents expected behavior):
```bash
# with a running daemon + token file containing "s3cret":
curl -s -H "Authorization: Bearer s3cret" http://127.0.0.1:8088/v1/tenants | head
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8088/v1/tenants   # → 401
```

- [ ] **Step 5: Full gate + commit**

```bash
cargo clippy --workspace --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all -- --check && echo FMT_OK
DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall bash scripts/coverage.sh 2>&1 | tail -5
git add bin/blackwalld
git commit -m "feat(api): mount read-only control API in blackwalld run"
```
Expected: clippy clean, fmt ok, coverage ≥90% for `blackwall-api` (glue excluded).

---

## Phase 1 Definition of Done

- `blackwall-api` crate: auth + all read endpoints + OpenAPI, ≥90% covered against `FakeState`.
- `api listen=… token-file=…` directive parses into `Policy.api`.
- Five new thin `Store` read methods with DB integration tests.
- API mounted in `blackwalld run`; `curl` with/without token returns 200/401.
- `cargo clippy --workspace --all-targets -- --deny warnings` clean; `cargo fmt` clean; coverage gate green.
- PR opened from `sp-am4-spec`, added to project board 4, merged on check-green.

## Phases 2–4 (separate plans, written after Phase 1 lands)

- **Phase 2 — mutation endpoints:** extend `AppState` with `create_service`/`delete_service`, tenant/ip CRUD (→ `apply_effective`), and `enqueue_rtbh`/`enqueue_flowspec`/`enqueue_xdp` (→ intent queues); every mutation writes an `audit_log` row in the same transaction; `POST /v1/apply`; `201`/`202`/`409` status handling. New DTOs for request bodies + validation (`400`).
- **Phase 3 — daemon supervision:** a supervisor owning the run daemon's long-running tasks (engine, metrics, flow, reconcile loops, API) with health + backoff-restart + graceful shutdown.
- **Phase 4 — `blackwall-bench`:** control-plane load/benchmark harness driving the API (reusing `blackwall-trafficgen` for correlated data-plane load), JSON report, non-required lab gate.
