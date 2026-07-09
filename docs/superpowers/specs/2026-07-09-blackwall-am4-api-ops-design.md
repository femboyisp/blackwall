# Blackwall A·M4 — API & Operations Design

**Status:** Approved (brainstorming) — 2026-07-09
**Tracking issue:** [A·M4] API & operations (#4)
**Depends on:** sub-project A (deception firewall + policy plane), the existing
`Store` (blackwall-state), the intent-queue/reconcile machinery in `blackwalld run`.

## Goal

Give Blackwall a programmable **operations control plane**: an authenticated,
tenant-aware HTTP API (axum) with a generated OpenAPI contract, embedded in the
long-running `blackwalld run` daemon, plus formalized daemon supervision and a
control-plane load/benchmark harness. This turns day-2 operations (create a
tenant, expose a service, queue an RTBH/FlowSpec/XDP mitigation, inspect live
state) into scriptable API calls instead of hand-edited config files, while the
config file remains a valid bootstrap path.

## Scope decisions (locked in brainstorming)

1. **Single-admin control plane, read + mutate.** Not multi-tenant self-service.
   One admin token. Resources are **tenant-aware** (URLs under
   `/v1/tenants/{name}/...`, queries filter by `tenant_id`) so per-tenant tokens
   become a later increment, not a rewrite.
2. **In-process with `blackwalld run`.** The API is one more supervised tokio
   task inside the run daemon, sharing the `Store` and the daemon's re-apply /
   intent-queue paths. No second process, no split-brain, no DB-poll IPC.
3. **axum + `utoipa`.** Framework speed is irrelevant at control-plane request
   rates (the data plane is the kernel XDP/nft path); axum embeds as a plain
   tokio task in the existing single-runtime daemon. OpenAPI is generated from
   code so the contract cannot drift.
4. **Bearer-token auth, TLS at a reverse proxy.** A static admin token, stored
   **hashed** in a token file, checked in constant time on every request. The
   daemon binds to localhost or a management interface; TLS termination is the
   operator's reverse proxy — matching the existing `metrics listen=`
   deployment model. (Built-in rustls and mTLS were considered and deferred.)
5. **Phased delivery** — four increments, each an independently reviewable PR:
   - **Phase 1** — `blackwall-api` crate: router, DTOs, auth layer, all
     **read-only** endpoints, generated `/openapi.json`, mounted in `run`
     behind a new `api listen=… token-file=…` directive.
   - **Phase 2** — mutation endpoints: tenant/service CRUD (→ `apply_effective`)
     and RTBH/FlowSpec/XDP add-remove (→ existing intent queues), every mutation
     writing an `audit_log` row atomically.
   - **Phase 3** — daemon supervision: a supervisor owning the run daemon's
     long-running tasks with health + backoff-restart + graceful shutdown.
   - **Phase 4** — `blackwall-bench`: control-plane load/benchmark harness.

## Global constraints

Copied from the project engineering standards — every task inherits these:

- **No `as` casts.** Use `TryFrom`/`try_from`, `to_be_bytes`, etc.
- **`#[expect(lint, reason = "…")]`, never bare `#[allow]`.**
- **Exact version pins** for every new dependency (`=x.y.z`), no caret ranges.
- **Rustdoc on all public items.**
- **≥90% line coverage** (`scripts/coverage.sh`, gate enforced in CI).
- **`cargo clippy --workspace --all-targets -- --deny warnings` clean; `cargo fmt` clean.**
- **No `Co-Authored-By` / `Claude-Session` commit trailers.**
- `DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall`
  (PostgreSQL on port 5433).
- Each increment lands from an isolated git worktree off `origin/main` → branch
  → PR → add to project board 4 → merge on check-green.

## Architecture

```
                         ┌─────────────────────────────────────────┐
   HTTP client / script  │            blackwalld run (daemon)        │
   (curl, dashboard) ───▶│                                           │
        Bearer token     │  ┌──────────────┐   ┌──────────────────┐ │
                         │  │ blackwall-api │   │ existing tasks:  │ │
                         │  │  Router       │   │  engine, metrics,│ │
                         │  │  auth layer   │   │  flow collector, │ │
                         │  │  handlers ────┼──▶│  RTBH/FlowSpec   │ │
                         │  │  DTOs         │   │  reconcile loops │ │
                         │  └──────┬───────┘   └────────┬─────────┘ │
                         │         │  AppState trait     │           │
                         │         ▼                     ▼           │
                         │   ┌──────────────────────────────────┐   │
                         │   │ Store (blackwall-state, sqlx→PG)  │   │
                         │   │ + apply_effective (nft/XDP apply) │   │
                         │   └──────────────────────────────────┘   │
                         │        supervised by Phase-3 supervisor   │
                         └───────────────────────────────────────────┘
```

### Components

**`blackwall-api` (new library crate).** The entire HTTP surface, kept pure
enough to unit-test against a fake state with no DB and no kernel:

- `router(state: Arc<dyn AppState>) -> axum::Router` — builds the router with the
  auth layer and all routes; `blackwalld` mounts and serves it.
- **DTOs** — request/response types deriving `serde` + `utoipa::ToSchema`, kept
  **separate** from internal `blackwall-core`/`blackwall-state` types so the wire
  contract is decoupled from internal models and can evolve independently.
- **Auth layer** — a tower middleware performing a constant-time comparison of
  the request's `Authorization: Bearer <token>` against the configured hashed
  token; `401` on absence/mismatch. The token id (a short non-secret label) is
  threaded into request extensions for audit attribution.
- **Handlers** under `/v1`, tenant-aware:
  - *Read:* `GET /v1/tenants`, `GET /v1/tenants/{name}`,
    `GET /v1/tenants/{name}/services`,
    `GET /v1/tenants/{name}/ip-assignments`,
    `GET /v1/mitigations/rtbh`, `GET /v1/mitigations/flowspec`,
    `GET /v1/mitigations/xdp`, `GET /v1/detections`,
    `GET /v1/sessions`, `GET /v1/audit`.
  - *Mutate (Phase 2):* `POST/DELETE /v1/tenants/{name}/services`,
    `POST/DELETE /v1/tenants` (tenant + ip-assignment CRUD),
    `POST/DELETE /v1/mitigations/{rtbh,flowspec,xdp}`,
    `POST /v1/apply` (operator-recoverable re-apply).
- **`AppState` trait** — the seam handlers depend on. Abstracts store reads,
  policy mutation (`apply_policy` + `apply_effective`), intent-queue writes, and
  audit-row writes. Handlers are generic over it; the real impl lives in
  `blackwalld`, a fake in-memory impl lives in the crate's tests.
- **OpenAPI** — a `utoipa::OpenApi` doc aggregating every handler + DTO schema,
  served at `GET /v1/openapi.json`.

**`blackwalld` glue (thin, coverage-excluded — mirrors the metrics glue).**
- `run` reads the `api` directive, constructs the concrete `AppState` (bridges to
  `Store`, `apply_effective`, and the intent queues), and spawns
  `axum::serve(TcpListener, router)` as a supervised task.
- The concrete `AppState` is where the atomic "write row + write `audit_log`
  row" transactions live and where `apply_effective` is invoked post-commit.

**`blackwall-bench` (new binary, Phase 4).** Drives the API with concurrent
mutation + read load (and reuses `blackwall-trafficgen` for correlated
data-plane load) and reports control-plane throughput/latency as JSON. Runs as a
non-required lab gate.

**Config directive.** `api listen=<ip:port> token-file=<path>` — parses in
`blackwall-config` exactly like the existing `metrics listen=` directive; the
`XdpConfig`/`engine`-style struct lives in `blackwall-core`. `None` (directive
absent) disables the API.

## Data flow

**Mutating request** — e.g. `POST /v1/tenants/acme/services`:

1. axum → **auth layer** (constant-time bearer check; `401` on miss).
2. Handler deserializes + validates the DTO: port in `0..=65535`, proto in
   `{tcp,udp}`, target well-formed, and the address belongs to the tenant's
   `ip_assignments`. Invalid input → `400` with a structured error body.
3. Handler calls `AppState`, which opens **one transaction**: writes the
   `services` row **and** an `audit_log` row
   (`actor="api:<token-id>"`, `action="service.create"`, `detail` = JSONB of the
   change) together, so the audited action and its effect commit atomically.
4. On commit, the concrete state triggers `apply_effective` (reconcile → render →
   `nft -j -f -`). For RTBH/FlowSpec/XDP the handler instead writes the **intent
   queue** and returns `202 Accepted` with the queued-intent mirror — the
   existing single-owner reconcile loop applies it asynchronously (identical to
   how the CLI `rtbh add`/`flowspec add` already behave).
5. Response DTO returns the created/updated resource (declarative CRUD, `201`) or
   the queued intent (`202`) as JSON.

**Read request:** auth → store query (tenant-scoped reads resolve `tenant_id`
from the `{name}` path segment, `404` if unknown) → DTO. No transaction, no
apply.

## Error handling

A single `ApiError` enum with an `IntoResponse` impl mapping each variant to an
HTTP status and a consistent JSON body:

```json
{ "error": { "code": "validation_failed", "message": "port must be 0..=65535" } }
```

| Variant             | Status | When                                                        |
|---------------------|--------|-------------------------------------------------------------|
| `Unauthorized`      | 401    | missing/invalid bearer token                                |
| `NotFound`          | 404    | unknown tenant / resource                                   |
| `Validation`        | 400    | malformed or semantically invalid input                     |
| `Conflict`          | 409    | uniqueness violation (duplicate service/address — DB `UNIQUE`)|
| `ApplyFailed`       | 500    | `nft`/XDP apply failed after the DB commit (logged)         |
| `Internal`          | 500    | store/other failure (logged; internals never leak to body)  |

**Apply-after-commit edge:** the DB write commits before `apply_effective`
runs; a transient `nft` failure therefore leaves the DB ahead of the kernel.
This matches the daemon's existing "kernel is safety-critical, surface the
failure" stance: the handler returns `500 ApplyFailed` and logs, and the
`POST /v1/apply` endpoint lets an operator re-drive reconciliation once the
transient cause clears. (Documented as a known, operator-recoverable edge, not a
silent inconsistency.)

## Testing strategy

- **`blackwall-api` unit/integration tests against a fake `AppState`**
  (in-memory) — every handler, auth pass/fail, DTO validation, status codes, and
  **tenant-scoping isolation** (tenant A cannot read/mutate tenant B), with no DB
  and no kernel. This carries the ≥90% coverage for the crate.
- **Concrete-`AppState` DB integration tests** (sqlx against the `5433`
  Postgres): audit row written atomically with the effect, `apply_effective`
  invoked on declarative CRUD, intent enqueued for RTBH/FlowSpec/XDP.
- **OpenAPI contract test:** assert the generated `/v1/openapi.json` lists every
  mounted route — fails if a handler is added without a `utoipa` annotation
  (prevents contract drift).
- **`blackwalld` glue stays coverage-excluded** (the bind/accept loop), matching
  the metrics-endpoint precedent.
- **Phase 4 lab gate (non-required):** spawn the daemon in a netns → authenticate
  → exercise CRUD + a mitigation → assert the resulting nft ruleset and DB rows.
  `blackwall-bench` doubles as the load driver.

## Dependencies (exact-pinned; versions confirmed at implementation time)

- `axum` — HTTP framework (tokio/hyper/tower).
- `tower` / `tower-http` — auth/timeout/tracing middleware.
- `utoipa` (+ `utoipa`'s axum binding) — code-first OpenAPI generation.
- A constant-time comparison primitive (`subtle`) and the token hash
  (reuse the workspace's existing hashing dependency if present; otherwise
  `sha2`) — chosen and pinned in Phase 1.

## Out of scope (explicitly deferred)

- Per-tenant API tokens / multi-tenant self-service authz (the tenant-aware URL
  layout keeps this a later increment).
- Built-in TLS termination (rustls) and mTLS.
- A web UI / dashboard (the API + OpenAPI make one a separate downstream project).
- Write-back of API mutations into the on-disk config file (the DB is the
  runtime source of truth; the config file remains a bootstrap input).
```
