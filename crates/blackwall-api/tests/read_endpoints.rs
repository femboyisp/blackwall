//! End-to-end tests: real `router()`, in-memory `FakeState`, requests driven
//! through `tower::ServiceExt::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use blackwall_api::state::{ServiceView, TenantView};
use blackwall_api::testutil::FakeState;
use blackwall_api::{router, AuthConfig};
use http_body_util::BodyExt as _;
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt as _;

/// Parse a literal IP address, panicking on malformed test fixtures.
fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Build the auth-guarded router over the given fake state, with a fixed
/// admin token of `s3cret`.
fn app(state: FakeState) -> axum::Router {
    let auth = Arc::new(AuthConfig::new("admin", "s3cret"));
    router(Arc::new(state), auth)
}

/// Issue a GET with a valid bearer token and decode the JSON body.
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
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

#[tokio::test]
async fn lists_tenants() {
    let state = FakeState {
        tenants: vec![TenantView {
            name: "acme".into(),
            owned: vec![addr("203.0.113.1")],
        }],
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
            TenantView {
                name: "acme".into(),
                owned: vec![],
            },
            TenantView {
                name: "other".into(),
                owned: vec![],
            },
        ],
        services: vec![
            ServiceView {
                tenant: "acme".into(),
                address: addr("203.0.113.1"),
                proto: "tcp".into(),
                port: 443,
                target: "accept".into(),
            },
            ServiceView {
                tenant: "other".into(),
                address: addr("203.0.113.2"),
                proto: "tcp".into(),
                port: 80,
                target: "accept".into(),
            },
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
        .oneshot(
            Request::builder()
                .uri("/v1/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_token_is_401() {
    let resp = app(FakeState::default())
        .oneshot(
            Request::builder()
                .uri("/v1/tenants")
                .header("authorization", "Bearer wrongtoken")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
