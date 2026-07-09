//! End-to-end tests: real `router()`, in-memory `FakeState`, requests driven
//! through `tower::ServiceExt::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use blackwall_api::state::{
    AuditView, DetectionView, FlowSpecView, IpAssignmentView, RtbhView, ServiceView, SessionView,
    TenantView, XdpView,
};
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

#[tokio::test]
async fn openapi_json_requires_auth() {
    // Without a token the OpenAPI document is guarded like every other route.
    let resp = app(FakeState::default())
        .oneshot(
            Request::builder()
                .uri("/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // With the admin bearer token it serves the spec.
    let (status, body) = get_json(app(FakeState::default()), "/v1/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["openapi"], "3.1.0");
}

#[tokio::test]
async fn tenant_ip_assignments_are_scoped() {
    let state = FakeState {
        tenants: vec![TenantView {
            name: "acme".into(),
            owned: vec![],
        }],
        ip_assignments: vec![IpAssignmentView {
            tenant: "acme".into(),
            address: addr("203.0.113.7"),
        }],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/tenants/acme/ip-assignments").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["address"], "203.0.113.7");
}

#[tokio::test]
async fn lists_rtbh() {
    let state = FakeState {
        rtbh: vec![RtbhView {
            target: addr("203.0.113.9"),
            origin: "operator".into(),
            announced_at_ms: 1_000,
            withdrawn_at_ms: None,
        }],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/mitigations/rtbh").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["target"], "203.0.113.9");
}

#[tokio::test]
async fn lists_flowspec() {
    let state = FakeState {
        flowspec: vec![FlowSpecView {
            dst: addr("203.0.113.10"),
            proto: 17,
            dst_port: 53,
            rate: 0.0,
            origin: "operator".into(),
            announced_at_ms: 2_000,
            withdrawn_at_ms: None,
        }],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/mitigations/flowspec").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["dst"], "203.0.113.10");
}

#[tokio::test]
async fn lists_xdp() {
    let state = FakeState {
        xdp: vec![XdpView {
            kind: "block".into(),
            target: addr("198.51.100.5"),
            prefixlen: None,
            rate_pps: None,
            burst: None,
            origin: "operator".into(),
            victim: None,
        }],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/mitigations/xdp").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["target"], "198.51.100.5");
}

#[tokio::test]
async fn lists_detections() {
    let state = FakeState {
        detections: vec![DetectionView {
            target: addr("203.0.113.11"),
            observed_pps: 1_234.0,
            observed_bps: 5_678.0,
            severity: "high".into(),
            first_seen_ms: 3_000,
            last_seen_ms: 4_000,
        }],
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/detections").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["target"], "203.0.113.11");
    assert_eq!(body[0]["severity"], "high");
}

/// Two sessions, one honeypot each, for the limit test below.
fn two_sessions() -> Vec<SessionView> {
    vec![
        SessionView {
            local_addr: addr("203.0.113.20"),
            local_port: 22,
            peer_addr: addr("198.51.100.20"),
            proto: "tcp".into(),
            emulator: "ssh".into(),
            bytes_in: 10,
            bytes_out: 20,
            note: Some("root:root".into()),
        },
        SessionView {
            local_addr: addr("203.0.113.21"),
            local_port: 23,
            peer_addr: addr("198.51.100.21"),
            proto: "tcp".into(),
            emulator: "telnet".into(),
            bytes_in: 30,
            bytes_out: 40,
            note: None,
        },
    ]
}

#[tokio::test]
async fn lists_sessions() {
    let state = FakeState {
        sessions: two_sessions(),
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/sessions").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert_eq!(body[0]["emulator"], "ssh");
}

#[tokio::test]
async fn sessions_respects_limit_query() {
    let state = FakeState {
        sessions: two_sessions(),
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/sessions?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["emulator"], "ssh");
}

/// Two audit rows for the limit test below.
fn two_audit_rows() -> Vec<AuditView> {
    vec![
        AuditView {
            at_ms: 5_000,
            actor: "api:admin".into(),
            action: "service.create".into(),
            detail: serde_json::json!({ "port": 443 }),
        },
        AuditView {
            at_ms: 6_000,
            actor: "api:admin".into(),
            action: "service.delete".into(),
            detail: serde_json::json!({ "port": 80 }),
        },
    ]
}

#[tokio::test]
async fn lists_audit() {
    let state = FakeState {
        audit: two_audit_rows(),
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert_eq!(body[0]["action"], "service.create");
}

#[tokio::test]
async fn audit_respects_limit_query() {
    let state = FakeState {
        audit: two_audit_rows(),
        ..Default::default()
    };
    let (status, body) = get_json(app(state), "/v1/audit?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["action"], "service.create");
}
