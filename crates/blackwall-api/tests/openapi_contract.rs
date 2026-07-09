//! Contract test: every route mounted by `router()` must appear in the
//! generated OpenAPI document.

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
        assert!(
            paths.contains_key(expected),
            "missing {expected} in OpenAPI doc"
        );
    }
}
