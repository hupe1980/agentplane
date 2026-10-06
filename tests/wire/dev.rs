//! The dev page's listener: who can reach it, and what every answer carries.
//!
//! The page runs on the author's machine, where every site their browser
//! opens can send requests to a loopback port. These tests hold the four
//! things that keep it the author's: the token on every data route, the
//! `Host` check before it, the `Origin` check on anything that changes
//! state, and the headers on every response.

#![cfg(all(feature = "dev", feature = "redb"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::api::dev::{
    self, CONTENT_SECURITY_POLICY, Declaration, DevPolicy, Replayed, StartRequest, Started,
    Workbench,
};
use agentplane::api::openapi::{Method, ROUTES};
use agentplane::api::tokens::{TokenAuthenticator, TokenEntry};
use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    PolicyDecision, PolicyEngine, PolicyRequest, PrincipalKind, RunId, TenantId,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::Runtime;
use agentplane::store::RedbStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const PORT: u16 = 47_311;
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ACTOR: &str = "dev:author";

/// A bench over a plane with no agents: the gate is what is under test.
struct Bench {
    plane: Arc<Runtime>,
}

#[async_trait::async_trait]
impl Workbench for Bench {
    async fn plane(&self) -> Arc<Runtime> {
        Arc::clone(&self.plane)
    }

    async fn declaration(&self) -> Declaration {
        Declaration {
            file: "agent.yaml".to_owned(),
            ..Declaration::default()
        }
    }

    async fn start(&self, _request: StartRequest) -> Result<Started, String> {
        Err("this bench starts nothing".to_owned())
    }

    async fn replay(&self, _run: Option<RunId>) -> Result<Vec<Replayed>, String> {
        Ok(Vec::new())
    }

    fn streams(&self) -> Arc<agentplane::api::dev::StreamHub> {
        agentplane::api::dev::StreamHub::new()
    }
}

fn router() -> axum::Router {
    let tenant = TenantId::new(dev::TENANT).unwrap();
    let store = Arc::new(
        RedbStore::open_in_memory()
            .unwrap()
            .for_tenant(tenant.clone()),
    );
    let plane = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store as Arc<dyn TaskStore>)
        .tenant(tenant)
        .policy(Arc::new(DevPolicy::new(ACTOR)) as Arc<dyn PolicyEngine>)
        .build();
    let auth = TokenAuthenticator::new(vec![TokenEntry {
        token: TOKEN.to_owned(),
        actor: ACTOR.to_owned(),
        roles: Vec::new(),
        tenant: Some(dev::TENANT.to_owned()),
        scope: None,
        not_after: None,
    }])
    .unwrap();
    dev::router(Arc::new(Bench { plane }), Arc::new(auth), PORT)
}

/// A request as the page's own tab sends it, before the token is decided.
fn request(method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("127.0.0.1:{PORT}"));
    if method != "GET" {
        builder = builder.header("origin", format!("http://127.0.0.1:{PORT}"));
    }
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// A body each operator route that takes one accepts, so a request without
/// a token reaches the gate rather than the body parser.
fn operator_body(operation: &str) -> Value {
    let case = "case_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    match operation {
        "cancel_run" => json!({ "reason": "stop" }),
        "reopen_run" | "abandon_run" => json!({ "reason": "checked" }),
        "reconcile_effect" => json!({
            "effect": "0".repeat(64),
            "disposition": "did_not_happen",
            "note": "none",
        }),
        "take_over_task" => json!({ "from": "alice" }),
        "decide_task" => json!({ "approved": true, "reason": "" }),
        "acknowledge_obligation" => json!({ "case": case, "obligation": "ack" }),
        "place_hold" => json!({ "case": case, "reason": "order" }),
        "release_hold" => json!({ "case": case }),
        "place_halt" => json!({ "scope": "tenant", "reason": "incident" }),
        "lift_halt" => json!({ "scope": "tenant" }),
        "deliver_event" => json!({ "id": "e", "kind": "k", "correlation": [], "payload": {} }),
        "rearm_push" => json!({ "run": "not-an-id", "id": "d" }),
        _ => json!({}),
    }
}

/// Every data route: the dev table, and the operator table under `/api`.
fn data_routes(token: Option<&str>) -> Vec<Request<Body>> {
    let mut requests = Vec::new();
    for route in dev::ROUTES {
        let path = route.path.replace("{run}", "not-an-id");
        requests.push(match route.method {
            Method::Get => request("GET", &path, token, None),
            Method::Post => request("POST", &path, token, Some(&json!({}))),
        });
    }
    for route in ROUTES {
        let path: String = route
            .path
            .split('/')
            .map(|s| if s.starts_with('{') { "not-an-id" } else { s })
            .collect::<Vec<_>>()
            .join("/");
        let path = format!("/api{path}");
        requests.push(match route.method {
            Method::Get => request("GET", &path, token, None),
            Method::Post => request("POST", &path, token, Some(&operator_body(route.operation))),
        });
    }
    requests
}

fn assert_hardened(response: &axum::response::Response, what: &str) {
    let headers = response.headers();
    for (name, value) in [
        ("content-security-policy", CONTENT_SECURITY_POLICY),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ] {
        assert_eq!(
            headers.get(name).and_then(|v| v.to_str().ok()),
            Some(value),
            "{what} answered {} without `{name}: {value}`",
            response.status()
        );
    }
}

/// **Every data route refuses a request without the session's token.**
#[tokio::test]
async fn every_dev_route_refuses_a_request_without_the_token() {
    let router = router();
    let requests = data_routes(None);
    assert!(
        dev::ROUTES.len() >= 5 && ROUTES.len() >= 9,
        "the walk found {} dev and {} operator routes — it read the wrong tables",
        dev::ROUTES.len(),
        ROUTES.len()
    );
    assert_eq!(requests.len(), dev::ROUTES.len() + ROUTES.len());
    for req in requests {
        let what = format!("{} {}", req.method(), req.uri());
        let response = router.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{what} answered without the token: {}",
            String::from_utf8_lossy(&body)
        );
    }
    for req in [request(
        "GET",
        "/dev/manifest",
        Some("not-the-token-but-long-enough-to-be-one-0000"),
        None,
    )] {
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a wrong token was accepted"
        );
    }
    // The walk tells the two apart: with the token, the same route answers.
    let response = router
        .oneshot(request("GET", "/dev/manifest", Some(TOKEN), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// **A request naming a `Host` other than the listener's own loopback
/// authority is refused before the token is read** — the DNS-rebinding shape.
#[tokio::test]
async fn a_request_naming_a_foreign_host_is_refused() {
    let router = router();
    for host in [
        format!("evil.example:{PORT}"),
        format!("127.0.0.1:{}", PORT + 1),
        format!("localhost.evil:{PORT}"),
        "127.0.0.1".to_owned(),
    ] {
        let mut req = request("GET", "/dev/manifest", Some(TOKEN), None);
        req.headers_mut().insert("host", host.parse().unwrap());
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Host {host} reached the gate"
        );
    }
    for host in [
        format!("127.0.0.1:{PORT}"),
        format!("localhost:{PORT}"),
        format!("[::1]:{PORT}"),
    ] {
        let mut req = request("GET", "/dev/manifest", Some(TOKEN), None);
        req.headers_mut().insert("host", host.parse().unwrap());
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "Host {host} was refused");
    }
}

/// **A request that changes state is refused unless it names the page's own
/// `Origin`** — absent, or another site's.
#[tokio::test]
async fn a_cross_origin_post_is_refused() {
    let router = router();
    for origin in [
        None,
        Some("https://evil.example"),
        Some("http://127.0.0.1:1"),
    ] {
        let mut req = request("POST", "/dev/replay", Some(TOKEN), Some(&json!({})));
        req.headers_mut().remove("origin");
        if let Some(origin) = origin {
            req.headers_mut().insert("origin", origin.parse().unwrap());
        }
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a POST with Origin {origin:?} reached the route"
        );
    }
    let response = router
        .oneshot(request(
            "POST",
            "/dev/replay",
            Some(TOKEN),
            Some(&json!({})),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the page's own POST was refused"
    );
}

/// **Every response carries the content security policy and the three
/// hardening headers**: the page, its assets, every data route with and
/// without the token, the fallback, and a refused `Host`.
#[tokio::test]
async fn every_dev_response_carries_the_content_security_policy() {
    let router = router();
    let mut requests: Vec<Request<Body>> = dev::SHELL
        .iter()
        .map(|(path, ..)| request("GET", path, None, None))
        .collect();
    requests.extend(data_routes(None));
    requests.extend(data_routes(Some(TOKEN)));
    requests.push(request("GET", "/no/such/page", None, None));
    let mut foreign = request("GET", "/", None, None);
    foreign
        .headers_mut()
        .insert("host", "evil.example".parse().unwrap());
    requests.push(foreign);
    let mut statuses = std::collections::BTreeSet::new();
    for req in requests {
        let what = format!("{} {}", req.method(), req.uri());
        let response = router.clone().oneshot(req).await.unwrap();
        statuses.insert(response.status().as_u16());
        assert_hardened(&response, &what);
    }
    for status in [200, 401, 403, 404] {
        assert!(
            statuses.contains(&status),
            "no response answered {status}, so its class went unchecked: {statuses:?}"
        );
    }
}

/// **The page's shell is served as its own types, without the token.**
#[tokio::test]
async fn the_page_and_its_assets_carry_no_data_and_need_no_token() {
    let router = router();
    for (path, content_type, body) in dev::SHELL {
        let response = router
            .clone()
            .oneshot(request("GET", path, None, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some(*content_type)
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], body.as_bytes());
    }
}

/// **The dev engine permits the session's actor on tenant `dev` and nobody
/// else**, admission and effects, and no release.
#[test]
fn the_dev_policy_permits_only_its_own_actor() {
    let policy = DevPolicy::new(ACTOR);
    let ask = |principal: &str, action: &str, tenant: &str| {
        policy.authorize(&PolicyRequest {
            principal,
            principal_kind: PrincipalKind::Subject,
            action,
            resource: "r",
            context: &json!({ "roles": [], "tenant": tenant }),
        })
    };
    assert!(matches!(
        ask(ACTOR, "api:run.read", "dev"),
        PolicyDecision::Permit
    ));
    assert!(matches!(
        ask(ACTOR, dev::action::RUN, "dev"),
        PolicyDecision::Permit
    ));
    assert!(
        matches!(
            ask("dev:somebody", "api:run.read", "dev"),
            PolicyDecision::Deny { .. }
        ),
        "another actor on tenant dev was permitted"
    );
    assert!(
        matches!(
            ask(ACTOR, "api:run.read", "acme"),
            PolicyDecision::Deny { .. }
        ),
        "the dev actor was permitted on another tenant"
    );
    assert!(matches!(
        ask("support.summarise", "run:admit", ""),
        PolicyDecision::Permit
    ));
    assert!(matches!(
        ask("support.summarise", "effect:perform", ""),
        PolicyDecision::Permit
    ));
    assert!(matches!(
        ask("support.summarise", "data:release", ""),
        PolicyDecision::Deny { .. }
    ));
}
