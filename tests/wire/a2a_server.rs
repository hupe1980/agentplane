#![cfg(all(feature = "a2a-server", feature = "redb"))]

//! The A2A server, as a conforming client would find it.
//!
//! Everything here asserts on the **wire**: the JSON a peer receives. A test
//! against the Rust types would pass with any `serde` rename at all, including a
//! wrong one, and the entire value of this surface is that software nobody here
//! wrote can parse it.
//!
//! Two properties get the most attention, because both fail silently:
//!
//! * the card is reachable **without credentials** and every method is not —
//!   an authenticated card cannot be discovered, and an unauthenticated method
//!   is an open door;
//! * a refusal carries the **spec's** error code, so a caller can tell "this
//!   agent cannot do that" from "you spelled it wrong". Both are refusals; only
//!   one is worth retrying differently.

use std::sync::{Arc, Mutex};

use agentplane::api::a2a::{A2aPushWorker, A2aServer, ServerSetupError, TaskState, action, code};
use agentplane::api::{AuthError, Authenticator, Caller};
use agentplane::case::{CaseStore, EventStore};
use agentplane::core::{
    AwaitSpec, CorrelationKey, DeadlineSpec, Digest, Outcome, PolicyBundleIdentity, PolicyDecision,
    PolicyEngine, PolicyRequest, RunId, Skill, SkillDescriptor, SkillError, Tainted, TenantId,
};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::peers::CardSecurity;
use agentplane::push::{Delivered, PushConfig, PushError, PushStore, PushTransport};
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// One capability, so the single-skill dispatch path is the default here.
const ONE_SKILL: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: settlement-checker
  version: "1.0.0"
spec:
  budgets:
    max_steps: 5
  capabilities:
    provides: [settlement.check]
"#;

/// Two capabilities, so naming one is required.
const TWO_SKILLS: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: settlement-checker
  version: "1.0.0"
spec:
  budgets:
    max_steps: 5
  capabilities:
    provides: [settlement.check, settlement.reverse]
"#;

/// Two agents in one file, the Kubernetes packaging convention. The first is
/// the one the well-known card describes.
const TWO_AGENTS: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: desk
  version: "1.0.0"
spec:
  budgets:
    max_steps: 5
  capabilities:
    provides: [support.answer]
---
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: researcher
  version: "1.0.0"
spec:
  budgets:
    max_steps: 5
  capabilities:
    provides: [research.dig]
"#;

/// What a skill saw: whether its input was untrusted, its provenance, the value.
type Seen = Arc<Mutex<Vec<(bool, Vec<String>, Value)>>>;

/// Records what its input was labelled, so a test can assert the taint survived.
#[derive(Debug, Clone)]
struct Echoes {
    capability: &'static str,
    seen: Seen,
}

#[async_trait::async_trait]
impl Skill for Echoes {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.capability).provides(self.capability)
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let label = input.label();
        self.seen.lock().unwrap().push((
            label.is_untrusted(),
            label
                .provenance
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            input.peek().clone(),
        ));
        Ok(Outcome::done(Tainted::trusted(json!({"ok": true}))))
    }
}

#[derive(Debug)]
struct HeaderAuth;

#[async_trait::async_trait]
impl Authenticator for HeaderAuth {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
        // Either scheme: the hand-built tests set `x-actor`, and the A2A client
        // sends a bearer token like a real peer would.
        if let Some(actor) = headers.get("x-actor").and_then(|v| v.to_str().ok()) {
            // `tenant:actor` when a test needs to be somebody else's tenant;
            // a bare actor is the default tenant.
            let (tenant, actor) = match actor.split_once(':') {
                Some((t, a)) => (TenantId::new(t).map_err(|_| AuthError::Rejected)?, a),
                None => (TenantId::default(), actor),
            };
            return Ok(Caller::new(actor, vec!["peer".to_owned()]).in_tenant(tenant));
        }
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::Missing)?;
        // Same `tenant:actor` shape as the header path. A real deployment reads
        // the tenant out of the credential too — it is the one field that must
        // not come from the request.
        let (tenant, actor) = match bearer.split_once(':') {
            Some((t, a)) => (TenantId::new(t).map_err(|_| AuthError::Rejected)?, a),
            None => (TenantId::default(), bearer),
        };
        Ok(Caller::new(actor, vec!["peer".to_owned()]).in_tenant(tenant))
    }
}

/// Permits, recording what it was asked — a gate nobody calls looks exactly
/// like a gate that permits.
#[derive(Debug, Default)]
struct Recording {
    seen: Mutex<Vec<String>>,
    /// Refuse at the API gate.
    deny: bool,
    /// Permit at the gate and refuse inside the runtime, which is the path a
    /// real deployment takes when a peer may call but not do this.
    deny_runs: bool,
    hidden_resource: Mutex<Option<String>>,
}

impl PolicyEngine for Recording {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        self.seen.lock().unwrap().push(request.action.to_owned());
        let hidden = self.hidden_resource.lock().unwrap();
        let refuse = self.deny
            || (self.deny_runs && !request.action.starts_with("a2a:"))
            || hidden.as_deref() == Some(request.resource);
        if refuse {
            PolicyDecision::deny("secret-rule: the test policy refuses this")
        } else {
            PolicyDecision::Permit
        }
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"a2a-test"), "agentplane-test/a2a-v1")
    }
}

struct Fixture {
    rt: Arc<Runtime>,
    store: Arc<RedbStore>,
    policy: Arc<Recording>,
    seen: Seen,
    manifest: Manifest,
}

fn fixture_from(yaml: &str, policy: Arc<Recording>) -> Fixture {
    // `parse_all`, so a room file wires every agent onto the one plane — which
    // is the arrangement the per-agent card work exists to serve.
    let all = Manifest::parse_all(yaml).expect("parse");
    let manifest = all.first().expect("at least one agent").clone();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut builder = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .policy(policy.clone() as Arc<dyn PolicyEngine>);
    for cap in all.iter().flat_map(|m| &m.spec.capabilities.provides) {
        // Leaked so the descriptor can hold a `&'static str`; these live for the
        // test process either way.
        let cap: &'static str = Box::leak(cap.clone().into_boxed_str());
        builder = builder.skill(Echoes {
            capability: cap,
            seen: seen.clone(),
        });
    }
    Fixture {
        rt: builder.build(),
        store,
        policy,
        seen,
        manifest,
    }
}

#[derive(Debug, Default)]
struct RecordingPush {
    payloads: Mutex<Vec<Value>>,
    failures: Mutex<usize>,
}

impl RecordingPush {
    fn fail_next(&self) {
        *self.failures.lock().unwrap() += 1;
    }
}

#[async_trait::async_trait]
impl PushTransport for RecordingPush {
    fn validate(&self, config: &PushConfig) -> Result<(), PushError> {
        if config.url.starts_with("https://client.example/") {
            Ok(())
        } else {
            Err(PushError::HostNotGranted(config.url.clone()))
        }
    }

    async fn deliver(
        &self,
        config: &PushConfig,
        message: &agentplane::push::PushMessage,
        _at: u64,
    ) -> Result<Delivered, PushError> {
        // The real `PushSender` re-checks the grant here, not only at
        // registration, because a registration outlives the configuration that
        // permitted it. A double that skipped it would be exempt from the one
        // control this path exists to apply — and every test written against it
        // would pass with the control removed.
        self.validate(config)?;
        self.payloads.lock().unwrap().push(message.payload.clone());
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            Ok(Delivered::Unreachable("offline".to_owned()))
        } else {
            Ok(Delivered::Accepted)
        }
    }
}

fn fixture() -> Fixture {
    fixture_from(ONE_SKILL, Arc::new(Recording::default()))
}

#[derive(Debug)]
struct NeedsInput;

#[async_trait::async_trait]
impl Skill for NeedsInput {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("needs-input").provides("settlement.check")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("reply", &DeadlineSpec::days(1), None).await?;
        let reply = cx
            .await_event(
                &AwaitSpec::new("a2a.task.input", "reply")
                    .correlate(CorrelationKey::new("task", "settlement")),
            )
            .await?;
        cx.meet_deadline("reply").await?;
        Ok(Outcome::done(reply))
    }
}

fn continuation_fixture() -> Fixture {
    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let policy = Arc::new(Recording::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn EventStore>)
        .policy(policy.clone() as Arc<dyn PolicyEngine>)
        .skill(NeedsInput)
        .build();
    Fixture {
        rt,
        store,
        policy,
        seen,
        manifest,
    }
}

fn card_security() -> CardSecurity {
    CardSecurity::bearer("bearer", ["peer"])
}

impl Fixture {
    fn router(&self) -> axum::Router {
        A2aServer::new(
            self.rt.clone(),
            Arc::new(HeaderAuth),
            &card_security(),
            &self.manifest,
            "https://plane.internal/a2a",
        )
        .expect("the fixture wires a policy engine")
        .router()
    }

    fn push_server(&self) -> (A2aServer, A2aPushWorker, Arc<RecordingPush>) {
        let transport = Arc::new(RecordingPush::default());
        let server = A2aServer::new(
            self.rt.clone(),
            Arc::new(HeaderAuth),
            &card_security(),
            &self.manifest,
            "https://plane.internal/a2a",
        )
        .expect("the fixture wires a policy engine")
        .with_push(
            Arc::clone(&self.store) as Arc<dyn agentplane::push::PushStore>,
            Arc::clone(&transport) as Arc<dyn PushTransport>,
        )
        .expect("push before signing");
        let worker = server.push_worker().expect("worker");
        (server, worker, transport)
    }
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 256 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A well-formed 1.0 call.
fn rpc(method: &str, params: &Value, actor: Option<&str>) -> Request<Body> {
    rpc_versioned(method, params, actor, Some("1.0"))
}

fn rpc_versioned(
    method: &str,
    params: &Value,
    actor: Option<&str>,
    version: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder()
        .uri("/a2a")
        .method("POST")
        .header("content-type", "application/json");
    if let Some(a) = actor {
        b = b.header("x-actor", a);
    }
    if let Some(v) = version {
        b = b.header("A2A-Version", v);
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    b.body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn text(t: &str) -> Value {
    json!({"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": t}]})
}

/// The error code from a JSON-RPC response, or a readable panic.
fn err_code(body: &Value) -> i64 {
    body.get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("expected a JSON-RPC error, got: {body:#}"))
}

/// The named constants are the raw numerals the A2A 1.0 error table assigns.
///
/// Every response assertion in this file compares `err_code(&body)` against
/// the same `code` module the server emits from, so both sides of those
/// comparisons would move together if a constant were mistyped or renumbered.
/// This is the one place the constants meet the spec's literal values instead
/// of themselves; with it, each `code::`-based response assertion becomes a
/// transitive raw pin. What this does NOT check is that the server *uses* the
/// right constant at each site — the response tests own that half.
#[test]
fn the_error_constants_carry_the_spec_tables_raw_values() {
    assert_eq!(code::TASK_NOT_FOUND, -32001);
    assert_eq!(code::TASK_NOT_CANCELABLE, -32002);
    assert_eq!(code::PUSH_NOT_SUPPORTED, -32003);
    assert_eq!(code::UNSUPPORTED_OPERATION, -32004);
    assert_eq!(code::CONTENT_TYPE_NOT_SUPPORTED, -32005);
    assert_eq!(code::EXTENDED_CARD_NOT_CONFIGURED, -32007);
    assert_eq!(code::VERSION_NOT_SUPPORTED, -32009);
    // Not spec-assigned: the server-defined back-pressure code. Pinned so it
    // cannot drift onto a value the spec's table does define, which would turn
    // "not right now" into whatever that code means to a compliant client.
    assert_eq!(code::QUOTA_EXHAUSTED, -32029);
}

// ── Discovery ───────────────────────────────────────────────────────────────

/// The card is served without credentials, and it is the derived one.
///
/// A card behind authentication cannot be discovered, which defeats the point
/// of publishing one: a caller reads it *before* it has anything to present.
#[tokio::test]
async fn the_agent_card_is_public() {
    let f = fixture();
    let req = Request::builder()
        .uri("/.well-known/agent-card.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send(&f.router(), req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the card must be reachable with no credentials: {body:#}"
    );
    assert_eq!(body["name"], "settlement-checker");
    assert_eq!(body["skills"][0]["id"], "settlement.check");
    assert_eq!(
        body["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"], "Bearer",
        "the server requires authentication but its card does not tell clients how to authenticate"
    );
    assert_eq!(
        body["securityRequirements"][0]["schemes"]["bearer"]["list"],
        json!(["peer"]),
        "the card omitted the scope required by the server fixture"
    );
    assert_eq!(
        body["capabilities"]["pushNotifications"], false,
        "the server advertised push because it was compiled even though this deployment \
         wired no push store or sender; every push method will refuse"
    );
    assert_eq!(
        body["supportedInterfaces"][0]["protocolVersion"], "1.0",
        "a client selects an interface by version, and one without it is unusable"
    );
    assert_eq!(
        f.policy.seen.lock().unwrap().len(),
        0,
        "the public card asked the policy engine, which means it is not public"
    );
}

#[tokio::test]
async fn the_card_advertises_push_only_with_a_durable_worker() {
    let f = fixture();
    let (server, _worker, _transport) = f.push_server();
    let req = Request::builder()
        .uri("/.well-known/agent-card.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let (_, card) = send(&server.router(), req).await;
    assert_eq!(card["capabilities"]["pushNotifications"], true);
}

#[tokio::test]
async fn malformed_inline_push_authentication_is_refused_before_admission() {
    let f = fixture();
    let (server, _worker, _transport) = f.push_server();
    let (_, body) = send(
        &server.router(),
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {
                        "url": "https://client.example/hook",
                        "authentication": {"scheme": "", "credentials": "secret"}
                    }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(err_code(&body), i64::from(code::INVALID_PARAMS), "{body:#}");
    assert!(
        f.seen.lock().unwrap().is_empty(),
        "malformed push input was rejected only after its skill ran"
    );
}

#[tokio::test]
async fn inline_push_has_its_own_authorization_gate() {
    let f = fixture();
    *f.policy.hidden_resource.lock().unwrap() = Some("new:settlement.check".to_owned());
    let (server, _worker, _transport) = f.push_server();
    let (_, body) = send(
        &server.router(),
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {
                        "url": "https://client.example/hook"
                    }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(body.get("error").is_some(), "{body:#}");
    assert!(
        f.policy
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|action| action == agentplane::api::a2a::action::TASK_PUSH),
        "inline push bypassed the push-specific policy action"
    );
    assert!(
        f.seen.lock().unwrap().is_empty(),
        "the push denial happened only after its skill ran"
    );
}

#[tokio::test]
async fn inline_push_requires_an_empty_task_id_before_admission() {
    let f = fixture();
    let (server, _worker, _transport) = f.push_server();
    let (_, body) = send(
        &server.router(),
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {
                        "taskId": "client-chosen-task",
                        "url": "https://client.example/hook"
                    }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(err_code(&body), i64::from(code::INVALID_PARAMS), "{body:#}");
    assert!(
        f.seen.lock().unwrap().is_empty(),
        "invalid inline taskId was rejected only after its skill ran"
    );
}

#[tokio::test]
async fn push_configuration_crud_is_authorized_and_redacted() {
    let f = fixture();
    let (_, sent) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let task = sent["result"]["task"]["id"].as_str().unwrap();
    let (server, _worker, _transport) = f.push_server();
    let router = server.router();
    let create = json!({
        "taskId": task,
        "id": "cfg-1",
        "url": "https://client.example/hook",
        "token": "opaque-token",
        "authentication": {"scheme": "Bearer", "credentials": "receiver-secret"}
    });
    let (_, created) = send(
        &router,
        rpc("CreateTaskPushNotificationConfig", &create, Some("peer-a")),
    )
    .await;
    assert_eq!(created["result"]["id"], "cfg-1");
    assert_eq!(created["result"]["authentication"]["scheme"], "Bearer");
    assert!(!created.to_string().contains("receiver-secret"));
    assert!(!created.to_string().contains("opaque-token"));

    let key = json!({"taskId": task, "id": "cfg-1"});
    let (_, got) = send(
        &router,
        rpc("GetTaskPushNotificationConfig", &key, Some("peer-a")),
    )
    .await;
    assert_eq!(got["result"]["url"], "https://client.example/hook");
    let (_, listed) = send(
        &router,
        rpc(
            "ListTaskPushNotificationConfigs",
            &json!({"taskId": task}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(listed["result"]["configs"].as_array().unwrap().len(), 1);

    send(
        &router,
        rpc("DeleteTaskPushNotificationConfig", &key, Some("peer-a")),
    )
    .await;
    let (_, missing) = send(
        &router,
        rpc("GetTaskPushNotificationConfig", &key, Some("peer-a")),
    )
    .await;
    assert_eq!(err_code(&missing), i64::from(code::TASK_NOT_FOUND));
}

/// A caller may not register into the namespace an operator destination owns.
///
/// Both share one push store and are told apart by an id prefix. A caller
/// allowed to write into that namespace could point one of the deployment's own
/// destinations at an address it chose — and operator destinations are
/// deliberately exempt from the host allowlist, HTTPS and the public-address
/// check, precisely because there is supposed to be no caller involved.
#[tokio::test]
async fn a_caller_may_not_register_in_the_operator_namespace() {
    let f = fixture();
    let (server, _worker, _transport) = f.push_server();
    let router = server.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {
                        "id": format!("{}bus", agentplane::push::OPERATOR_PREFIX),
                        "url": "https://client.example/hook"
                    }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(err_code(&sent), i64::from(code::INVALID_PARAMS), "{sent:#}");
    assert!(
        sent["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("this deployment configured for itself"),
        "{sent:#}"
    );

    // The ordinary id is accepted, so the refusal is about the namespace and
    // not about ids being refused generally.
    let (_, ok) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {
                        "id": "peer-hook",
                        "url": "https://client.example/hook"
                    }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(ok["result"]["task"]["id"].is_string(), "{ok:#}");
}

#[tokio::test]
async fn push_worker_retries_from_the_same_journal_cursor_and_cleans_terminal_tasks() {
    let f = fixture();
    let (server, worker, transport) = f.push_server();
    transport.fail_next();
    let router = server.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {
                        "url": "https://client.example/hook",
                        "authentication": {
                            "scheme": "Bearer",
                            "credentials": "receiver-secret"
                        }
                    }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(sent["result"]["task"]["id"].is_string(), "{sent:#}");

    let failed = worker.run_once(10, 10).await.expect("failed sweep");
    assert_eq!(failed.retries, 1);
    assert_eq!(failed.deliveries, 0);
    assert_eq!(worker.run_once(10, 10).await.unwrap().registrations, 0);

    let delivered = worker.run_once(11, 10).await.expect("retry sweep");
    assert!(delivered.deliveries > 0);
    assert_eq!(delivered.completed, 1);
    {
        let payloads = transport.payloads.lock().unwrap();
        assert_eq!(payloads[0], payloads[1], "retry skipped the failed payload");
        assert!(
            payloads
                .iter()
                .any(|payload| payload.get("artifactUpdate").is_some()),
            "terminal output was not pushed"
        );
    }
    assert_eq!(worker.run_once(12, 10).await.unwrap().registrations, 0);
}

#[tokio::test]
async fn push_registration_after_completion_delivers_the_terminal_record() {
    let f = fixture();
    let (server, worker, transport) = f.push_server();
    let router = server.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let task = sent["result"]["task"]["id"].as_str().unwrap();
    assert_eq!(
        sent["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );

    let (_, created) = send(
        &router,
        rpc(
            "CreateTaskPushNotificationConfig",
            &json!({
                "taskId": task,
                "id": "late",
                "url": "https://client.example/hook"
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(created["result"]["id"], "late", "{created:#}");

    let report = worker.run_once(10, 10).await.expect("late sweep");
    assert_eq!(report.completed, 1);
    assert!(
        transport
            .payloads
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload.get("artifactUpdate").is_some()),
        "late registration omitted the completed task's artifact"
    );
    assert_eq!(worker.run_once(11, 10).await.unwrap().registrations, 0);
}

#[tokio::test]
async fn push_worker_cleans_up_after_advance_won_the_race_with_a_crash() {
    let f = fixture();
    let (server, worker, _transport) = f.push_server();
    let router = server.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let task = RunId::parse(sent["result"]["task"]["id"].as_str().unwrap()).unwrap();
    let (_, created) = send(
        &router,
        rpc(
            "CreateTaskPushNotificationConfig",
            &json!({
                "taskId": task.to_string(),
                "id": "crashed-after-advance",
                "url": "https://client.example/hook"
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(created["result"]["id"], "crashed-after-advance");
    let head = f.rt.journal().head(task).await.unwrap();
    f.store
        .advance(task, "crashed-after-advance", head.seq.saturating_add(1))
        .await
        .unwrap();

    let report = worker.run_once(10, 10).await.unwrap();
    assert_eq!(report.completed, 1);
    assert!(
        f.store
            .get(task, "crashed-after-advance")
            .await
            .unwrap()
            .is_none(),
        "a terminal registration survived forever after advance-before-delete"
    );
}

/// A receiver that answers 500 is `Rejected`, and the cursor stays put.
///
/// This is the one test that drives the real `PushSender` at a real HTTP
/// receiver — every other push test doubles the transport, so the
/// status-to-outcome mapping at the bottom of `deliver` (2xx is `Accepted`,
/// anything else answered is `Rejected`) had no coverage and
/// `Delivered::Rejected` was constructed nowhere in the suite. Two halves:
/// the sender itself must report `Rejected(500)` as an *outcome* rather than
/// an error, and the durable worker consuming that outcome must not advance
/// the delivery cursor — proven by the retry re-sending the identical
/// payload once the receiver recovers. What this does NOT cover is the
/// abandonment ceiling for a receiver that never recovers; the worker's own
/// tests own that.
#[cfg(feature = "testkit")]
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_receiver_answering_500_is_rejected_and_the_cursor_does_not_advance() {
    use agentplane::push::{PushPolicy, PushSender};

    #[derive(Clone, Default)]
    struct Receiver {
        bodies: Arc<Mutex<Vec<Value>>>,
        failures: Arc<Mutex<usize>>,
    }
    let receiver = Receiver::default();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post({
            let state = receiver.clone();
            move |axum::Json(body): axum::Json<Value>| {
                let state = state.clone();
                async move {
                    state.bodies.lock().unwrap().push(body);
                    let mut failures = state.failures.lock().unwrap();
                    if *failures > 0 {
                        *failures -= 1;
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        StatusCode::OK
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hook",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // The loopback exception is `testkit`-only and lifts HTTPS and the
    // public-address check for this literal host; the host grant still runs.
    let sender =
        PushSender::new(PushPolicy::new().allow_host("127.0.0.1")).allow_plaintext_loopback();

    // First half: a 500 is an outcome, not an error, and it is `Rejected`
    // carrying the status the receiver answered with.
    *receiver.failures.lock().unwrap() = 1;
    let probe = PushConfig {
        id: "probe".to_owned(),
        task: RunId::generate(),
        url: url.clone(),
        token: None,
        authentication: None,
    };
    let outcome = sender
        .deliver(
            &probe,
            &agentplane::push::PushMessage::json("probe", json!({"probe": true})),
            0,
        )
        .await
        .expect("an answered request is an outcome, never a PushError");
    assert_eq!(
        outcome,
        Delivered::Rejected {
            status: 500,
            retry_after: None
        },
        "the status must survive"
    );

    // Second half: the worker consuming that outcome leaves the cursor where
    // it was. Same registration flow as production, real sender throughout.
    let f = fixture();
    let server = A2aServer::new(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &f.manifest,
        "https://plane.internal/a2a",
    )
    .expect("the fixture wires a policy engine")
    .with_push(
        Arc::clone(&f.store) as Arc<dyn PushStore>,
        Arc::new(sender) as Arc<dyn PushTransport>,
    )
    .expect("push before signing");
    let worker = server.push_worker().expect("worker");
    let router = server.router();

    *receiver.failures.lock().unwrap() = 1;
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": { "url": url }
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(sent["result"]["task"]["id"].is_string(), "{sent:#}");

    let before = receiver.bodies.lock().unwrap().len();
    let rejected = worker.run_once(10, 10).await.expect("failed sweep");
    assert_eq!(rejected.deliveries, 0, "a 500 was counted as delivered");
    assert_eq!(
        rejected.retries, 1,
        "a rejected delivery must be rescheduled"
    );

    // The receiver has recovered; the retry must carry the exact payload the
    // 500 answered, which is only possible if the cursor did not move.
    let delivered = worker.run_once(13, 10).await.expect("retry sweep");
    assert!(delivered.deliveries > 0, "the retry never happened");
    let bodies = receiver.bodies.lock().unwrap();
    assert_eq!(
        bodies[before],
        bodies[before + 1],
        "the cursor advanced past the rejected record, skipping its payload"
    );
}

/// Every method authenticates, and the card is the only route that does not.
#[tokio::test]
async fn every_method_is_authenticated() {
    let f = fixture();
    let router = f.router();

    for (method, params) in [
        ("SendMessage", json!({"message": text("check this")})),
        ("GetTask", json!({"id": "01JRJ0000000000000000000000"})),
        ("CancelTask", json!({"id": "01JRJ0000000000000000000000"})),
        ("GetExtendedAgentCard", json!({})),
        (
            "CreateTaskPushNotificationConfig",
            json!({"taskId": "01JRJ0000000000000000000000", "url": "https://client.example/hook"}),
        ),
        (
            "GetTaskPushNotificationConfig",
            json!({"taskId": "01JRJ0000000000000000000000", "id": "cfg"}),
        ),
        (
            "ListTaskPushNotificationConfigs",
            json!({"taskId": "01JRJ0000000000000000000000"}),
        ),
        (
            "DeleteTaskPushNotificationConfig",
            json!({"taskId": "01JRJ0000000000000000000000", "id": "cfg"}),
        ),
    ] {
        let (_, body) = send(&router, rpc(method, &params, None)).await;
        assert!(
            body.get("error").is_some(),
            "{method} answered an unauthenticated caller: {body:#}"
        );
        assert!(
            body.get("result").is_none(),
            "{method} produced a result for a caller with no identity: {body:#}"
        );
    }
}

/// And the gate is a real gate: a denying policy stops every method.
#[tokio::test]
async fn a_denying_policy_stops_every_method() {
    let f = fixture_from(
        ONE_SKILL,
        Arc::new(Recording {
            seen: Mutex::new(Vec::new()),
            deny: true,
            deny_runs: false,
            hidden_resource: Mutex::new(None),
        }),
    );
    let router = f.router();

    let (_, body) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(
        body.get("result").is_none(),
        "a refused caller started a run: {body:#}"
    );
    assert_eq!(
        f.seen.lock().unwrap().len(),
        0,
        "the skill ran despite the policy refusing the call"
    );
    assert!(
        f.policy
            .seen
            .lock()
            .unwrap()
            .contains(&action::MESSAGE_SEND.to_owned()),
        "SendMessage did not ask the policy engine at all"
    );
    // The denial does not teach: a Cedar reason names the action, resource and
    // the policy ids that fired, which is a probe-able map of the authorization
    // vocabulary handed to an external caller. The reason stays operator-side;
    // the caller learns only that it was declined.
    assert!(
        !body.to_string().contains("secret-rule"),
        "the policy's reason leaked to the external caller: {body:#}"
    );
}

// ── Version negotiation ─────────────────────────────────────────────────────

/// A missing `A2A-Version` header is a 0.3 client, and is refused as one.
///
/// The spec is explicit: an empty value means 0.3. Answering it with 1.0
/// semantics is how a caller silently loses half the protocol — it would read
/// our 1.0 response shape as a 0.3 one and mis-parse every field that moved.
#[tokio::test]
async fn a_request_without_a_version_is_refused_as_zero_three() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc_versioned(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
            None,
        ),
    )
    .await;

    assert_eq!(
        err_code(&body),
        i64::from(code::VERSION_NOT_SUPPORTED),
        "a version-less request must be refused as 0.3: {body:#}"
    );
    assert!(
        body["error"]["message"].as_str().unwrap().contains("0.3"),
        "the refusal must say what version it read, or the caller cannot fix \
         it: {body:#}"
    );

    // The positive half: with the header, the same call goes through.
    let (_, ok) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(
        ok.get("result").is_some(),
        "a correctly-versioned request was refused too, so the check refuses \
         everything rather than refusing 0.3: {ok:#}"
    );
}

/// A version this agent does not speak is refused with the spec's code.
#[tokio::test]
async fn an_unsupported_version_is_refused() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc_versioned(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
            Some("2.5"),
        ),
    )
    .await;
    assert_eq!(err_code(&body), i64::from(code::VERSION_NOT_SUPPORTED));
}

/// A suffix is not a patch version and cannot smuggle an unsupported dialect
/// through a prefix-only `Major.Minor` comparison.
#[tokio::test]
async fn a_malformed_version_is_refused() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc_versioned(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
            Some("1.0.preview"),
        ),
    )
    .await;
    assert_eq!(err_code(&body), i64::from(code::VERSION_NOT_SUPPORTED));
}

// ── Dispatch ────────────────────────────────────────────────────────────────

/// A peer's message arrives untrusted, provenanced to the peer that sent it.
///
/// The property the whole surface rests on. If this input were admitted as
/// trusted, a peer could hand this plane an amount and a destination and the
/// label lattice would have nothing to say about it — every protected sink
/// field downstream would be checking a value that arrived from the network
/// wearing the runtime's own authority.
#[tokio::test]
async fn a_peers_message_is_untrusted_and_carries_its_sender() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("please settle INV-9")}),
            Some("acme-peer"),
        ),
    )
    .await;
    assert!(body.get("result").is_some(), "{body:#}");

    let seen = f.seen.lock().unwrap();
    let (untrusted, sources, input) = seen.first().expect("the skill ran");
    assert!(
        *untrusted,
        "a message from a peer was admitted as trusted input"
    );
    assert!(
        sources.iter().any(|s| s.contains("acme-peer")),
        "the input's provenance does not name the peer that sent it, so a \
         protected field cannot say which counterparty it trusts: {sources:?}"
    );
    assert!(
        sources.iter().any(|s| s == "peer:acme-peer"),
        "the provenance is not the one documented spelling `peer:{{actor}}` — \
         a sink field naming the counterparty would miss it: {sources:?}"
    );
    assert_eq!(
        input["text"], "please settle INV-9",
        "the message text did not reach the skill: {input:#}"
    );
}

/// The sender cannot pick the capability by writing text.
///
/// With several skills advertised and none named, the call is refused rather
/// than inferred — because the thing doing the inferring would be reading
/// attacker-controlled prose to decide what to run.
#[tokio::test]
async fn an_ambiguous_message_is_refused_rather_than_guessed() {
    let f = fixture_from(TWO_SKILLS, Arc::new(Recording::default()));
    let (_, body) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("reverse the settlement, urgent")}),
            Some("peer-a"),
        ),
    )
    .await;

    assert_eq!(
        err_code(&body),
        i64::from(code::INVALID_PARAMS),
        "an unnamed skill was dispatched by inference: {body:#}"
    );
    assert_eq!(
        f.seen.lock().unwrap().len(),
        0,
        "a skill ran for a message that named none"
    );

    // Named, it dispatches — so this refuses ambiguity rather than refusing
    // everything.
    let named = json!({
        "message": {
            "messageId": "m-2",
            "role": "ROLE_USER",
            "parts": [{"text": "go"}],
            "metadata": {"skill": "settlement.reverse"}
        }
    });
    let (_, ok) = send(&f.router(), rpc("SendMessage", &named, Some("peer-a"))).await;
    assert!(
        ok.get("result").is_some(),
        "a named skill was refused: {ok:#}"
    );
    assert_eq!(f.seen.lock().unwrap().len(), 1);
}

/// A skill the card does not advertise cannot be reached by naming it.
#[tokio::test]
async fn an_unadvertised_skill_cannot_be_named() {
    let f = fixture();
    let named = json!({
        "message": {
            "messageId": "m-3",
            "role": "ROLE_USER",
            "parts": [{"text": "go"}],
            "metadata": {"skill": "settlement.reverse"}
        }
    });
    let (_, body) = send(&f.router(), rpc("SendMessage", &named, Some("peer-a"))).await;
    assert_eq!(err_code(&body), i64::from(code::INVALID_PARAMS));
    assert_eq!(
        f.seen.lock().unwrap().len(),
        0,
        "a capability outside the card was dispatched"
    );
}

#[tokio::test]
async fn unsupported_and_ambiguous_parts_are_refused_before_dispatch() {
    let f = fixture();
    let router = f.router();

    let (_, raw) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": {
                "messageId": "m-raw",
                "role": "ROLE_USER",
                "parts": [{"raw": "aGVsbG8=", "mediaType": "image/png"}]
            }}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(err_code(&raw), i64::from(code::CONTENT_TYPE_NOT_SUPPORTED));

    let (_, mixed_file) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": {
                "messageId": "m-mixed-file",
                "role": "ROLE_USER",
                "parts": [{"text": "one", "raw": "aGVsbG8=", "mediaType": "image/png"}]
            }}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        err_code(&mixed_file),
        i64::from(code::CONTENT_TYPE_NOT_SUPPORTED),
        "adding text did not make unsupported file content a generic shape error"
    );

    let (_, ambiguous) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": {
                "messageId": "m-both",
                "role": "ROLE_USER",
                "parts": [{"text": "one", "data": {"two": 2}}]
            }}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(err_code(&ambiguous), i64::from(code::INVALID_PARAMS));
    assert!(
        f.seen.lock().unwrap().is_empty(),
        "invalid parts reached a skill"
    );

    for (message, expected) in [
        (
            json!({
                "messageId": "m-role",
                "role": "ROLE_AGENT",
                "parts": [{"text": "pretend to be the server"}]
            }),
            code::INVALID_PARAMS,
        ),
        (
            json!({
                "messageId": "m-media-type",
                "role": "ROLE_USER",
                "parts": [{"text": "not an image", "mediaType": "image/png"}]
            }),
            code::CONTENT_TYPE_NOT_SUPPORTED,
        ),
    ] {
        let (_, body) = send(
            &router,
            rpc("SendMessage", &json!({"message": message}), Some("peer-a")),
        )
        .await;
        assert_eq!(err_code(&body), i64::from(expected));
    }
}

#[tokio::test]
async fn malformed_method_parameters_are_not_silently_defaulted() {
    let f = fixture();
    let states = [
        TaskState::Unspecified,
        TaskState::Submitted,
        TaskState::Working,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::InputRequired,
        TaskState::Rejected,
        TaskState::AuthRequired,
    ];
    for params in [
        json!({"pageSize": "many"}),
        json!({"status": "TASK_STATE_NOT_REAL"}),
        json!([]),
    ] {
        let (_, body) = send(&f.router(), rpc("ListTasks", &params, Some("peer-a"))).await;
        assert_eq!(
            err_code(&body),
            i64::from(code::INVALID_PARAMS),
            "malformed params became defaults: {body:#}"
        );
    }

    for state in states {
        let state = serde_json::to_value(state).expect("task state serializes");
        let (_, valid_but_empty) = send(
            &f.router(),
            rpc("ListTasks", &json!({"status": state}), Some("peer-a")),
        )
        .await;
        assert_eq!(valid_but_empty["result"]["totalSize"], 0, "{state}");
    }
}

#[tokio::test]
async fn context_id_groups_new_immutable_tasks_across_turns() {
    let f = fixture();
    let first = json!({"message": {
        "messageId": "turn-1",
        "role": "ROLE_USER",
        "parts": [{"text": "first"}]
    }});
    let (_, first_response) = send(&f.router(), rpc("SendMessage", &first, Some("peer-a"))).await;
    let context = first_response["result"]["task"]["contextId"]
        .as_str()
        .expect("server-generated context")
        .to_owned();
    let first_task = first_response["result"]["task"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let second = json!({"message": {
        "messageId": "turn-2",
        "contextId": context,
        "role": "ROLE_USER",
        "parts": [{"text": "second"}]
    }});
    let (_, second_response) = send(&f.router(), rpc("SendMessage", &second, Some("peer-a"))).await;
    assert_eq!(second_response["result"]["task"]["contextId"], context);
    assert_ne!(
        second_response["result"]["task"]["id"], first_task,
        "a new turn mutated the prior immutable run instead of creating a task in its context"
    );

    let task_continuation = json!({"message": {
        "messageId": "turn-bad",
        "taskId": first_task,
        "role": "ROLE_USER",
        "parts": [{"text": "mutate prior task"}]
    }});
    let (_, refused) = send(
        &f.router(),
        rpc("SendMessage", &task_continuation, Some("peer-a")),
    )
    .await;
    assert_eq!(err_code(&refused), i64::from(code::UNSUPPORTED_OPERATION));
}

/// **A content filter's cost has a ceiling, and crossing it is a refusal —
/// not a truncated total, and not a scan the caller sizes.**
///
/// `status` and `contextId` can only be evaluated by reading each candidate's
/// journal, and the spec's `totalSize` is the exact pre-pagination count — so
/// an unbounded implementation hands any authenticated peer a scan of every
/// run the tenant ever wrote, per request, by adding one field. The bound
/// refuses over-budget filters and names `statusTimestampAfter` as the lever,
/// because that one is answered from the index and narrows for free. A
/// truncated count instead would be a lie shaped like an answer: a smaller
/// tenant, not a bounded scan.
#[tokio::test]
async fn a_filter_past_its_scan_budget_is_refused_naming_the_lever() {
    let f = fixture();
    for n in 0..2 {
        let msg = json!({"message": {
            "messageId": format!("budget-turn-{n}"),
            "role": "ROLE_USER",
            "parts": [{"text": "hello"}]
        }});
        send(&f.router(), rpc("SendMessage", &msg, Some("peer-a"))).await;
    }
    let tight = A2aServer::new(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &f.manifest,
        "https://plane.internal/a2a",
    )
    .expect("the fixture wires a policy engine")
    .filter_scan_budget(1)
    .router();

    // Two candidates, a budget of one: the exact total cannot be computed
    // within the ceiling, so the request is refused with the narrowing lever.
    let list = json!({"status": "TASK_STATE_COMPLETED", "pageSize": 1});
    let (_, refused) = send(&tight, rpc("ListTasks", &list, Some("peer-a"))).await;
    assert_eq!(err_code(&refused), i64::from(code::INVALID_PARAMS));
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("statusTimestampAfter"),
        "the refusal must name the filter that narrows without reading: {refused}"
    );

    // The positive halves. An unfiltered listing over the same store is
    // index-only and unaffected by the budget; and the same filter under the
    // default budget answers exactly.
    let unfiltered = json!({"pageSize": 1});
    let (_, listed) = send(&tight, rpc("ListTasks", &unfiltered, Some("peer-a"))).await;
    assert_eq!(
        listed["result"]["totalSize"], 2,
        "an unfiltered listing reads no journals beyond its page and owes no \
         budget: {listed}"
    );
    let (_, roomy) = send(&f.router(), rpc("ListTasks", &list, Some("peer-a"))).await;
    assert!(
        roomy["result"]["totalSize"].is_u64(),
        "the same filter under the default budget answers exactly: {roomy}"
    );
}

#[tokio::test]
async fn list_tasks_filters_context_and_uses_opaque_cursor_pages() {
    let f = fixture();
    let first = json!({"message": {
        "messageId": "list-turn-1",
        "role": "ROLE_USER",
        "parts": [{"text": "first"}]
    }});
    let (_, response) = send(&f.router(), rpc("SendMessage", &first, Some("peer-a"))).await;
    let context = response["result"]["task"]["contextId"]
        .as_str()
        .unwrap()
        .to_owned();
    let second = json!({"message": {
        "messageId": "list-turn-2",
        "contextId": context,
        "role": "ROLE_USER",
        "parts": [{"text": "second"}]
    }});
    send(&f.router(), rpc("SendMessage", &second, Some("peer-a"))).await;

    let list = json!({
        "contextId": context,
        "status": "TASK_STATE_COMPLETED",
        "pageSize": 1,
        "historyLength": 1
    });
    let (_, page_one) = send(&f.router(), rpc("ListTasks", &list, Some("peer-a"))).await;
    assert_eq!(page_one["result"]["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(page_one["result"]["totalSize"], 2);
    assert!(page_one["result"]["tasks"][0]["history"].is_array());
    let token = page_one["result"]["nextPageToken"].as_str().unwrap();
    assert!(!token.is_empty());

    let mut next = list;
    next["pageToken"] = json!(token);
    let (_, page_two) = send(&f.router(), rpc("ListTasks", &next, Some("peer-a"))).await;
    assert_eq!(page_two["result"]["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(page_two["result"]["nextPageToken"], "");

    let (_, with_artifacts) = send(
        &f.router(),
        rpc(
            "ListTasks",
            &json!({"contextId": context, "includeArtifacts": true}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(
        with_artifacts["result"]["tasks"][0]["artifacts"].is_array(),
        "includeArtifacts was accepted but artifacts were not reconstructed: {with_artifacts:#}"
    );
}

/// `includeArtifacts` is a metered read, and the meter says its own name.
///
/// Each completed task's artifacts are a full strict replay, and a page holds
/// up to a hundred tasks — so the replays per request are budgeted, a task
/// past the budget comes back with its omission **marked** in `Task.metadata`
/// (a bounded result must not be shaped like a complete one),
/// and sealed runs already replayed are served from cache so repeated listings
/// converge on complete instead of paying the same replays forever.
#[tokio::test]
async fn include_artifacts_is_budgeted_marked_and_cached() {
    let f = fixture();
    let server = A2aServer::new(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &f.manifest,
        "https://plane.internal/a2a",
    )
    .expect("the fixture wires a policy engine")
    .artifact_replay_budget(1);
    let router = server.router();

    for n in 0..3 {
        send(
            &router,
            rpc(
                "SendMessage",
                &json!({"message": {
                    "messageId": format!("budget-{n}"),
                    "role": "ROLE_USER",
                    "parts": [{"text": "go"}]
                }}),
                Some("peer-a"),
            ),
        )
        .await;
    }

    let list = json!({"includeArtifacts": true});
    let omitted_key = agentplane::api::a2a::ARTIFACTS_OMITTED_KEY;
    let count = |body: &Value| {
        let tasks = body["result"]["tasks"].as_array().expect("tasks").clone();
        assert_eq!(tasks.len(), 3, "{body:#}");
        let with = tasks.iter().filter(|t| t["artifacts"].is_array()).count();
        let marked = tasks
            .iter()
            .filter(|t| t["metadata"][omitted_key] == json!(true))
            .count();
        (with, marked)
    };

    // One replay allowed: one task complete, two marked — never two silent
    // absences shaped like tasks without artifacts.
    let (_, first) = send(&router, rpc("ListTasks", &list, Some("peer-a"))).await;
    assert_eq!(count(&first), (1, 2), "{first:#}");

    // The replayed run is cached, so the same request converges: one more
    // replay, one fewer mark.
    let (_, second) = send(&router, rpc("ListTasks", &list, Some("peer-a"))).await;
    assert_eq!(count(&second), (2, 1), "{second:#}");

    // And the third finishes the job — cache hits are free, so a budget of one
    // still reaches a complete listing.
    let (_, third) = send(&router, rpc("ListTasks", &list, Some("peer-a"))).await;
    assert_eq!(count(&third), (3, 0), "{third:#}");
}

#[tokio::test]
async fn list_tasks_omits_tasks_the_caller_cannot_read() {
    let f = fixture();
    let router = f.router();
    let (_, first) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("first")}),
            Some("peer-a"),
        ),
    )
    .await;
    let hidden = first["result"]["task"]["id"].as_str().unwrap().to_owned();
    send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("second")}),
            Some("peer-a"),
        ),
    )
    .await;
    *f.policy.hidden_resource.lock().unwrap() = Some(hidden.clone());

    let (_, listed) = send(&router, rpc("ListTasks", &json!({}), Some("peer-a"))).await;
    let tasks = listed["result"]["tasks"].as_array().unwrap();
    assert_eq!(listed["result"]["totalSize"], 1);
    assert!(tasks.iter().all(|task| task["id"] != hidden));
}

#[tokio::test]
async fn task_id_continues_the_exact_input_required_task() {
    let f = continuation_fixture();
    let router = f.router();
    let (_, first) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": {
                "messageId": "m-initial",
                "role": "ROLE_USER",
                "parts": [{"text": "begin"}]
            }}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        first["result"]["task"]["status"]["state"],
        "TASK_STATE_INPUT_REQUIRED"
    );
    let task = first["result"]["task"]["id"]
        .as_str()
        .expect("task id")
        .to_owned();
    let context = first["result"]["task"]["contextId"]
        .as_str()
        .expect("context id")
        .to_owned();

    // `contextId` is intentionally omitted: A2A requires the server to infer
    // it from taskId. The response and reconstructed history carry it.
    let continuation = json!({
        "message": {
            "messageId": "m-followup",
            "taskId": task,
            "role": "ROLE_USER",
            "parts": [{"data": {"approved": true}, "mediaType": "application/json"}]
        },
        "configuration": {"historyLength": 10}
    });
    let (_, completed) = send(&router, rpc("SendMessage", &continuation, Some("peer-a"))).await;
    assert_eq!(
        completed["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{completed:#}"
    );
    assert_eq!(completed["result"]["task"]["contextId"], context);
    let history = completed["result"]["task"]["history"]
        .as_array()
        .expect("history");
    assert_eq!(
        history.len(),
        2,
        "both client turns must survive: {history:#?}"
    );
    assert_eq!(history[0]["messageId"], "m-initial");
    assert_eq!(history[1]["messageId"], "m-followup");
    assert_eq!(history[1]["taskId"], task);
    assert_eq!(history[1]["contextId"], context);
    assert!(
        f.policy
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|action| action == action::TASK_CONTINUE),
        "continuation never reached its task-specific policy gate"
    );

    // A transport retry with the same messageId is idempotent even though the
    // first delivery completed and sealed the task.
    let (_, duplicate) = send(&router, rpc("SendMessage", &continuation, Some("peer-a"))).await;
    assert_eq!(
        duplicate["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
}

/// A blocking call returns the answer as a task artifact.
#[tokio::test]
async fn a_blocking_call_returns_the_agents_answer() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;

    assert_eq!(
        body["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "the blocking response was not a completed task: {body:#}"
    );
    assert_eq!(
        body["result"]["task"]["artifacts"][0]["parts"][0]["data"],
        json!({"ok": true}),
        "the skill succeeded but its output was discarded: {body:#}"
    );
}

/// The trailing-slash spelling of the endpoint answers like the bare one.
///
/// Production registers `/a2a` and `/a2a/` as two axum routes, because a
/// reverse proxy that appends a slash is common and axum treats the two as
/// distinct paths. Until now only the network-gated TCK ever requested the
/// slash form, so a refactor that dropped the second `.route(...)` would pass
/// every CI test and break behind exactly the proxies the route exists for.
/// This does NOT test any proxy behaviour itself — only that both spellings
/// reach the same dispatcher.
#[tokio::test]
async fn the_trailing_slash_route_answers_like_the_bare_one() {
    let f = fixture();
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
        "params": {"message": text("go")},
    });
    let req = Request::builder()
        .uri("/a2a/")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-actor", "peer-a")
        .header("A2A-Version", "1.0")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, body) = send(&f.router(), req).await;
    assert_eq!(status, StatusCode::OK, "{body:#}");
    assert_eq!(
        body["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "the slash spelling did not reach the dispatcher: {body:#}"
    );
}

#[tokio::test]
async fn get_task_honors_history_length_and_reconstructs_artifacts() {
    let f = fixture();
    let router = f.router();
    let message = json!({
        "messageId": "history-message",
        "role": "ROLE_USER",
        "parts": [{
            "text": "remember this",
            "mediaType": "text/plain",
            "metadata": {"part": true}
        }],
        "metadata": {"request": true},
        "extensions": ["https://example.test/a2a/history/v1"],
        "referenceTaskIds": ["related-task"]
    });
    let (_, sent) = send(
        &router,
        rpc("SendMessage", &json!({"message": message}), Some("peer-a")),
    )
    .await;
    let id = sent["result"]["task"]["id"].as_str().unwrap();

    let (_, got) = send(
        &router,
        rpc(
            "GetTask",
            &json!({"id": id, "historyLength": 1}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(got["result"]["history"].as_array().unwrap().len(), 1);
    assert_eq!(
        got["result"]["history"][0]["messageId"],
        message["messageId"]
    );
    assert_eq!(got["result"]["history"][0]["parts"], message["parts"]);
    assert_eq!(got["result"]["history"][0]["taskId"], id);
    assert_eq!(
        got["result"]["history"][0]["contextId"],
        got["result"]["contextId"]
    );
    assert!(got["result"]["artifacts"].is_array());

    let (_, without_history) = send(
        &router,
        rpc(
            "GetTask",
            &json!({"id": id, "historyLength": 0}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(without_history["result"].get("history").is_none());

    let (_, blocking_history) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("another"),
                "configuration": {"historyLength": 1}
            }),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(blocking_history["result"]["task"]["history"].is_array());
}

#[tokio::test]
async fn send_configuration_refuses_impossible_output_modes_and_inline_push() {
    let f = fixture();
    for (configuration, expected) in [
        (
            json!({"acceptedOutputModes": ["image/png"]}),
            code::CONTENT_TYPE_NOT_SUPPORTED,
        ),
        (
            json!({"taskPushNotificationConfig": {"url": "https://client.example/hook"}}),
            code::PUSH_NOT_SUPPORTED,
        ),
    ] {
        let (_, body) = send(
            &f.router(),
            rpc(
                "SendMessage",
                &json!({"message": text("go"), "configuration": configuration}),
                Some("peer-a"),
            ),
        )
        .await;
        assert_eq!(err_code(&body), i64::from(expected), "{body:#}");
    }
}

// ── Refusals say which kind they are ────────────────────────────────────────

/// Unwired push and genuinely unknown methods use distinct protocol errors.
#[tokio::test]
async fn unwired_push_and_unknown_methods_are_told_apart() {
    let f = fixture();
    let router = f.router();

    for method in [
        "CreateTaskPushNotificationConfig",
        "GetTaskPushNotificationConfig",
        "ListTaskPushNotificationConfigs",
        "DeleteTaskPushNotificationConfig",
    ] {
        let (_, body) = send(&router, rpc(method, &json!({}), Some("peer-a"))).await;
        assert_eq!(
            err_code(&body),
            i64::from(code::PUSH_NOT_SUPPORTED),
            "{method} must be refused with the push-specific code: {body:#}"
        );
        // The raw numeral, so the pin does not share the constant it checks:
        // -32003 is PushNotificationNotSupportedError in the A2A 1.0
        // error-code table, and that number is what a spec-written client
        // matches on.
        assert_eq!(err_code(&body), -32003, "{method}: {body:#}");
    }

    // And a genuinely unknown method still says so, or the two are
    // indistinguishable.
    let (_, body) = send(&router, rpc("SendMesage", &json!({}), Some("peer-a"))).await;
    assert_eq!(
        err_code(&body),
        i64::from(code::METHOD_NOT_FOUND),
        "a misspelled method must be method-not-found, or a caller cannot tell \
         a typo from a missing feature: {body:#}"
    );
}

/// The 0.3 method names are not answered.
///
/// 1.0 renamed every method. A server that also answers `message/send` accepts
/// clients that have silently lost half the protocol — and they would never
/// find out, because the call works.
#[tokio::test]
async fn the_old_zero_three_method_names_are_not_served() {
    let f = fixture();
    let router = f.router();
    for old in ["message/send", "tasks/get", "tasks/cancel"] {
        let (_, body) = send(
            &router,
            rpc(old, &json!({"message": text("go")}), Some("peer-a")),
        )
        .await;
        assert_eq!(
            err_code(&body),
            i64::from(code::METHOD_NOT_FOUND),
            "the 0.3 name {old} was served: {body:#}"
        );
    }
}

/// A finished run cannot be cancelled, and says so with the spec's code.
#[tokio::test]
async fn cancelling_a_finished_task_is_not_cancelable() {
    let f = fixture();
    let router = f.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let id = sent["result"]["task"]["id"].as_str().unwrap().to_owned();

    let (_, body) = send(
        &router,
        rpc("CancelTask", &json!({"id": id}), Some("peer-a")),
    )
    .await;
    assert_eq!(
        err_code(&body),
        i64::from(code::TASK_NOT_CANCELABLE),
        "cancelling a completed run reported something other than \
         not-cancelable: {body:#}"
    );
    // The raw numeral, beside the named constant. Every other assertion in
    // this file compares against the same `code` module the server emits from,
    // so a typo in the constant would agree with itself on both sides of the
    // comparison. -32002 is TaskNotCancelableError in the A2A 1.0 error-code
    // table, and a client written against the spec matches on the number.
    assert_eq!(err_code(&body), -32002, "{body:#}");
}

/// One counterparty, one provenance spelling: `peer:{actor}`, on every door.
///
/// Three spellings used to exist for the same peer — bare `{actor}` on
/// operator-API events, `a2a:peer:{actor}` on A2A task continuations,
/// `peer:{actor}` on A2A message inputs. Nothing downstream distinguishes
/// transports: an event's `source` becomes the delivered value's provenance
/// exactly as a message input's `SourceId` does, so a protected sink field
/// naming the counterparty it accepts would match or miss depending on which
/// door the value came through. This pins the unified spelling on both A2A
/// doors; the operator API routes through the same helper.
#[tokio::test]
async fn a_peers_provenance_is_spelled_the_same_on_every_door() {
    let f = continuation_fixture();
    let router = f.router();
    let (_, first) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("begin")}),
            Some("peer-a"),
        ),
    )
    .await;
    let task = first["result"]["task"]["id"].as_str().unwrap().to_owned();

    // Continue the task, so the peer's message travels the *event* door.
    let continuation = json!({"message": {
        "messageId": "m-followup",
        "taskId": task,
        "role": "ROLE_USER",
        "parts": [{"data": {"approved": true}, "mediaType": "application/json"}]
    }});
    let (_, completed) = send(&router, rpc("SendMessage", &continuation, Some("peer-a"))).await;
    assert_eq!(
        completed["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
        "{completed:#}"
    );

    let run = RunId::parse(&task).unwrap();
    let records = f.store.read(run, 1).await.expect("journal");
    let event_source = records
        .iter()
        .find_map(|record| match record.kind() {
            agentplane::journal::RecordKind::EffectDone {
                source: Some(source),
                ..
            } => Some(source.clone()),
            _ => None,
        })
        .expect("the awaited event recorded its sender");
    assert_eq!(
        event_source, "peer:peer-a",
        "the event door spells the peer's provenance differently from the \
         message door, so a sink field naming the counterparty matches on one \
         transport and misses on the other"
    );
}

/// The cancel response is a `Task`, and it carries the task's `contextId`.
///
/// Every other path resolves the context from the run's records; this one
/// hard-coded it absent, so the one response a canceling caller holds was the
/// one task object it could not correlate or continue — A2A 1.0 puts
/// `contextId` on every task, not on every task except this reply.
#[tokio::test]
async fn cancelling_a_task_answers_with_its_context_id() {
    let f = continuation_fixture();
    let router = f.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("begin")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        sent["result"]["task"]["status"]["state"], "TASK_STATE_INPUT_REQUIRED",
        "{sent:#}"
    );
    let id = sent["result"]["task"]["id"].as_str().unwrap().to_owned();
    let context = sent["result"]["task"]["contextId"]
        .as_str()
        .expect("every task carries a contextId")
        .to_owned();

    let (_, body) = send(
        &router,
        rpc("CancelTask", &json!({"id": id}), Some("peer-a")),
    )
    .await;
    assert_eq!(
        body["result"]["contextId"].as_str(),
        Some(context.as_str()),
        "the cancel response dropped the contextId every other path resolves: {body:#}"
    );
    assert_eq!(body["result"]["id"], json!(id));
}

/// An unknown task id is not found — and so is an unparseable one.
///
/// Deliberately the same answer: whether a string is a well-formed run id this
/// plane could have issued is not something a caller should learn from the shape
/// of the refusal.
#[tokio::test]
async fn an_unknown_task_is_not_found() {
    let f = fixture();
    let router = f.router();
    for id in ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "not-an-id-at-all"] {
        let (_, body) = send(&router, rpc("GetTask", &json!({"id": id}), Some("peer-a"))).await;
        assert_eq!(
            err_code(&body),
            i64::from(code::TASK_NOT_FOUND),
            "id {id} produced something other than not-found: {body:#}"
        );
    }
}

/// A JSON-RPC refusal is HTTP 200 with an error body.
///
/// JSON-RPC carries its own error channel. A transport status for an
/// application-level decline is how a client ends up retrying a permanent
/// refusal: many treat 5xx as retryable without parsing the body at all.
#[tokio::test]
async fn refusals_are_json_rpc_errors_not_http_failures() {
    let f = fixture();
    let (status, body) = send(&f.router(), rpc("NoSuchMethod", &json!({}), Some("peer-a"))).await;
    assert_eq!(status, StatusCode::OK, "{body:#}");
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1, "the response must echo the request id");
    assert_eq!(err_code(&body), i64::from(code::METHOD_NOT_FOUND));
}

// ── Tenancy ─────────────────────────────────────────────────────────────────

/// A request routed to another tenant is refused, not served from ours.
///
/// A2A's own multi-tenancy mechanism: the client echoes the `tenant` from the
/// interface it selected on the card. A value that is not ours is a request
/// meant for a different agent, plausibly another plane behind the same
/// address — and answering it serves one tenant's caller from another tenant's
/// runs.
#[tokio::test]
async fn a_request_for_another_tenant_is_refused() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"tenant": "globex", "message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        err_code(&body),
        i64::from(code::INVALID_PARAMS),
        "a request naming another tenant was served: {body:#}"
    );
    assert_eq!(f.seen.lock().unwrap().len(), 0, "the skill ran anyway");
}

/// A plane serving a named tenant advertises it, and requires it back.
///
/// The card is what tells a client to send one at all: A2A says to echo the
/// interface's `tenant` and to omit it when the interface omits it. So a plane
/// on `default` must not advertise one — every caller would send a routing
/// identifier that routes nowhere — and a plane on `acme` must.
#[tokio::test]
async fn a_named_tenant_is_advertised_and_required() {
    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let store = Arc::new(
        RedbStore::open_in_memory()
            .unwrap()
            .for_tenant(TenantId::new("acme").expect("valid")),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(store as Arc<dyn CaseStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .tenant(TenantId::new("acme").expect("valid"))
        .skill(Echoes {
            capability: "settlement.check",
            seen,
        })
        .build();
    let router = A2aServer::new(
        rt,
        Arc::new(HeaderAuth),
        &card_security(),
        &manifest,
        "https://plane.internal/a2a",
    )
    .expect("wired")
    .router();

    let card = Request::builder()
        .uri("/.well-known/agent-card.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let (_, body) = send(&router, card).await;
    assert_eq!(
        body["supportedInterfaces"][0]["tenant"], "acme",
        "a plane serving a named tenant must advertise it, or no client will \
         ever send one: {body:#}"
    );

    // A client following the card is served.
    let (_, ok) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"tenant": "acme", "message": text("go")}),
            Some("acme:peer-a"),
        ),
    )
    .await;
    assert!(ok.get("result").is_some(), "{ok:#}");

    // One that omits it is not — it selected an interface it did not read.
    let (_, missing) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("acme:peer-a"),
        ),
    )
    .await;
    assert_eq!(err_code(&missing), i64::from(code::INVALID_PARAMS));
}

/// A peer authenticated into one tenant cannot name another in the request.
///
/// `check_tenant` compares the request's routing identifier against the card;
/// this compares it against the **credential**. Without the second check a peer
/// holding a valid credential for any tenant could be served from another's
/// runs by putting its name in a field — and a peer holding exactly that is who
/// would try. The two halves are separate because they can disagree, and the
/// disagreement is the attack.
#[tokio::test]
async fn a_peer_cannot_name_a_tenant_its_credential_does_not_hold() {
    let f = fixture(); // serves the default tenant
    let (_, body) = send(
        &f.router(),
        // Authenticated into `globex`, asking to be served as the default.
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("globex:eve"),
        ),
    )
    .await;

    assert_eq!(
        err_code(&body),
        i64::from(code::INVALID_PARAMS),
        "a peer authenticated into another tenant was served from this one: \
         {body:#}"
    );
    assert_eq!(
        f.seen.lock().unwrap().len(),
        0,
        "the skill ran for a peer belonging to a different tenant"
    );
}

// ── Setup refusals ──────────────────────────────────────────────────────────

/// A plane with no policy engine cannot be served to other agents.
///
/// The operator API refuses this for its own routes. This surface is reachable
/// by *other agents*, so it is the last place that should be the one exception.
#[tokio::test]
async fn a_plane_without_a_policy_engine_is_not_served() {
    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>).build();

    let built = A2aServer::new(
        rt,
        Arc::new(HeaderAuth),
        &card_security(),
        &manifest,
        "https://plane.internal/a2a",
    );
    assert!(
        matches!(built, Err(ServerSetupError::NoPolicy)),
        "an ungoverned plane was published to other agents"
    );
}

/// A declined request is the agent saying no, not the agent breaking.
///
/// Reported as `-32603 Internal error` this reads to a caller as "the far side
/// is faulty, retry later" — and it retries a decision that will never change.
/// A2A's response is a oneof precisely so an agent can answer with a message
/// instead of a task.
///
/// And the refusal says **nothing about why**. The runtime's own denial names
/// the action and resource the gate keyed on — this crate's internal
/// authorization vocabulary — and a peer that can send messages and read
/// refusals could map that vocabulary by probing it. What the peer can act on is
/// that it was declined; the operator gets the rest from the journal.
#[tokio::test]
async fn a_policy_denial_is_a_decline_not_a_server_fault() {
    let f = fixture_from(
        ONE_SKILL,
        Arc::new(Recording {
            seen: Mutex::new(Vec::new()),
            deny: false,
            deny_runs: true,
            hidden_resource: Mutex::new(None),
        }),
    );
    let (status, body) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("settle INV-9")}),
            Some("peer-a"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:#}");
    assert!(
        body.get("error").is_none(),
        "a declined request was reported as an error rather than an answer, so \
         the caller cannot tell a refusal from an outage: {body:#}"
    );
    let message = &body["result"]["message"];
    assert_eq!(
        message["role"], "ROLE_AGENT",
        "the decline must come back as a message from the agent: {body:#}"
    );
    assert!(
        body["result"].get("task").is_none(),
        "nothing was admitted, so there is no task to poll — advertising one \
         gives the caller an id that will never resolve: {body:#}"
    );

    let said = serde_json::to_string(&body).unwrap();
    assert!(
        !said.contains("may not"),
        "the refusal passed the runtime's own denial through to the peer, \
         which names the action and resource the gate keyed on — enough to map \
         this plane's authorization vocabulary by probing it: {body:#}"
    );
}

/// A full quota answers with the server-defined back-pressure code, and the
/// quota arithmetic stays inside.
///
/// Two enforcements meet here. First the code: this used to be `-32004
/// UnsupportedOperationError`, a permanent missing-capability code that
/// teaches a compliant caller to abandon rather than back off; the raw
/// numeral `-32029` is asserted so reverting the mapping fails loudly.
/// Second the message: `QuotaError`'s own rendering names the running count
/// and the ceiling, numbers an unauthenticated prober has no business
/// learning, so the wire message must carry no digits at all. What this test
/// does NOT cover is the peer-side classification of the new code — that
/// lives with the A2A client driver.
#[tokio::test]
async fn a_full_quota_is_back_pressure_with_no_arithmetic_in_the_answer() {
    use agentplane::quota::{QuotaStore, TenantQuota};

    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let policy = Arc::new(Recording::default());
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let scoped = Arc::new(store.as_ref().clone().for_tenant(TenantId::default()));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .policy(policy.clone() as Arc<dyn PolicyEngine>)
        // A ceiling of zero: every admission is refused as back-pressure.
        .quota(
            scoped as Arc<dyn QuotaStore>,
            TenantQuota {
                max_concurrent_runs: Some(0),
                ..TenantQuota::default()
            },
        )
        .skill(Echoes {
            capability: "settlement.check",
            seen: seen.clone(),
        })
        .build();
    let f = Fixture {
        rt,
        store,
        policy,
        seen,
        manifest,
    };

    let (status, body) = send(
        &f.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:#}");
    // The raw numeral, not `code::QUOTA_EXHAUSTED`: the pin must not share
    // the constant it exists to check.
    assert_eq!(
        err_code(&body),
        -32029,
        "a full quota must be the server-defined back-pressure code, not a \
         spec-defined permanent one: {body:#}"
    );
    let message = body["error"]["message"].as_str().expect("an error message");
    assert!(
        !message.contains(|c: char| c.is_ascii_digit()),
        "the quota's counters leaked to an external caller: {message}"
    );

    // The positive half: the identical request against the identical fixture
    // shape minus the quota completes, so the refusal above is the ceiling
    // and not a broken fixture.
    let unlimited = fixture();
    let (_, ok) = send(
        &unlimited.router(),
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        ok["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
}

/// This crate's own A2A client, calling this crate's own A2A server.
///
/// Every other test here drives the server with hand-built JSON, which proves
/// the server matches *my reading* of the spec. This one proves the two halves
/// agree with each other over a real socket — method name, version header,
/// response envelope, all of it. The halves were written months apart against
/// the same document, which is exactly the situation where two readings drift
/// and both look right in isolation.
#[cfg(feature = "a2a")]
#[tokio::test]
async fn this_planes_client_can_call_this_planes_server() {
    use agentplane::core::{Delegation, Principal, Scope};
    use agentplane::peers::a2a::{A2aClient, Endpoint};
    use agentplane::peers::{PeerClient, PeerCredential, PeerId, PeerTask};

    let f = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = f.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let peer = PeerId::new("self");
    let chain = Delegation::root(Principal::new("user:operator", Scope::root()));
    let client = A2aClient::new(Endpoint::new(format!("http://{addr}/a2a")))
        .unwrap()
        .allow_loopback();
    let credential = PeerCredential::for_audience(peer.clone(), "acme-peer");

    let answer = client
        .send(
            &peer,
            "settlement.check",
            &json!({"amount": 10}),
            &chain,
            Some(&credential),
            None,
        )
        .await
        .expect("this plane's client could not complete a call to its own server");

    // The client parsed the server's `SendMessageResponse` oneof, which means
    // both halves agree on the envelope as well as the method.
    assert!(
        answer.is_object(),
        "the client got something it could not read back: {answer:#}"
    );
    let task = PeerTask::from_response(peer.clone(), &answer)
        .expect("valid response")
        .expect("the server returned a task");
    let polled = client
        .get_task(&peer, &task.id, Some(&credential))
        .await
        .expect("GetTask through the same client");
    assert_eq!(polled["id"], task.id);
    assert_eq!(polled["status"]["state"], "TASK_STATE_COMPLETED");

    // And the server really ran the skill, with the peer's identity as
    // provenance — the round trip carried the credential end to end.
    let seen = f.seen.lock().unwrap();
    let (untrusted, sources, _) = seen.first().expect("the skill did not run");
    assert!(*untrusted);
    assert!(
        sources.iter().any(|s| s.contains("acme-peer")),
        "the bearer identity did not become the message's provenance: {sources:?}"
    );
}

/// `returnImmediately` returns as soon as the task exists, and the task is real.
///
/// The spec is explicit that this MUST return after *creating* the task rather
/// than after finishing it, leaving the caller to poll. Ignoring the field would
/// hold the connection open for the whole run while looking like compliance —
/// the response is identical, just late.
///
/// The half that matters most: admission still happens before the call returns,
/// so the id handed back is one `GetTask` can already answer for. A server that
/// spawned first and admitted later would hand out ids for runs the policy gate
/// went on to refuse, turning a decline into a task that never appears.
#[tokio::test]
async fn a_non_blocking_send_returns_a_task_that_already_exists() {
    let f = fixture();
    let router = f.router();
    let (_, body) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {"returnImmediately": true}
            }),
            Some("peer-a"),
        ),
    )
    .await;

    let task = &body["result"]["task"];
    let id = task["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no task id: {body:#}"));
    assert_eq!(
        task["status"]["state"], "TASK_STATE_WORKING",
        "a non-blocking send must report an in-progress state; a terminal one \
         means it waited after all: {task:#}"
    );

    // The id is immediately answerable — the run was admitted, not merely
    // promised.
    let (_, got) = send(&router, rpc("GetTask", &json!({"id": id}), Some("peer-a"))).await;
    assert!(
        got.get("error").is_none(),
        "the task id returned by a non-blocking send cannot be read back, so \
         the caller was handed a handle to nothing: {got:#}"
    );
    assert_eq!(got["result"]["id"], id);
}

/// Blocking is the default, and unset means blocking.
///
/// The spec's default, and the more dangerous one to get wrong: a caller that
/// says nothing expects a finished task, and returning `WORKING` would have it
/// poll for a result it already had — or worse, treat an unfinished run as done.
#[tokio::test]
async fn an_unconfigured_send_blocks() {
    let f = fixture();
    for configuration in [json!(null), json!({}), json!({"returnImmediately": false})] {
        let (_, body) = send(
            &f.router(),
            rpc(
                "SendMessage",
                &json!({"message": text("go"), "configuration": configuration}),
                Some("peer-a"),
            ),
        )
        .await;
        assert_eq!(
            body["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED",
            "configuration {configuration} did not block, so a caller \
             expecting a finished task got an unfinished one: {body:#}"
        );
    }
}

// ── Streaming ───────────────────────────────────────────────────────────────

/// Read an SSE body into its `data:` payloads.
///
/// Parsed from the raw bytes rather than trusted: the framing *is* the contract
/// here, and a test that deserialises straight into a struct would pass with a
/// body no `EventSource` on earth can read.
async fn sse_frames(router: &axum::Router, req: Request<Body>) -> (StatusCode, String, Vec<Value>) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    // Bounded, because the failure this guards against is a stream that never
    // closes — and an unbounded read turns that into a hung test rather than a
    // failed one. A hang stalls CI and the mutation sweep and tells nobody what
    // broke; this says exactly what broke.
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(res.into_body(), 1024 * 1024),
    )
    .await
    .expect(
        "the stream never closed. A2A requires closing when the task reaches a \
         terminal state; a client left holding this connection waits forever for \
         a run that already finished",
    )
    .unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let frames = text
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect();
    (status, content_type, frames)
}

/// The first `data:` frame of a stream, without waiting for it to close.
///
/// The sibling above drains to EOF, which is right for a run that terminates
/// and wrong for the only tasks a subscription accepts: a subscription to a
/// **terminal** task is refused before it reaches the stream, and one to a live
/// task stays open by design. So the surface that opens every subscription is
/// unreadable by a helper that requires an ending, and this reads the opening
/// snapshot and hangs up.
async fn sse_opening_frame(router: &axum::Router, req: Request<Body>) -> Option<Value> {
    use futures_util::StreamExt as _;
    let res = router.clone().oneshot(req).await.unwrap();
    let mut body = res.into_body().into_data_stream();
    let mut buffered = String::new();
    // Bounded for the reason the drain is: a stream that never produces its
    // first frame must fail this test rather than hang CI.
    let deadline = std::time::Duration::from_secs(10);
    tokio::time::timeout(deadline, async {
        while let Some(chunk) = body.next().await {
            buffered.push_str(&String::from_utf8_lossy(&chunk.ok()?));
            if let Some(frame) = buffered
                .lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .find_map(|d| serde_json::from_str::<Value>(d).ok())
            {
                return Some(frame);
            }
        }
        None
    })
    .await
    .expect("a subscription produced no opening frame within the deadline")
}

/// `SendStreamingMessage` answers with an SSE stream that opens with the task.
///
/// The spec requires the stream to begin with the `Task` and to close when it
/// reaches a terminal state, so a subscriber can learn the current state without
/// having been present for the events that produced it.
#[tokio::test]
async fn a_streaming_send_opens_with_the_task_and_closes_when_it_finishes() {
    let f = fixture();
    let (status, content_type, frames) = sse_frames(
        &f.router(),
        rpc(
            "SendStreamingMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/event-stream"),
        "a streaming response must be an event stream; a client picks its parser \
         from this header: {content_type}"
    );
    assert!(
        !frames.is_empty(),
        "the stream carried no `data:` frames at all"
    );

    // Every frame is a JSON-RPC envelope echoing the request id, and carries a
    // StreamResponse — a oneof, so exactly one member.
    for frame in &frames {
        assert_eq!(frame["jsonrpc"], "2.0", "not a JSON-RPC frame: {frame:#}");
        assert_eq!(frame["id"], 1, "a frame did not echo the request id");
        let result = &frame["result"];
        let members = ["task", "message", "statusUpdate", "artifactUpdate"]
            .iter()
            .filter(|m| result.get(*m).is_some())
            .count();
        assert_eq!(
            members, 1,
            "a StreamResponse is a oneof and this frame has {members} members: {frame:#}"
        );
    }

    assert!(
        frames[0]["result"]["task"].is_object(),
        "the stream must open with the Task: {:#}",
        frames[0]
    );

    let last = frames.last().expect("frames");
    let state = last["result"]["statusUpdate"]["status"]["state"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(
        state, "TASK_STATE_COMPLETED",
        "the stream must close on a terminal state, and its last word is what a \
         client records as the outcome: {last:#}"
    );
}

/// A status update carries the ids a client needs to correlate it.
///
/// `taskId` and `contextId` are both required by the schema. A run with no case
/// has no case id, and this carries the run's own — a standalone run genuinely
/// is its whole context, so it is a true statement about grouping rather than a
/// placeholder every client has to special-case.
#[tokio::test]
async fn a_status_update_carries_its_task_and_context() {
    let f = fixture();
    let (_, _, frames) = sse_frames(
        &f.router(),
        rpc(
            "SendStreamingMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;

    let task_id = frames[0]["result"]["task"]["id"].as_str().expect("id");
    let update = frames
        .iter()
        .find(|f| f["result"].get("statusUpdate").is_some())
        .expect("no status update was emitted, so the stream reports no progress");

    assert_eq!(update["result"]["statusUpdate"]["taskId"], task_id);
    assert!(
        update["result"]["statusUpdate"]["contextId"]
            .as_str()
            .is_some_and(|c| !c.is_empty()),
        "contextId is required and must not be empty: {update:#}"
    );
    assert!(
        frames
            .iter()
            .any(|frame| frame["result"].get("artifactUpdate").is_some()),
        "the streaming task completed without delivering its output artifact: {frames:#?}"
    );
}

/// A2A 1.0 permits subscription only while a task can still update.
#[tokio::test]
async fn subscribing_to_a_finished_task_is_unsupported() {
    let f = fixture();
    let router = f.router();

    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let id = sent["result"]["task"]["id"].as_str().unwrap().to_owned();

    let (_, body) = send(
        &router,
        rpc("SubscribeToTask", &json!({"id": id}), Some("peer-a")),
    )
    .await;
    assert_eq!(
        err_code(&body),
        i64::from(code::UNSUPPORTED_OPERATION),
        "a terminal task incorrectly opened a subscription: {body:#}"
    );
}

/// Subscribing to a task that does not exist is not found, not an empty stream.
#[tokio::test]
async fn subscribing_to_an_unknown_task_is_refused() {
    let f = fixture();
    let (_, body) = send(
        &f.router(),
        rpc(
            "SubscribeToTask",
            &json!({"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        err_code(&body),
        i64::from(code::TASK_NOT_FOUND),
        "an unknown task opened a stream that would never produce anything: {body:#}"
    );
}

/// Streaming authenticates and authorizes exactly as the rest does.
#[tokio::test]
async fn streaming_is_gated_too() {
    let f = fixture_from(
        ONE_SKILL,
        Arc::new(Recording {
            seen: Mutex::new(Vec::new()),
            deny: true,
            deny_runs: false,
            hidden_resource: Mutex::new(None),
        }),
    );
    let (_, body) = send(
        &f.router(),
        rpc(
            "SendStreamingMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(
        body.get("error").is_some(),
        "a refused caller opened a stream: {body:#}"
    );
    assert_eq!(
        f.seen.lock().unwrap().len(),
        0,
        "the skill ran for a caller the policy refused"
    );
}

/// The served card carries a signature a peer can verify.
///
/// Signed at publish rather than at derivation, because the signature must cover
/// the card as *served* — interface URL and tenant included. A signature taken
/// before those were set would cover a document nobody serves.
#[cfg(feature = "signing")]
#[tokio::test]
async fn a_published_card_can_be_signed_and_verified() {
    use agentplane::peers::{AgentCard, CardSigner, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let signer = Ed25519Signer::new("did:example:plane", &[3u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:plane", &signer.verifying_key())
        .expect("a valid key");

    let f = fixture();
    let router = A2aServer::new(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &f.manifest,
        "https://plane.internal/a2a",
    )
    .expect("wired")
    .signing_cards_with(&signer as &dyn CardSigner)
    .expect("sign")
    .router();

    let req = Request::builder()
        .uri("/.well-known/agent-card.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("signatures").is_some(),
        "the served card carries no signature: {body:#}"
    );

    // Round-tripped through the wire, which is the only form a peer ever sees.
    let card: AgentCard = serde_json::from_value(body.clone()).expect("parse the served card");
    assert_eq!(
        card.verify(&verifier as &dyn CardVerifier)
            .expect("the served card did not verify")
            .as_str(),
        "did:example:plane"
    );

    // And the signature is about *this* deployment: change the URL a caller
    // would connect to and it stops verifying.
    let mut moved = card;
    moved.supported_interfaces[0].url = "https://attacker.example/a2a".to_owned();
    assert!(
        moved.verify(&verifier as &dyn CardVerifier).is_err(),
        "a card whose interface URL was rewritten still verified — a peer would \
         connect to an address the publisher never named"
    );
}

// ── Discovery ───────────────────────────────────────────────────────────────

/// A client discovers this plane's card, verifies it, and calls the interface
/// it names — including the tenant.
///
/// The whole client half in one path, against a real socket. Each step is
/// worthless alone: discovery that skips verification trusts whoever answered,
/// verification that ignores the selected interface calls an address the
/// signature never covered, and selection that drops the tenant can only ever
/// reach an agent serving the default one.
#[cfg(all(feature = "signing", feature = "a2a"))]
#[tokio::test]
async fn a_client_discovers_verifies_and_calls_a_tenant_scoped_agent() {
    use agentplane::core::{Delegation, Principal, Scope, TenantId};
    use agentplane::peers::a2a::A2aClient;
    use agentplane::peers::{
        CardClient, CardSigner, CardVerifier, PeerClient, PeerCredential, PeerId,
    };
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let signer = Ed25519Signer::new("did:example:acme", &[5u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:acme", &signer.verifying_key())
        .expect("a valid key");

    // A plane serving a *named* tenant, so the card advertises one and the
    // client has to echo it back.
    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let tenant = TenantId::new("acme").expect("valid");
    let store = Arc::new(
        RedbStore::open_in_memory()
            .unwrap()
            .for_tenant(tenant.clone()),
    );
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(store as Arc<dyn CaseStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .tenant(tenant)
        .skill(Echoes {
            capability: "settlement.check",
            seen: seen.clone(),
        })
        .build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = A2aServer::new(
        rt,
        Arc::new(HeaderAuth),
        &card_security(),
        &manifest,
        format!("http://{addr}/a2a"),
    )
    .expect("wired")
    .signing_cards_with(&signer as &dyn CardSigner)
    .expect("sign")
    .router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Discovery, with verification made mandatory.
    let cards = CardClient::new()
        .allow_loopback()
        .verifying_with(Arc::new(verifier) as Arc<dyn CardVerifier>);
    let card = cards
        .discover(&format!("http://{addr}"))
        .await
        .expect("the plane's own signed card did not survive discovery");
    assert_eq!(card.name, "settlement-checker");

    // Interface selection carries the tenant the card advertises.
    let endpoint = card
        .endpoint()
        .expect("the card offers no usable interface");
    assert_eq!(
        endpoint.tenant.as_deref(),
        Some("acme"),
        "the endpoint dropped the tenant the card advertises, so every request \
         would be refused as meant for a different agent"
    );

    // And a call through it is served — which it would not be without the
    // tenant, because the server checks the request against its own card.
    let peer = PeerId::new("acme-plane");
    let chain = Delegation::root(Principal::new("user:operator", Scope::root()));
    let client = A2aClient::new(endpoint).unwrap().allow_loopback();
    let credential = PeerCredential::for_audience(peer.clone(), "acme:caller");
    client
        .send(
            &peer,
            "settlement.check",
            &json!({"amount": 10}),
            &chain,
            Some(&credential),
            None,
        )
        .await
        .expect("a discovered, verified, tenant-scoped call was refused");

    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "the call did not reach the skill"
    );
}

/// A card whose signature does not verify is refused at discovery.
#[cfg(all(feature = "signing", feature = "a2a"))]
#[tokio::test]
async fn discovery_refuses_a_card_signed_by_a_stranger() {
    use agentplane::peers::{CardClient, CardSigner, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let stranger = Ed25519Signer::new("did:example:stranger", &[8u8; 32]);
    let expected = Ed25519Signer::new("did:example:acme", &[5u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:acme", &expected.verifying_key())
        .expect("a valid key");

    let f = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = A2aServer::new(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &f.manifest,
        format!("http://{addr}/a2a"),
    )
    .expect("wired")
    .signing_cards_with(&stranger as &dyn CardSigner)
    .expect("sign")
    .router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let cards = CardClient::new()
        .allow_loopback()
        .verifying_with(Arc::new(verifier) as Arc<dyn CardVerifier>);
    assert!(
        cards.discover(&format!("http://{addr}")).await.is_err(),
        "a card signed by an unknown key was accepted, so verification checks \
         nothing"
    );
}

/// With verification configured, an **unsigned** card is refused.
///
/// The downgrade an attacker performs is removing the signature, not forging
/// one. A verifier that checks "if a signature is present" is one that can be
/// switched off by whoever serves the document.
#[cfg(all(feature = "signing", feature = "a2a"))]
#[tokio::test]
async fn discovery_refuses_an_unsigned_card_when_verification_is_required() {
    use agentplane::peers::{CardClient, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let key = Ed25519Signer::new("did:example:acme", &[5u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:acme", &key.verifying_key())
        .expect("a valid key");

    let f = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Served unsigned.
    let router = f.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let cards = CardClient::new()
        .allow_loopback()
        .verifying_with(Arc::new(verifier) as Arc<dyn CardVerifier>);
    assert!(
        cards.discover(&format!("http://{addr}")).await.is_err(),
        "an unsigned card was accepted while verification was required — the \
         downgrade is removing the signature, not forging one"
    );

    // Without a verifier the same card is fine, so this refuses the *unsigned*
    // case rather than refusing everything.
    assert!(
        CardClient::new()
            .allow_loopback()
            .discover(&format!("http://{addr}"))
            .await
            .is_ok()
    );
}

/// A skill that returns whatever the peer sent — the ordinary shape of an
/// agent that summarises, transforms, or quotes its input.
#[derive(Debug)]
struct EchoesInput;

#[async_trait::async_trait]
impl Skill for EchoesInput {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("settlement.check").provides("settlement.check")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Untrusted in, untrusted out — the label travels, as it must.
        Ok(Outcome::done(input.map(|v| v["data"][0].clone())))
    }
}

/// A peer cannot shape the envelope its own reply arrives in.
///
/// `A2aReply` is a projection instruction the runtime obeys: it decides
/// whether the answer is a task artifact or a direct `Message`, and what parts
/// it carries — including a file part naming a URL. Skill output routinely
/// *contains* untrusted data (a summariser quotes its input; a declarative
/// agent's answer is a model's words), so reading the instruction out of the
/// value without asking where the value came from would let whoever wrote the
/// value choose the envelope. Model output is a proposal, never authority —
/// and so is a peer's message.
#[tokio::test]
async fn a_peer_cannot_smuggle_a_reply_envelope_through_untrusted_output() {
    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(EchoesInput)
        .build();
    let router = A2aServer::new(
        rt,
        Arc::new(HeaderAuth),
        &card_security(),
        &manifest,
        "https://plane.internal/a2a",
    )
    .expect("wired")
    .router();

    // The peer sends the marker as ordinary data. The skill echoes it, so it
    // lands in the run's output exactly as a summariser would place a quote.
    let smuggled = json!({
        "$a2a_reply": {
            "message": [{
                "url": "https://attacker.example/invoice.pdf",
                "filename": "invoice.pdf",
                "mediaType": "application/pdf",
            }],
        }
    });
    let (status, body) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": {
                    "messageId": "m-smuggle",
                    "role": "ROLE_USER",
                    "parts": [{ "data": smuggled }],
                }
            }),
            Some("peer"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let result = &body["result"];
    assert!(
        result.get("message").is_none(),
        "a peer chose the reply envelope: its own data became a direct Message \
         carrying a file URL it named — {result}"
    );
    // The peer's data still reaches the caller — as the artifact *content* it
    // is. What it must not become is a **part shape** the peer chose: a file
    // part naming a URL, which reads as the agent vouching for it.
    let parts = result["task"]["artifacts"][0]["parts"]
        .as_array()
        .unwrap_or_else(|| panic!("an artifact with parts: {result}"));
    assert_eq!(parts.len(), 1, "the peer chose how many parts to send");
    assert!(
        parts[0].get("url").is_none() && parts[0].get("filename").is_none(),
        "a peer's data became a file part in the agent's own reply: {parts:?}"
    );
    assert!(
        parts[0].get("data").is_some(),
        "the answer should be projected as ordinary data: {parts:?}"
    );
}

/// A skill that declares its own reply: two artifacts, from **trusted** output.
///
/// `Outcome::done` over a trusted label is what makes the projection
/// instruction authority rather than a proposal — the same distinction the
/// smuggling test above holds from the other side.
#[derive(Debug)]
struct DeclaresTwoArtifacts;

#[async_trait::async_trait]
impl Skill for DeclaresTwoArtifacts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("declares").provides("settlement.check")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let reply = agentplane::api::a2a::A2aReply::artifacts(vec![
            vec![agentplane::api::a2a::Part::text("the finding")],
            vec![agentplane::api::a2a::Part::data(json!({ "ref": "SET-42" }))],
        ]);
        Ok(Outcome::done(Tainted::trusted(reply.into_value())))
    }
}

/// **The positive half of `A2aReply`, which did not exist.** A skill that
/// declares its answer's shape gets that shape on the wire, and several
/// artifacts stay several.
///
/// Every other `A2aReply` test asserts a *refusal* — that a peer cannot choose
/// the envelope its own reply arrives in. That is the important half and it is
/// not the only half: with only refusals on the record, making `of_output`
/// return `None` unconditionally leaves the whole declared-reply feature
/// silently absent while the suite stays green, because "the reply was not
/// applied" is exactly what the refusal tests assert. Checked by mutation
/// rather than believed: `A2aReplyNeverApplies` in `tools/mutants.py` breaks it
/// on purpose, and before this test nothing failed.
///
/// The **plural** constructor is the one exercised, deliberately. The singular
/// `artifact` is the path the TCK example takes, so it has interoperability
/// evidence; `artifacts` had no caller anywhere in the repository, and the
/// thing a second artifact can get wrong — sharing the first one's
/// `artifactId`, which makes two results read as one revised result — is
/// invisible at a count of one.
#[tokio::test]
async fn a_skill_declares_several_artifacts_and_they_arrive_as_several() {
    let manifest = Manifest::parse(ONE_SKILL).expect("parse");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(DeclaresTwoArtifacts)
        .build();
    let router = A2aServer::new(
        rt,
        Arc::new(HeaderAuth),
        &card_security(),
        &manifest,
        "https://plane.internal/a2a",
    )
    .expect("wired")
    .router();

    let (status, body) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": {
                    "messageId": "m-declared",
                    "role": "ROLE_USER",
                    "parts": [{ "text": "settle it" }],
                }
            }),
            Some("peer"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let artifacts = body["result"]["task"]["artifacts"]
        .as_array()
        .unwrap_or_else(|| panic!("the declared reply produced no artifacts: {body}"));
    assert_eq!(
        artifacts.len(),
        2,
        "a declared two-artifact reply collapsed on the wire: {artifacts:?}"
    );

    // The parts arrived in the declared shape, in the declared order — not
    // merely in the declared number.
    assert_eq!(
        artifacts[0]["parts"][0]["text"], "the finding",
        "{artifacts:?}"
    );
    assert_eq!(
        artifacts[1]["parts"][0]["data"]["ref"], "SET-42",
        "{artifacts:?}"
    );

    // Distinct ids, because A2A identifies an artifact by `artifactId` and a
    // client that keys on it would treat two shared ids as one artifact
    // revised — silently discarding a result rather than failing.
    let ids: Vec<&str> = artifacts
        .iter()
        .map(|a| a["artifactId"].as_str().expect("an artifactId"))
        .collect();
    assert_ne!(ids[0], ids[1], "two artifacts share one id: {ids:?}");
}

/// **A task reports one state, whichever path a client takes.**
///
/// The immediate `SendMessage` response and every read-back path — `GetTask`,
/// `SubscribeToTask`, streamed status updates — used to derive the A2A state
/// from *different* functions: one exhaustive over `RunStatus`, one matching
/// the sealed outcome string behind a `_ => Failed`. They agreed only because
/// the catch-all happened to cover the four variants that mean failure.
///
/// The compiler kept the enum-shaped one honest and kept nothing else honest.
/// A `RunStatus` variant added for something that is *not* a failure — an
/// authorization wait, a rejection — would have surfaced correctly to the caller
/// holding the response and as `Failed` to the caller who polled for it. Same
/// task, two answers, decided by which path the client happened to take.
///
/// Asserted end to end on the wire rather than by comparing the two functions,
/// because the claim is about what a *client* sees.
#[tokio::test]
async fn the_live_answer_and_the_read_back_answer_are_the_same_state() {
    let f = fixture();
    let router = f.router();
    let (status, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": {
                    "messageId": "m-agree",
                    "role": "ROLE_USER",
                    "parts": [{ "text": "settle it" }],
                }
            }),
            Some("peer"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");

    let live = sent["result"]["task"]["status"]["state"].clone();
    let task_id = sent["result"]["task"]["id"].as_str().expect("a task id");
    assert!(live.is_string(), "{sent}");

    let (status, fetched) = send(
        &router,
        rpc("GetTask", &json!({ "id": task_id }), Some("peer")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");

    assert_eq!(
        fetched["result"]["status"]["state"], live,
        "the immediate response and the read-back disagree about the same task's \
         state — a client that held the response and one that polled for it would \
         see different tasks: live={live}, fetched={fetched}"
    );
}

/// **A card URL is a dereference, and gets what every dereference here gets.**
///
/// Discovery fetches a URL that arrives from a config, a registry entry or a
/// message — routinely the first attacker-influenced string a deployment
/// handles. `netguard`'s own documentation used to enumerate the crate's URL
/// dereferences as *two*, governed media and push delivery, while this was a
/// third: a bare client with no address check, no redirect policy and no
/// timeout, behind an allowlist that is optional and therefore absent by
/// default.
///
/// Three assertions, because the three controls fail independently and only one
/// of them is visible in a passing fetch.
#[tokio::test]
async fn card_discovery_refuses_an_inward_address_a_redirect_and_a_hang() {
    use agentplane::peers::{CardClient, DiscoveryError, WELL_KNOWN_PATH};
    use axum::Router;
    use axum::routing::get;

    // 1. An address that resolves inward. With no allowlist configured this is
    //    the only lock, and it is the one that stands between a hostile card URL
    //    and the cloud metadata service.
    let refused = CardClient::new()
        .discover("http://169.254.169.254")
        .await
        .expect_err("the link-local metadata address was fetched");
    assert!(
        matches!(&refused, DiscoveryError::Refused(m) if m.contains("169.254.169.254")),
        "a card fetch reached the metadata service: {refused:?}"
    );

    // 2. A redirect. The check above runs on the URL the caller supplied and
    //    says nothing about where an allowed host forwards to, so following one
    //    hands the whole decision to the card server.
    let redirector = Router::new().route(
        WELL_KNOWN_PATH,
        get(|| async {
            (
                StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://169.254.169.254/card")],
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, redirector).await;
    });
    let followed = CardClient::new()
        .allow_loopback()
        .discover(&format!("http://{addr}"))
        .await
        .expect_err("the redirect to the metadata service was followed");
    // Named, not merely "an error": with redirects off the 302 is returned as
    // the response, so the refusal says *302*. Accepting any error here would
    // pass just as well on a malformed body, which is what an empty redirect
    // response also produces once something else has gone wrong.
    assert!(
        matches!(&followed, DiscoveryError::Unreachable(m) if m.contains("302")),
        "the fetch failed, but not by declining to follow the redirect — the \
         address check would then be covering only the first hop: {followed:?}"
    );

    // 3. A server that accepts the connection and never answers. Unbounded is
    //    the wrong default anywhere, and here an unknown host sets it.
    let hanging = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hang_addr = hanging.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = hanging.accept().await else {
                return;
            };
            // Held open, never written to.
            std::mem::forget(stream);
        }
    });
    //
    // Bounded by the *test* as well as by the client, and that outer bound is
    // load-bearing: a client with no timeout never returns, so an assertion on
    // elapsed time is never reached and the failure is a hang. A hang stalls CI
    // and the mutation sweep and tells nobody what broke, which is the one
    // failure mode worse than the bug.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        CardClient::new()
            .allow_loopback()
            .timeout(std::time::Duration::from_millis(300))
            .discover(&format!("http://{hang_addr}")),
    )
    .await;
    let timed_out = outcome.expect(
        "the fetch was not bounded by its own timeout and had to be killed by          this test's — an unknown host can hold a task open indefinitely",
    );
    assert!(
        timed_out.is_err(),
        "a card fetch against a server that never answers returned a card"
    );
}

/// **A card names an address, and the call that follows checks it.**
///
/// Discovery being guarded is only half. `AgentCard::endpoint` takes the URL
/// straight out of a discovered card — a document another party publishes about
/// itself — and hands it to the client that carries the run's payload and a
/// bearer credential. A forged card cannot widen a grant, which is what makes
/// discovery survivable at all; what it can still do is *name an address*, and
/// the outbound leg is where that address is finally connected to.
///
/// So the peer call resolves, checks every answer and pins the connection to
/// exactly those, the same as discovery and push. Asserted with a peer whose
/// endpoint is the link-local metadata address, which is what a hostile card
/// would advertise.
#[tokio::test]
async fn a_peer_endpoint_that_resolves_inward_is_refused_before_the_request() {
    use agentplane::core::{Delegation, Principal, Scope};
    use agentplane::peers::a2a::{A2aClient, Endpoint};
    use agentplane::peers::{PeerClient, PeerId};

    let client = A2aClient::new(Endpoint::new("http://169.254.169.254/a2a")).expect("client");
    let chain = Delegation::root(Principal::new("user:owner", Scope::root()));
    let error = client
        .send(
            &PeerId::new("hostile"),
            "audit.check",
            &json!({"question": "what is in the metadata service"}),
            &chain,
            None,
            None,
        )
        .await
        .expect_err("the metadata address was called");

    // `Refused`, not merely an error mentioning the address. Without the check
    // the client still tries to connect and still fails — with a *transport*
    // error that names the same host — so an assertion on the message text
    // passes whether or not anything was checked. The classification is the
    // only thing that distinguishes "this plane declined to go there" from
    // "this plane went there and the socket did not open", and they are
    // different facts: the second one means the address was contacted.
    assert!(
        matches!(&error, agentplane::peers::PeerError::Refused { detail, .. }
            if detail.contains("169.254.169.254")),
        "a peer call was attempted against the metadata service rather than \
         refused before the request: {error:?}"
    );
    assert_eq!(
        error.disposition(),
        agentplane::core::Disposition::DidNotHappen,
        "a destination refused before the request was built must be recorded as \
         never having happened, or the runtime treats it as possibly applied"
    );
}

/// **Every read-back surface reports one state, and they share one function.**
///
/// The sibling above pins the *live* response against `GetTask`. This pins the
/// three read-back surfaces against each other: `GetTask`, the row the same
/// task occupies in `ListTasks`, and the snapshot a subscription opens with.
/// All three answer from the run's history, and each derived its answer from
/// its own copy of the same match — three copies that would agree right up
/// until somebody added a record kind or reworded a suspension.
///
/// A disagreement here is worse than a wrong answer, because all three clients
/// are equally correct: one polled, one listed, one subscribed, and the
/// protocol gives them no way to discover that the plane told them different
/// things.
///
/// Driven on a task that is **input-required** rather than finished, which is
/// the only state all three can be asked about at once: a subscription to a
/// terminal task is refused before it reaches the stream, so a completed run
/// would leave the third surface untested — the gap this test exists to close.
#[tokio::test]
async fn every_read_back_surface_reports_the_same_state() {
    let f = continuation_fixture();
    let router = f.router();
    let (status, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": {
                "messageId": "m-surfaces",
                "role": "ROLE_USER",
                "parts": [{"text": "begin"}]
            }}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let task_id = sent["result"]["task"]["id"]
        .as_str()
        .expect("a task id")
        .to_owned();

    let (_, fetched) = send(
        &router,
        rpc("GetTask", &json!({ "id": task_id }), Some("peer-a")),
    )
    .await;
    let got = fetched["result"]["status"]["state"].clone();
    assert_eq!(
        got, "TASK_STATE_INPUT_REQUIRED",
        "the fixture stopped producing a live task, so the three surfaces below \
         are being compared on a state only one of them can report: {fetched}"
    );

    let (_, listed) = send(&router, rpc("ListTasks", &json!({}), Some("peer-a"))).await;
    let row = listed["result"]["tasks"]
        .as_array()
        .expect("a task list")
        .iter()
        .find(|t| t["id"] == task_id.as_str())
        .unwrap_or_else(|| panic!("the task is absent from its own listing: {listed}"));
    assert_eq!(
        row["status"]["state"], got,
        "the same task reads one state from GetTask and another from ListTasks \
         — a client that polled and a client that listed would each be correct \
         and disagree: get={got}, list={listed}"
    );

    let opening = sse_opening_frame(
        &router,
        rpc("SubscribeToTask", &json!({ "id": task_id }), Some("peer-a")),
    )
    .await
    .unwrap_or_else(|| panic!("a subscription to a live task carried no frames"));
    let streamed = opening["result"]["task"]["status"]["state"].clone();
    assert_eq!(
        streamed, got,
        "the snapshot a subscription opens with disagrees with GetTask about the \
         same task, and the subscribing client has no way to find out: \
         stream={streamed}, get={got}"
    );
}

/// A webhook this deployment will never deliver to stops being retried.
///
/// The grant is re-checked at delivery precisely because a registration
/// outlives the configuration that permitted it — but noticing a permanent
/// refusal and then scheduling it again forever is detection without delivery
/// (I13): the operator sees `retries: 1` on an info line, the same shape a
/// receiver that is merely down produces, and nothing ever says *this one is
/// never going to work*.
///
/// Registered through the store rather than the RPC, because that is the real
/// sequence: granted at registration, revoked afterwards.
#[tokio::test]
async fn a_permanently_refused_webhook_is_abandoned_rather_than_retried_forever() {
    let f = fixture();
    let (server, worker, _transport) = f.push_server();
    let router = server.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let task = RunId::parse(sent["result"]["task"]["id"].as_str().unwrap()).unwrap();

    f.store
        .put(
            &PushConfig {
                id: "revoked".to_owned(),
                task,
                url: "https://revoked.example/hook".to_owned(),
                token: None,
                authentication: None,
            },
            1,
        )
        .await
        .unwrap();

    let report = worker.run_once(10, 10).await.unwrap();

    assert_eq!(
        report.parked, 1,
        "a permanent refusal was rescheduled instead of being given up on: {report:?}"
    );
    assert_eq!(
        report.retries, 0,
        "a decision no backoff can change was queued for another attempt: {report:?}"
    );
    assert!(
        report.needs_attention(),
        "the tick that gave up on a peer's webhook reads exactly like a quiet one: {report:?}"
    );
    // Out of the due order, and still readable: parking keeps the cursor, so
    // an operator who re-grants the host resumes at the first record this
    // receiver never took rather than at the head of the run.
    assert!(
        PushStore::due(&*f.store, 1_000_000, 10)
            .await
            .unwrap()
            .is_empty(),
        "a webhook refused by the operator's own grant is still queued"
    );
    let parked = f.store.parked(10).await.unwrap();
    assert_eq!(
        parked.len(),
        1,
        "the refusal deleted the cursor: {parked:?}"
    );
    assert!(
        f.store
            .unpark(task, &parked[0].config.id, 1_000)
            .await
            .unwrap(),
        "a parked registration could not be re-armed"
    );
    let rearmed = PushStore::due(&*f.store, 1_000, 10).await.unwrap();
    assert_eq!(
        rearmed.first().map(|row| row.next_seq),
        Some(parked[0].next_seq),
        "re-arming rewound the cursor, so an operator who re-grants a host \
         replays what the receiver already took: {rearmed:?}"
    );
}

/// A receiver that never comes back is abandoned too, and only after the
/// ceiling.
///
/// The positive half is what does the work here: a change that abandoned on the
/// *first* transient failure would satisfy the assertion above perfectly while
/// dropping every notification to a receiver that was rebooting. So this asserts
/// both edges — one attempt short of the ceiling still retries, and the ceiling
/// itself gives up.
#[tokio::test]
async fn an_unreachable_receiver_is_retried_up_to_the_ceiling_and_then_abandoned() {
    let f = fixture();
    let (server, worker, transport) = f.push_server();
    let worker = worker.max_attempts(3);
    let router = server.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({
                "message": text("go"),
                "configuration": {
                    "taskPushNotificationConfig": {"url": "https://client.example/hook"}
                }
            }),
            Some("peer-a"),
        ),
    )
    .await;
    let task = RunId::parse(sent["result"]["task"]["id"].as_str().unwrap()).unwrap();
    for _ in 0..10 {
        transport.fail_next();
    }

    let mut at = 10u64;
    let mut ticks = Vec::new();
    for _ in 0..3 {
        ticks.push(worker.run_once(at, 10).await.unwrap());
        at += 4096;
    }

    assert_eq!(
        (ticks[0].retries, ticks[1].retries),
        (1, 1),
        "a receiver short of the ceiling was abandoned early: {ticks:?}"
    );
    assert!(
        !ticks[0].needs_attention() && !ticks[1].needs_attention(),
        "an ordinary backoff was reported as something a human must clear: {ticks:?}"
    );
    assert_eq!(
        ticks[2].parked, 1,
        "the third failure of a ceiling of three did not give up: {ticks:?}"
    );
    assert!(ticks[2].needs_attention(), "{:?}", ticks[2]);
    assert!(
        PushStore::due(&*f.store, 1_000_000, 10)
            .await
            .unwrap()
            .is_empty(),
        "a parked registration is still queued"
    );
    let parked = f.store.parked(10).await.unwrap();
    assert_eq!(
        parked.len(),
        1,
        "the ceiling deleted the cursor instead of parking it"
    );
    // And an operator who fixed the receiver gets it back, from where it
    // stopped rather than from the top.
    let id = parked[0].config.id.clone();
    assert!(
        f.store.unpark(task, &id, at).await.unwrap(),
        "a parked registration could not be re-armed"
    );
    assert_eq!(
        PushStore::due(&*f.store, at, 10).await.unwrap().len(),
        1,
        "an unparked registration is not due"
    );
    assert!(
        !f.store.unpark(task, &id, at).await.unwrap(),
        "unparking a live registration reported that it had done something"
    );
}

/// A parameter this method does not take is refused, not ignored.
///
/// One `CommonParams` served every method — the same shape the binary's
/// arguments had before they moved onto per-verb structs, where a flag
/// belonging to one verb was silently accepted by another and did nothing. On
/// the wire it reads worse, because the caller is a stranger who cannot see the
/// source.
///
/// `ListTasks` is the case that matters and it is why this is a defect rather
/// than untidiness: a request whose `contextId` was misspelled parsed cleanly,
/// dropped the filter, and answered with **every** task the caller may see —
/// shaped exactly like the scoped list that was asked for, so nothing
/// downstream could tell. It was found by the protocol project's own
/// conformance kit, whose JSON-RPC client sends `context_id`: five CORE-LIST
/// rows had been passing over a filter that never ran.
///
/// The specification is what licenses refusing it rather than accepting both:
/// A2A §5.5 says JSON field names MUST be camelCase, and A2A §9.4.4's own example sends
/// `contextId`. A server that also answers the other spelling accepts clients
/// that have lost half the protocol, and the call working is why they never
/// find out.
#[tokio::test]
async fn a_parameter_that_belongs_to_another_method_is_refused() {
    let f = fixture();
    let router = f.router();
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go")}),
            Some("peer-a"),
        ),
    )
    .await;
    let context = sent["result"]["task"]["contextId"]
        .as_str()
        .unwrap()
        .to_owned();

    // The scoped question, spelled the way the specification spells it.
    let (_, ok) = send(
        &router,
        rpc("ListTasks", &json!({"contextId": context}), Some("peer-a")),
    )
    .await;
    let scoped = ok["result"]["tasks"].as_array().expect("a task list").len();
    assert_eq!(scoped, 1, "{ok:#}");

    // The same question misspelled. It must not come back as an answer.
    for (params, what) in [
        (json!({"contxtId": context}), "a typo in the filter"),
        (
            json!({"context_id": context}),
            "the snake_case spelling the specification forbids",
        ),
    ] {
        let (_, refused) = send(&router, rpc("ListTasks", &params, Some("peer-a"))).await;
        assert_eq!(
            err_code(&refused),
            i64::from(code::INVALID_PARAMS),
            "{what} was accepted: {refused:#}"
        );
        assert!(
            refused["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("ListTasks"),
            "the refusal does not name the method or the field: {refused:#}"
        );
    }

    // A field this surface knows, on a method that does not take it.
    let (_, refused) = send(
        &router,
        rpc(
            "CancelTask",
            &json!({"id": "run_x", "pageSize": 5}),
            Some("peer-a"),
        ),
    )
    .await;
    assert_eq!(
        err_code(&refused),
        i64::from(code::INVALID_PARAMS),
        "a paging parameter on CancelTask was accepted: {refused:#}"
    );

    // And the positive half, so a refuse-everything change cannot pass: the
    // specification defines `metadata` on SendMessageRequest, so a conforming
    // client sending it must not meet -32602.
    let (_, ok) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": text("go"), "metadata": {"trace": "abc"}}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(
        ok["result"]["task"]["id"].is_string(),
        "a specification-defined field was refused: {ok:#}"
    );
}

/// A plane serves a card per agent, and the well-known one says where they are.
///
/// A2A's well-known card path is singular per host, so a plane hosting several
/// declared agents could give each its own card only by running a server per
/// agent — 28 specialists, 28 processes. The discriminator is deliberately a
/// **path** and not `AgentInterface::tenant`: that field's documented meaning is
/// the tenant id a caller echoes back on every request, so overloading it to
/// select an *agent* would put two meanings in one string the moment a plane
/// served several tenants too.
///
/// Three things are asserted, and the third is the one that keeps this honest:
/// the well-known card is still a single valid card describing a real agent; the
/// directory extension names every agent and where its card is; and **skill
/// dispatch spans all of them**, because they were always on the runtime and
/// what was missing was only discovery.
#[tokio::test]
async fn a_plane_serves_one_card_per_agent_and_a_directory() {
    let f = fixture_from(TWO_AGENTS, Arc::new(Recording::default()));
    let manifests = Manifest::parse_all(TWO_AGENTS).expect("two agents");
    let refs: Vec<&Manifest> = manifests.iter().collect();
    let server = A2aServer::hosting(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &refs,
        "https://plane.internal/a2a",
    )
    .expect("a plane may host several agents");
    let router = server.router();

    // 1. The well-known path is still one valid card, describing a real agent.
    let http = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(http.status(), StatusCode::OK);
    let card: Value = serde_json::from_slice(
        &axum::body::to_bytes(http.into_body(), 256 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(card["name"], "desk", "{card:#}");

    // 2. The directory extension names every agent and its card path.
    let directory = card["capabilities"]["extensions"]
        .as_array()
        .expect("extensions")
        .iter()
        .find(|e| e["uri"].as_str() == Some(agentplane::peers::EXT_AGENT_DIRECTORY))
        .expect("the directory extension is absent")["params"]["agents"]
        .as_array()
        .expect("agents")
        .clone();
    let names: Vec<&str> = directory
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert_eq!(names, ["desk", "researcher"], "{directory:#?}");
    assert!(
        directory
            .iter()
            .all(|a| a["manifestDigest"].as_str().is_some_and(|d| d.len() == 64)),
        "every entry carries the digest a consumer pins: {directory:#?}"
    );

    // 3. Each agent's own card is served, and is the card it would have alone —
    //    sharing a plane must not change the identity a consumer pins.
    for (name, expect_skill) in [("desk", "support.answer"), ("researcher", "research.dig")] {
        let http = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(agentplane::peers::agent_card_path(name))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(http.status(), StatusCode::OK, "{name}");
        let one: Value = serde_json::from_slice(
            &axum::body::to_bytes(http.into_body(), 256 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(one["name"], name);
        assert_eq!(one["skills"][0]["id"], expect_skill, "{one:#}");
    }

    // An unknown agent is a plain 404 that enumerates nothing.
    let http = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/agents/nobody/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(http.status(), StatusCode::NOT_FOUND);

    // 4. Dispatch spans both agents — the non-primary one is reachable.
    let (_, sent) = send(
        &router,
        rpc(
            "SendMessage",
            &json!({"message": {
                "messageId": "m-1",
                "role": "ROLE_USER",
                "parts": [{"text": "go"}],
                "metadata": {"skill": "research.dig"}
            }}),
            Some("peer-a"),
        ),
    )
    .await;
    assert!(
        sent["result"]["task"]["id"].is_string(),
        "the second agent's skill did not dispatch: {sent:#}"
    );
}

/// Two agents claiming one skill is refused at construction.
///
/// A2A dispatch is **named, never inferred** — that is the rule that keeps a
/// model reading attacker-controlled text out of the decision about which
/// capability runs. A skill id resolving to two agents would put the routing
/// decision back where the caller cannot see it, so the plane refuses to serve
/// rather than picking. The positive half is the ordinary room, which must
/// still build.
#[tokio::test]
async fn two_agents_claiming_one_skill_are_refused() {
    const COLLIDING: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: desk, version: "1.0.0" }
spec:
  budgets: { max_steps: 5 }
  capabilities: { provides: [support.answer] }
---
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: night-desk, version: "1.0.0" }
spec:
  budgets: { max_steps: 5 }
  capabilities: { provides: [support.answer] }
"#;
    let f = fixture_from(TWO_AGENTS, Arc::new(Recording::default()));
    let colliding = Manifest::parse_all(COLLIDING).expect("two agents");
    let refs: Vec<&Manifest> = colliding.iter().collect();
    let err = A2aServer::hosting(
        f.rt.clone(),
        Arc::new(HeaderAuth),
        &card_security(),
        &refs,
        "https://plane.internal/a2a",
    )
    .expect_err("one skill on two agents was served");
    assert!(
        matches!(&err, ServerSetupError::AmbiguousSkill { skill, .. } if skill == "support.answer"),
        "wrong refusal: {err}"
    );

    // An empty plane has nothing for the well-known path to answer with.
    assert!(matches!(
        A2aServer::hosting(
            f.rt.clone(),
            Arc::new(HeaderAuth),
            &card_security(),
            &[],
            "https://plane.internal/a2a",
        ),
        Err(ServerSetupError::NoAgents)
    ));
}
