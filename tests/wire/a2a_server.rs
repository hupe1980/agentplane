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

use agentplane::api::a2a::{A2aServer, ServerSetupError, action, code};
use agentplane::api::{AuthError, Authenticator, Caller};
use agentplane::core::{
    Digest, Outcome, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Skill,
    SkillDescriptor, SkillError, Tainted, TenantId,
};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
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
        Ok(Caller::new(bearer, vec!["peer".to_owned()]))
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
}

impl PolicyEngine for Recording {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        self.seen.lock().unwrap().push(request.action.to_owned());
        let refuse = self.deny || (self.deny_runs && !request.action.starts_with("a2a:"));
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
    policy: Arc<Recording>,
    seen: Seen,
    manifest: Manifest,
}

fn fixture_from(yaml: &str, policy: Arc<Recording>) -> Fixture {
    let manifest = Manifest::parse(yaml).expect("parse");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut builder = Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(policy.clone() as Arc<dyn PolicyEngine>);
    for cap in &manifest.spec.capabilities.provides {
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
        policy,
        seen,
        manifest,
    }
}

fn fixture() -> Fixture {
    fixture_from(ONE_SKILL, Arc::new(Recording::default()))
}

impl Fixture {
    fn router(&self) -> axum::Router {
        A2aServer::new(
            self.rt.clone(),
            Arc::new(HeaderAuth),
            &self.manifest,
            "https://plane.internal/a2a",
        )
        .expect("the fixture wires a policy engine")
        .router()
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
        body["supportedInterfaces"][0]["protocolVersion"], "1.0",
        "a client selects an interface by version, and one without it is unusable"
    );
    assert_eq!(
        f.policy.seen.lock().unwrap().len(),
        0,
        "the public card asked the policy engine, which means it is not public"
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

/// The task returned uses A2A's own state spelling.
#[tokio::test]
async fn a_completed_run_is_reported_as_a_completed_task() {
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

    let task = &body["result"]["task"];
    assert_eq!(
        task["status"]["state"], "TASK_STATE_COMPLETED",
        "the state must use the ProtoJSON spelling a client matches on: {task:#}"
    );
    assert!(
        task["id"].as_str().is_some_and(|s| !s.is_empty()),
        "the task must carry the run id, or the caller cannot poll it: {task:#}"
    );
}

// ── Refusals say which kind they are ────────────────────────────────────────

/// Unimplemented operations are refused as unsupported, not as unknown.
///
/// A caller that reads `-32601 Method not found` concludes it spelled the method
/// wrong and retries; one that reads `-32004` concludes this agent cannot do it
/// and stops. Both are refusals, and only one is correct here — the card
/// already advertises these as false.
#[tokio::test]
async fn unimplemented_operations_are_refused_as_unsupported() {
    let f = fixture();
    let router = f.router();

    for method in ["SendStreamingMessage", "SubscribeToTask", "ListTasks"] {
        let (_, body) = send(&router, rpc(method, &json!({}), Some("peer-a"))).await;
        assert_eq!(
            err_code(&body),
            i64::from(code::UNSUPPORTED_OPERATION),
            "{method} was refused as something other than unsupported: {body:#}"
        );
    }

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
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
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
    use agentplane::peers::{PeerClient, PeerCredential, PeerId};

    let f = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = f.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let peer = PeerId::new("self");
    let chain = Delegation::root(Principal::new("user:operator", Scope::root()));
    let client = A2aClient::new(Endpoint::new(format!("http://{addr}/a2a"))).unwrap();
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
    assert_eq!(got["result"]["task"]["id"], id);
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
