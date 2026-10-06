//! The HTTP surface.
//!
//! Every test here is about the same question: **can a caller become somebody
//! else?** In-process, four-eyes and role eligibility are enforced against an
//! actor the embedder supplies, and the embedder is trusted. On a socket the
//! actor would come from whoever is connected, and a reviewer who can name
//! themselves can name the person who proposed the action — which is precisely
//! the control four-eyes is.
//!
//! So these are not plumbing tests. The plumbing is a few hundred lines of
//! axum; what is worth testing is that the identity on the request cannot be
//! influenced by the request, that authorization runs before anything else, and
//! that neither can be skipped by a route somebody adds next year.

#![cfg(all(feature = "http", feature = "redb"))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::api::openapi::{Body as Shape, ErrorClass, ROUTES, Route};
use agentplane::api::{Api, ApiSetupError, AuthError, Authenticator, Caller, action};
use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    BudgetExceeded, CorrelationKey, DeadlineSpec, Digest, Justification, Outcome,
    PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Priority, Skill,
    SkillDescriptor, SkillError, StepError, Tainted, TaskSpec,
};
use agentplane::journal::{Append, JournalStore, RecordKind};
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

// ── Fixture ─────────────────────────────────────────────────────────────────

/// Proposes a refund, bars its own proposer, and waits for a human.
#[derive(Debug)]
struct ProposesRefund;

#[async_trait::async_trait]
impl Skill for ProposesRefund {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("proposes-refund").provides("demo.refund")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("approval", &DeadlineSpec::days(2), None)
            .await?;

        let spec = TaskSpec::new(
            "refund-approval",
            Justification::new(
                Tainted::trusted("invoice disputed".to_owned()),
                json!({ "action": "refund", "amount_eur": 4200 }),
            )
            // A line the run did not write — here a counterparty's, as a
            // dry-run preview or a completion would be.
            .evidence(Tainted::from_source(
                "counterparty says the meter was replaced".to_owned(),
                agentplane::core::SourceId::new("peer:utility-co"),
            )),
            "approval",
        )
        .role("compliance-officer")
        .priority(Priority::High)
        // The proposer. Whoever this is may not approve it.
        .excluding("alice");

        let decision = cx.task(&spec).await?;
        Ok(Outcome::done(Tainted::trusted(json!({
            "approved": decision.approved,
            "by": decision.decided.to_string(),
        }))))
    }
}

/// Authenticates from a header, because the tests need *an* identity scheme and
/// this crate deliberately ships none.
#[derive(Debug)]
struct HeaderAuth;

#[async_trait::async_trait]
impl Authenticator for HeaderAuth {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
        let actor = headers
            .get("x-actor")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::Missing)?;
        if actor == "mallory" {
            return Err(AuthError::Rejected);
        }
        // Roles are derived here, from the identity — never read from the
        // request. That is the whole point of the seam.
        let roles = match actor {
            "bob" | "alice" => vec!["compliance-officer".to_owned()],
            _ => vec!["clerk".to_owned()],
        };
        Ok(Caller::new(actor, roles))
    }
}

/// Authenticates `tenant:actor`, so a test can be several tenants at once.
///
/// The tenant comes from the credential, never the request body — the same rule
/// as `actor` and `roles`, and the one that matters most here, since it decides
/// which store answers.
#[derive(Debug)]
struct TenantAuth;

#[async_trait::async_trait]
impl Authenticator for TenantAuth {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
        let raw = headers
            .get("x-actor")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::Missing)?;
        let (tenant, actor) = raw.split_once(':').ok_or(AuthError::Rejected)?;
        let tenant = agentplane::core::TenantId::new(tenant).map_err(|_| AuthError::Rejected)?;
        Ok(Caller::new(actor, vec!["compliance-officer".to_owned()]).in_tenant(tenant))
    }
}

/// Permits the `api:` actions, recording what it was asked.
///
/// Recording is what lets a test assert that a route asked *at all* — a gate
/// nobody calls looks exactly like a gate that permits.
#[derive(Debug, Default)]
struct Recording {
    seen: Mutex<Vec<(String, String, Vec<String>)>>,
    deny: bool,
}

impl Recording {
    fn asked(&self) -> Vec<(String, String, Vec<String>)> {
        self.seen.lock().unwrap().clone()
    }
}

impl PolicyEngine for Recording {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        let roles: Vec<String> = request
            .context
            .get("roles")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        self.seen.lock().unwrap().push((
            request.principal.to_owned(),
            request.action.to_owned(),
            roles,
        ));
        if self.deny {
            PolicyDecision::deny("the test policy refuses everything")
        } else {
            PolicyDecision::Permit
        }
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"test-policy"), "agentplane-test/api-policy-v1")
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
}

fn fixture_with(policy: &Arc<Recording>) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .policy(policy.clone() as Arc<dyn PolicyEngine>)
        .skill(ProposesRefund);
    #[cfg(feature = "push")]
    let rt = rt.push(store.clone() as Arc<dyn agentplane::push::PushStore>);
    let rt = rt.build();
    Fixture { store, rt }
}

fn fixture() -> Fixture {
    fixture_with(&Arc::new(Recording::default()))
}

impl Fixture {
    fn router(&self) -> axum::Router {
        Api::new(self.rt.clone(), Arc::new(HeaderAuth))
            .expect("the fixture wires a policy engine")
            .router()
    }

    /// Start a run that suspends on a human task, and return the task id.
    async fn pending_task(&self) -> String {
        let out = self
            .rt
            .run_correlated(
                "demo.refund",
                Tainted::trusted(json!({})),
                "dispute",
                &[CorrelationKey::new("document", "INV-1")],
            )
            .await
            .unwrap();
        assert!(out.status.is_suspended(), "got {:?}", out.status);

        let queued = (self.store.clone() as Arc<dyn TaskStore>)
            .queue(&["compliance-officer".to_owned()], 10)
            .await
            .unwrap();
        assert_eq!(queued.len(), 1);
        queued[0].id.to_hex()
    }
}

// ── Request helpers ─────────────────────────────────────────────────────────

/// Send a request, and hold its answer to the published document.
///
/// Every answer any test here receives is validated against the schema the
/// `OpenAPI` document gives for its operation and status, so a member the
/// schema lacks, a status the operation does not list, or a refusal that is
/// not the documented error object fails whichever test provoked it.
async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    if let Err(why) = conforms(&method, &path, status, &bytes) {
        panic!("{method} {path} answered {status} off the document: {why}");
    }
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

// ── The published document ──────────────────────────────────────────────────

fn document() -> &'static Value {
    static DOCUMENT: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DOCUMENT.get_or_init(agentplane::api::openapi::document)
}

/// The operation a request path is served by: the most specific template that
/// matches, so `/runs/live` is not read as `/runs/{run}`.
fn operation_for(method: &str, path: &str) -> Option<&'static Route> {
    let matches = |template: &str| {
        let (t, p): (Vec<&str>, Vec<&str>) =
            (template.split('/').collect(), path.split('/').collect());
        t.len() == p.len()
            && t.iter()
                .zip(&p)
                .all(|(t, p)| t == p || (t.starts_with('{') && !p.is_empty()))
    };
    ROUTES
        .iter()
        .filter(|r| r.method.as_str().eq_ignore_ascii_case(method) && matches(r.path))
        .min_by_key(|r| r.path.matches('{').count())
}

/// Whether an answer is the one the document describes.
fn conforms(method: &str, path: &str, status: StatusCode, bytes: &[u8]) -> Result<(), String> {
    let Some(route) = operation_for(method, path) else {
        // Only the tests that probe a route the surface does not serve.
        return if matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ) {
            Ok(())
        } else {
            Err("no documented operation serves this request".to_owned())
        };
    };
    let answer =
        &document()["paths"][route.path][route.method.as_str()]["responses"][status.as_str()];
    if answer.is_null() {
        return Err(format!("{} does not list {status}", route.operation));
    }
    let Some(schema) = answer.pointer("/content/application~1json/schema") else {
        return if bytes.is_empty() {
            Ok(())
        } else {
            Err("the document gives this answer no body".to_owned())
        };
    };
    let body: Value = serde_json::from_slice(bytes).map_err(|e| {
        format!(
            "the body is not JSON ({e}): {}",
            String::from_utf8_lossy(bytes)
        )
    })?;
    let validator = validator(schema);
    let errors: Vec<String> = validator
        .iter_errors(&body)
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("{errors:?} in {body}"))
    }
}

/// A validator for one schema of the document, its references resolved
/// against the document's components.
fn validator(schema: &Value) -> Arc<jsonschema::Validator> {
    static CACHE: std::sync::OnceLock<
        Mutex<std::collections::HashMap<String, Arc<jsonschema::Validator>>>,
    > = std::sync::OnceLock::new();
    let key = schema.to_string();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(found) = cache.lock().unwrap().get(&key) {
        return Arc::clone(found);
    }
    let root = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "components": document()["components"],
        "allOf": [schema],
    });
    let built = Arc::new(jsonschema::validator_for(&root).expect("a documented schema compiles"));
    cache.lock().unwrap().insert(key, Arc::clone(&built));
    built
}

fn get(path: &str, actor: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(path).method("GET");
    if let Some(a) = actor {
        b = b.header("x-actor", a);
    }
    b.body(Body::empty()).unwrap()
}

fn post(path: &str, actor: Option<&str>, body: &Value) -> Request<Body> {
    let mut b = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json");
    if let Some(a) = actor {
        b = b.header("x-actor", a);
    }
    b.body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

// ── The identity cannot come from the request ───────────────────────────────

/// A body that names an actor is refused outright.
///
/// The field does not exist on [`agentplane::api::DecisionRequest`], so serde
/// could simply ignore it — and that is the dangerous outcome, not the safe one.
/// An integrator who writes `"actor": "alice"` and gets a 200 believes they
/// decided as Alice; the journal says Bob. The disagreement surfaces at an
/// audit, months later, with nobody left who remembers.
#[tokio::test]
async fn a_body_that_names_an_actor_is_refused_rather_than_ignored() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": true, "reason": "ok", "actor": "alice" }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a body carrying an actor was accepted; silently ignoring it is how an \
         integrator ends up believing they can impersonate"
    );
    assert!(
        body["error"].as_str().is_some_and(|e| e.contains("actor")),
        "the refusal does not say which member it refused: {body}"
    );

    // And nothing was decided.
    let task_id = agentplane::core::TaskId::parse(&task).unwrap();
    let found = (f.store.clone() as Arc<dyn TaskStore>)
        .task(task_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        found.state.is_pending(),
        "the refused request still decided the task"
    );
}

/// **A reviewer is told which sentences the run did not write.**
///
/// The labels are inside `justification` already, so this flag is derivable —
/// and it is served anyway, because the failure mode is a client that renders
/// the text and never walks the labels. A reviewer who is not shown the
/// distinction has not been given it.
#[tokio::test]
async fn a_task_says_whether_it_carries_prose_the_run_did_not_write() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let (status, body) = send(&router, get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["has_untrusted_prose"], true,
        "the task carries a counterparty's sentence and does not say so: {body}"
    );

    // And the label is on the sentence itself, so a client that wants to badge
    // one line rather than the whole task can.
    assert_eq!(
        body["justification"]["evidence"][0]["label"]["trust"], "untrusted",
        "the evidence entry lost its provenance on the wire: {body}"
    );
    assert_eq!(
        body["justification"]["summary"]["label"]["trust"], "trusted",
        "the run's own sentence was served as somebody else's: {body}"
    );
}

/// The decision is recorded under the authenticated caller.
#[tokio::test]
async fn the_decision_is_recorded_under_the_authenticated_caller() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": true, "reason": "verified against the meter data" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decided_by"], "bob");

    // The run resumed and carries Bob's name, from the journal rather than from
    // the response we just wrote.
    let records = (f.store.clone() as Arc<dyn JournalStore>)
        .read(
            (f.store.clone() as Arc<dyn TaskStore>)
                .task(agentplane::core::TaskId::parse(&task).unwrap())
                .await
                .unwrap()
                .unwrap()
                .run,
            1,
        )
        .await
        .unwrap();
    let decided = records
        .iter()
        .find_map(|r| match r.kind() {
            agentplane::journal::RecordKind::EffectDone { output, .. } => {
                output.get("decided").cloned()
            }
            _ => None,
        })
        .expect("the awaited decision is on the record");

    // The basis, not only the name. This is the one surface that can say
    // `authenticated` — an `Authenticator` named the caller before the route
    // ran — and a terminal holding the store cannot. Recording every decision
    // the same way would make the strong claim on behalf of the weak one, and
    // an auditor reading `bob` would have no way to tell which happened.
    assert_eq!(
        decided,
        json!({ "by": { "actor": "bob", "basis": "authenticated" } }),
        "the journal must carry what established the decider's name"
    );
}

/// Four-eyes survives the hop.
///
/// Alice proposed the refund and holds the right role. In-process the store
/// refuses her; the question is whether the HTTP path still routes through that
/// refusal rather than around it.
#[tokio::test]
async fn the_proposer_cannot_approve_their_own_proposal_over_http() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("alice"),
            &json!({ "approved": true, "reason": "looks fine to me" }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the proposer approved their own proposal: {body}"
    );

    let found = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(found.state.is_pending(), "the refusal still decided it");

    // And Bob can still do it afterwards — the refusal did not consume the task.
    let (status, _) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": true, "reason": "checked" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// Roles come from the authenticator, so a caller cannot widen their queue.
#[tokio::test]
async fn a_caller_sees_only_the_queue_their_roles_entitle_them_to() {
    let f = fixture();
    f.pending_task().await;
    let router = f.router();

    let (status, body) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tasks"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["tasks"][0]["decidable_by_you"], true);
    assert_eq!(body["truncated"], false);

    // Carol is a clerk. There is nowhere in the request to say otherwise — not a
    // header the authenticator reads, not a query parameter, not a body.
    let (status, body) = send(
        &router,
        get("/tasks?roles=compliance-officer", Some("carol")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["tasks"].as_array().unwrap().len(),
        0,
        "a clerk saw a compliance queue: {body}"
    );
}

/// A barred reviewer is told so on the item, not by a refusal after the fact.
///
/// Alice can see the task — hiding it would leave her wondering where it went —
/// and the item itself says she may not decide it.
#[tokio::test]
async fn the_worklist_says_which_items_this_caller_may_decide() {
    let f = fixture();
    f.pending_task().await;
    let router = f.router();

    let (_, body) = send(&router, get("/tasks", Some("alice"))).await;
    assert_eq!(body["tasks"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(
        body["tasks"][0]["decidable_by_you"], false,
        "the proposer was told she may approve her own proposal"
    );

    let (_, body) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(body["tasks"][0]["decidable_by_you"], true);
}

/// A page that was cut off says so.
///
/// The crate refuses silent truncation everywhere else, and a bare JSON array
/// cannot express it: a queue of 140 items paged at 100 returns 100, and reads
/// exactly like a queue of 100. An operator working a backlog would never learn
/// there was one.
#[tokio::test]
async fn a_truncated_worklist_says_it_was_truncated() {
    let f = fixture();
    // Three tasks, one per run — see `two_runs_of_one_plan_do_not_share_one_task`
    // in tests/tasks.rs for why that is not a given.
    for doc in ["INV-1", "INV-2", "INV-3"] {
        f.rt.run_correlated(
            "demo.refund",
            Tainted::trusted(json!({})),
            "dispute",
            &[CorrelationKey::new("document", doc)],
        )
        .await
        .unwrap();
    }

    let router = Api::new(f.rt.clone(), Arc::new(HeaderAuth))
        .unwrap()
        .limit(2)
        .router();

    let (status, body) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tasks"].as_array().unwrap().len(), 2, "{body}");
    assert_eq!(
        body["truncated"], true,
        "a cut-off page reported itself as the whole queue: {body}"
    );

    // And a page that exactly fills the limit is *not* truncated — inferring it
    // from a full page would cry wolf on every queue of exactly `limit`.
    let router = Api::new(f.rt.clone(), Arc::new(HeaderAuth))
        .unwrap()
        .limit(3)
        .router();
    let (_, body) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(body["tasks"].as_array().unwrap().len(), 3, "{body}");
    assert_eq!(
        body["truncated"], false,
        "a queue that exactly fills the page was called truncated: {body}"
    );
}

/// Stopping a run over HTTP: the actor is the caller, and the answer is 202.
///
/// `202` rather than `200` because the request is durable but the run stops at
/// its next step boundary. Claiming `200` would tell an operator a running agent
/// has already halted when it may not have.
#[tokio::test]
async fn a_run_can_be_stopped_and_the_stopper_is_named() {
    let f = fixture();
    let task = f.pending_task().await;
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .run;
    let router = f.router();

    let (status, body) = send(
        &router,
        post(
            &format!("/runs/{run}/cancel"),
            Some("bob"),
            &json!({ "reason": "counterparty withdrew" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["requested_by"], "bob");
    assert_eq!(body["recorded"], true);

    // The run is stopped, and the view says so.
    let (_, body) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    assert_eq!(body["status"], "cancelled", "{body}");

    // A second operator is told plainly that somebody else owns the
    // intervention, rather than being allowed to believe it was theirs.
    let (status, body) = send(
        &router,
        post(
            &format!("/runs/{run}/cancel"),
            Some("carol"),
            &json!({ "reason": "me too" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["recorded"], false, "{body}");
}

/// A stop request body cannot name the actor either.
#[tokio::test]
async fn a_stop_body_that_names_an_actor_is_refused() {
    let f = fixture();
    let task = f.pending_task().await;
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .run;
    let router = f.router();

    let (status, _) = send(
        &router,
        post(
            &format!("/runs/{run}/cancel"),
            Some("bob"),
            &json!({ "reason": "x", "actor": "alice" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a stop naming somebody else was accepted"
    );
}

/// A pending stop is visible before the run has acted on it.
#[tokio::test]
async fn a_pending_stop_is_visible_on_the_run() {
    let f = fixture();
    let task = f.pending_task().await;
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .run;
    let router = f.router();

    let (_, before) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    assert!(before["cancellation_requested_by"].is_null(), "{before}");

    send(
        &router,
        post(
            &format!("/runs/{run}/cancel"),
            Some("bob"),
            &json!({ "reason": "withdrawn" }),
        ),
    )
    .await;

    let (_, after) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    // Two fields, not a rendered sentence: an operator reading a name needs to
    // know whether an authenticator produced it or whether somebody holding the
    // store typed it, and a client must not have to parse that back out of
    // prose.
    assert_eq!(
        after["cancellation_requested_by"],
        json!({ "actor": "bob", "basis": "authenticated" }),
        "an operator cannot see who asked for the stop, or on what basis: {after}"
    );
}

// ── Claiming ────────────────────────────────────────────────────────────────

/// A claim reserves the task against the rest of the queue.
///
/// Without this the queue is first-past-the-post at *decision* time: two
/// reviewers read the same case in parallel and one of them discovers, at the
/// moment they submit, that the work was wasted.
#[tokio::test]
async fn a_claimed_task_is_reserved_against_other_reviewers() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let (status, body) = send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("bob"), &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "claimed");
    assert_eq!(body["assignee"], "bob");

    // Carol is a clerk, so she is refused for a different reason — use a second
    // eligible reviewer to test contention rather than eligibility.
    let (status, body) = send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("alice"), &json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the proposer claimed a task she may not decide: {body}"
    );

    // And the holder can claim their own again — a retried request must not
    // knock a reviewer off their own work.
    let (status, _) = send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("bob"), &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// Contention and ineligibility are different answers.
///
/// One says try again or ask Bob; the other says this will never be yours.
/// Collapsing them is how a reviewer retries something that cannot succeed.
#[tokio::test]
async fn contention_and_ineligibility_are_told_apart() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("bob"), &json!({})),
    )
    .await;

    // Ineligible: the four-eyes exclusion.
    let (status, body) = send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("alice"), &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("proposed"),
        "the refusal does not say why: {body}"
    );

    // Ineligible for a different reason: the wrong role. Also a 403, and also
    // named — the two call for different fixes.
    let (status, body) = send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("carol"), &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"].as_str().unwrap_or_default().contains("role"),
        "a role refusal reads like a four-eyes refusal: {body}"
    );
}

/// A reviewer can give a task back, and only the holder can.
#[tokio::test]
async fn only_the_holder_can_release_a_claim() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    send(
        &router,
        post(&format!("/tasks/{task}/claim"), Some("bob"), &json!({})),
    )
    .await;

    // Carol is not the holder. The store matches the assignee in the `UPDATE`,
    // so this frees nothing.
    let (status, body) = send(
        &router,
        post(&format!("/tasks/{task}/release"), Some("carol"), &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not held"),
        "the refusal does not say what went wrong: {body}"
    );

    let (_, body) = send(&router, get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(body["assignee"], "bob", "a stranger released Bob's claim");

    let (status, _) = send(
        &router,
        post(&format!("/tasks/{task}/release"), Some("bob"), &json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = send(&router, get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(body["state"], "open");
    assert!(body["assignee"].is_null(), "{body}");
}

// ── Both gates, on every route ──────────────────────────────────────────────

/// The webhook routes. Every build serves them: one without the `push`
/// feature gates them like any other and then answers 501.
fn push_routes(actor: Option<&str>) -> Vec<Request<Body>> {
    vec![
        get("/push", actor),
        post(
            "/push/rearm",
            actor,
            &json!({ "run": "not-an-id", "id": "d" }),
        ),
    ]
}

/// The preservation-register routes.
///
/// Extracted so the walks below are a list of
/// claims, and three more inline request literals in each of them pushes the
/// test past the point where the claim is what a reader sees.
fn hold_routes(actor: Option<&str>) -> Vec<Request<Body>> {
    vec![
        get("/holds", actor),
        get("/holds?state=released", actor),
        post(
            "/holds",
            actor,
            &json!({ "case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "reason": "order" }),
        ),
        post(
            "/holds/release",
            actor,
            &json!({ "case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
        ),
    ]
}

/// The emergency-stop routes.
fn halt_routes(actor: Option<&str>) -> Vec<Request<Body>> {
    vec![
        get("/halts", actor),
        get("/halts?state=lifted", actor),
        post(
            "/halts",
            actor,
            &json!({ "scope": "tenant", "reason": "incident 42" }),
        ),
        post("/halts/lift", actor, &json!({ "scope": "tenant" })),
    ]
}

/// No credentials, no answer — on every route.
#[tokio::test]
async fn an_unauthenticated_request_is_refused_everywhere() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let mut requests = vec![
        get("/runs?outcome=quarantined", None),
        get("/runs/live", None),
        get("/runs/waiting", None),
        get("/attention", None),
        get("/drill", None),
        get("/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV", None),
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/cancel",
            None,
            &json!({ "reason": "stop" }),
        ),
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/reopen",
            None,
            &json!({ "reason": "checked the provider" }),
        ),
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/abandon",
            None,
            &json!({ "reason": "nobody can tell" }),
        ),
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/reconcile",
            None,
            &json!({
                "effect": "0".repeat(64),
                "disposition": "did_not_happen",
                "note": "the provider has no record"
            }),
        ),
        get("/tasks", None),
        get(&format!("/tasks/{task}"), None),
        get("/cases/case_01ARZ3NDEKTSV4RRFFQ69G5FAV", None),
        post(&format!("/tasks/{task}/claim"), None, &json!({})),
        post(&format!("/tasks/{task}/release"), None, &json!({})),
        post(
            &format!("/tasks/{task}/decide"),
            None,
            &json!({ "approved": true, "reason": "" }),
        ),
        post(
            "/events",
            None,
            &json!({ "id": "e", "kind": "k", "correlation": [], "payload": {} }),
        ),
        get("/dead-letters", None),
        post(
            "/obligations/acknowledge",
            None,
            &json!({ "case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "obligation": "ack" }),
        ),
    ];
    requests.extend(hold_routes(None));
    requests.extend(halt_routes(None));
    requests.extend(push_routes(None));
    for req in requests {
        let uri = req.uri().to_string();
        let (status, _) = send(&router, req).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{uri} answered anonymously"
        );
    }

    // A presented-but-rejected credential is the other half of the seam.
    let (status, _) = send(&router, get("/tasks", Some("mallory"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Every route this surface serves, as a request under `bob`'s roles.
///
/// Lifted out of the test rather than inlined because the list is the *data*
/// the test walks: a route added next year belongs here, and a hundred-line
/// function is where an addition stops being noticed.
fn every_declared_route() -> Vec<axum::http::Request<axum::body::Body>> {
    vec![
        get("/runs/not-an-id", Some("bob")),
        // Its own verb, and asked before the id is even parsed: the records of
        // a run are its inputs and every argument it sent, which is not what a
        // deployment granted when it granted the status view.
        get("/runs/not-an-id/history", Some("bob")),
        post(
            "/runs/not-an-id/cancel",
            Some("bob"),
            &json!({ "reason": "stop" }),
        ),
        post(
            "/runs/not-an-id/reopen",
            Some("bob"),
            &json!({ "reason": "checked the provider" }),
        ),
        post(
            "/runs/not-an-id/abandon",
            Some("bob"),
            &json!({ "reason": "nobody can tell" }),
        ),
        post(
            "/runs/not-an-id/reconcile",
            Some("bob"),
            &json!({
                "effect": "0".repeat(64),
                "disposition": "did_not_happen",
                "note": "the provider has no record"
            }),
        ),
        get("/tasks", Some("bob")),
        get("/tasks/not-an-id", Some("bob")),
        get("/cases/not-an-id", Some("bob")),
        post("/tasks/not-an-id/claim", Some("bob"), &json!({})),
        post("/tasks/not-an-id/release", Some("bob"), &json!({})),
        post(
            "/tasks/not-an-id/takeover",
            Some("bob"),
            &json!({ "from": "alice" }),
        ),
        post(
            "/tasks/not-an-id/decide",
            Some("bob"),
            &json!({ "approved": true, "reason": "" }),
        ),
        post(
            "/events",
            Some("bob"),
            &json!({ "id": "e", "kind": "k", "correlation": [], "payload": {} }),
        ),
        // The listing routes — the backlogs, each answering a question whose
        // asker does not already know the answer. Leaving one out here while
        // its verb is also missing from `action::ALL` makes the equality below
        // hold by cancelling omissions, and a deployment enumerating `ALL` then
        // never writes a rule for it.
        get("/runs", Some("bob")),
        get("/runs/live", Some("bob")),
        get("/runs/waiting", Some("bob")),
        get("/attention", Some("bob")),
        get("/drill", Some("bob")),
        get("/cases", Some("bob")),
        get("/obligations", Some("bob")),
        post(
            "/obligations/acknowledge",
            Some("bob"),
            &json!({ "case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "obligation": "ack" }),
        ),
        get("/dead-letters", Some("bob")),
    ]
}

/// Authentication is not authorization: a denying policy stops every route.
///
/// The check is `403`, not `404` or `400` — a route that parses the path or
/// touches the store before asking the policy engine has already leaked whether
/// the thing exists.
#[tokio::test]
async fn a_denying_policy_stops_every_route_before_it_touches_anything() {
    let policy = Arc::new(Recording {
        seen: Mutex::new(Vec::new()),
        deny: true,
    });
    let f = fixture_with(&policy);
    let router = f.router();

    let mut requests = every_declared_route();
    requests.extend(hold_routes(Some("bob")));
    requests.extend(halt_routes(Some("bob")));
    requests.extend(push_routes(Some("bob")));
    for req in requests {
        let uri = req.uri().to_string();
        let (status, body) = send(&router, req).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} got past the policy gate"
        );
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("refuses"),
            "the denial did not carry the policy's reason: {body}"
        );
    }

    // Every route asked, as itself, with the caller's authenticated roles — and
    // between them they covered the whole declared vocabulary. A route asking
    // under somebody else's verb would be authorized by somebody else's rule.
    let asked = policy.asked();
    let mut actions: Vec<String> = asked.iter().map(|(_, a, _)| a.clone()).collect();
    actions.sort_unstable();
    actions.dedup();
    let mut declared: Vec<String> = action::ALL.iter().map(|s| (*s).to_owned()).collect();
    declared.sort_unstable();
    assert_eq!(
        actions, declared,
        "the routes and the declared action list disagree"
    );
    assert!(
        asked
            .iter()
            .all(|(p, _, r)| p == "bob" && r == &["compliance-officer".to_owned()]),
        "a route asked the policy engine about the wrong principal or roles: {asked:?}"
    );
}

/// A surface with no authorization layer does not start.
#[test]
fn the_surface_refuses_to_build_without_a_policy_engine() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>).build();

    let err = Api::new(rt, Arc::new(HeaderAuth)).unwrap_err();
    assert!(matches!(err, ApiSetupError::NoPolicy));
    assert!(
        err.to_string().contains("DenyAll"),
        "the refusal does not say how to fix it: {err}"
    );
}

/// Every documented operation is exercised by a test in this file.
///
/// The gate tests above are only as good as the list of routes they walk. A
/// route added next year would be authenticated and authorized by construction —
/// `gate` is the only way to get a `Caller` — but nothing would prove it, and
/// "nothing proves it" is how the first ungated route gets written.
#[test]
fn every_route_is_walked_by_the_gate_tests() {
    let here = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/wire/api.rs"))
        .expect("this file");

    for route in ROUTES {
        // `/tasks/{task}` in the table is `/tasks/not-an-id` in a request, so
        // the comparison is on the fixed prefix rather than the whole path.
        let prefix: String = route.path.split('{').next().unwrap_or_default().to_owned();
        assert!(
            here.contains(&format!("\"{prefix}")) || here.contains(&format!("(\"{prefix}")),
            "route {} is documented but no test in tests/wire/api.rs walks it",
            route.path
        );
    }
    assert!(
        ROUTES.len() >= 9,
        "found only {} routes — this check read the wrong thing",
        ROUTES.len()
    );
}

// ── The document and the router are one table ───────────────────────────────

/// A body each operation that takes one accepts, so a walk reaches the gate.
///
/// An operation with a body and no example here fails the walks that need
/// one, so a route added to the table is added here too.
fn example_body(operation: &str) -> Value {
    let case = "case_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    match operation {
        "cancel_run" => json!({ "reason": "stop" }),
        "reopen_run" | "abandon_run" => json!({ "reason": "checked the provider" }),
        "reconcile_effect" => json!({
            "effect": "0".repeat(64),
            "disposition": "did_not_happen",
            "note": "the provider has no record",
        }),
        "take_over_task" => json!({ "from": "alice" }),
        "decide_task" => json!({ "approved": true, "reason": "" }),
        "acknowledge_obligation" => json!({ "case": case, "obligation": "ack" }),
        "place_hold" => json!({ "case": case, "reason": "order" }),
        "release_hold" => json!({ "case": case }),
        "place_halt" => json!({ "scope": "tenant", "reason": "incident 42" }),
        "lift_halt" => json!({ "scope": "tenant" }),
        "deliver_event" => json!({ "id": "e", "kind": "k", "correlation": [], "payload": {} }),
        "rearm_push" => json!({ "run": "not-an-id", "id": "d" }),
        other => panic!("no example body for {other}"),
    }
}

/// A request for one documented operation, its path parameters filled.
fn request_for(route: &Route, actor: Option<&str>) -> Request<Body> {
    let path = route
        .path
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') {
                "not-an-id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    match (route.method.as_str(), route.body) {
        ("get", _) => get(&path, actor),
        (_, Some(_)) => post(&path, actor, &example_body(route.operation)),
        _ => post(&path, actor, &json!({})),
    }
}

/// **Every route the router serves is a documented operation, and nothing else.**
///
/// The router is built from the table the document is generated from, so the
/// one way to serve an undocumented route is to add one beside the table. This
/// reads the module for exactly that.
#[test]
fn every_routed_operation_is_documented_and_no_other() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/mod.rs"))
        .expect("the api module");
    let code: String = src
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");

    let served: Vec<&str> = code
        .split(".route(")
        .skip(1)
        .map(|call| call.split([',', ')']).next().unwrap_or_default().trim())
        .collect();
    assert_eq!(
        served,
        ["route.path"],
        "a route is served beside the table the document is generated from"
    );
    for elsewhere in [".nest(", ".merge(", ".fallback(", ".route_service("] {
        assert!(
            !code.contains(elsewhere),
            "the operator router is extended with {elsewhere} outside the table"
        );
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    for route in ROUTES {
        assert!(
            seen.insert((route.method.as_str(), route.path)),
            "{} {} is in the table twice",
            route.method.as_str(),
            route.path
        );
        assert!(
            names.insert(route.operation),
            "{} is named twice",
            route.operation
        );
        // The document is published, never served: an unauthenticated route
        // would be the first exception to the gate, and a gated one is useless
        // to a generator.
        assert!(
            !route.path.contains("openapi") && route.operation != "openapi",
            "the operator API serves its own document at {}",
            route.path
        );
        let documented = &document()["paths"][route.path][route.method.as_str()];
        assert_eq!(
            documented["operationId"],
            route.operation,
            "{} {} is not in the document",
            route.method.as_str(),
            route.path
        );
    }
    let documented: usize = document()["paths"]
        .as_object()
        .expect("paths")
        .values()
        .map(|item| item.as_object().map_or(0, serde_json::Map::len))
        .sum();
    assert_eq!(
        documented,
        ROUTES.len(),
        "the document lists an operation the table does not"
    );
}

/// **The dispositions the document enumerates are the ones reconcile accepts.**
///
/// A client that validates against the document sends only the listed values;
/// a value listed and refused, or accepted and unlisted, is a reconcile that
/// cannot be written from the document.
#[tokio::test]
async fn the_documented_dispositions_are_the_ones_reconcile_accepts() {
    let f = fixture();
    let router = f.router();
    let document = agentplane::api::openapi::document();
    let listed: Vec<String> =
        document["components"]["schemas"]["ReconcileRequest"]["properties"]["disposition"]["enum"]
            .as_array()
            .expect("the document enumerates the dispositions")
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
    let refused = |body: &Value| {
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("'disposition' must be")
    };
    let run = agentplane::core::RunId::generate().to_string();
    let reconcile = |disposition: &str| {
        let mut body = json!({ "effect": "0".repeat(64), "disposition": disposition, "note": "n" });
        if disposition == "landed" {
            body["output"] = json!({ "ok": true });
        }
        post(&format!("/runs/{run}/reconcile"), Some("bob"), &body)
    };
    for disposition in &listed {
        let (_, body) = send(&router, reconcile(disposition)).await;
        assert!(
            !refused(&body),
            "{disposition} is listed and refused: {body}"
        );
    }
    let (status, body) = send(&router, reconcile("maybe")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(refused(&body), "{body}");
    assert_eq!(
        listed.len(),
        2,
        "the handler accepts two dispositions: {listed:?}"
    );
}

/// **Every documented operation is served, and asks the action it documents.**
///
/// Under a policy that refuses everything, a served route answers `403` — a
/// `404` or `405` is a documented operation the router does not serve — and
/// the action the policy was asked is the one the document names.
#[tokio::test]
async fn every_documented_operation_answers_through_the_router() {
    let policy = Arc::new(Recording {
        seen: Mutex::new(Vec::new()),
        deny: true,
    });
    let f = fixture_with(&policy);
    let router = f.router();

    for route in ROUTES {
        let request = request_for(route, Some("bob"));
        let (status, body) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{} {} is documented and not served as documented: {body}",
            route.method.as_str(),
            route.path
        );
        let asked = policy.asked();
        let (_, action, _) = asked.last().expect("the policy was asked");
        assert_eq!(
            action,
            route.action,
            "{} {} documents {} and asks {action}",
            route.method.as_str(),
            route.path,
            route.action
        );
    }
}

/// **A refused body answers with the documented error object.**
///
/// axum's extractors refuse in plain text, with the statuses a client must tell
/// apart: malformed JSON, a body not sent as JSON, a member the operation does
/// not take. Each answers its own status and `{"error": "<sentence>"}`, the
/// shape every other refusal takes.
#[tokio::test]
async fn a_refused_body_answers_with_the_documented_error() {
    let f = fixture();
    let router = f.router();
    let raw = |route: &Route, content_type: &str, body: &str| {
        let path = route
            .path
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') {
                    "not-an-id"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        Request::builder()
            .uri(path)
            .method("POST")
            .header("content-type", content_type)
            .header("x-actor", "bob")
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    let error_only = |body: &Value| {
        body.as_object().is_some_and(|o| {
            o.len() == 1 && o["error"].as_str().is_some_and(|e| !e.trim().is_empty())
        })
    };

    let mut walked = 0;
    for route in ROUTES {
        let Some(shape) = route.body else { continue };
        let mut extra = example_body(route.operation);
        extra["unexpected"] = json!(1);
        let mut cases = vec![
            (raw(route, "application/json", "{"), StatusCode::BAD_REQUEST),
            (
                raw(route, "application/json", &extra.to_string()),
                if matches!(shape, Shape::Json(_)) {
                    StatusCode::UNPROCESSABLE_ENTITY
                } else {
                    StatusCode::BAD_REQUEST
                },
            ),
        ];
        if matches!(shape, Shape::Json(_)) {
            cases.push((
                raw(
                    route,
                    "text/plain",
                    &example_body(route.operation).to_string(),
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ));
        }
        for (request, wanted) in cases {
            let (status, body) = send(&router, request).await;
            assert_eq!(status, wanted, "{}: {body}", route.operation);
            assert!(
                error_only(&body),
                "{} refused without the error object: {body}",
                route.operation
            );
            walked += 1;
        }
    }
    assert!(
        walked >= 30,
        "walked only {walked} refusals — this check read the wrong thing"
    );
}

/// **Every answer is the body the document gives its operation and status**,
/// including the refusals only a particular plane can provoke: a store it was
/// built without, and a decision naming a stale version.
#[tokio::test]
async fn a_response_validates_against_the_document() {
    // The validator itself: a status an operation does not list is refused.
    assert!(conforms("GET", "/tasks", StatusCode::IM_A_TEAPOT, b"{}").is_err());
    assert!(
        conforms(
            "GET",
            "/tasks",
            StatusCode::OK,
            br#"{"tasks": [], "truncated": false, "more": 1}"#
        )
        .is_err()
    );

    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();
    let (status, view) = send(&router, get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert!(view["digest"].is_string(), "{view}");
    for request in [
        get("/tasks", Some("bob")),
        get("/runs?outcome=quarantined", Some("bob")),
        get("/runs/waiting", Some("bob")),
        get("/attention", Some("bob")),
        get("/drill", Some("bob")),
        get("/cases?status=open", Some("bob")),
        get("/obligations", Some("bob")),
        get("/holds", Some("bob")),
        get("/dead-letters", Some("bob")),
        post(&format!("/tasks/{task}/claim"), Some("bob"), &json!({})),
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": false, "reason": "no", "digest": Digest::of(b"stale").to_hex() }),
        ),
    ] {
        let (status, body) = send(&router, request).await;
        assert!(
            status.is_success() || status == StatusCode::PRECONDITION_FAILED,
            "{status}: {body}"
        );
    }

    // A plane with no quota store answers 501 on the routes that need one.
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let bare = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();
    for route in ROUTES
        .iter()
        .filter(|r| r.errors.contains(&ErrorClass::NotWired))
    {
        let (status, body) = send(&bare, request_for(route, Some("bob"))).await;
        assert!(
            status == StatusCode::NOT_IMPLEMENTED || status == StatusCode::BAD_REQUEST,
            "{}: {status} {body}",
            route.operation
        );
    }
    let (status, _) = send(&bare, get("/runs/live", Some("bob"))).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
}

// ── What an operator sees ───────────────────────────────────────────────────

/// A suspended run says what it is waiting for.
#[tokio::test]
async fn a_suspended_run_reports_what_it_is_waiting_for() {
    let f = fixture();
    let task = f.pending_task().await;
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .run;
    let router = f.router();

    let (status, body) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "suspended");
    assert!(
        body["waiting_for"]
            .as_str()
            .unwrap_or_default()
            .contains("awaiting"),
        "a suspended run did not say what it waits for: {body}"
    );
    assert_eq!(body["sealed"], false);
    assert!(body["case"].is_string(), "the case is not reported: {body}");
}

/// A run that suspended, resumed, and finished is not reported as suspended.
///
/// The obvious implementation scans the journal for a `RunSuspended` and reports
/// suspension if it finds one. Every run that ever waited for a human has one,
/// forever — so every completed approval flow would show up on an operator's
/// screen as permanently stuck, which is worse than showing nothing at all.
#[tokio::test]
async fn a_resumed_run_is_not_still_reported_as_suspended() {
    let f = fixture();
    let task = f.pending_task().await;
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .run;
    let router = f.router();

    let (status, _) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": true, "reason": "checked" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    assert_ne!(
        body["status"], "suspended",
        "a run that resumed and finished still reads as stuck: {body}"
    );
    assert!(
        body["waiting_for"].is_null(),
        "a finished run still claims to be waiting: {body}"
    );
    assert_eq!(body["sealed"], true, "{body}");
}

/// A failed run's view says why, and a successful one carries no reason.
///
/// The sealed twin of `waiting_for`: "failed" alone sends an operator into
/// the journal for the one sentence the seal already records. The absence
/// half matters equally — a success with a `reason` key would read as a
/// failure with no explanation.
#[tokio::test]
async fn a_failed_runs_view_carries_the_reason_the_seal_records() {
    #[derive(Debug)]
    struct Refuses;

    #[async_trait::async_trait]
    impl Skill for Refuses {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("refuses").provides("demo.refusal")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::fail(
                "the counterparty ledger refused the transfer",
            ))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(Refuses)
        .build();
    let out = rt
        .run("demo.refusal", Tainted::trusted(json!({})))
        .await
        .unwrap();
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();

    let (status, body) = send(&router, get(&format!("/runs/{}", out.run_id), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "failed", "{body}");
    assert_eq!(
        body["reason"], "the counterparty ledger refused the transfer",
        "the view must say what the seal says: {body}"
    );
    assert_eq!(
        body["sealed"], false,
        "a resumable failed conclusion was reported as a closed journal: {body}"
    );
}

/// A failed run a resume retried to the same failure still reads as failed.
///
/// A plane on one backend has its quota ledger wired, so every resume opens
/// a quota pass. A pass that wrote nothing must leave no marker behind the
/// conclusion: the view reads the run's last record, and a marker there
/// reports a failed run as still running.
#[tokio::test]
async fn a_failed_run_resumed_to_the_same_failure_still_reads_as_failed() {
    #[derive(Debug)]
    struct Refuses;

    #[async_trait::async_trait]
    impl Skill for Refuses {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("refuses").provides("demo.refusal")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::fail("the dependency is still down"))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder_on(store)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(Refuses)
        .build();
    let out = rt
        .run("demo.refusal", Tainted::trusted(json!({})))
        .await
        .unwrap();
    for _ in 0..2 {
        rt.replay(out.run_id, agentplane::runtime::Mode::Resume)
            .await
            .unwrap();
    }
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();

    let (status, body) = send(&router, get(&format!("/runs/{}", out.run_id), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "failed", "{body}");
}

/// Exhaustion stays machine-readable through the operator surface.
#[tokio::test]
async fn an_exhausted_runs_view_carries_the_typed_ceiling() {
    #[derive(Debug)]
    struct Exhausts;

    #[async_trait::async_trait]
    impl Skill for Exhausts {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("exhausts").provides("demo.exhausts")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Err(StepError::Budget(BudgetExceeded::Effects {
                allowed: 3,
                used: 3,
            })
            .into())
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(Exhausts)
        .build();
    let out = rt
        .run("demo.exhausts", Tainted::trusted(json!({})))
        .await
        .unwrap();
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();

    let (status, body) = send(&router, get(&format!("/runs/{}", out.run_id), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "exhausted", "{body}");
    assert_eq!(body["exhaustion"]["limit"], "effects", "{body}");
    assert_eq!(body["exhaustion"]["allowed"], 3, "{body}");
    assert_eq!(body["exhaustion"]["used"], 3, "{body}");
    assert_eq!(body["sealed"], false, "{body}");
}

/// **A run's journal is readable from the surface that answers about runs.**
///
/// The status view serves a *count* of records, which answers "is it doing
/// anything" and nothing about what it did. `GET /cases/{case}` has always
/// served the records of a matter, so the asymmetry was the tell: a plane whose
/// thesis is that the journal is the plan of record had no in-band way to read
/// one run's journal, leaving `agentplane export` — an offline artifact over the
/// whole plane — as the answer to a question about one run.
///
/// The cursor is asserted rather than the contents: what makes a bounded
/// history usable is that a reader can continue it, and a `truncated` flag with
/// no cursor beside it tells somebody there is more without telling them where.
#[tokio::test]
async fn a_runs_journal_is_readable_and_pages_from_a_cursor() {
    let f = fixture();
    let router = f.router();
    let task = f.pending_task().await;
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).expect("a task id"))
        .await
        .unwrap()
        .expect("the task")
        .run;

    let (status, body) = send(&router, get(&format!("/runs/{run}/history"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let records = body["records"].as_array().expect("records");
    assert!(
        records.len() > 1,
        "a completed run has a history worth reading: {body}"
    );
    assert_eq!(records[0]["seq"], 1, "{body}");
    assert_eq!(records[0]["kind"], "RunAdmitted", "{body}");
    assert!(
        records[0]["record"].is_object(),
        "the record itself, not only its name: {body}"
    );

    // The envelope, not only the payload. Without it a reader sees that an
    // effect started and not *which* effect, cannot pair a start with its
    // outcome or one attempt with the next, and cannot carry a row back to the
    // span that performed it — which is what `agentplane.effect.key` is for.
    let started = records
        .iter()
        .find(|r| r["kind"] == "EffectStarted")
        .unwrap_or_else(|| panic!("a completed run performed an effect: {body}"));
    assert!(
        started["effect_key"]
            .as_str()
            .is_some_and(|k| !k.is_empty()),
        "a record about an effect does not say which effect: {started}"
    );
    assert!(
        started["step"].as_str().is_some_and(|s| !s.is_empty()),
        "a record written inside a step does not name it: {started}"
    );
    assert_eq!(
        started["phase"], "forward",
        "a reader must not have to know the default to read the absence: {started}"
    );

    assert_eq!(body["truncated"], false, "this run fits in a page: {body}");
    assert!(
        body["next_from"].is_null(),
        "a complete page hands back no cursor, or a caller loops on it forever: {body}"
    );

    // A cursor past the first record skips exactly it, which is what makes the
    // read resumable for a consumer that already has the prefix.
    let (status, body) = send(
        &router,
        get(&format!("/runs/{run}/history?from=2"), Some("bob")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["from"], 2, "{body}");
    assert_eq!(body["records"][0]["seq"], 2, "{body}");

    // Past the end is an empty page, not a 404: the run exists and the reader
    // has caught up, which are different facts from "no such run".
    let (status, body) = send(
        &router,
        get(&format!("/runs/{run}/history?from=100000"), Some("bob")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["records"].as_array().expect("records").is_empty(),
        "{body}"
    );

    let (status, _) = send(
        &router,
        get("/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/history", Some("bob")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown run is not an empty one"
    );
}

/// An unknown run is a 404, and a malformed one a 400 — after the gate.
#[tokio::test]
async fn an_unknown_run_is_not_confused_with_a_malformed_one() {
    let f = fixture();
    let router = f.router();

    let (status, _) = send(&router, get("/runs/not-an-id", Some("bob"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &router,
        get("/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV", Some("bob")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── The backlogs an alert points at ─────────────────────────────────────────

/// A dead letter is readable by the person the alert reaches.
///
/// `agentplane.event.dead_lettered` says *how many* messages arrived and found
/// nobody; the index behind it named them and nothing served it, so an operator
/// holding the alert had to open the database. A count with no listing behind
/// it is detection without delivery.
///
/// And the listing is the *diagnosis*, not the message: a dead letter means a
/// correlation key does not match what a run subscribed to, so the keys are
/// what it carries — and the counterparty's payload is what it does not.
#[tokio::test]
async fn a_dead_letter_is_readable_and_carries_no_payload() {
    use agentplane::core::{InboundEvent, Timestamp};

    let f = fixture();
    let events = f.store.clone() as Arc<dyn EventStore>;
    let arrived = Timestamp::from_unix_timestamp(1_700_000_000).unwrap();
    let event = InboundEvent {
        source: "acme.erp".into(),
        id: "MSG-1".into(),
        kind: "acknowledgement.received".into(),
        correlation: vec![CorrelationKey::new("document", "INV-9")],
        payload: json!({ "iban": "DE02120300000000202051" }),
        by: None,
    };
    events.buffer(&event, arrived).await.unwrap();
    let retired = events
        .sweep_unclaimed(
            Timestamp::from_unix_timestamp(1_700_000_600).unwrap(),
            "no run claimed this event within the grace window",
        )
        .await
        .unwrap();
    assert_eq!(retired, 1);

    let (status, body) = send(&f.router(), get("/dead-letters", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let letter = &body["dead_letters"][0];
    assert_eq!(letter["source"], "acme.erp");
    assert_eq!(letter["id"], "MSG-1");
    assert_eq!(letter["correlation"][0]["value"], "INV-9");
    assert!(
        letter["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "an operator needs the sweep's own words: {letter}"
    );
    assert_eq!(body["truncated"], false);
    assert!(
        !body.to_string().contains("DE02120300000000202051"),
        "the counterparty's payload has no business on a diagnostic listing: {body}"
    );
}

/// A parked webhook registration is listed, and re-arming one is answered
/// honestly.
///
/// Parking exists so the cursor survives a receiver that stopped accepting
/// deliveries — its own docs call that "the difference between a backlog an
/// operator can act on and a warning line in yesterday's logs", and until this
/// route neither the listing nor the re-arm had a caller anywhere.
#[cfg(feature = "push")]
#[tokio::test]
async fn a_parked_registration_is_listed_and_re_armed() {
    use agentplane::core::Secret;
    use agentplane::push::{PushConfig, PushStore};

    let f = fixture();
    let push = f.store.clone() as Arc<dyn PushStore>;
    let run = agentplane::core::RunId::generate();
    let config = PushConfig {
        id: "receiver-1".into(),
        task: run,
        url: "https://receiver.example/hook".into(),
        token: Some(Secret::new("a-correlation-secret")),
        authentication: None,
    };
    push.put(&config, 1).await.unwrap();
    push.park(run, "receiver-1", "410 Gone").await.unwrap();

    let router = f.router();
    let (status, body) = send(&router, get("/push", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["parked"][0]["config"]["id"], "receiver-1");
    assert_eq!(body["parked"][0]["last_error"], "410 Gone");
    assert!(
        !body.to_string().contains("a-correlation-secret"),
        "a listing is not where a receiver's token is handed back: {body}"
    );

    let (status, body) = send(
        &router,
        post(
            "/push/rearm",
            Some("bob"),
            &json!({ "run": run.to_string(), "id": "receiver-1" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rearmed"], true, "{body}");
    assert!(
        push.parked(10).await.unwrap().is_empty(),
        "re-arming has to take it off the backlog it was on"
    );

    // Already live: an answer, not a silence. An operator told nothing waits
    // for a sweep that has nothing to do.
    let (status, body) = send(
        &router,
        post(
            "/push/rearm",
            Some("bob"),
            &json!({ "run": run.to_string(), "id": "receiver-1" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rearmed"], false, "{body}");
}

/// A mistyped id is a 404, a state refusal a 409 — never one status for both.
///
/// The cancel and decide routes classify what the runtime refused: an id that
/// names nothing sends the operator to check their copy-paste, a conflict
/// sends them to read who got there first. Answered as one status, the
/// operator with a typo goes hunting for a record that does not exist.
#[tokio::test]
async fn a_mistyped_id_is_a_404_not_a_conflict() {
    let f = fixture();
    let router = f.router();

    // A well-formed run id that names nothing.
    let (status, body) = send(
        &router,
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/cancel",
            Some("bob"),
            &json!({ "reason": "mistyped" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // A well-formed task id that names nothing. The decide route answers with
    // the claim protocol's own classification — the same one the claim route
    // uses — so an unknown task is not dressed up as an eligibility refusal.
    let missing = "0".repeat(64);
    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{missing}/decide"),
            Some("bob"),
            &json!({ "approved": true, "reason": "sure" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// The case history's truncation flag is a fact, not an inference from a full
/// page: a matter with exactly the limit's worth of records is complete, and
/// one past it is cut — the same one-more-than-the-page rule every list route
/// here follows.
#[tokio::test]
async fn a_case_history_of_exactly_the_limit_is_not_called_truncated() {
    let f = fixture();
    let task = f.pending_task().await;
    let case = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .case
        .expect("the run was opened in a case");

    // However many records this matter actually has, ask for exactly that many.
    let full = (f.store.clone() as Arc<dyn JournalStore>)
        .case_history(case, 1000)
        .await
        .unwrap()
        .len();
    assert!(full > 1, "the fixture's case must have some history");

    let at_limit = Api::new(f.rt.clone(), Arc::new(HeaderAuth))
        .unwrap()
        .history_limit(full)
        .router();
    let (status, body) = send(&at_limit, get(&format!("/cases/{case}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["history"].as_array().unwrap().len(), full);
    assert_eq!(
        body["history_truncated"], false,
        "a history of exactly the limit is complete, not cut off: {body}"
    );

    let past_limit = Api::new(f.rt.clone(), Arc::new(HeaderAuth))
        .unwrap()
        .history_limit(full - 1)
        .router();
    let (status, body) = send(&past_limit, get(&format!("/cases/{case}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["history"].as_array().unwrap().len(), full - 1);
    assert_eq!(
        body["history_truncated"], true,
        "a history one past the limit was shortened, and the response must say so: {body}"
    );
}

/// The case view carries the deadlines, because "when does this stop being my
/// problem" is the question that follows "what is this".
#[tokio::test]
async fn the_case_view_carries_its_deadlines() {
    let f = fixture();
    let task = f.pending_task().await;
    let case = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .case
        .expect("the run was opened in a case");
    let router = f.router();

    let (status, body) = send(&router, get(&format!("/cases/{case}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Ids serialize bare and display prefixed; `parse` accepts both, so this is
    // the round trip an operator's client actually performs.
    assert_eq!(
        agentplane::CaseId::parse(body["case"]["id"].as_str().unwrap()).unwrap(),
        case
    );
    let deadlines = body["deadlines"].as_array().expect("deadlines");
    assert_eq!(deadlines.len(), 1, "{body}");
    assert_eq!(deadlines[0]["name"], "approval");
}

/// Delivery reports what happened in a word a client can key on.
#[tokio::test]
async fn event_delivery_reports_the_outcome_by_name() {
    let f = fixture();
    let router = f.router();

    let event = json!({
        "id": "evt-1",
        "kind": "acknowledgement.received",
        "correlation": [{ "namespace": "document", "value": "INV-9" }],
        "payload": { "ok": true }
    });

    let (status, body) = send(&router, post("/events", Some("bob"), &event)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivery"], "buffered");

    // A counterparty that retries must not be punished for it.
    let (status, body) = send(&router, post("/events", Some("bob"), &event)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["delivery"], "duplicate");
}

/// A task's answer, as an outside party would forge it.
///
/// Everything in it is readable by a caller: the kind is the plane's own
/// constant, and the correlation is the task id `GET /tasks` serves.
fn forged_decision(task: &str) -> Value {
    json!({
        "id": format!("forged-{task}"),
        "kind": "agentplane.task.decided",
        "correlation": [{ "namespace": "task", "value": task }],
        "payload": serde_json::to_value(agentplane::core::Decision::approve(
            agentplane::core::Operator::asserted("bob").unwrap(),
            "approved",
        ))
        .unwrap()
    })
}

/// **A task is decided on the worklist, never by posting its answer.**
///
/// A run waiting on a human task is woken by an event of a kind this plane
/// mints, correlated by the task's id. Accepted from `POST /events`, that
/// message decides the task for whoever may post an event — Carol, a clerk
/// the task's roles exclude, approving as Bob with no claim, no eligibility
/// check and no four-eyes. The policy here permits every delivery, so the
/// refusal cannot be the gate's; it is the namespace's.
#[tokio::test]
async fn a_decision_posted_as_an_event_is_forbidden() {
    let f = fixture();
    let task = f.pending_task().await;
    let task_id = agentplane::core::TaskId::parse(&task).unwrap();
    let run = (f.store.clone() as Arc<dyn TaskStore>)
        .task(task_id)
        .await
        .unwrap()
        .unwrap()
        .run;
    let router = f.router();

    let (status, body) = send(
        &router,
        post("/events", Some("carol"), &forged_decision(&task)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a clerk answered a compliance officer's task by posting its answer: {body}"
    );

    assert!(
        (f.store.clone() as Arc<dyn TaskStore>)
            .task(task_id)
            .await
            .unwrap()
            .unwrap()
            .state
            .is_pending(),
        "the forged answer decided the task"
    );
    assert!(
        (f.store.clone() as Arc<dyn JournalStore>)
            .waiting_runs(10)
            .await
            .unwrap()
            .iter()
            .any(|w| w.run == run),
        "the forged answer resumed the run"
    );
}

/// **A forged answer posted before its task opens is not held for it.**
///
/// An event nobody waits for is buffered, so the task that opens later finds it
/// already there and takes it as its answer. Refused at the door, it is never
/// in the buffer to be found.
#[tokio::test]
async fn a_decision_posted_before_its_task_opens_is_not_buffered() {
    let f = fixture();
    let router = f.router();
    // A task id is derived from its run and its wait, so an attacker who can
    // predict both can post ahead of the task; any id stands in for one here.
    let ahead = "7".repeat(64);

    let (status, body) = send(
        &router,
        post("/events", Some("carol"), &forged_decision(&ahead)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        f.rt.sweep_events(std::time::Duration::ZERO).await.unwrap(),
        0,
        "the refused answer sat in the buffer, where a task opening later would claim it"
    );
}

/// A store failure does not describe the store, and a store this plane was
/// built without is one answer on every route: 501, naming the store.
#[tokio::test]
async fn a_missing_store_does_not_describe_the_plane() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();

    let task = [
        get("/tasks", Some("bob")),
        post(
            &format!("/tasks/{}/decide", "7".repeat(64)),
            Some("bob"),
            &json!({ "approved": true, "reason": "" }),
        ),
    ];
    for request in task {
        let route = request.uri().path().to_owned();
        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{route}: {body}");
        assert_eq!(body["error"], "this plane has no task store", "{route}");
    }

    let (status, body) = send(
        &router,
        post(
            "/events",
            Some("bob"),
            &json!({ "id": "e", "kind": "k", "correlation": [], "payload": {} }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert_eq!(body["error"], "this plane has no event store");

    let quota = [
        get("/halts", Some("bob")),
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "tenant", "reason": "incident 3" }),
        ),
        post("/halts/lift", Some("bob"), &json!({ "scope": "tenant" })),
        get("/runs/live", Some("bob")),
    ];
    for request in quota {
        let route = request.uri().path().to_owned();
        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{route}: {body}");
        assert_eq!(body["error"], "this plane has no quota store", "{route}");
    }
    // Built with the `push` feature or without it, the answer is the same.
    let push = [
        get("/push", Some("bob")),
        post(
            "/push/rearm",
            Some("bob"),
            &json!({ "run": agentplane::core::RunId::generate().to_string(), "id": "receiver-1" }),
        ),
    ];
    for request in push {
        let route = request.uri().path().to_owned();
        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{route}: {body}");
        assert_eq!(body["error"], "this plane has no push store", "{route}");
    }
}

/// An event store whose writes fail with a message naming its connection.
#[derive(Debug)]
struct LeakyEvents(Arc<RedbStore>);

#[async_trait::async_trait]
impl EventStore for LeakyEvents {
    async fn buffer(
        &self,
        _event: &agentplane::core::InboundEvent,
        _at: agentplane::core::Timestamp,
    ) -> Result<bool, agentplane::core::StoreError> {
        Err(agentplane::core::StoreError::Backend(
            "connection refused: dsn=secret".into(),
        ))
    }
    async fn subscribe(
        &self,
        sub: &agentplane::core::Subscription,
        at: agentplane::core::Timestamp,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.subscribe(sub, at).await
    }
    async fn claim_for(
        &self,
        sub: &agentplane::core::Subscription,
        at: agentplane::core::Timestamp,
    ) -> Result<Option<agentplane::case::BufferedEvent>, agentplane::core::StoreError> {
        self.0.claim_for(sub, at).await
    }
    async fn match_waiter(
        &self,
        event: &agentplane::core::InboundEvent,
        at: agentplane::core::Timestamp,
    ) -> Result<Option<agentplane::core::Subscription>, agentplane::core::StoreError> {
        self.0.match_waiter(event, at).await
    }
    async fn deliver_to(
        &self,
        run: agentplane::core::RunId,
        event: &agentplane::core::InboundEvent,
        at: agentplane::core::Timestamp,
    ) -> Result<agentplane::case::TargetedDelivery, agentplane::core::StoreError> {
        self.0.deliver_to(run, event, at).await
    }
    async fn unsubscribe(
        &self,
        run: agentplane::core::RunId,
        effect: agentplane::core::EffectKey,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.unsubscribe(run, effect).await
    }
    async fn unsubscribe_run(
        &self,
        run: agentplane::core::RunId,
        unanswered: &[agentplane::core::EffectKey],
    ) -> Result<agentplane::case::Retired, agentplane::core::StoreError> {
        self.0.unsubscribe_run(run, unanswered).await
    }
    async fn park_wait(
        &self,
        sub: &agentplane::core::Subscription,
        at: agentplane::core::Timestamp,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.park_wait(sub, at).await
    }
    async fn parked_waits(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::core::Subscription>, agentplane::core::StoreError> {
        self.0.parked_waits(limit).await
    }
    async fn minter(
        &self,
        source: &str,
        id: &str,
    ) -> Result<Option<agentplane::case::Minter>, agentplane::core::StoreError> {
        self.0.minter(source, id).await
    }
    async fn erase_payload(
        &self,
        source: &str,
        id: &str,
    ) -> Result<bool, agentplane::core::StoreError> {
        self.0.erase_payload(source, id).await
    }
    async fn sweep_unclaimed(
        &self,
        older_than: agentplane::core::Timestamp,
        reason: &str,
    ) -> Result<usize, agentplane::core::StoreError> {
        self.0.sweep_unclaimed(older_than, reason).await
    }
    async fn dead_letters(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::core::DeadLetter>, agentplane::core::StoreError> {
        self.0.dead_letters(limit).await
    }
    async fn waiting(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::core::Subscription>, agentplane::core::StoreError> {
        self.0.waiting(limit).await
    }
}

/// A store outage is a 503 a bus retries, and it does not describe the store.
///
/// The backend's own message carries its DSN, host and table; a counterparty
/// posting an event learns only that the plane could not take it right now.
#[tokio::test]
async fn an_event_store_outage_does_not_describe_the_store() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .events(Arc::new(LeakyEvents(Arc::clone(&store))) as Arc<dyn EventStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();
    let event = json!({"id": "evt-1", "kind": "acknowledgement.received", "payload": {}});
    let (status, body) = send(&router, post("/events", Some("bob"), &event)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        !body.to_string().contains("dsn=secret"),
        "the store's own error reached the caller: {body}"
    );
}

/// A caller cannot choose the source of the event it delivers.
///
/// `source` is half the deduplication identity and the sender's name in
/// provenance. A body that set it would hand a caller both halves of
/// `(source, id)` — so one counterparty could deduplicate against another's
/// messages by naming them, or post under a name a policy trusts. It comes from
/// the transport's authenticated identity instead.
#[tokio::test]
async fn a_delivered_events_source_is_the_authenticated_caller() {
    let f = fixture();
    let router = f.router();

    // The body claims to be somebody else. The claim is simply not read.
    let response = send(
        &router,
        post(
            "/events",
            Some("alice"),
            &json!({
                "source": "urn:someone-else",
                "id": "EV-SRC-1",
                "kind": "acknowledgement.received",
                "correlation": [],
                "payload": {}
            }),
        ),
    )
    .await;
    assert_eq!(
        response.0,
        StatusCode::OK,
        "an unknown `source` field must be ignored, not rejected — a caller \
         sending one is mistaken, not hostile: {:?}",
        response.1
    );

    // Same id, same *actual* source, so it deduplicates — proving the source
    // used was the caller's and not the two different ones in the bodies.
    let again = send(
        &router,
        post(
            "/events",
            Some("alice"),
            &json!({
                "source": "urn:a-third-name",
                "id": "EV-SRC-1",
                "kind": "acknowledgement.received",
                "correlation": [],
                "payload": {}
            }),
        ),
    )
    .await;
    assert_eq!(
        again.1["delivery"], "duplicate",
        "the two bodies named different sources and still deduplicated, which \
         is only true if the body's claim was ignored: {:?}",
        again.1
    );

    // And the half that proves the source is the *caller* rather than some
    // constant: a different caller sending the same id is a different event.
    // With one fixed source these would collide, which is exactly the
    // cross-party collision `(source, id)` exists to prevent.
    let other_caller = send(
        &router,
        post(
            "/events",
            Some("bob"),
            &json!({
                "id": "EV-SRC-1",
                "kind": "acknowledgement.received",
                "correlation": [],
                "payload": {}
            }),
        ),
    )
    .await;
    assert_ne!(
        other_caller.1["delivery"], "duplicate",
        "a different authenticated caller's message deduplicated against the \
         first, so every caller shares one source and one party can swallow \
         another's events: {:?}",
        other_caller.1
    );
}

/// A bus posts a `CloudEvent`, and the plane accepts one.
///
/// The envelope this plane **emits** — `RunCompleted` posts a structured-mode
/// `CloudEvent` per sealed run — is the envelope its own event route refused
/// to read, so every deployment whose producers speak `CloudEvents` had to
/// translate one by hand. The translations in the field agreed on getting the
/// deduplication identity wrong: they keyed on `id` alone, which is unique only
/// within one producer.
///
/// Both content modes are accepted, because a bus chooses which it sends and
/// the receiver does not get a vote.
#[tokio::test]
async fn a_cloudevent_is_accepted_in_either_content_mode() {
    let f = fixture();
    let router = f.router();

    let structured = Request::builder()
        .uri("/events")
        .method("POST")
        .header(
            "content-type",
            "application/cloudevents+json; charset=UTF-8",
        )
        .header("x-actor", "bob")
        .body(Body::from(
            json!({
                "specversion": "1.0",
                "id": "ce-1",
                "source": "/edmd",
                "type": "acknowledgement.received",
                "data": {"ok": true}
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(&router, structured).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivery"], "buffered");

    // The same event again, this time in binary mode. A producer that switched
    // modes did not produce a second event, and a receiver that thought so
    // would run the same work twice.
    let binary = Request::builder()
        .uri("/events")
        .method("POST")
        .header("content-type", "application/json")
        .header("ce-specversion", "1.0")
        .header("ce-id", "ce-1")
        .header("ce-source", "/edmd")
        .header("ce-type", "acknowledgement.received")
        .header("x-actor", "bob")
        .body(Body::from(r#"{"ok":true}"#))
        .unwrap();
    let (status, body) = send(&router, binary).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["delivery"], "duplicate",
        "the two content modes of one event were taken as two events: {body}"
    );
}

/// Two producers behind one gateway are two producers.
///
/// This is the whole reason `CloudEvents` defines uniqueness as `(source, id)`
/// and not as `id`. A relay authenticates as itself, so the transport identity
/// cannot separate the producers behind it — and both of them number their
/// messages from one. Keying on `id` alone silently drops the second
/// counterparty's message as a retry of the first.
#[tokio::test]
async fn two_producers_behind_one_gateway_do_not_collide() {
    let f = fixture();
    let router = f.router();

    let from = |source: &str| {
        Request::builder()
            .uri("/events")
            .method("POST")
            .header("content-type", "application/cloudevents+json")
            .header("x-actor", "gateway")
            .body(Body::from(
                json!({
                    "specversion": "1.0",
                    "id": "1",
                    "source": source,
                    "type": "acknowledgement.received",
                    "data": {}
                })
                .to_string(),
            ))
            .unwrap()
    };

    let (_, first) = send(&router, from("/edmd")).await;
    assert_eq!(first["delivery"], "buffered");
    let (_, second) = send(&router, from("/erp")).await;
    assert_ne!(
        second["delivery"], "duplicate",
        "a second producer's message was swallowed as a retry of the first: \
         {second}"
    );
    let (_, retry) = send(&router, from("/edmd")).await;
    assert_eq!(
        retry["delivery"], "duplicate",
        "a genuine retry was taken as a new event: {retry}"
    );
}

/// An envelope this plane has not understood is refused, not guessed at.
#[tokio::test]
async fn a_cloudevent_this_plane_cannot_read_is_refused() {
    let f = fixture();
    let router = f.router();

    for (label, body) in [
        (
            "another spec version",
            json!({"specversion": "0.3", "id": "1", "source": "/x", "type": "t"}),
        ),
        (
            "no id",
            json!({"specversion": "1.0", "source": "/x", "type": "t"}),
        ),
        (
            "binary data a run cannot address",
            json!({
                "specversion": "1.0", "id": "1", "source": "/x", "type": "t",
                "data_base64": "aGk="
            }),
        ),
    ] {
        let request = Request::builder()
            .uri("/events")
            .method("POST")
            .header("content-type", "application/cloudevents+json")
            .header("x-actor", "bob")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, answer) = send(&router, request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was accepted: {answer}"
        );
    }
}

// ── Serving several tenants from one process ────────────────────────────────

/// An authenticated caller reaches their own tenant's runs and no others.
///
/// The whole point of the registry. Both planes share one database, so the
/// isolation cannot come from having separate files — it comes from the caller's
/// tenant selecting a store handle whose keys cannot name another tenant's rows.
///
/// The attacker here holds a **valid run id** belonging to the other tenant,
/// which is the realistic leak: not a guessed id, but a real one arriving
/// through a path that never checked whose it was.
#[tokio::test]
async fn a_caller_cannot_read_another_tenants_run() {
    use agentplane::api::Planes;
    use agentplane::core::TenantId;

    let acme = TenantId::new("acme").expect("valid");
    let globex = TenantId::new("globex").expect("valid");
    let base = RedbStore::open_in_memory().unwrap();

    let plane = |tenant: TenantId| {
        let store = Arc::new(base.clone().for_tenant(tenant.clone()));
        Runtime::builder(store.clone() as Arc<dyn JournalStore>)
            .cases(store.clone() as Arc<dyn CaseStore>)
            .events(store.clone() as Arc<dyn EventStore>)
            .tasks(store as Arc<dyn TaskStore>)
            .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
            .tenant(tenant)
            .skill(ProposesRefund)
            .build()
    };
    let acme_plane = plane(acme.clone());
    let globex_plane = plane(globex.clone());

    // A real run in acme, whose id globex will present.
    let theirs = acme_plane
        .run_correlated(
            "demo.refund",
            Tainted::trusted(json!({})),
            "dispute",
            &[CorrelationKey::new("document", "INV-7")],
        )
        .await
        .unwrap()
        .run_id
        .to_string();

    let router = Api::new(
        Planes::one(acme_plane).and(globex_plane),
        Arc::new(TenantAuth),
    )
    .expect("both planes are governed")
    .router()
    .clone();

    let (status, body) = send(&router, get(&format!("/runs/{theirs}"), Some("globex:eve"))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one tenant read another tenant's run while holding nothing but a \
         valid id: {body:#}"
    );

    // And acme still reads its own, so this isolated rather than broke it.
    let (status, body) = send(&router, get(&format!("/runs/{theirs}"), Some("acme:alice"))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owning tenant lost access to its own run: {body:#}"
    );
    assert_eq!(body["run"], theirs);
}

/// **Each tenant is judged by its own policy engine, not by whichever one the
/// process happened to reach first.**
///
/// The registry resolves the plane *before* asking the policy question, and the
/// engine it then asks belongs to that plane. Getting this backwards — one
/// shared engine in front of many tenants — would let the laxest tenant's rules
/// set everybody's, and it would look like working software for exactly as long
/// as every tenant's policy agreed.
///
/// This is also the evidence behind a claim the constitution makes about
/// tenancy: identities, policy bundles and manifests are per-*plane*, and a
/// plane is one tenant, so per-plane **is** tenant-scoped. That sentence is only
/// true while the resolution order holds, and nothing else pins it.
#[tokio::test]
async fn each_tenants_own_policy_engine_decides_its_requests() {
    use agentplane::api::Planes;
    use agentplane::core::TenantId;

    let acme = TenantId::new("acme").expect("valid");
    let globex = TenantId::new("globex").expect("valid");
    let base = RedbStore::open_in_memory().unwrap();

    // Two engines that disagree, so which one answered is observable.
    let permits = Arc::new(Recording::default());
    let denies = Arc::new(Recording {
        deny: true,
        ..Recording::default()
    });

    let plane = |tenant: TenantId, policy: Arc<Recording>| {
        let store = Arc::new(base.clone().for_tenant(tenant.clone()));
        Runtime::builder(store.clone() as Arc<dyn JournalStore>)
            .cases(store.clone() as Arc<dyn CaseStore>)
            .tasks(store as Arc<dyn TaskStore>)
            .policy(policy as Arc<dyn PolicyEngine>)
            .tenant(tenant)
            .build()
    };

    let router = Api::new(
        Planes::one(plane(acme, Arc::clone(&permits))).and(plane(globex, Arc::clone(&denies))),
        Arc::new(TenantAuth),
    )
    .expect("both planes are governed")
    .router()
    .clone();

    let (status, _) = send(&router, get("/tasks", Some("acme:alice"))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "acme's permitting engine did not decide acme's request"
    );
    let (status, _) = send(&router, get("/tasks", Some("globex:eve"))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "globex's denying engine did not decide globex's request — one tenant's \
         rules were applied to another's, which is how the laxest tenant's \
         policy becomes everybody's"
    );

    // And each engine saw only its own tenant's traffic. Without this the
    // assertions above pass for a router that asks *both* engines and takes
    // whichever answers first.
    assert_eq!(
        permits.asked().len(),
        1,
        "acme's engine was asked about a request that was not acme's"
    );
    assert_eq!(
        denies.asked().len(),
        1,
        "globex's engine was asked about a request that was not globex's"
    );
}

/// **Which obligations were missed, after the matter is closed.**
///
/// Closure is the load-bearing half: a route serving breaches only on open
/// cases passes a version of this test that stops early, and loses the record
/// of what a matter missed at the moment the matter is filed away.
#[tokio::test]
async fn a_missed_obligation_is_listable_after_its_case_is_closed() {
    use agentplane::core::{Deadline, DeadlineState, Digest};

    let f = fixture();
    f.pending_task().await;
    let cases = Arc::clone(&f.store) as Arc<dyn CaseStore>;
    let mut found = None;
    for status in agentplane::core::CaseStatus::ALL {
        if let Some(c) = cases
            .by_status(status, 10)
            .await
            .unwrap()
            .into_iter()
            .next()
        {
            found = Some(c.id);
            break;
        }
    }
    let case = found.expect("the suspended run opened a case");
    let router = f.router();

    // A healthy plane reports nothing, and the empty answer is a real answer.
    let (status, body) = send(&router, get("/obligations", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["obligations"].as_array().map(Vec::len),
        Some(0),
        "a plane that missed nothing reported a breach: {body}"
    );
    assert_eq!(body["truncated"], false);

    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap(),
            calendar_digest: Digest::of(b"cal"),
            warn_at: None,
            state: DeadlineState::Pending,
            acknowledged: None,
        })
        .await
        .expect("register");
    cases
        .set_deadline_state(case, "respond-by", DeadlineState::Breached)
        .await
        .expect("breach");

    let (status, body) = send(&router, get("/obligations", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["obligations"].as_array().map(Vec::len),
        Some(1),
        "the breach is not findable by anyone who does not already know the \
         case: {body}"
    );
    assert_eq!(body["obligations"][0]["name"], "respond-by");

    // The half that matters. Closing the matter must not retire the record of
    // what it missed. The suspended task bounds its own wait with an
    // obligation, and that one is still outstanding — cancel it, so the close
    // below is blocked by nothing except the thing under test.
    for d in cases.deadlines(case).await.expect("deadlines") {
        if d.state.is_open() {
            cases
                .set_deadline_state(case, &d.name, DeadlineState::Cancelled)
                .await
                .expect("cancel");
        }
    }
    cases
        .close(case)
        .await
        .expect("a breached obligation is resolved, so the case closes");
    let (status, body) = send(&router, get("/obligations", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["obligations"].as_array().map(Vec::len),
        Some(1),
        "closing the case took the breach off the surface, so the one query \
         that answers *what did we miss* goes quiet exactly when the matter \
         stops being watched: {body}"
    );
}

/// **What is escalated right now, without already knowing which case.**
///
/// An escalation is the sweeper's most consequential conclusion: an obligation
/// was missed and somebody was told. "Told" meant a status on the case and a
/// metric, and the only way to read it back was `/cases/{case}` — which needs
/// the id. So the answer was available to everyone except the person who needed
/// to ask it, which is detection without delivery.
///
/// The sibling route listing quarantined runs asserted the opposite in a
/// comment — *every other backlog here is findable by whoever must clear it,
/// escalated cases included* — on the route that had just closed this same hole
/// one surface over. A claim about the other doors, made while looking at this
/// one.
#[tokio::test]
async fn escalated_cases_are_listable_without_knowing_the_case_id() {
    use agentplane::core::CaseStatus;

    let f = fixture();
    // A run that suspends on a human task, so a real case exists.
    f.pending_task().await;
    let cases = Arc::clone(&f.store) as Arc<dyn CaseStore>;
    let mut found = None;
    for status in CaseStatus::ALL {
        if let Some(c) = cases
            .by_status(status, 10)
            .await
            .unwrap()
            .into_iter()
            .next()
        {
            found = Some(c.id);
            break;
        }
    }
    let case = found.expect("the suspended run opened a case");

    let router = f.router();

    // Nothing is escalated yet, and the empty answer is a real answer.
    let (status, body) = send(&router, get("/cases", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "escalated");
    assert_eq!(
        body["cases"].as_array().map(Vec::len),
        Some(0),
        "a healthy plane reported an escalation: {body}"
    );
    assert_eq!(body["truncated"], false);

    // Now the obligation is breached, exactly as the sweeper would leave it.
    cases
        .set_status(case, CaseStatus::Escalated)
        .await
        .expect("escalate");

    let (status, body) = send(&router, get("/cases", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body["cases"].as_array().expect("an array");
    assert_eq!(
        listed.len(),
        1,
        "the escalated case is not findable by anyone who does not already \
         know its id — which is the group that does not need to ask: {body}"
    );
    assert_eq!(
        listed[0]["id"],
        serde_json::to_value(case).expect("a case id serializes"),
        "the listed case is not the escalated one"
    );

    // The default is what somebody is looking for, but the filter is real.
    let (status, body) = send(&router, get("/cases?status=closed", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["cases"].as_array().map(Vec::len),
        Some(0),
        "the status filter was ignored: {body}"
    );

    // An unknown status is refused rather than defaulted. Quietly falling back
    // to `open` would answer "what is escalated" with a list of healthy cases,
    // which reads as an empty backlog.
    let (status, _) = send(&router, get("/cases?status=on-fire", Some("bob"))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unrecognised status was silently treated as some other one"
    );
}

/// A caller whose tenant this process does not serve is refused, not defaulted.
///
/// A fallback to some default plane would turn an unregistered tenant into
/// somebody else's data — and it would look exactly like working software.
#[tokio::test]
async fn an_unregistered_tenant_is_refused_rather_than_defaulted() {
    use agentplane::api::Planes;
    use agentplane::core::TenantId;

    let f = fixture();
    let tenant = TenantId::new("acme").expect("valid");
    let acme = Arc::new(
        RedbStore::open_in_memory()
            .unwrap()
            .for_tenant(tenant.clone()),
    );
    let acme_plane = Runtime::builder(acme.clone() as Arc<dyn JournalStore>)
        .cases(acme.clone() as Arc<dyn CaseStore>)
        .tasks(acme as Arc<dyn TaskStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .tenant(tenant)
        .build();
    let _ = &f;

    let router = Api::new(Planes::one(acme_plane), Arc::new(TenantAuth))
        .expect("governed")
        .router();

    let (status, _) = send(&router, get("/tasks", Some("globex:eve"))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller from an unserved tenant was answered by some other tenant's \
         plane"
    );

    // The served tenant still works.
    let (status, _) = send(&router, get("/tasks", Some("acme:alice"))).await;
    assert_eq!(status, StatusCode::OK);
}

/// A surface serving no planes is refused at build.
#[test]
fn a_surface_over_no_planes_is_refused() {
    use agentplane::api::Planes;

    let built = Api::new(Planes::default(), Arc::new(HeaderAuth));
    assert!(
        matches!(built, Err(ApiSetupError::NoPlanes)),
        "a surface that would authenticate every caller and then refuse them \
         all was accepted as configured"
    );
}

// ── One derivation of "what happened to this run" ───────────────────────────

/// A run that concluded `failed`, so its journal stays open for appending.
async fn open_concluded_run() -> (
    Arc<RedbStore>,
    Arc<agentplane::runtime::Runtime>,
    agentplane::core::RunId,
) {
    #[derive(Debug)]
    struct Fails;

    #[async_trait::async_trait]
    impl Skill for Fails {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("fails").provides("demo.fails")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::fail(
                "the counterparty ledger refused the transfer",
            ))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(Fails)
        .build();
    let out = rt
        .run("demo.fails", Tainted::trusted(json!({})))
        .await
        .unwrap();
    (store, rt, out.run_id)
}

/// Append a conclusion this build did not write, as a foreign or older writer
/// would have left it.
async fn append_conclusion(
    store: &Arc<RedbStore>,
    run: agentplane::core::RunId,
    outcome: &str,
    exhaustion: Option<BudgetExceeded>,
) {
    let journal = store.clone() as Arc<dyn JournalStore>;
    let lease = journal
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    let head = journal.head(run).await.unwrap();
    journal
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunConcluded {
                    outcome: outcome.to_owned(),
                    reason: Some("written by another build".into()),
                    exhaustion,
                    live_spend: agentplane::core::Spend::default(),
                    chain_head: head.hash,
                },
            )],
        )
        .await
        .unwrap();
}

/// **An `exhausted` conclusion with no typed ceiling is not an exhaustion.**
///
/// I14 names the operator API as one of three surfaces where an exhausted run
/// keeps the exact ceiling verdict. The runtime's own reader quarantines a
/// conclusion that says `exhausted` and carries no verdict — there is nothing
/// to raise and nothing to act on. The view had its own copy of that match and
/// reported plain `exhausted` with the field simply absent, so automation
/// deciding *which limit to raise* read `null` and an operator was told a
/// ceiling stopped the run without being told which.
#[tokio::test]
async fn an_exhaustion_with_no_ceiling_is_not_reported_as_an_exhaustion() {
    let (store, rt, run) = open_concluded_run().await;
    append_conclusion(&store, run, "exhausted", None).await;

    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();
    let (status, body) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["status"], "quarantined",
        "an exhaustion with no ceiling verdict was reported as an ordinary \
         exhaustion, so nothing says which limit to raise: {body}"
    );
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|r| r.contains("ceiling")),
        "the view does not say what is wrong with the record: {body}"
    );
}

/// **An outcome this build cannot interpret fails closed.**
///
/// The runtime's reader answers `quarantined` — "a conclusion this build cannot
/// interpret is not permission to treat the run as ordinary". The view passed
/// the string through as the status, so a word no code anywhere acts on arrived
/// at an operator's dashboard looking like a state.
#[tokio::test]
async fn an_unrecognised_outcome_is_quarantined_rather_than_echoed() {
    let (store, rt, run) = open_concluded_run().await;
    append_conclusion(&store, run, "settled-ish", None).await;

    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();
    let (status, body) = send(&router, get(&format!("/runs/{run}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["status"], "quarantined",
        "an outcome this build does not recognise was echoed as a status: {body}"
    );
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|r| r.contains("settled-ish")),
        "the refusal does not name the outcome it could not read: {body}"
    );
}

/// **The preservation register, over the wire.**
///
/// A hold that can only be read by naming the case it is on delivers nothing to
/// the person whose job is to certify what a deployment is still keeping — so
/// the listing is the half under test here, and it has to carry the *reason*,
/// because that sentence is the whole of what somebody acts on two years later.
///
/// The idempotency half matters on this surface more than on the store's: a
/// second placement does not move the instant or rewrite the reason, and a
/// caller who assumed theirs won would report an instruction the plane is not
/// acting on. So the response says what is actually in force, not what was sent.
#[tokio::test]
async fn a_hold_is_placed_listed_with_its_reason_and_released() {
    use agentplane::case::CaseStore;

    let f = fixture();
    let cases = f.store.clone() as Arc<dyn CaseStore>;
    let case = cases
        .correlate_or_open(
            "dispute",
            &[CorrelationKey::new("document", "INV-HOLD")],
            agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap(),
        )
        .await
        .unwrap()
        .case_id();

    let router = f.router();
    let (status, body) = send(
        &router,
        post(
            "/holds",
            Some("bob"),
            &json!({ "case": case.to_string(), "reason": "preservation order 2026-114" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["placed"], true);

    // A second placement is refused the right way round: accepted, ignored, and
    // honest about which instruction stands.
    let (_, body) = send(
        &router,
        post(
            "/holds",
            Some("bob"),
            &json!({ "case": case.to_string(), "reason": "a retry that must not win" }),
        ),
    )
    .await;
    assert_eq!(body["placed"], false, "a retry claimed to place the hold");
    assert_eq!(
        body["in_force"]["reason"], "preservation order 2026-114",
        "the response reports an instruction the plane is not acting on: {body}"
    );

    let (status, body) = send(&router, get("/holds", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = &body["holds"][0];
    assert_eq!(listed["case"], case.to_string());
    assert_eq!(
        listed["reason"], "preservation order 2026-114",
        "the register does not say on whose instruction the matter is kept"
    );

    // A reason nobody can account for is refused, not stored blank.
    let (status, _) = send(
        &router,
        post(
            "/holds",
            Some("bob"),
            &json!({ "case": case.to_string(), "reason": "   " }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a blank reason was accepted"
    );

    // A matter that is not there is told apart from a store that broke.
    let (status, _) = send(
        &router,
        post(
            "/holds",
            Some("bob"),
            &json!({ "case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "reason": "on nothing" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = send(
        &router,
        post(
            "/holds/release",
            Some("bob"),
            &json!({ "case": case.to_string() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lifted"], true);

    let (_, body) = send(&router, get("/holds", Some("bob"))).await;
    assert!(
        body["holds"].as_array().is_some_and(Vec::is_empty),
        "a released hold is still in the register: {body}"
    );
}

/// A router whose policy permits exactly one `api:` action.
///
/// So a refusal names the capability that was missing rather than the fixture's
/// mood — which is what makes the two halt authorities testable at all.
fn halt_router(store: &Arc<RedbStore>, policy: Arc<dyn PolicyEngine>) -> axum::Router {
    use agentplane::quota::QuotaStore;
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .quota(
            store.clone() as Arc<dyn QuotaStore>,
            agentplane::quota::TenantQuota::default(),
        )
        .policy(policy)
        .build();
    Api::new(rt, Arc::new(HeaderAuth))
        .expect("the fixture wires a policy engine")
        .router()
}

/// Permits exactly one `api:` action and denies the rest.
#[derive(Debug)]
struct OnlyAllows(&'static str);

impl PolicyEngine for OnlyAllows {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        if request.action == self.0 || !request.action.starts_with("api:") {
            PolicyDecision::Permit
        } else {
            PolicyDecision::deny(format!("this caller does not hold {}", request.action))
        }
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"only-allows"), "agentplane-test/one-verb")
    }
}

/// **The emergency stop, over the wire.**
///
/// The switch existed only against a *store*, and the embedded backend admits
/// one writer process — so on a single-node plane it was unreachable from any
/// process while the plane it stops was running, which is the one state it
/// exists for.
///
/// The register has to round-trip *with its reason*: the person who finds a
/// plane stopped is usually not the person who stopped it, and that sentence is
/// the whole of what they have to act on.
#[tokio::test]
async fn a_halt_is_thrown_listed_with_its_reason_and_lifted() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let router = halt_router(
        &store,
        Arc::new(Recording::default()) as Arc<dyn PolicyEngine>,
    );

    // Throw it, and the response says how far it reaches — the sentence an
    // operator would otherwise learn the shape of during the outage.
    let (status, body) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "agent:payments-clerk", "reason": "incident 42: looping" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["halted"], true);
    assert!(
        body["reach"]
            .as_str()
            .is_some_and(|s| s.contains("cancel a run to reach work in flight")),
        "the response does not say what a workload-scoped halt leaves running: {body}"
    );

    // A blank reason is refused rather than stored.
    let (status, _) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "tenant", "reason": "  " }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a blank reason was stored");

    // A scope this build cannot read is refused, not silently written: a halt
    // keyed on something nobody can look up stops work for no stated reason.
    let (status, _) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "everything", "reason": "typo" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unreadable scope was accepted"
    );

    let (status, body) = send(&router, get("/halts", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["halts"][0]["scope"], "agent:payments-clerk");
    assert_eq!(
        body["halts"][0]["reason"], "incident 42: looping",
        "the listing does not say why the plane is stopped: {body}"
    );

    let (status, body) = send(
        &router,
        post(
            "/halts/lift",
            Some("bob"),
            &json!({ "scope": "agent:payments-clerk" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["halted"], false);

    let (_, body) = send(&router, get("/halts", Some("bob"))).await;
    assert!(
        body["halts"].as_array().is_some_and(Vec::is_empty),
        "a lifted halt is still standing: {body}"
    );
}

/// **A withdrawal says it reaches work in flight, because it does.**
///
/// Three halt scopes name a workload and close admission; `subject:` names an
/// authority and pauses the runs already executing under it. One sentence for
/// all four is false for this one, and false in the expensive direction: an
/// operator who has just withdrawn a credential, told that the stop does not
/// reach running work and to cancel instead, unwinds completed work that the
/// withdrawal deliberately left standing.
///
/// This is also the scope a deployment's own revocation relay uses, since the
/// intake for a revocation signal belongs to the deployment rather than to this
/// crate — so the sentence it reads back is part of the supported integration
/// rather than a nicety.
///
/// Both arms are asserted here and in the test above: an assertion that the
/// subject sentence appears passes just as well if *every* scope started
/// returning it, which is the same defect pointing the other way.
#[tokio::test]
async fn a_withdrawal_says_it_reaches_the_work_a_workload_halt_leaves_running() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let router = halt_router(
        &store,
        Arc::new(Recording::default()) as Arc<dyn PolicyEngine>,
    );

    let (status, body) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({
                "scope": "subject:alice",
                "reason": "credential withdrawn: laptop lost",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "subject:alice", "{body}");

    let reach = body["reach"].as_str().unwrap_or_default();
    assert!(
        reach.contains("pause at their next step boundary"),
        "a withdrawal does not say it reaches running work: {body}"
    );
    assert!(
        !reach.contains("cancel a run to reach work in flight"),
        "a withdrawal repeats the workload scopes' sentence, which sends an \
         operator to unwind work this halt left standing on purpose: {body}"
    );
}

/// **Throwing the emergency stop and lifting it are different authorities.**
///
/// A deployment that hands out *stop the plane* has said nothing about who may
/// start it again, and a single `api:halt` grant would have made that
/// distinction unwritable. Both directions are asserted, because one of them is
/// the dangerous one and a test of only the other passes on a merged grant.
#[tokio::test]
async fn throwing_a_halt_and_lifting_one_are_separate_authorities() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());

    let lifter = halt_router(
        &store,
        Arc::new(OnlyAllows(agentplane::api::action::HALT_LIFT)),
    );
    let (status, _) = send(
        &lifter,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "tenant", "reason": "not mine to throw" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller holding only the lift capability threw the switch"
    );

    let thrower = halt_router(
        &store,
        Arc::new(OnlyAllows(agentplane::api::action::HALT_PLACE)),
    );
    let (status, _) = send(
        &thrower,
        post("/halts/lift", Some("bob"), &json!({ "scope": "tenant" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller holding only the place capability lifted the switch"
    );
}

/// **What is executing right now, over the wire.**
///
/// `GET /runs` answers from the journal's outcome index, which only *concluded*
/// runs are in — so the operator surface could enumerate everything finished and
/// nothing in flight, while `POST /runs/{run}/cancel` took an id that no listing
/// produced. The store answered this question on both backends and was reached
/// by nothing outside its own conformance battery.
///
/// The claim that would rot quietly is the second one: a slot whose lease has
/// lapsed is **marked, not omitted**. Those belong to the recovery sweep, which
/// resumes them — so an operator who cannot tell them from live work will cancel
/// a run that was about to continue, which unwinds it. A listing that returned
/// bare ids reads identically whether or not that distinction is made.
#[tokio::test]
async fn the_live_listing_attributes_each_run_and_marks_a_stranded_slot() {
    use agentplane::quota::QuotaStore;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let quotas = store.clone() as Arc<dyn QuotaStore>;
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .quota(quotas.clone(), agentplane::quota::TenantQuota::default())
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let router = Api::new(rt, Arc::new(HeaderAuth))
        .expect("the fixture wires a policy engine")
        .router();

    let at = agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap();
    let held = agentplane::core::RunId::generate();
    quotas
        .reserve(held, &agentplane::quota::TenantQuota::default(), None, at)
        .await
        .unwrap();

    let (status, body) = send(&router, get("/runs/live", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let runs = body["runs"].as_array().expect("a listing");
    assert_eq!(runs.len(), 1, "the held slot is not listed: {body}");
    assert_eq!(runs[0]["run"], held.to_string());
    assert_eq!(
        runs[0]["stranded"], false,
        "a slot with no lapsed lease was reported as stranded: {body}"
    );
    // Nothing journaled this run, so there is nothing to attribute it with —
    // and the listing says so with `null` rather than inventing a name.
    assert!(
        runs[0]["agent"].is_null(),
        "an unattributed run claimed an agent: {body}"
    );

    // ── A stranded slot is marked ────────────────────────────────────────
    //
    // A real lapsed lease rather than a stub: the flag is a join against
    // `abandoned_runs`, and asserting only the `false` case above would pass on
    // a field hard-coded to `false`. One second is the store's own granularity
    // floor, so this is the shortest honest version of the wait.
    let stranded = agentplane::core::RunId::generate();
    quotas
        .reserve(
            stranded,
            &agentplane::quota::TenantQuota::default(),
            None,
            at,
        )
        .await
        .unwrap();
    (store.clone() as Arc<dyn JournalStore>)
        .acquire(
            stranded,
            "an-instance-that-died",
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;

    let (_, body) = send(&router, get("/runs/live", Some("bob"))).await;
    let rows = body["runs"].as_array().expect("a listing");
    let stranded_row = rows
        .iter()
        .find(|r| r["run"] == stranded.to_string())
        .unwrap_or_else(|| panic!("the stranded slot is not listed at all: {body}"));
    assert_eq!(
        stranded_row["stranded"], true,
        "a slot held by a run whose lease lapsed reads as live work, so an \
         operator cancels what the recovery sweep was about to resume: {body}"
    );
    let live_row = rows
        .iter()
        .find(|r| r["run"] == held.to_string())
        .unwrap_or_else(|| panic!("the live slot vanished: {body}"));
    assert_eq!(
        live_row["stranded"], false,
        "every slot was marked stranded, so the flag distinguishes nothing: {body}"
    );

    // ── Narrowing by authority ───────────────────────────────────────────
    //
    // The query that turns *withdraw a credential* into *and here is what is
    // still acting under it*. Neither slot here was journaled, so neither has a
    // subject — which is the case that must return nothing rather than
    // everything, since a filter that falls back to the unfiltered listing is
    // how an operator concludes a withdrawal reached work it did not.
    let (_, body) = send(&router, get("/runs/live?subject=alice", Some("bob"))).await;
    assert!(
        body["runs"].as_array().is_some_and(Vec::is_empty),
        "an unattributed run matched a subject filter: {body}"
    );

    // The slot is given back at settlement, and the listing empties with it.
    quotas.release(held).await.unwrap();
    quotas.release(stranded).await.unwrap();
    let (_, body) = send(&router, get("/runs/live", Some("bob"))).await;
    assert!(
        body["runs"].as_array().is_some_and(Vec::is_empty),
        "a released slot is still listed as running: {body}"
    );
}

/// **A subject filter over a truncated page says the page was truncated.**
///
/// The page bounds what is read, and the filter narrows what was read. Asked
/// "what is still acting under alice" with more runs live than one page, the
/// runs past the page were never looked at — so `truncated: false` beside an
/// empty list would tell a responder a withdrawal reached everything it had to
/// when it was never checked.
#[tokio::test]
async fn a_filtered_live_listing_reports_the_truncation_of_its_page() {
    use agentplane::quota::QuotaStore;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let quotas = store.clone() as Arc<dyn QuotaStore>;
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .quota(quotas.clone(), agentplane::quota::TenantQuota::default())
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let router = Api::new(rt, Arc::new(HeaderAuth))
        .expect("the fixture wires a policy engine")
        .limit(1)
        .router();

    let at = agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap();
    for _ in 0..2 {
        quotas
            .reserve(
                agentplane::core::RunId::generate(),
                &agentplane::quota::TenantQuota::default(),
                None,
                at,
            )
            .await
            .unwrap();
    }

    let (status, body) = send(&router, get("/runs/live?subject=alice", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["runs"].as_array().is_some_and(Vec::is_empty), "{body}");
    assert_eq!(
        body["truncated"], true,
        "two runs are live and one page of one was read, yet the filtered answer \
         claims it saw everything: {body}"
    );
}

/// Finishes at once, so a test has a sealed run to point at.
#[derive(Debug)]
struct Finishes;

#[async_trait::async_trait]
impl Skill for Finishes {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("finishes").provides("demo.finish")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(input))
    }
}

/// **Stopping a run says what it can and cannot do, in the status it means.**
///
/// A blank reason is a request that documents nobody's judgement, and is the
/// caller's to fix: 400. A run that already concluded has nothing left to
/// stop, and `202 recorded: true` would tell the operator a stop was on its
/// way: 409, as A2A answers `TaskNotCancelable`. An authenticator that named
/// nobody is the deployment's defect, not the request's: 500.
#[tokio::test]
async fn a_cancel_is_refused_in_the_status_its_cause_calls_for() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .skill(Finishes)
        .build();
    let sealed = rt
        .run("demo.finish", Tainted::trusted(json!({})))
        .await
        .expect("a run that finishes")
        .run_id;
    let router = Api::new(rt.clone(), Arc::new(HeaderAuth))
        .expect("policy wired")
        .router();
    let path = format!("/runs/{sealed}/cancel");

    let (status, body) = send(&router, post(&path, Some("bob"), &json!({"reason": "  "}))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a blank reason was accepted: {body}"
    );

    let (status, body) = send(
        &router,
        post(&path, Some("bob"), &json!({"reason": "stop"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a stop was accepted for a run that already concluded: {body}"
    );
    assert!(
        rt.cancellation(sealed).await.expect("read").is_none(),
        "a request against a sealed run was stored anyway"
    );

    let (status, body) = send(&router, post(&path, Some(""), &json!({"reason": "stop"}))).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an authenticator that named nobody was blamed on the request: {body}"
    );
}

/// **A refusal names what was wrong, in words.**
///
/// The identifier helper produced "not a disposition: expected … id" for a
/// field that is not an identifier at all.
#[tokio::test]
async fn a_malformed_reconciliation_is_refused_in_a_sentence() {
    let f = fixture();
    let (status, body) = send(
        &f.router(),
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/reconcile",
            Some("bob"),
            &json!({
                "effect": "0000000000000000000000000000000000000000000000000000000000000000",
                "disposition": "maybe",
                "note": "looked"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let said = body["error"].as_str().unwrap_or_default();
    assert!(
        said.contains("'landed' or 'did_not_happen'") && !said.ends_with(" id"),
        "the refusal did not read as a sentence: {said}"
    );
}

/// **A hold or event carrying a field this plane does not know is refused.**
///
/// Accepted silently, a misspelt field is a request that did something other
/// than what its sender believes.
#[tokio::test]
async fn unknown_fields_on_a_hold_or_an_event_are_refused() {
    let f = fixture();
    let router = f.router();
    for (path, body) in [
        (
            "/holds",
            json!({"case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "reason": "litigation", "untill": "never"}),
        ),
        (
            "/holds/release",
            json!({"case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "reason": "settled", "force": true}),
        ),
        (
            "/holds/release",
            json!({"case": "case_01ARZ3NDEKTSV4RRFFQ69G5FAV", "actor": "someone-else"}),
        ),
        (
            "/halts/lift",
            json!({"scope": "tenant", "basis": "authenticated"}),
        ),
        (
            "/events",
            json!({"id": "e-1", "kind": "k", "payload": {}, "corelation": []}),
        ),
    ] {
        let (status, answer) = send(&router, post(path, Some("bob"), &body)).await;
        assert!(
            status.is_client_error(),
            "{path} accepted an unknown field: {status} {answer}"
        );
    }
}

/// **`/events` authenticates before it reads the body.**
///
/// The parser's refusals describe the shapes the route accepts; a caller with
/// no identity is owed none of them.
#[tokio::test]
async fn an_unauthenticated_event_is_refused_before_its_body_is_read() {
    let f = fixture();
    let (status, body) = send(
        &f.router(),
        post("/events", None, &json!({"nonsense": true})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unauthenticated body was parsed and critiqued: {body}"
    );
}

// ── What a reviewer is shown ────────────────────────────────────────────────

/// Put one task straight onto the worklist, as a store holding it would.
async fn listed_task(
    store: &Arc<RedbStore>,
    summary: &str,
    proposed: Value,
    withheld: Option<agentplane::core::Withheld>,
) -> String {
    use agentplane::core::{
        EffectDescriptor, EffectKey, OnExpiry, Phase, RunId, StepId, Task, TaskId, TaskState,
    };
    let run = RunId::generate();
    let key = EffectKey::for_effect(
        StepId(0),
        Phase::Forward,
        0,
        1,
        &EffectDescriptor::new("agent.approve_call", json!({ "summary": summary })),
    );
    let task = Task {
        id: TaskId::derive(run, key),
        run,
        case: None,
        kind: "approval".into(),
        justification: Justification::new(Tainted::trusted(summary.to_owned()), proposed),
        candidate_roles: vec!["compliance-officer".into()],
        escalate_to: Vec::new(),
        assignee: None,
        priority: Priority::Normal,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        excluded_actors: Vec::new(),
        created_at: time::OffsetDateTime::now_utc(),
        due_at: None,
        withheld,
    };
    (Arc::clone(store) as Arc<dyn TaskStore>)
        .open(&task)
        .await
        .expect("listed");
    task.id.to_hex()
}

/// **A withheld proposal is served as withheld, never as an envelope.**
///
/// A plane that cannot open a proposal — no key ring here, a destroyed key, a
/// damaged envelope — used to serve the sealed `{"$sealed": …}` object as the
/// proposal, a value a client renders as if it were the arguments. The view
/// says *withheld, and why*, and carries no envelope anywhere.
#[tokio::test]
async fn a_withheld_proposal_is_served_as_withheld() {
    let f = fixture();
    let task = listed_task(
        &f.store,
        "Refund the disputed invoice",
        json!({ "$sealed": "AAECAwQFBgc=" }),
        Some(agentplane::core::Withheld::Sealed),
    )
    .await;

    let (status, body) = send(&f.router(), get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["withheld"], "sealed", "{body}");
    assert_eq!(
        body["justification"]["proposed_action"],
        Value::Null,
        "{body}"
    );
    assert_eq!(body["rendering"]["withheld"], "sealed", "{body}");
    assert_eq!(body["rendering"]["proposed_action"], Value::Null, "{body}");
    assert!(
        !body.to_string().contains("$sealed"),
        "the envelope was served as a value: {body}"
    );
}

/// **The served digest is the version of the stored row**, not of the
/// withheld view served beside it — so a rejection of a proposal this plane
/// cannot open, naming the digest it was served, records.
#[tokio::test]
async fn a_served_digest_is_of_the_stored_row() {
    let f = fixture();
    let task = listed_task(
        &f.store,
        "Refund the disputed invoice",
        json!({ "$sealed": "AAECAwQFBgc=" }),
        Some(agentplane::core::Withheld::Sealed),
    )
    .await;
    let stored = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap()
        .justification
        .digest()
        .to_hex();
    let router = f.router();

    let (status, view) = send(&router, get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["digest"], stored, "{view}");
    let (status, list) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["tasks"][0]["digest"], stored, "{list}");

    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": false, "reason": "cannot see it", "digest": view["digest"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// **A decision naming a version the row no longer holds is 412**, and the task
/// is left open and unassigned; naming the served version records.
#[tokio::test]
async fn a_stale_digest_is_refused_with_412() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();
    let decide = |digest: Value| {
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": false, "reason": "no", "digest": digest }),
        )
    };

    let stale = agentplane::core::Digest::of(b"another version").to_hex();
    let (status, body) = send(&router, decide(json!(stale))).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
    let found = (f.store.clone() as Arc<dyn TaskStore>)
        .task(agentplane::core::TaskId::parse(&task).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        found.state.is_pending() && found.assignee.is_none(),
        "{found:?}"
    );

    let (_, view) = send(&router, get(&format!("/tasks/{task}"), Some("bob"))).await;
    let (status, body) = send(&router, decide(view["digest"].clone())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// **An approval of a withheld proposal is refused in a class of its own.**
///
/// Not a conflict — nobody else holds the task and retrying here fails the
/// same way. 422 with the reason, and the rejection that needs no proposal
/// still records.
#[tokio::test]
async fn a_withheld_proposal_refuses_an_approval_with_its_own_status() {
    let f = fixture();
    let task = listed_task(
        &f.store,
        "Refund the disputed invoice",
        json!({ "$sealed": "AAECAwQFBgc=" }),
        Some(agentplane::core::Withheld::Erased),
    )
    .await;
    let router = f.router();

    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": true, "reason": "looks fine" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.to_string().contains("erased"), "{body}");

    let (status, body) = send(
        &router,
        post(
            &format!("/tasks/{task}/decide"),
            Some("bob"),
            &json!({ "approved": false, "reason": "cannot see it, so no" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a rejection of the unseen is safe: {body}"
    );
}

/// **Every hidden or direction-changing code point is shown, on the view a
/// person reads.**
///
/// A tag-character suffix on a destination, a right-to-left override that
/// reverses an amount's digits, a zero-width space in a payee: each renders
/// as nothing, or as something else, in a client that prints the value. The
/// rendering escapes each in place and says it did.
#[tokio::test]
async fn every_surface_escapes_what_a_reviewer_cannot_see() {
    let f = fixture();
    let task = listed_task(
        &f.store,
        "Pay\u{200B} the vendor",
        json!({
            "destination": "DE89\u{E0041}\u{E0042}",
            "amount": "\u{202E}0001",
        }),
        None,
    )
    .await;

    let (status, body) = send(&f.router(), get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let shown = &body["rendering"];
    assert_eq!(shown["escaped"], true, "{body}");
    assert_eq!(shown["summary"], "Pay\\u{200B} the vendor", "{body}");
    assert_eq!(
        shown["proposed_action"]["destination"], "DE89\\u{E0041}\\u{E0042}",
        "{body}"
    );
    assert_eq!(
        shown["proposed_action"]["amount"], "\\u{202E}0001",
        "{body}"
    );
    let rendered = shown.to_string();
    for hidden in ['\u{200B}', '\u{E0041}', '\u{202E}'] {
        assert!(
            !rendered.contains(hidden),
            "U+{:04X} reached the rendering raw: {rendered}",
            hidden as u32
        );
    }
}

/// **A word mixing alphabets is flagged beside it, and left as written.**
///
/// A Cyrillic `а` in a Latin payee is the homoglyph a reviewer cannot see.
/// The plane holds no script policy, so it refuses nothing and changes
/// nothing — it says which word, where, and which scripts.
#[tokio::test]
async fn a_word_mixing_scripts_is_flagged() {
    let f = fixture();
    let task = listed_task(
        &f.store,
        "Pay the vendor",
        json!({ "payee": "P\u{430}ypal Europe" }),
        None,
    )
    .await;

    let (_, body) = send(&f.router(), get(&format!("/tasks/{task}"), Some("bob"))).await;
    let shown = &body["rendering"];
    assert_eq!(shown["escaped"], false, "nothing here is hidden: {body}");
    assert_eq!(
        shown["proposed_action"]["payee"], "P\u{430}ypal Europe",
        "a flagged word is shown as written: {body}"
    );
    assert_eq!(
        shown["mixed_script"],
        json!([{
            "at": "proposed_action/payee",
            "word": "P\u{430}ypal",
            "scripts": ["Latin", "Cyrillic"],
        }]),
        "{body}"
    );
}

/// **Clear arguments spelled like the sealed marker are arguments.**
///
/// Nothing sealed them, so nothing withholds them: the view shows them as
/// the value they are, and only the out-of-band reason could say otherwise.
#[tokio::test]
async fn an_argument_spelled_like_the_sealed_marker_is_not_withheld() {
    let f = fixture();
    let task = listed_task(
        &f.store,
        "Store this note",
        json!({ "$sealed": "AAECAwQFBgc=" }),
        None,
    )
    .await;
    let (_, body) = send(&f.router(), get(&format!("/tasks/{task}"), Some("bob"))).await;
    assert!(body.get("withheld").is_none(), "{body}");
    assert_eq!(
        body["rendering"]["proposed_action"],
        json!({ "$sealed": "AAECAwQFBgc=" }),
        "{body}"
    );
}

/// The one record of the run `record` names, from `store`'s journal.
async fn sole_record(store: &Arc<RedbStore>, record: &Value) -> agentplane::journal::Record {
    let run =
        agentplane::core::RunId::parse(record.as_str().expect("a record run")).expect("a run id");
    let mut page = store
        .read_page(run, 1, 1)
        .await
        .expect("a readable journal");
    assert_eq!(page.len(), 1, "the run holds its record");
    page.remove(0)
}

/// **A release and a lift name who made them, in the journal.**
///
/// Neither register keeps a row once its entry goes, so the record each act
/// writes before the row goes is the account of who let a matter be swept or
/// work start again — named from the credential, not from the body.
#[tokio::test]
async fn a_hold_release_and_a_halt_lift_name_who_made_them() {
    use agentplane::case::CaseStore;

    let f = fixture();
    let cases = f.store.clone() as Arc<dyn CaseStore>;
    let case = cases
        .correlate_or_open(
            "dispute",
            &[CorrelationKey::new("document", "INV-WHO")],
            agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap(),
        )
        .await
        .unwrap()
        .case_id();
    let router = f.router();
    let (status, _) = send(
        &router,
        post(
            "/holds",
            Some("bob"),
            &json!({ "case": case.to_string(), "reason": "preservation order 7" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, released) = send(
        &router,
        post(
            "/holds/release",
            Some("carol"),
            &json!({ "case": case.to_string() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{released}");
    assert_eq!(released["lifted"], true, "{released}");
    assert_eq!(released["removed"], true, "{released}");
    assert_eq!(released["by"], "carol", "{released}");
    assert_eq!(released["basis"], "authenticated", "{released}");
    let record = sole_record(&f.store, &released["record"]).await;
    assert_eq!(record.body.case, Some(case));
    match record.kind() {
        RecordKind::HoldReleased { by, placed_by, .. } => {
            assert_eq!(by.actor(), "carol");
            assert_eq!(by.basis().as_str(), "authenticated");
            assert_eq!(placed_by.actor(), "bob");
        }
        other => panic!("a release run holds a release record, not {other:?}"),
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let halts = halt_router(
        &store,
        Arc::new(Recording::default()) as Arc<dyn PolicyEngine>,
    );
    let (status, _) = send(
        &halts,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "tenant", "reason": "incident 9" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, lifted) = send(
        &halts,
        post("/halts/lift", Some("dave"), &json!({ "scope": "tenant" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{lifted}");
    assert_eq!(lifted["was_standing"], true, "{lifted}");
    assert_eq!(lifted["removed"], true, "{lifted}");
    assert_eq!(lifted["by"], "dave", "{lifted}");
    assert_eq!(lifted["basis"], "authenticated", "{lifted}");
    let record = sole_record(&store, &lifted["record"]).await;
    match record.kind() {
        RecordKind::HaltLifted {
            scope,
            by,
            reason,
            thrown_by,
            ..
        } => {
            assert_eq!(scope, "tenant");
            assert_eq!(by.actor(), "dave");
            assert_eq!(by.basis().as_str(), "authenticated");
            assert_eq!(reason, "incident 9");
            assert_eq!(thrown_by.actor(), "bob");
        }
        other => panic!("a lift run holds a lift record, not {other:?}"),
    }

    // A second lift finds nothing standing, writes nothing and says so.
    let (status, again) = send(
        &halts,
        post("/halts/lift", Some("dave"), &json!({ "scope": "tenant" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["was_standing"], false, "{again}");
    assert_eq!(again["removed"], false, "{again}");
    assert!(again["record"].is_null(), "{again}");
}

/// A policy set that cannot evaluate anything, and says why in its own words.
#[derive(Debug)]
struct Unevaluable;

impl PolicyEngine for Unevaluable {
    fn authorize(&self, _request: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::Malformed {
            reason: "policy `ops-secret-7` reads `context.clearance`, which is absent".to_owned(),
        }
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"unevaluable"), "agentplane-test/unevaluable")
    }
}

/// **A policy set that cannot evaluate says so in a sentence, not in its
/// rules.** The engine's reason names policy ids and attributes — a map of
/// the authorization vocabulary — and it belongs in the operator's log.
#[tokio::test]
async fn an_unevaluable_policy_set_is_a_fixed_sentence_to_the_caller() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let router = halt_router(&store, Arc::new(Unevaluable) as Arc<dyn PolicyEngine>);
    let (status, body) = send(&router, get("/halts", Some("bob"))).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let text = body.to_string();
    assert!(
        !text.contains("ops-secret-7") && !text.contains("clearance"),
        "the engine's reason reached the caller: {text}"
    );
}

/// A plane with both registers wired, at a page of `limit`.
fn register_router(store: &Arc<RedbStore>, limit: usize) -> axum::Router {
    use agentplane::quota::QuotaStore;
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .quota(
            store.clone() as Arc<dyn QuotaStore>,
            agentplane::quota::TenantQuota::default(),
        )
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    Api::new(rt, Arc::new(HeaderAuth))
        .expect("the fixture wires a policy engine")
        .limit(limit)
        .router()
}

/// A matter correlated on `doc`, as its case id.
async fn open_matter(store: &Arc<RedbStore>, doc: &str) -> String {
    (store.clone() as Arc<dyn CaseStore>)
        .correlate_or_open(
            "dispute",
            &[CorrelationKey::new("document", doc)],
            agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap(),
        )
        .await
        .unwrap()
        .case_id()
        .to_string()
}

/// **The listings say who, both for what stands now and for what was ended.**
///
/// A standing entry names who threw or placed it; `?state=lifted` and
/// `?state=released` read the recorded lifts and releases back, newest first,
/// each with its lifter and the control it ended.
#[tokio::test]
async fn the_halt_and_hold_listings_name_who_now_and_before() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let router = register_router(&store, 1);
    let matters = [
        open_matter(&store, "INV-L1").await,
        open_matter(&store, "INV-L2").await,
    ];

    let (status, _) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "agent:a", "reason": "first" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, standing) = send(&router, get("/halts", Some("bob"))).await;
    assert_eq!(standing["halts"][0]["by"], "bob", "{standing}");
    assert_eq!(standing["halts"][0]["basis"], "authenticated", "{standing}");
    assert!(standing["halts"][0]["thrown_at"].is_i64(), "{standing}");

    let (status, _) = send(
        &router,
        post("/halts/lift", Some("carol"), &json!({ "scope": "agent:a" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "agent:b", "reason": "second" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        post("/halts/lift", Some("dave"), &json!({ "scope": "agent:b" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, history) = send(&router, get("/halts?state=lifted", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert_eq!(history["halts"], json!([]), "{history}");
    assert_eq!(
        history["truncated"], true,
        "a page of one over two lifts: {history}"
    );
    let newest = &history["lifted"][0];
    assert_eq!(newest["scope"], "agent:b", "newest first: {history}");
    assert_eq!(newest["by"], "dave", "{history}");
    assert_eq!(newest["basis"], "authenticated", "{history}");
    assert_eq!(newest["thrown_by"], "bob", "{history}");
    assert_eq!(newest["reason"], "second", "{history}");

    for (case, who) in matters.iter().zip(["carol", "dave"]) {
        let (status, _) = send(
            &router,
            post(
                "/holds",
                Some("bob"),
                &json!({ "case": case, "reason": "order" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, standing) = send(&router, get("/holds", Some("bob"))).await;
        assert_eq!(standing["holds"][0]["by"], "bob", "{standing}");
        assert_eq!(standing["holds"][0]["basis"], "authenticated", "{standing}");
        let (status, _) = send(
            &router,
            post("/holds/release", Some(who), &json!({ "case": case })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, history) = send(&router, get("/holds?state=released", Some("bob"))).await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert_eq!(history["truncated"], true, "{history}");
    let newest = &history["released"][0];
    assert_eq!(
        newest["case"],
        matters[1].as_str(),
        "newest first: {history}"
    );
    assert_eq!(newest["by"], "dave", "{history}");
    assert_eq!(newest["placed_by"], "bob", "{history}");

    let (_, case_view) = send(&router, get(&format!("/cases/{}", matters[1]), Some("bob"))).await;
    assert!(
        case_view["history"]
            .as_array()
            .is_some_and(|h| h.iter().any(|r| r.to_string().contains("HoldReleased"))),
        "the release is in the matter's history: {case_view}"
    );

    for path in ["/halts?state=other", "/holds?state=lifted"] {
        let (status, body) = send(&router, get(path, Some("bob"))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
    }
}

/// **A lift by a caller no record can name lifts nothing.**
///
/// The name is the whole of the record; a credential that yields an empty
/// actor is refused before the register is read, and the control stands.
#[tokio::test]
async fn a_lift_by_an_unusable_caller_is_refused_and_lifts_nothing() {
    use agentplane::quota::QuotaStore;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let router = register_router(&store, 100);
    let case = open_matter(&store, "INV-U").await;
    let (status, _) = send(
        &router,
        post(
            "/halts",
            Some("bob"),
            &json!({ "scope": "tenant", "reason": "r" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        post(
            "/holds",
            Some("bob"),
            &json!({ "case": case, "reason": "r" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    for req in [
        post("/halts/lift", Some(" "), &json!({ "scope": "tenant" })),
        post("/holds/release", Some(" "), &json!({ "case": case })),
    ] {
        let (status, body) = send(&router, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert!(
            body.to_string().contains("cannot be recorded"),
            "the documented sentence: {body}"
        );
    }
    assert_eq!(
        (store.clone() as Arc<dyn QuotaStore>)
            .halts()
            .await
            .unwrap()
            .len(),
        1
    );
    let (_, holds) = send(&router, get("/holds", Some("bob"))).await;
    assert_eq!(holds["holds"].as_array().map(Vec::len), Some(1), "{holds}");
    for outcome in ["halt-lifted", "hold-released"] {
        assert!(store.runs_by_outcome(outcome, 10).await.unwrap().is_empty());
    }
}

/// A quota register whose conditional removal fails after the lift is recorded.
#[derive(Debug)]
struct RemovalFails(Arc<RedbStore>);

#[async_trait::async_trait]
impl agentplane::quota::QuotaStore for RemovalFails {
    fn tenant(&self) -> &str {
        agentplane::quota::QuotaStore::tenant(self.0.as_ref())
    }
    async fn reserve(
        &self,
        run: agentplane::RunId,
        quota: &agentplane::quota::TenantQuota,
        hold: Option<&agentplane::quota::SpendHold>,
        at: agentplane::core::Timestamp,
    ) -> Result<(), agentplane::quota::QuotaError> {
        self.0.reserve(run, quota, hold, at).await
    }
    async fn release(&self, run: agentplane::RunId) -> Result<(), agentplane::core::StoreError> {
        agentplane::quota::QuotaStore::release(self.0.as_ref(), run).await
    }
    async fn carry(
        &self,
        run: agentplane::RunId,
        period: &str,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.carry(run, period).await
    }
    async fn reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::quota::Held>, agentplane::core::StoreError> {
        self.0.reservations(limit).await
    }
    async fn reserved(
        &self,
        period: &str,
    ) -> Result<agentplane::core::Spend, agentplane::core::StoreError> {
        self.0.reserved(period).await
    }
    async fn set_halt(
        &self,
        scope: &agentplane::quota::HaltScope,
        by: &agentplane::core::Operator,
        at: agentplane::core::Timestamp,
        reason: &str,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.set_halt(scope, by, at, reason).await
    }
    async fn lift_halt(
        &self,
        scope: &agentplane::quota::HaltScope,
    ) -> Result<bool, agentplane::core::StoreError> {
        self.0.lift_halt(scope).await
    }
    async fn lift_halt_if(
        &self,
        _: &agentplane::quota::Halt,
    ) -> Result<bool, agentplane::core::StoreError> {
        Err(agentplane::core::StoreError::Backend(
            "injected removal outage".to_owned(),
        ))
    }
    async fn halts(&self) -> Result<Vec<agentplane::quota::Halt>, agentplane::core::StoreError> {
        self.0.halts().await
    }
    async fn settle(
        &self,
        settlement: &agentplane::quota::QuotaSettlement,
    ) -> Result<(), agentplane::core::StoreError> {
        self.0.settle(settlement).await
    }
    async fn spent(
        &self,
        period: &str,
    ) -> Result<agentplane::core::Spend, agentplane::core::StoreError> {
        self.0.spent(period).await
    }
    async fn running(&self) -> Result<u32, agentplane::core::StoreError> {
        self.0.running().await
    }
    async fn running_runs(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::RunId>, agentplane::core::StoreError> {
        self.0.running_runs(limit).await
    }
    async fn reserve_rate(
        &self,
        reservation: &agentplane::quota::RateReservation,
    ) -> Result<(), agentplane::quota::QuotaError> {
        self.0.reserve_rate(reservation).await
    }
    async fn rate_room(
        &self,
        grant: &str,
        ceilings: &[agentplane::quota::RateCeiling],
        at: agentplane::core::Timestamp,
    ) -> Result<(), agentplane::quota::QuotaError> {
        self.0.rate_room(grant, ceilings, at).await
    }
}

/// **A lift recorded over a row that stayed answers naming the record's run.**
///
/// The record is written before the row goes, so a removal that fails leaves a
/// record of a lift that did not happen and a halt that still stands. Answered
/// as a bare store failure, the operator retries and writes a second record
/// with no way to find the first.
#[tokio::test]
async fn a_lift_whose_removal_fails_names_the_record_it_wrote() {
    use agentplane::quota::QuotaStore;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    store
        .set_halt(
            &agentplane::quota::HaltScope::Tenant,
            &agentplane::core::Operator::asserted("ops").unwrap(),
            agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000).unwrap(),
            "incident 47",
        )
        .await
        .unwrap();
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .quota(
            Arc::new(RemovalFails(store.clone())) as Arc<dyn QuotaStore>,
            agentplane::quota::TenantQuota::default(),
        )
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let router = Api::new(Arc::clone(&rt), Arc::new(HeaderAuth))
        .expect("the fixture wires a policy engine")
        .router();

    let (status, body) = send(
        &router,
        post("/halts/lift", Some("bob"), &json!({ "scope": "tenant" })),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let lifts = rt.lifted_halts(10).await.expect("lifts");
    assert_eq!(lifts.len(), 1, "the lift was recorded before the removal");
    let run = lifts[0].body.run.to_string();
    let said = body.to_string();
    assert!(
        said.contains(&run) && said.contains("still stands"),
        "the answer does not name the record's run: {body}"
    );
    assert_eq!(
        store.halts().await.unwrap().len(),
        1,
        "the halt was removed"
    );
}
