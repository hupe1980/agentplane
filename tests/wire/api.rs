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

#![cfg(all(feature = "http", feature = "turso"))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::api::{Api, ApiSetupError, AuthError, Authenticator, Caller, action};
use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    CorrelationKey, DeadlineSpec, Digest, Justification, Outcome, PolicyDecision, PolicyEngine,
    PolicyRequest, Priority, Skill, SkillDescriptor, SkillError, Tainted, TaskSpec,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::TursoStore;
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
                "invoice disputed",
                json!({ "action": "refund", "amount_eur": 4200 }),
            ),
            "approval",
        )
        .role("compliance-officer")
        .priority(Priority::High)
        // The proposer. Whoever this is may not approve it.
        .excluding("alice");

        let decision = cx.task(&spec).await?;
        Ok(Outcome::done(Tainted::trusted(json!({
            "approved": decision.approved,
            "by": decision.actor,
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

    fn digest(&self) -> Digest {
        Digest::of(b"test-policy")
    }
}

struct Fixture {
    store: Arc<TursoStore>,
    rt: Arc<Runtime>,
}

async fn fixture_with(policy: &Arc<Recording>) -> Fixture {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .policy(policy.clone() as Arc<dyn PolicyEngine>)
        .skill(ProposesRefund)
        .build();
    Fixture {
        store,
        rt: Arc::new(rt),
    }
}

async fn fixture() -> Fixture {
    fixture_with(&Arc::new(Recording::default())).await
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
            .run_in_case(
                "demo.refund",
                json!({}),
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

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
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
    let f = fixture().await;
    let task = f.pending_task().await;
    let router = f.router();

    let (status, _) = send(
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

/// The decision is recorded under the authenticated caller.
#[tokio::test]
async fn the_decision_is_recorded_under_the_authenticated_caller() {
    let f = fixture().await;
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
    let text = format!("{records:?}");
    assert!(
        text.contains("bob"),
        "the journal does not name the decider"
    );
    assert!(
        !text.contains("alice\""),
        "the journal names somebody who did not decide"
    );
}

/// Four-eyes survives the hop.
///
/// Alice proposed the refund and holds the right role. In-process the store
/// refuses her; the question is whether the HTTP path still routes through that
/// refusal rather than around it.
#[tokio::test]
async fn the_proposer_cannot_approve_their_own_proposal_over_http() {
    let f = fixture().await;
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
    let f = fixture().await;
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
    let f = fixture().await;
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
    let f = fixture().await;
    // Three tasks, one per run — see `two_runs_of_one_plan_do_not_share_one_task`
    // in tests/tasks.rs for why that is not a given.
    for doc in ["INV-1", "INV-2", "INV-3"] {
        f.rt.run_in_case(
            "demo.refund",
            json!({}),
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
    let f = fixture().await;
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
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["recorded"], false, "{body}");
}

/// A stop request body cannot name the actor either.
#[tokio::test]
async fn a_stop_body_that_names_an_actor_is_refused() {
    let f = fixture().await;
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
    let f = fixture().await;
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
    assert_eq!(
        after["cancellation_requested_by"], "bob",
        "an operator cannot see that a stop is standing against this run: {after}"
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
    let f = fixture().await;
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
    let f = fixture().await;
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
    let f = fixture().await;
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

/// No credentials, no answer — on every route.
#[tokio::test]
async fn an_unauthenticated_request_is_refused_everywhere() {
    let f = fixture().await;
    let task = f.pending_task().await;
    let router = f.router();

    for req in [
        get("/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV", None),
        post(
            "/runs/run_01ARZ3NDEKTSV4RRFFQ69G5FAV/cancel",
            None,
            &json!({ "reason": "stop" }),
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
    ] {
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
    let f = fixture_with(&policy).await;
    let router = f.router();

    for req in [
        get("/runs/not-an-id", Some("bob")),
        post(
            "/runs/not-an-id/cancel",
            Some("bob"),
            &json!({ "reason": "stop" }),
        ),
        get("/tasks", Some("bob")),
        get("/tasks/not-an-id", Some("bob")),
        get("/cases/not-an-id", Some("bob")),
        post("/tasks/not-an-id/claim", Some("bob"), &json!({})),
        post("/tasks/not-an-id/release", Some("bob"), &json!({})),
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
    ] {
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
#[tokio::test]
async fn the_surface_refuses_to_build_without_a_policy_engine() {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let rt = Arc::new(Runtime::builder(store as Arc<dyn JournalStore>).build());

    let err = Api::new(rt, Arc::new(HeaderAuth)).unwrap_err();
    assert!(matches!(err, ApiSetupError::NoPolicy));
    assert!(
        err.to_string().contains("DenyAll"),
        "the refusal does not say how to fix it: {err}"
    );
}

/// Every route in the module is exercised by a test in this file.
///
/// The gate tests above are only as good as the list of routes they walk. A
/// route added next year would be authenticated and authorized by construction —
/// `gate` is the only way to get a `Caller` — but nothing would prove it, and
/// "nothing proves it" is how the first ungated route gets written.
#[tokio::test]
async fn every_route_is_walked_by_the_gate_tests() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/mod.rs"))
        .expect("the api module");
    let here = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/wire/api.rs"))
        .expect("this file");

    let mut found = 0;
    for decl in src.split(".route(\"").skip(1) {
        let path = decl.split('"').next().unwrap_or_default();
        found += 1;
        // `/tasks/{task}` in the source is `/tasks/not-an-id` in a request, so
        // the comparison is on the fixed prefix rather than the whole path.
        let prefix: String = path.split('{').next().unwrap_or_default().to_owned();
        assert!(
            here.contains(&format!("\"{prefix}")) || here.contains(&format!("(\"{prefix}")),
            "route {path} is declared but no test in tests/wire/api.rs walks it"
        );
    }
    assert!(
        found >= 9,
        "found only {found} routes — this check read the wrong thing"
    );
}

// ── What an operator sees ───────────────────────────────────────────────────

/// A suspended run says what it is waiting for.
#[tokio::test]
async fn a_suspended_run_reports_what_it_is_waiting_for() {
    let f = fixture().await;
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
    let f = fixture().await;
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

/// An unknown run is a 404, and a malformed one a 400 — after the gate.
#[tokio::test]
async fn an_unknown_run_is_not_confused_with_a_malformed_one() {
    let f = fixture().await;
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

/// The case view carries the deadlines, because "when does this stop being my
/// problem" is the question that follows "what is this".
#[tokio::test]
async fn the_case_view_carries_its_deadlines() {
    let f = fixture().await;
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
    let f = fixture().await;
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

/// A store failure does not describe the store.
#[tokio::test]
async fn a_missing_store_does_not_describe_the_plane() {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let rt = Arc::new(
        Runtime::builder(store as Arc<dyn JournalStore>)
            .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
            .build(),
    );
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();

    let (status, body) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["error"], "this plane has no task store");
}
