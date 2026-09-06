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
    let f = fixture();
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
    assert_eq!(status, StatusCode::ACCEPTED);
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

/// The webhook routes, when this build serves them.
///
/// Empty without the feature, so the walks below extend **unconditionally**. A
/// `#[cfg]` on the `extend` instead leaves the vector's `mut` unused in the
/// build that omits it, and `-D warnings` then fails the one job that compiles
/// exactly that combination — `just test-http`, which is a separate CI job and
/// not part of `just ci`.
fn push_routes(actor: Option<&str>) -> Vec<Request<Body>> {
    #[cfg(feature = "push")]
    {
        vec![
            get("/push", actor),
            post(
                "/push/rearm",
                actor,
                &json!({ "run": "not-an-id", "id": "d" }),
            ),
        ]
    }
    #[cfg(not(feature = "push"))]
    {
        let _ = actor;
        Vec::new()
    }
}

/// No credentials, no answer — on every route.
#[tokio::test]
async fn an_unauthenticated_request_is_refused_everywhere() {
    let f = fixture();
    let task = f.pending_task().await;
    let router = f.router();

    let mut requests = vec![
        get("/runs?outcome=quarantined", None),
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
    ];
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

    let mut requests = vec![
        get("/runs/not-an-id", Some("bob")),
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
        get("/cases", Some("bob")),
        get("/obligations", Some("bob")),
        get("/dead-letters", Some("bob")),
    ];
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

/// Every route in the module is exercised by a test in this file.
///
/// The gate tests above are only as good as the list of routes they walk. A
/// route added next year would be authenticated and authorized by construction —
/// `gate` is the only way to get a `Caller` — but nothing would prove it, and
/// "nothing proves it" is how the first ungated route gets written.
#[test]
fn every_route_is_walked_by_the_gate_tests() {
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

/// A store failure does not describe the store.
#[tokio::test]
async fn a_missing_store_does_not_describe_the_plane() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(Arc::new(Recording::default()) as Arc<dyn PolicyEngine>)
        .build();
    let router = Api::new(rt, Arc::new(HeaderAuth)).unwrap().router();

    let (status, body) = send(&router, get("/tasks", Some("bob"))).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["error"], "this plane has no task store");
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
