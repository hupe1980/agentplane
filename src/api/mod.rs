//! An HTTP surface for the people who have to look after a plane.
//!
//! # The rule this module is shaped by
//!
//! **Who is acting comes from the request's identity, never from its body.**
//!
//! Four-eyes is enforced in [`TaskStore::claim`](crate::case::TaskStore::claim),
//! which takes an actor and a set of roles. Inside the process those come from
//! the embedder's own code. Over HTTP they would come from whoever is on the
//! socket — and a reviewer who can name themselves can name the person who
//! proposed the action, which is the exact control four-eyes exists to be.
//!
//! Discipline is not enough for that. So the wire types here **have no actor
//! field**: [`DecisionRequest`] carries a verdict, a reason, and an optional
//! amendment. A caller cannot spoof what they cannot express, and a later
//! handler cannot be talked into reading it, because there is nothing to read.
//!
//! Roles work the same way. They come from [`Caller::roles`], which the
//! [`Authenticator`] produced, so a caller cannot grant themselves eligibility
//! for a queue they are not on.
//!
//! # Two gates, both mandatory
//!
//! Authentication says *who*. It does not say *what they may do*, and an
//! operator surface that stops at authentication grants every authenticated
//! caller the whole plane. So every route also passes through the runtime's
//! [`PolicyEngine`](crate::core::PolicyEngine) with an `api:` action, and [`Api::new`] **refuses to build**
//! against a runtime that has none.
//!
//! That refusal is the point. Inside the process an absent engine is a choice —
//! the caller is the embedder. On a socket it is a hole, and the failure mode of
//! a permissive default is that nobody finds out until the port is reachable.
//! [`DenyAll`](crate::core::DenyAll) exists for wiring the surface up before its
//! rules are written; starting closed and opening deliberately is the order that
//! fails safe.
//!
//! # No authenticator is shipped
//!
//! Same reasoning as the policy engine and the tracing exporter: the deployment
//! owns its identity system, and a bearer-token parser baked in here would be
//! wrong for the mutual-TLS deployment and load-bearing for the other. What this
//! crate owns is the shape — every route runs behind
//! [`Authenticator::authenticate`], and there is no route that does not.
//!
//! # What an operator actually needs
//!
//! The endpoints come from the questions a person asks at three in the morning,
//! not from the crate's type graph:
//!
//! * *What is this run doing, and why is it not finishing?* — a suspended run
//!   reports **what it is waiting for**, because "suspended" alone sends someone
//!   into the journal.
//! * *What is waiting for me?* — the worklist, filtered to the caller's roles,
//!   with each item saying whether **this** caller may decide it and who has
//!   already reserved it.
//! * *This one is mine; don't let a colleague duplicate the work.* — claim, and
//!   release again if it turns out not to be theirs after all.
//! * *Let me approve this.* — with four-eyes intact.
//! * *This message arrived; wake whoever wanted it.* — event delivery.
//! * *Stop it.* — the other half of oversight, and the one most surfaces omit.
//! * *What has happened on this matter?* — the case, its deadlines, its tasks.
//!
//! There is no `/health` and no `/metrics`. The embedder owns the port and the
//! process; a liveness probe answered by this router would be one more route
//! that must not authenticate, and the one route that skips the gate is the one
//! that eventually grows a feature.
//!
//! # Wiring it up
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use agentplane::api::{Api, AuthError, Authenticator, Caller};
//! # use agentplane::runtime::Runtime;
//! # #[derive(Debug)]
//! # struct MyAuth;
//! # #[async_trait::async_trait]
//! # impl Authenticator for MyAuth {
//! #     async fn authenticate(&self, h: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
//! #         let _ = h;
//! #         Err(AuthError::Missing)
//! #     }
//! # }
//! # async fn serve(runtime: Arc<Runtime>) -> Result<(), Box<dyn std::error::Error>> {
//! // `Api::new` fails here if the runtime has no policy engine.
//! let router = Api::new(runtime, Arc::new(MyAuth))?.router();
//!
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
//! axum::serve(listener, router).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::{
    CaseId, Decision, Delivery, InboundEvent, PolicyDecision, PolicyRequest, RunId, Task, TaskId,
};
use crate::journal::RecordKind;
use crate::runtime::Runtime;

/// Who is on the other end of the request.
///
/// Produced by the [`Authenticator`]; never parsed from a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The identity a decision is recorded under. Permanent — an approval with
    /// no name attached is not an approval.
    pub actor: String,
    /// What this caller is eligible for. Not self-declared.
    pub roles: Vec<String>,
}

impl Caller {
    pub fn new(actor: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            actor: actor.into(),
            roles,
        }
    }
}

/// Establishes who is calling.
///
/// Given the whole header map rather than a parsed token on purpose: a
/// deployment may authenticate by bearer token, mutual TLS, or a signed header
/// from a gateway, and this crate should not have an opinion about which.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync + std::fmt::Debug {
    /// Identify the caller, or refuse.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the request carries no usable identity. Returning an
    /// anonymous caller instead would put an unnamed actor on an approval.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Caller, AuthError>;
}

/// Why a request has no usable identity.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no credentials were presented")]
    Missing,
    /// Deliberately does not say *why* the credential was rejected: expired,
    /// unknown signer, and wrong audience are all the same sentence to whoever
    /// is probing.
    #[error("the credentials presented were not accepted")]
    Rejected,
}

/// Why the surface could not be built.
#[derive(Debug, thiserror::Error)]
pub enum ApiSetupError {
    /// The runtime has no [`PolicyEngine`](crate::core::PolicyEngine).
    ///
    /// Caught here rather than at the first request because a plane that boots
    /// and serves is a plane somebody believes is configured.
    #[error(
        "this runtime has no policy engine — an HTTP surface with no authorization \
         layer grants every authenticated caller the whole plane; wire one (start \
         with `DenyAll`) before opening a port"
    )]
    NoPolicy,
}

/// What a stop request looks like on the wire.
///
/// No actor, for the same reason [`DecisionRequest`] has none: the person
/// stopping a run is recorded permanently, and an intervention somebody else can
/// sign is not an intervention. The reason is **required** — a stop with no
/// stated cause is indistinguishable from an outage to whoever finds the run
/// tomorrow.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub reason: String,
}

/// What a decision looks like on the wire.
///
/// Note what is absent: **no actor, no roles**. Both come from the
/// [`Authenticator`], and leaving them out of the type means a request cannot
/// carry them even in principle.
///
/// `deny_unknown_fields` is the other half of that. Without it a body carrying
/// `"actor": "alice"` is accepted and silently ignored — the integrator who
/// wrote it believes they are deciding as Alice, the journal says otherwise, and
/// nobody finds out until an audit asks why the two disagree. Refusing the
/// request says so at the first call instead.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    pub approved: bool,
    pub reason: String,
    #[serde(default)]
    pub amendment: Value,
}

/// A run, to somebody working out why it has stopped.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunView {
    pub run: String,
    /// `running`, `suspended`, or the sealed outcome.
    pub status: String,
    /// Why it is not finishing, in words.
    ///
    /// The field that earns this endpoint. "Suspended" tells an operator the run
    /// is stuck; it does not tell them whether to go and approve something, wait
    /// for a counterparty, or page somebody.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_for: Option<String>,
    pub sealed: bool,
    /// Who asked for this run to stop, if anyone has.
    ///
    /// Shown because a run that is still `running` with a stop standing against
    /// it is a *different* situation from one nobody has touched — it is about
    /// to unwind, and an operator who cannot see that will ask again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_requested_by: Option<String>,
    /// Journal length — the operator's handle on "is it doing anything".
    pub records: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
}

/// A task as an operator sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TaskView {
    pub id: String,
    pub run: String,
    pub kind: String,
    pub justification: Value,
    pub priority: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_at: Option<String>,
    /// Who has reserved it, if anyone.
    ///
    /// Shown because the alternative is two reviewers reading the same case in
    /// parallel and one of them discovering, at the moment they submit, that the
    /// work was wasted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// Whether **this** caller may decide it.
    ///
    /// Computed per caller rather than left for the client to infer: whoever
    /// proposed the action can see the task, and has to be told here that it is
    /// not theirs to approve — rather than finding out from a refusal after
    /// they have read the case and made up their mind.
    pub decidable_by_you: bool,
}

impl TaskView {
    fn of(task: Task, caller: &Caller) -> Self {
        Self {
            // The same predicate the store enforces, not a re-implementation of
            // it. A second copy of an authorization rule drifts, and the copy
            // that drifts is the one people read.
            decidable_by_you: task.may_decide(&caller.actor, &caller.roles),
            assignee: task.assignee,
            id: task.id.to_hex(),
            run: task.run.to_string(),
            kind: task.kind,
            justification: serde_json::to_value(&task.justification).unwrap_or(Value::Null),
            priority: task.priority.as_str().to_owned(),
            state: task.state.as_str().to_owned(),
            case: task.case.map(|c| c.to_string()),
            due_at: task.due_at.and_then(|d| {
                d.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            }),
        }
    }
}

/// One page of the worklist.
///
/// An object rather than a bare array, for one reason: it can say it was cut
/// off. A queue of 140 items paged at 100 returns 100, and a bare array reads
/// exactly like a queue of 100 — which is the silent truncation this crate
/// refuses everywhere else.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Worklist {
    pub tasks: Vec<TaskView>,
    /// Whether there is more than this page.
    ///
    /// Determined by asking the store for one more than the page size and
    /// dropping it, so it is a fact about the queue rather than a guess from a
    /// full page.
    pub truncated: bool,
}

/// Everything the routes need.
#[derive(Clone)]
pub struct Api {
    runtime: Arc<Runtime>,
    auth: Arc<dyn Authenticator>,
    policy: Arc<dyn crate::core::PolicyEngine>,
    /// How many worklist items one request may return.
    limit: usize,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("policy", &self.policy.digest())
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// Default worklist page size.
    pub const DEFAULT_LIMIT: usize = 100;

    /// Build the surface.
    ///
    /// # Errors
    ///
    /// [`ApiSetupError::NoPolicy`] if the runtime has no policy engine. See the
    /// module docs on why that is a build-time refusal and not a warning.
    pub fn new(runtime: Arc<Runtime>, auth: Arc<dyn Authenticator>) -> Result<Self, ApiSetupError> {
        let policy = runtime.policy().ok_or(ApiSetupError::NoPolicy)?.clone();
        Ok(Self {
            runtime,
            auth,
            policy,
            limit: Self::DEFAULT_LIMIT,
        })
    }

    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// The router.
    ///
    /// Every route authenticates and then authorizes. There is no
    /// unauthenticated one to forget about and no "internal" path that skips
    /// either gate — `tests/wire/api.rs` walks the route table and asserts it.
    pub fn router(self) -> Router {
        Router::new()
            .route("/runs/{run}", get(run_view))
            .route("/runs/{run}/cancel", post(cancel_run))
            .route("/tasks", get(worklist))
            .route("/tasks/{task}", get(task_view))
            .route("/tasks/{task}/claim", post(claim))
            .route("/tasks/{task}/release", post(release))
            .route("/tasks/{task}/decide", post(decide))
            .route("/cases/{case}", get(case_view))
            .route("/events", post(deliver))
            .with_state(self)
    }

    /// Authenticate, then authorize, then hand back the caller.
    ///
    /// One function so that a route cannot do half of it. `action` is the `api:`
    /// verb the policy set keys on.
    async fn gate(
        &self,
        headers: &HeaderMap,
        action: &str,
        resource: &str,
    ) -> Result<Caller, ApiError> {
        let caller = self.auth.authenticate(headers).await?;
        // Roles go in the context so a policy set can key on them without this
        // crate deciding what a role means.
        let context = json!({ "roles": caller.roles });
        let decision = self.policy.authorize(&PolicyRequest {
            principal: &caller.actor,
            action,
            resource,
            context: &context,
        });
        match decision {
            PolicyDecision::Permit => Ok(caller),
            PolicyDecision::Deny { reason } => Err(ApiError(StatusCode::FORBIDDEN, reason)),
        }
    }
}

/// Actions this surface asks the policy engine about.
///
/// Named constants rather than inline literals so a deployment writing rules and
/// this crate dispatching them cannot disagree about spelling — and so a route
/// added without an action fails to compile rather than falling through to
/// somebody else's verb.
pub mod action {
    pub const RUN_READ: &str = "api:run.read";
    pub const RUN_CANCEL: &str = "api:run.cancel";
    pub const TASK_LIST: &str = "api:task.list";
    pub const TASK_READ: &str = "api:task.read";
    pub const TASK_CLAIM: &str = "api:task.claim";
    pub const TASK_RELEASE: &str = "api:task.release";
    pub const TASK_DECIDE: &str = "api:task.decide";
    pub const CASE_READ: &str = "api:case.read";
    pub const EVENT_DELIVER: &str = "api:event.deliver";

    /// Every action this surface can ask about.
    ///
    /// Exists so a deployment can enumerate what it must write rules for, and so
    /// a test can assert the route table and this list agree.
    pub const ALL: &[&str] = &[
        RUN_READ,
        RUN_CANCEL,
        TASK_LIST,
        TASK_READ,
        TASK_CLAIM,
        TASK_RELEASE,
        TASK_DECIDE,
        CASE_READ,
        EVENT_DELIVER,
    ];
}

/// An error as it reaches the wire.
///
/// Deliberately terse. A stack of internal detail on a 500 is how a store's
/// schema, a peer's hostname, or a policy's shape leaks to whoever is probing.
/// Policy denials are the exception: their reason is written by the deployment
/// for the caller to act on, and withholding it is how an authorization layer
/// becomes something people route around.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        Self(StatusCode::UNAUTHORIZED, e.to_string())
    }
}

fn bad(what: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, format!("not a {what} id"))
}

fn unavailable(what: &str) -> ApiError {
    ApiError(
        StatusCode::NOT_IMPLEMENTED,
        format!("this plane has no {what} store"),
    )
}

/// Reads are refused the same way whether the thing is missing or the store
/// broke, from the caller's side: both are 404 or 500 with no detail.
fn store_failed() -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the store is unavailable".into(),
    )
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("no such {what}"))
}

async fn run_view(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(run): Path<String>,
) -> Result<Json<RunView>, ApiError> {
    // Authorized against the run id, so a policy set can scope a caller to the
    // runs they are entitled to see rather than to the endpoint.
    api.gate(&headers, action::RUN_READ, &run).await?;
    let id = RunId::parse(&run).map_err(|_| bad("run"))?;

    let records = api
        .runtime
        .journal()
        .read(id, 1)
        .await
        .map_err(|_| store_failed())?;
    let Some(last) = records.last() else {
        return Err(not_found("run"));
    };

    // Status is read from the **last** record, not from whether a suspension
    // appears anywhere. A run that waited for an event, got it, and carried on
    // has a `RunSuspended` in its history and is not suspended now; scanning for
    // one would report every resumed run as stuck forever.
    let (status, waiting_for, sealed) = match last.kind() {
        RecordKind::RunSuspended { reason } => {
            ("suspended".to_owned(), Some(reason.to_string()), false)
        }
        RecordKind::RunSealed { outcome, .. } => (outcome.clone(), None, true),
        _ => ("running".to_owned(), None, false),
    };

    let case = records
        .iter()
        .find_map(|r| r.body.case.map(|c| c.to_string()));

    let cancellation_requested_by = api
        .runtime
        .cancellation(id)
        .await
        .map_err(|_| store_failed())?
        .map(|c| c.actor);

    Ok(Json(RunView {
        run: id.to_string(),
        status,
        waiting_for,
        sealed,
        cancellation_requested_by,
        records: records.len() as u64,
        case,
    }))
}

/// Stop a run.
///
/// Returns `202`, not `200`: the request is durable when this returns, and the
/// run stops at its next step boundary. Reporting `200` would claim the run had
/// already stopped, which is true only when it was suspended — and an operator
/// who believes a running agent has halted when it has not is worse off than one
/// who knows they are waiting.
async fn cancel_run(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(run): Path<String>,
    Json(body): Json<CancelRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let caller = api.gate(&headers, action::RUN_CANCEL, &run).await?;
    let id = RunId::parse(&run).map_err(|_| bad("run"))?;

    // The actor is the authenticated caller; `CancelRequest` has no field for
    // one. Same rule as deciding a task.
    let fresh = api
        .runtime
        .request_cancel(id, &caller.actor, &body.reason)
        .await
        .map_err(|e| ApiError(StatusCode::CONFLICT, e.to_string()))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "requested_by": caller.actor,
            // False means somebody else got there first, and *their* name is on
            // the record. Told plainly rather than swallowed, so a second
            // operator does not believe they own the intervention.
            "recorded": fresh,
        })),
    ))
}

async fn worklist(State(api): State<Api>, headers: HeaderMap) -> Result<Json<Worklist>, ApiError> {
    let caller = api.gate(&headers, action::TASK_LIST, "*").await?;
    let tasks = api.runtime.tasks().ok_or_else(|| unavailable("task"))?;

    // Filtered by the caller's *authenticated* roles. A caller cannot widen the
    // queue by asking for one they do not hold, because there is nowhere in the
    // request to ask.
    //
    // One more than the page, so a full page and an overflowing one are
    // distinguishable. Inferring it from `len() == limit` would call a queue of
    // exactly 100 truncated.
    let mut queued = tasks
        .queue(&caller.roles, api.limit + 1)
        .await
        .map_err(|_| store_failed())?;
    let truncated = queued.len() > api.limit;
    queued.truncate(api.limit);

    Ok(Json(Worklist {
        tasks: queued
            .into_iter()
            .map(|t| TaskView::of(t, &caller))
            .collect(),
        truncated,
    }))
}

async fn task_view(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(task): Path<String>,
) -> Result<Json<TaskView>, ApiError> {
    let caller = api.gate(&headers, action::TASK_READ, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = api.runtime.tasks().ok_or_else(|| unavailable("task"))?;

    let found = tasks
        .task(id)
        .await
        .map_err(|_| store_failed())?
        .ok_or_else(|| not_found("task"))?;

    // Eligibility is not a reason to hide a task: a reviewer barred by four-eyes
    // still needs to see that the item exists and why they cannot act on it.
    // `decidable_by_you` carries that, and the store — not this handler —
    // remains the thing that refuses the decision.
    Ok(Json(TaskView::of(found, &caller)))
}

/// Reserve a task, so two reviewers do not both work it.
///
/// Not merely advisory: `TaskStore::claim` enforces four-eyes and role
/// eligibility in the same transaction that reserves, so a reviewer who is not
/// permitted to decide is refused *here*, before they read the case — rather
/// than after they have made up their mind.
///
/// There is no body. The claimant is the authenticated caller, for the same
/// reason the decider is.
async fn claim(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(task): Path<String>,
) -> Result<Json<TaskView>, ApiError> {
    let caller = api.gate(&headers, action::TASK_CLAIM, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = api.runtime.tasks().ok_or_else(|| unavailable("task"))?;

    let claimed = tasks
        .claim(id, &caller.actor, &caller.roles)
        .await
        .map_err(|e| claim_refused(&e))?;
    Ok(Json(TaskView::of(claimed, &caller)))
}

/// Give a task back without deciding it.
///
/// The endpoint that makes claiming safe to use. Without it a reviewer who
/// claims something and then cannot decide it has parked the item until an
/// operator edits the database — so the queue develops a habit of not claiming,
/// and the reservation stops meaning anything.
async fn release(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(task): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = api.gate(&headers, action::TASK_RELEASE, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = api.runtime.tasks().ok_or_else(|| unavailable("task"))?;

    // Only the holder may release. The store enforces it by matching the
    // assignee in the `UPDATE`, so a caller cannot free somebody else's work.
    tasks
        .release(id, &caller.actor)
        .await
        .map_err(|e| claim_refused(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// How a refused claim reaches the wire.
///
/// Ineligibility is a `403` and contention is a `409`, because the two ask
/// different things of the person reading them: one is "this is not yours to
/// decide", the other is "try again, or ask Bob". Collapsing them into one
/// status is how a reviewer retries something that will never succeed.
fn claim_refused(e: &crate::case::ClaimError) -> ApiError {
    use crate::case::ClaimError;
    let status = match *e {
        ClaimError::Excluded { .. } | ClaimError::WrongRole { .. } => StatusCode::FORBIDDEN,
        ClaimError::NotFound(_) => StatusCode::NOT_FOUND,
        ClaimError::AlreadyClaimed { .. }
        | ClaimError::NotPending { .. }
        | ClaimError::NotHeld { .. } => StatusCode::CONFLICT,
        ClaimError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    // The store's own words: "you proposed this action" and "you hold the wrong
    // role" call for different fixes, and a generic denial sends an operator
    // hunting through a policy set for which of forty rules fired.
    let detail = if status == StatusCode::INTERNAL_SERVER_ERROR {
        "the store is unavailable".to_owned()
    } else {
        e.to_string()
    };
    ApiError(status, detail)
}

async fn decide(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(task): Path<String>,
    Json(body): Json<DecisionRequest>,
) -> Result<Json<Value>, ApiError> {
    let caller = api.gate(&headers, action::TASK_DECIDE, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;

    // The actor is the authenticated caller. There is no other source for it:
    // `DecisionRequest` has no such field, so this is not a convention being
    // followed but the only construction available.
    let decision = Decision {
        approved: body.approved,
        actor: caller.actor.clone(),
        reason: body.reason,
        amendment: body.amendment,
    };

    // Roles likewise, and `decide_task` re-runs the four-eyes and eligibility
    // checks against the store. The control lives there, not in this handler —
    // an HTTP surface that enforced it itself would be a second copy that can
    // disagree with the one the in-process caller goes through.
    api.runtime
        .decide_task(id, &decision, &caller.roles)
        .await
        .map_err(|e| match e {
            // A refused claim is a 403 with the store's own reason: "you
            // proposed this action" and "you hold the wrong role" call for
            // different fixes.
            crate::core::RuntimeError::PolicyDenied(_) => {
                ApiError(StatusCode::FORBIDDEN, e.to_string())
            }
            other => ApiError(StatusCode::CONFLICT, other.to_string()),
        })?;

    Ok(Json(json!({
        "decided_by": caller.actor,
        "approved": decision.approved,
    })))
}

async fn case_view(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(case): Path<String>,
) -> Result<Json<Value>, ApiError> {
    api.gate(&headers, action::CASE_READ, &case).await?;
    let id = CaseId::parse(&case).map_err(|_| bad("case"))?;
    let cases = api.runtime.cases().ok_or_else(|| unavailable("case"))?;

    let found = cases
        .case(id)
        .await
        .map_err(|_| store_failed())?
        .ok_or_else(|| not_found("case"))?;
    let deadlines = cases.deadlines(id).await.map_err(|_| store_failed())?;

    Ok(Json(json!({
        "case": serde_json::to_value(&found).unwrap_or(Value::Null),
        // Shown with the case because "when does this stop being my problem" is
        // the question that follows "what is this".
        "deadlines": serde_json::to_value(&deadlines).unwrap_or(Value::Null),
    })))
}

async fn deliver(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(event): Json<InboundEvent>,
) -> Result<Json<Value>, ApiError> {
    // Authorized on the event *kind*, so a policy set can let a counterparty
    // gateway post `acknowledgement.received` without also letting it post
    // whatever else the plane happens to wait on.
    api.gate(&headers, action::EVENT_DELIVER, &event.kind)
        .await?;

    let delivery = api
        .runtime
        .deliver(&event)
        .await
        .map_err(|e| ApiError(StatusCode::CONFLICT, e.to_string()))?;

    // Spelled out rather than `Debug`-formatted: this is a wire contract, and a
    // client keying on it should not break when someone renames a field.
    Ok(Json(match delivery {
        Delivery::Resumed { run } => json!({ "delivery": "resumed", "run": run.to_string() }),
        Delivery::Buffered => json!({ "delivery": "buffered" }),
        Delivery::Duplicate => json!({ "delivery": "duplicate" }),
    }))
}
