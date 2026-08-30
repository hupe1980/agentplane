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
//! caller the whole plane. So every route also passes through the answering
//! plane's [`PolicyEngine`](crate::core::PolicyEngine) with an `api:` action,
//! and [`Api::new`] **refuses to build** if any plane has none — one ungoverned
//! tenant among governed ones is the one an attacker looks for.
//!
//! That refusal is the point. Inside the process an absent engine is a choice —
//! the caller is the embedder. On a socket it is a hole, and the failure mode of
//! a permissive default is that nobody finds out until the port is reachable.
//! [`DenyAll`](crate::core::DenyAll) exists for wiring the surface up before its
//! rules are written; starting closed and opening deliberately is the order that
//! fails safe.
//!
//! # One surface, many tenants
//!
//! [`Api::new`] takes [`Planes`] — a registry keyed by tenant — so one process
//! can serve several. A single-tenant deployment passes its runtime and reads
//! exactly as before.
//!
//! Which plane answers comes from [`Caller::tenant`], which the
//! [`Authenticator`] derives from the credential like `actor` and `roles`. That
//! is the field selecting a *store*, so a body-supplied one would be a
//! cross-tenant read with an authentication step in front of it.
//!
//! The gate hands each route the resolved plane **with** the caller, and this
//! struct holds no runtime of its own. A handler therefore cannot read a store
//! without having established whose it is, and every lookup on the registry
//! names a *caller* rather than a tenant — so the tenant a route can reach is
//! the one its credential resolved to, and reaching another is
//! [`Planes::cross`], which records the crossing first. A caller whose tenant
//! has no plane is refused, never served by a default — a fallback would turn
//! an unregistered tenant into somebody else's data, and it would look like
//! working software.
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

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::{
    CaseId, CaseStatus, CloudEvent, Decision, Delivery, InboundEvent, PolicyDecision,
    PolicyRequest, RunId, Task, TaskId, TenantId,
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
    /// Whose data this caller may reach.
    ///
    /// Derived by the [`Authenticator`] from the credential, exactly as `actor`
    /// and `roles` are, and for the same reason: a request that can name its own
    /// tenant is a request that can name somebody else's. It is the one field
    /// here that decides which *store* answers, so a body-supplied value would
    /// be a cross-tenant read with an authentication step in front of it.
    ///
    /// Defaults to [`TenantId::DEFAULT`] via [`Caller::new`], which is the whole
    /// of a single-tenant deployment: one real tenant rather than an absence, so
    /// the single-tenant path is the same code as the multi-tenant one.
    pub tenant: TenantId,
    /// On whose behalf this caller acts, when the credential says.
    ///
    /// Derived by the [`Authenticator`] like everything else here — a chain
    /// the body claimed would be a caller naming its own authority. Every run
    /// this caller starts is admitted under it: checked against the plan,
    /// held to its audience and validity, journaled as the run's
    /// `IdentityBound`. `None` means the credential carried no chain, and
    /// the run acts under the plane's own ([`RuntimeBuilder::acting_as`]) —
    /// or under none.
    ///
    /// [`RuntimeBuilder::acting_as`]: crate::runtime::RuntimeBuilder::acting_as
    pub acting_as: Option<crate::core::Delegation>,
}

impl Caller {
    /// A caller in the default tenant.
    pub fn new(actor: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            actor: actor.into(),
            roles,
            tenant: TenantId::default(),
            acting_as: None,
        }
    }

    /// A caller in a named tenant.
    #[must_use]
    pub fn in_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = tenant;
        self
    }

    /// A caller whose credential carried a delegation chain.
    #[must_use]
    pub fn acting_as(mut self, chain: crate::core::Delegation) -> Self {
        self.acting_as = Some(chain);
        self
    }
}

/// The provenance source under which a counterparty's data enters this plane:
/// `peer:{actor}`, one spelling for every transport.
///
/// The `{actor}` is the **authenticated** caller, never a name the body
/// claimed. One spelling covers every door a counterparty arrives through —
/// operator-API events, A2A task continuations, A2A message inputs — because
/// nothing downstream distinguishes transports: the event `source` becomes the
/// delivered value's provenance exactly as a message input's `SourceId` does.
/// So a protected sink field naming the one counterparty it accepts a value
/// from would match or miss depending on which door the value came through,
/// which is a hole shaped like a spelling. One helper, so the spellings
/// cannot drift again; a transport-qualified variant may return only when
/// something depends on telling transports apart, and today nothing does.
pub(crate) fn peer_source(actor: &str) -> String {
    format!("peer:{actor}")
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

    /// No plane was registered, so the surface would answer for nobody.
    ///
    /// Serving zero tenants is not a configuration, it is a startup that looks
    /// successful and refuses every request — the failure an operator debugs
    /// from the wrong end.
    #[error(
        "no planes were registered — this surface would authenticate callers \
         and then refuse all of them; register at least one with `Planes::one`"
    )]
    NoPlanes,
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
    /// Why it ended the way it did, when the ending has a why.
    ///
    /// The sealed twin of `waiting_for`, absent for a success. Without it a
    /// failed run answers with the word "failed" and sends the reader into
    /// the journal for the one sentence the seal already records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

#[cfg(feature = "a2a-server")]
pub mod a2a;
#[cfg(feature = "a2a-server")]
mod a2a_stream;
pub mod tokens;

/// The tenants this process serves, one plane each.
///
/// # Why a registry rather than a tenant parameter
///
/// The tenant is a key component of a store handle, not an argument to it — a
/// query that forgets a predicate returns another tenant's rows, and a query
/// that cannot name them returns nothing. Keeping that property while serving
/// several tenants means several handles, and therefore several planes: one per
/// tenant, sharing one database and one connection pool.
///
/// So this maps a caller's tenant to the plane that answers for it. A caller
/// whose tenant has no plane is **refused**, not served from a default — a
/// fallback here would turn an unregistered tenant into somebody else's data.
///
/// # Registration cannot put a plane under the wrong name
///
/// A plane is filed under the tenant it was built with, never under a name given
/// alongside it. Two arguments that must agree are two arguments that can
/// disagree, and the disagreement here is silent: the plane works, and it
/// answers for the wrong people.
#[derive(Debug, Clone, Default)]
pub struct Planes {
    by_tenant: std::collections::HashMap<TenantId, Arc<Runtime>>,
}

impl Planes {
    /// Serve one tenant — the single-tenant deployment, spelled out.
    #[must_use]
    pub fn one(plane: Arc<Runtime>) -> Self {
        Self::default().and(plane)
    }

    /// Also serve this plane's tenant.
    ///
    /// # Panics
    ///
    /// If a plane for that tenant is already registered. Two planes for one
    /// tenant is a wiring mistake with no correct resolution — whichever wins,
    /// half the configuration is silently inert.
    #[must_use]
    pub fn and(mut self, plane: Arc<Runtime>) -> Self {
        let tenant = plane.tenant().clone();
        assert!(
            self.by_tenant.insert(tenant.clone(), plane).is_none(),
            "two planes are registered for tenant '{tenant}'. Whichever won, \
             the other's skills, budgets and policy would be silently inert"
        );
        self
    }

    /// The plane answering for **this caller's own** tenant, if this process
    /// serves it.
    ///
    /// The tenant is read out of the caller rather than passed beside it, and
    /// that is the whole of the control. A signature taking a bare
    /// [`TenantId`] cannot tell *my tenant* from *somebody else's*, so it
    /// serves both and the difference lives in whether the handler remembered
    /// to pass the right one — which is a convention, and a control that must
    /// be invoked is not one. Here the only tenant a handler can name is the
    /// one its credential resolved to, and reaching any other is spelled
    /// [`Planes::cross`], which records the crossing first.
    ///
    /// What this does **not** claim is that a cross-tenant read is impossible:
    /// an embedder can build a [`Caller`] naming any tenant. That is the
    /// [`Authenticator`]'s job and a deliberate act, not a forgotten step, and
    /// it is the seam where a deployment decides what a credential means. The
    /// property held here is narrower and worth stating exactly: **no code path
    /// reaches another tenant's plane by accident**, because none can name one.
    #[must_use]
    pub fn get(&self, caller: &Caller) -> Option<&Arc<Runtime>> {
        self.by_tenant.get(&caller.tenant)
    }

    /// Reach a tenant that is **not** the caller's, recording the crossing first.
    ///
    /// The one sanctioned exception to isolation, and the only door through
    /// which it is spelled. [`Runtime::record_break_glass`] writes the record
    /// and returns an error if it cannot; this makes that record a
    /// **precondition of holding the plane** rather than a step an admin
    /// handler is asked to remember. A failure to record is therefore a failure
    /// to access, by construction — which is the sentence the operations guide
    /// has always used and, until this existed, described a convention.
    ///
    /// That is the same move as the rest of this registry. The tenant gate
    /// returns the plane *with* the caller so a handler cannot reach an
    /// unresolved store; a crossing returns the plane only *after* the crossed
    /// tenant's journal says who crossed it and why. A control that must be
    /// invoked is not one, and break-glass was the last one here that had to be.
    ///
    /// The whole [`Caller`] is taken rather than an actor, a role list and a
    /// tenant separately, because those three are one fact — who authenticated
    /// — and splitting them lets a handler record one operator's name against
    /// another's crossing. Four arguments that must agree are four arguments
    /// that can disagree, and the disagreement is silent: the record is
    /// written, it is signed, and it names the wrong person.
    ///
    /// The caller's own tenant as `target` is refused: reading your own data is
    /// not a crossing, and recording it as one would fill the break-glass
    /// backlog with non-events until nobody reads it.
    ///
    /// Who may pull it remains the deployment's policy decision. This decides
    /// only that pulling it is on the record.
    ///
    /// # Errors
    ///
    /// * [`RuntimeError::PlanContract`](crate::core::RuntimeError::PlanContract) if `target` is the caller's own
    ///   tenant, or if the reason is blank.
    /// * [`RuntimeError::UnknownTenant`](crate::core::RuntimeError::UnknownTenant) if this process serves no plane for
    ///   `target` — refused rather than defaulted, exactly as [`Planes::get`] is.
    /// * Whatever the store returned if the record could not be written. The
    ///   plane is not handed back in that case.
    pub async fn cross(
        &self,
        caller: &Caller,
        target: &TenantId,
        reason: &str,
    ) -> Result<&Arc<Runtime>, crate::core::RuntimeError> {
        if caller.tenant == *target {
            return Err(crate::core::RuntimeError::PlanContract(format!(
                "'{target}' is the caller's own tenant, so this is not a crossing — \
                 use `Planes::get`. Recording it as break-glass would bury the real \
                 crossings among routine reads"
            )));
        }
        let plane = self
            .by_tenant
            .get(target)
            .ok_or_else(|| crate::core::RuntimeError::UnknownTenant(target.to_string()))?;
        // The record first, and the plane only if it landed.
        plane
            .record_break_glass(&caller.actor, &caller.roles, reason)
            .await?;
        Ok(plane)
    }

    /// Every tenant served, for an operator checking their wiring.
    pub fn tenants(&self) -> impl Iterator<Item = &TenantId> {
        self.by_tenant.keys()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_tenant.is_empty()
    }
}

impl From<Arc<Runtime>> for Planes {
    fn from(plane: Arc<Runtime>) -> Self {
        Self::one(plane)
    }
}

/// What one authenticated request may touch.
///
/// The plane travels with the caller, and there is deliberately no other way for
/// a route to reach one: `Api` holds a *registry*, not a runtime, so a handler
/// cannot read a store without first having resolved which tenant's store it is.
/// The registry's own lookups take the caller too, so a route cannot name a
/// tenant other than the one it authenticated — the accidental cross-tenant
/// read is not guarded against here, it is unspellable. The deliberate one is
/// [`Planes::cross`], and it is on the record.
struct Session {
    caller: Caller,
    plane: Arc<Runtime>,
}

/// Everything the routes need.
#[derive(Clone)]
pub struct Api {
    planes: Planes,
    auth: Arc<dyn Authenticator>,
    /// How many worklist items one request may return.
    limit: usize,
    /// How much of a matter's history one case view returns.
    history: usize,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("tenants", &self.planes.tenants().collect::<Vec<_>>())
            .field("limit", &self.limit)
            .field("history", &self.history)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// Default worklist page size.
    pub const DEFAULT_LIMIT: usize = 100;

    /// Default bound on how much of a matter's history one case view returns.
    ///
    /// Bounded because a case can run for months and an operator page is not a
    /// bulk export. The response says when it truncated, because a shortened
    /// list is shaped exactly like a complete one and a reader who cannot tell
    /// will read absence as evidence.
    pub const DEFAULT_HISTORY_LIMIT: usize = 200;

    /// Build the surface over one plane, or several.
    ///
    /// Takes anything that becomes [`Planes`], so a single-tenant deployment
    /// still passes its runtime and reads the same as before.
    ///
    /// # Errors
    ///
    /// [`ApiSetupError::NoPolicy`] if **any** plane has no policy engine — one
    /// ungoverned tenant among governed ones is the one an attacker looks for.
    /// [`ApiSetupError::NoPlanes`] if none was registered, which would serve
    /// nobody while starting cleanly.
    pub fn new(
        planes: impl Into<Planes>,
        auth: Arc<dyn Authenticator>,
    ) -> Result<Self, ApiSetupError> {
        let planes = planes.into();
        if planes.is_empty() {
            return Err(ApiSetupError::NoPlanes);
        }
        for plane in planes.by_tenant.values() {
            if plane.policy().is_none() {
                return Err(ApiSetupError::NoPolicy);
            }
        }
        Ok(Self {
            planes,
            auth,
            limit: Self::DEFAULT_LIMIT,
            history: Self::DEFAULT_HISTORY_LIMIT,
        })
    }

    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// How much of a matter's history one case view returns.
    ///
    /// Its own knob rather than [`limit`](Self::limit), because the two bound
    /// different readings: a list page is scanned, a history is followed — and
    /// an operator who widens the worklist page should not silently deepen
    /// every case view with it.
    #[must_use]
    pub const fn history_limit(mut self, limit: usize) -> Self {
        self.history = limit;
        self
    }

    /// The router.
    ///
    /// Every route authenticates and then authorizes. There is no
    /// unauthenticated one to forget about and no "internal" path that skips
    /// either gate — `tests/wire/api.rs` walks the route table and asserts it.
    pub fn router(self) -> Router {
        Router::new()
            .route("/runs", get(runs_by_outcome))
            .route("/runs/{run}", get(run_view))
            .route("/runs/{run}/cancel", post(cancel_run))
            .route("/tasks", get(worklist))
            .route("/tasks/{task}", get(task_view))
            .route("/tasks/{task}/claim", post(claim))
            .route("/tasks/{task}/release", post(release))
            .route("/tasks/{task}/takeover", post(take_over))
            .route("/tasks/{task}/decide", post(decide))
            .route("/cases", get(cases_by_status))
            .route("/obligations", get(breached_obligations))
            .route("/cases/{case}", get(case_view))
            .route("/events", post(deliver))
            .with_state(self)
    }

    /// Authenticate, resolve the tenant's plane, then authorize.
    ///
    /// One function so that a route cannot do part of it, and returning the
    /// plane so that a route cannot reach a different one. `action` is the
    /// `api:` verb the policy set keys on.
    ///
    /// The order is load-bearing. The plane is resolved **before** the policy
    /// question, because the policy that answers it belongs to that tenant: a
    /// shared engine would let one tenant's rules decide another's requests, and
    /// the tenant with the laxest rules would effectively set everybody's.
    async fn gate(
        &self,
        headers: &HeaderMap,
        action: &str,
        resource: &str,
    ) -> Result<Session, ApiError> {
        let caller = self.auth.authenticate(headers).await?;

        // Refused, never defaulted. Falling back to a default plane would turn
        // an unregistered tenant into somebody else's data, and it would look
        // like working software.
        let plane = self.planes.get(&caller).ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                "this deployment serves no plane for your tenant".to_owned(),
            )
        })?;
        let policy = plane.policy().ok_or_else(|| {
            ApiError(StatusCode::FORBIDDEN, "this plane is ungoverned".to_owned())
        })?;

        // Roles and tenant go in the context so a policy set can key on them
        // without this crate deciding what either means.
        let context = json!({ "roles": caller.roles, "tenant": caller.tenant.as_str() });
        let decision = policy.authorize(&PolicyRequest {
            principal: &caller.actor,
            action,
            resource,
            context: &context,
        });
        match decision {
            PolicyDecision::Permit => Ok(Session {
                caller,
                plane: Arc::clone(plane),
            }),
            PolicyDecision::Deny { reason } => Err(ApiError(StatusCode::FORBIDDEN, reason)),
            // Refused, and it is the plane that is broken rather than the
            // request: 500 rather than 403, because 403 tells an operator to
            // fix their credentials and this one is fixed in the policy set.
            PolicyDecision::Malformed { reason } => {
                tracing::error!(target: "agentplane::api", policy_error = true, reason, "the policy set could not be evaluated");
                Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, reason))
            }
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
    pub const RUN_LIST: &str = "api:run.list";
    pub const RUN_CANCEL: &str = "api:run.cancel";
    pub const TASK_LIST: &str = "api:task.list";
    pub const TASK_READ: &str = "api:task.read";
    pub const TASK_CLAIM: &str = "api:task.claim";
    pub const TASK_RELEASE: &str = "api:task.release";
    /// Displacing a named absent holder. Its own verb rather than a widened
    /// `task.claim`, so a policy set can hand it to a queue lead without
    /// handing displacement to every reviewer.
    pub const TASK_TAKEOVER: &str = "api:task.takeover";
    pub const TASK_DECIDE: &str = "api:task.decide";
    pub const CASE_READ: &str = "api:case.read";
    pub const CASE_LIST: &str = "api:case.list";
    /// Listing obligations that were missed. Its own verb rather than a widened
    /// `case.list`, because the party who must answer for a breach is a
    /// compliance function that has no reason to read matter state.
    pub const OBLIGATION_LIST: &str = "api:obligation.list";
    pub const EVENT_DELIVER: &str = "api:event.deliver";

    /// Every action this surface can ask about.
    ///
    /// Exists so a deployment can enumerate what it must write rules for, and so
    /// a test can assert the route table and this list agree.
    ///
    /// Completeness here is load-bearing, not documentation: a deployment
    /// writes its rules by enumerating this list against a deny-by-default
    /// engine, so a verb omitted from it is a route refused to everybody —
    /// and the routes behind these verbs are the backlogs somebody must be
    /// able to clear. The gate-denial walk in `tests/wire/api.rs` therefore
    /// covers **every** route, not a sample: a sampled walk compared against
    /// this list can omit the same verb from both sides and pass.
    pub const ALL: &[&str] = &[
        RUN_READ,
        RUN_LIST,
        RUN_CANCEL,
        TASK_TAKEOVER,
        TASK_LIST,
        TASK_READ,
        TASK_CLAIM,
        TASK_RELEASE,
        TASK_DECIDE,
        CASE_READ,
        CASE_LIST,
        OBLIGATION_LIST,
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
    let s = api.gate(&headers, action::RUN_READ, &run).await?;
    let id = RunId::parse(&run).map_err(|_| bad("run"))?;

    let records = s
        .plane
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
    let (status, waiting_for, reason, sealed) = match last.kind() {
        RecordKind::RunSuspended { reason } => (
            "suspended".to_owned(),
            Some(reason.to_string()),
            None,
            false,
        ),
        RecordKind::RunSealed {
            outcome, reason, ..
        } => (outcome.clone(), None, reason.clone(), true),
        _ => ("running".to_owned(), None, None, false),
    };

    let case = records
        .iter()
        .find_map(|r| r.body.case.map(|c| c.to_string()));

    let cancellation_requested_by = s
        .plane
        .cancellation(id)
        .await
        .map_err(|_| store_failed())?
        .map(|c| c.actor);

    Ok(Json(RunView {
        run: id.to_string(),
        status,
        waiting_for,
        reason,
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
    let s = api.gate(&headers, action::RUN_CANCEL, &run).await?;
    let id = RunId::parse(&run).map_err(|_| bad("run"))?;

    // The actor is the authenticated caller; `CancelRequest` has no field for
    // one. Same rule as deciding a task.
    //
    // Classified, not collapsed. A mistyped run id is a 404, a store outage a
    // 500 — answering either as 409 tells the operator "somebody else got
    // there first", which sends them to read a record that does not exist, or
    // teaches them a retryable outage is permanent. 409 is kept for what it
    // means: the run's state refuses the request.
    let fresh = s
        .plane
        .request_cancel(id, &s.caller.actor, &body.reason)
        .await
        .map_err(|e| match e {
            crate::core::RuntimeError::Store(crate::core::StoreError::NotFound(_)) => {
                not_found("run")
            }
            crate::core::RuntimeError::Store(_) => store_failed(),
            other => ApiError(StatusCode::CONFLICT, other.to_string()),
        })?;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "requested_by": s.caller.actor,
            // False means somebody else got there first, and *their* name is on
            // the record. Told plainly rather than swallowed, so a second
            // operator does not believe they own the intervention.
            "recorded": fresh,
        })),
    ))
}

/// Runs that ended a given way — in practice, *what is quarantined right now*.
///
/// A quarantine is the most serious conclusion this runtime reaches, and a
/// status, an `error!` and a counter are not things an operator can ask for. A
/// run started with `spawn` returns before its status exists, so for those there
/// is nothing else to read.
///
/// One of four backlogs, and each is delivered by its own route because each has
/// a different party to reach: [`cases_by_status`], [`breached_obligations`],
/// [`worklist`].
async fn runs_by_outcome(
    State(api): State<Api>,
    headers: HeaderMap,
    Query(q): Query<OutcomeQuery>,
) -> Result<Json<Value>, ApiError> {
    let outcome = q.outcome.unwrap_or_else(|| "quarantined".to_owned());
    let s = api.gate(&headers, action::RUN_LIST, &outcome).await?;

    // One more than the page, so a full page and an overflowing one are
    // distinguishable — the same reason the worklist asks for one extra.
    let mut found = s
        .plane
        .journal()
        .runs_by_outcome(&outcome, api.limit + 1)
        .await
        .map_err(|_| store_failed())?;
    let truncated = found.len() > api.limit;
    found.truncate(api.limit);

    Ok(Json(json!({
        "outcome": outcome,
        "runs": found.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "truncated": truncated,
    })))
}

/// Which ending to list. Defaults to the one somebody is looking for.
#[derive(serde::Deserialize)]
struct OutcomeQuery {
    outcome: Option<String>,
}

async fn worklist(State(api): State<Api>, headers: HeaderMap) -> Result<Json<Worklist>, ApiError> {
    let s = api.gate(&headers, action::TASK_LIST, "*").await?;
    let tasks = s.plane.tasks().ok_or_else(|| unavailable("task"))?;

    // Filtered by the caller's *authenticated* roles. A caller cannot widen the
    // queue by asking for one they do not hold, because there is nowhere in the
    // request to ask.
    //
    // One more than the page, so a full page and an overflowing one are
    // distinguishable. Inferring it from `len() == limit` would call a queue of
    // exactly 100 truncated.
    let mut queued = tasks
        .queue(&s.caller.roles, api.limit + 1)
        .await
        .map_err(|_| store_failed())?;
    let truncated = queued.len() > api.limit;
    queued.truncate(api.limit);

    Ok(Json(Worklist {
        tasks: queued
            .into_iter()
            .map(|t| TaskView::of(t, &s.caller))
            .collect(),
        truncated,
    }))
}

async fn task_view(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(task): Path<String>,
) -> Result<Json<TaskView>, ApiError> {
    let s = api.gate(&headers, action::TASK_READ, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = s.plane.tasks().ok_or_else(|| unavailable("task"))?;

    let found = tasks
        .task(id)
        .await
        .map_err(|_| store_failed())?
        .ok_or_else(|| not_found("task"))?;

    // Eligibility is not a reason to hide a task: a reviewer barred by four-eyes
    // still needs to see that the item exists and why they cannot act on it.
    // `decidable_by_you` carries that, and the store — not this handler —
    // remains the thing that refuses the decision.
    Ok(Json(TaskView::of(found, &s.caller)))
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
    let s = api.gate(&headers, action::TASK_CLAIM, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = s.plane.tasks().ok_or_else(|| unavailable("task"))?;

    let claimed = tasks
        .claim(id, &s.caller.actor, &s.caller.roles)
        .await
        .map_err(|e| claim_refused(&e))?;
    Ok(Json(TaskView::of(claimed, &s.caller)))
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
    let s = api.gate(&headers, action::TASK_RELEASE, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = s.plane.tasks().ok_or_else(|| unavailable("task"))?;

    // Only the holder may release. The store enforces it by matching the
    // assignee in the `UPDATE`, so a caller cannot free somebody else's work.
    tasks
        .release(id, &s.caller.actor)
        .await
        .map_err(|e| claim_refused(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Take a task over from a holder who is not coming back.
///
/// The body names the holder being displaced, and the store treats that as a
/// compare-and-swap: a take-over decided from a stale queue view fails rather
/// than displacing whoever holds the task now. Eligibility — four-eyes
/// exclusion included — is re-checked in full for the caller, who is the new
/// holder for the same reason the claimant and the decider are the
/// authenticated caller and never a body field.
async fn take_over(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(task): Path<String>,
    Json(body): Json<TakeOverBody>,
) -> Result<Json<TaskView>, ApiError> {
    let s = api.gate(&headers, action::TASK_TAKEOVER, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;
    let tasks = s.plane.tasks().ok_or_else(|| unavailable("task"))?;

    let taken = tasks
        .take_over(id, &body.from, &s.caller.actor, &s.caller.roles)
        .await
        .map_err(|e| claim_refused(&e))?;
    Ok(Json(TaskView::of(taken, &s.caller)))
}

/// The one field a take-over carries: whose claim is being displaced.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TakeOverBody {
    from: String,
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
    let s = api.gate(&headers, action::TASK_DECIDE, &task).await?;
    let id = TaskId::parse(&task).map_err(|_| bad("task"))?;

    // The actor is the authenticated caller. There is no other source for it:
    // `DecisionRequest` has no such field, so this is not a convention being
    // followed but the only construction available.
    let decision = Decision {
        approved: body.approved,
        actor: s.caller.actor.clone(),
        reason: body.reason,
        amendment: body.amendment,
    };

    // Roles likewise, and `decide_task` re-runs the four-eyes and eligibility
    // checks against the store. The control lives there, not in this handler —
    // an HTTP surface that enforced it itself would be a second copy that can
    // disagree with the one the in-process caller goes through.
    s.plane
        .decide_task(id, &decision, &s.caller.roles)
        .await
        .map_err(|e| match e {
            // The same classification the claim route answers with, from the
            // same function: an ineligible decider is a 403 with the store's
            // own reason, an unknown task a 404, contention a 409, and a store
            // outage a 500 — not one status a client cannot act on.
            crate::core::RuntimeError::TaskClaim(claim) => claim_refused(&claim),
            crate::core::RuntimeError::PolicyDenied(_) => {
                ApiError(StatusCode::FORBIDDEN, e.to_string())
            }
            // An outage while recording the answer, after the claim held. Not
            // a 409: a conflict tells the decider their verdict lost a race,
            // and this one was simply not written yet.
            crate::core::RuntimeError::Store(_) => store_failed(),
            other => ApiError(StatusCode::CONFLICT, other.to_string()),
        })?;

    Ok(Json(json!({
        "decided_by": s.caller.actor,
        "approved": decision.approved,
    })))
}

/// Cases in a given state — in practice, *what is escalated right now*.
///
/// An escalation is the sweeper's most consequential conclusion: an obligation
/// was missed and somebody was told. Until this route, "told" meant a status
/// written onto the case and a metric, and the only way to read it back was
/// [`case_view`] — which needs the case id. So the answer was available to
/// anyone who already knew which case had escalated, which is the one group
/// that did not need to ask.
///
/// That is detection without delivery, and the sibling route listing quarantined
/// runs claimed the opposite in as many words: *every other backlog here is
/// findable by whoever must clear it — escalated cases, overdue tasks, breached
/// obligations*. Overdue tasks were, through the worklist. Escalated cases were
/// not, and the claim was made in a comment on the route that had just fixed the
/// same hole one surface over.
///
/// `status` defaults to `escalated` for the same reason the run listing defaults
/// to `quarantined`: the default should be what somebody is looking for.
async fn cases_by_status(
    State(api): State<Api>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<Json<Value>, ApiError> {
    let asked = q.status.unwrap_or_else(|| "escalated".to_owned());
    let s = api.gate(&headers, action::CASE_LIST, &asked).await?;
    let status = CaseStatus::parse(&asked).ok_or_else(|| bad("status"))?;
    let cases = s.plane.cases().ok_or_else(|| unavailable("case"))?;

    // One more than the page, so a full page and an overflowing one are
    // distinguishable — a backlog of 140 shown as 100 reads as a backlog of 100,
    // and the cases that fell off the end are the ones nobody clears.
    let mut found = cases
        .by_status(status, api.limit + 1)
        .await
        .map_err(|_| store_failed())?;
    let truncated = found.len() > api.limit;
    found.truncate(api.limit);

    Ok(Json(json!({
        "status": status.as_str(),
        "cases": found
            .iter()
            .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
            .collect::<Vec<_>>(),
        "truncated": truncated,
    })))
}

/// Which case state to list. Defaults to the one somebody is looking for.
#[derive(serde::Deserialize)]
struct StatusQuery {
    status: Option<String>,
}

/// Obligations that were missed, longest-overdue first.
///
/// Reads the obligation's own row rather than the status of the case it
/// escalated, so it still answers after that case is closed — `close` admits a
/// case once nothing is still *outstanding*, and a breach is not outstanding.
///
/// No status parameter: a breach is the only obligation state anyone has to be
/// told about, the rest being either still watched by the sweep or answered.
async fn breached_obligations(
    State(api): State<Api>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let s = api
        .gate(&headers, action::OBLIGATION_LIST, "breached")
        .await?;
    let cases = s.plane.cases().ok_or_else(|| unavailable("case"))?;

    // One more than the page, for the reason the sibling routes take one more:
    // a backlog of 140 shown as 100 reads as a backlog of 100.
    let mut found = cases
        .breached(api.limit + 1)
        .await
        .map_err(|_| store_failed())?;
    let truncated = found.len() > api.limit;
    found.truncate(api.limit);

    Ok(Json(json!({
        "obligations": found
            .iter()
            .map(|d| serde_json::to_value(d).unwrap_or(Value::Null))
            .collect::<Vec<_>>(),
        "truncated": truncated,
    })))
}

async fn case_view(
    State(api): State<Api>,
    headers: HeaderMap,
    Path(case): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let s = api.gate(&headers, action::CASE_READ, &case).await?;
    let id = CaseId::parse(&case).map_err(|_| bad("case"))?;
    let cases = s.plane.cases().ok_or_else(|| unavailable("case"))?;

    let found = cases
        .case(id)
        .await
        .map_err(|_| store_failed())?
        .ok_or_else(|| not_found("case"))?;
    let deadlines = cases.deadlines(id).await.map_err(|_| store_failed())?;

    // "Why is this escalated" is the question that follows "what is this", and
    // the state alone cannot answer it: a breached deadline looks the same
    // whether the sweep set it at 02:00 or somebody edited it. The history can.
    //
    // A scan over the matter rather than a walk over its runs, because a sweep
    // belongs to no case and its record would otherwise be unreachable from
    // the very case it escalated.
    // One more than the page, exactly as the list routes ask: truncation is a
    // fact about the history, not an inference from a full page — a matter
    // with exactly the limit's worth of records is complete, not cut off.
    let mut history = s
        .plane
        .journal()
        .case_history(id, api.history + 1)
        .await
        .map_err(|_| store_failed())?;
    let history_truncated = history.len() > api.history;
    history.truncate(api.history);

    Ok(Json(json!({
        "case": serde_json::to_value(&found).unwrap_or(Value::Null),
        // Shown with the case because "when does this stop being my problem" is
        // the question that follows "what is this".
        "deadlines": serde_json::to_value(&deadlines).unwrap_or(Value::Null),
        "history": history
            .iter()
            .map(|r| json!({
                "seq": r.seq(),
                "run": r.body.run.to_string(),
                "kind": r.kind().kind_str(),
                "record": serde_json::to_value(r.kind()).unwrap_or(Value::Null),
            }))
            .collect::<Vec<_>>(),
        // Said out loud: a truncated history is shaped exactly like a complete
        // one, and a reader who cannot tell will read absence as evidence.
        "history_truncated": history_truncated,
    })))
}

/// An event as a caller may state it, in this plane's own shape.
///
/// Deliberately **not** [`InboundEvent`]: that carries a `source`, and a caller
/// does not get to choose one. The source is half the deduplication identity and
/// the sender's name in provenance, so a body that set it would let one
/// counterparty deduplicate against another's messages, or post under a name a
/// policy trusts. It comes from the authenticated caller instead.
#[derive(serde::Deserialize)]
struct DeliverBody {
    id: String,
    kind: String,
    #[serde(default)]
    correlation: Vec<crate::core::CorrelationKey>,
    payload: Value,
}

/// The two shapes this route accepts, and what each becomes.
///
/// A bus speaks [`CloudEvents`](`CloudEvent`); an operator's `curl` speaks
/// whatever this plane documents. Before both were accepted here, a deployment
/// whose producers emit `CloudEvents` — which is every deployment that also
/// **receives** this plane's own `RunCompleted` output — had to translate the
/// envelope itself, and the translations in the field got the deduplication
/// identity wrong in the same way each time: they keyed on `id` alone, which
/// is unique only within one producer, so two counterparties numbering their
/// messages from one silently collapsed into one.
///
/// Both forms end up as an [`InboundEvent`] whose `source` is the
/// **authenticated caller**, for the reason [`DeliverBody`] gives.
enum DeliverInput {
    Native(DeliverBody),
    Cloud(CloudEvent),
}

impl DeliverInput {
    /// Which event kind the policy gate is asked about.
    fn kind(&self) -> &str {
        match self {
            Self::Native(body) => &body.kind,
            Self::Cloud(event) => event.event_type(),
        }
    }

    fn into_event(self, source: String) -> InboundEvent {
        match self {
            Self::Native(body) => {
                let mut event = InboundEvent::new(source, body.id, body.kind, body.payload);
                event.correlation = body.correlation;
                event
            }
            // The correlation keys of a CloudEvent are the ones a run declared
            // interest in, and a CloudEvents extension attribute is a flat
            // lowercase string with no namespace — so there is nothing here to
            // map them from that would not be this plane inventing a
            // convention and calling it the spec. A bus that must correlate
            // posts the native shape, where the keys are stated.
            Self::Cloud(event) => event.into_inbound(source),
        }
    }
}

/// Read the body as whichever shape it announced.
///
/// The `Content-Type` decides, and a `CloudEvent` in *binary* content mode
/// announces itself with `ce-` headers instead — which is why this takes the
/// whole header map and not just one value.
fn parse_delivery(headers: &HeaderMap, body: &[u8]) -> Result<DeliverInput, ApiError> {
    // The one predicate the CloudEvents parser itself uses. A second
    // spelling here is free to disagree about which mode a message is in,
    // and the caller then sees a native-shape "missing field" error for a
    // conformant CloudEvents post.
    let structured = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(crate::core::is_cloudevent_media_type);
    let binary = headers.keys().any(|name| {
        name.as_str()
            .starts_with(crate::core::CLOUDEVENT_HEADER_PREFIX)
    });
    if structured || binary {
        let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            match value.to_str() {
                Ok(value) => pairs.push((name.as_str(), value)),
                // Dropped silently, a raw-UTF8 `ce-source` reads as a
                // *missing* source rather than as the illegal header it is
                // (the binding says to percent-encode it).
                Err(_)
                    if name
                        .as_str()
                        .starts_with(crate::core::CLOUDEVENT_HEADER_PREFIX) =>
                {
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "header '{name}' is not visible ASCII — the CloudEvents HTTP \
                             binding percent-encodes non-ASCII attribute values"
                        ),
                    ));
                }
                Err(_) => {}
            }
        }
        return CloudEvent::from_http(pairs, body)
            .map(DeliverInput::Cloud)
            .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()));
    }
    let body = serde_json::from_slice::<DeliverBody>(body)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))?;
    // The same non-emptiness the CloudEvents shape enforces: an empty id
    // collapses every one of a caller's events into one deduplication key,
    // and an empty kind can never match a waiter.
    if body.id.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "an event needs a non-empty 'id'".to_owned(),
        ));
    }
    if body.kind.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "an event needs a non-empty 'kind'".to_owned(),
        ));
    }
    Ok(DeliverInput::Native(body))
}

async fn deliver(
    State(api): State<Api>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let input = parse_delivery(&headers, &body)?;

    // Authorized on the event *kind*, so a policy set can let a counterparty
    // gateway post `acknowledgement.received` without also letting it post
    // whatever else the plane happens to wait on. A CloudEvent's `type` is that
    // kind — the same question, asked of whichever envelope arrived.
    let s = api
        .gate(&headers, action::EVENT_DELIVER, input.kind())
        .await?;

    // The source is who the transport says they are, never who the body claims.
    // A self-asserted source would make `(source, id)` a pair a caller controls
    // both halves of — so one counterparty could deduplicate against another's
    // messages by naming them. Spelled `peer:{actor}` like every other door a
    // counterparty's data enters through — see [`peer_source`].
    let event = input.into_event(peer_source(&s.caller.actor));

    // A store outage is the plane's problem, answered 503 so a conformant bus
    // retries; everything else is a statement about the request, and a 409 a
    // bus treats as permanent is the honest answer only for those.
    let delivery = s.plane.deliver(&event).await.map_err(|e| match e {
        crate::core::RuntimeError::Store(_) => {
            ApiError(StatusCode::SERVICE_UNAVAILABLE, e.to_string())
        }
        _ => ApiError(StatusCode::CONFLICT, e.to_string()),
    })?;

    // Spelled out rather than `Debug`-formatted: this is a wire contract, and a
    // client keying on it should not break when someone renames a field.
    Ok(Json(match delivery {
        Delivery::Resumed { run } => json!({ "delivery": "resumed", "run": run.to_string() }),
        Delivery::Buffered => json!({ "delivery": "buffered" }),
        Delivery::Duplicate => json!({ "delivery": "duplicate" }),
    }))
}
