//! The operator API as an `OpenAPI` 3.1 document.
//!
//! [`ROUTES`] is the one list of operations. [`Api::router`](super::Api::router)
//! serves exactly what it lists, and [`document`] describes exactly what it
//! lists, so a route cannot be served undocumented or documented unserved. The
//! request, query and answer schemas are derived from the types the handlers
//! read and write, with the same schema derive the manifest format uses.
//!
//! What the table cannot make true by construction is held by tests: that each
//! entry names the action its handler asks the policy engine, and that every
//! body the API answers validates against the schema given for its operation
//! and status.
//!
//! The document describes the API, not one build: every build serves every
//! operation. One a feature adds is marked `x-agentplane-feature`, and a build
//! without that feature gates it like any other and then answers 501.

use std::collections::BTreeSet;

use axum::routing::{MethodFilter, MethodRouter, on};
use schemars::generate::{SchemaGenerator, SchemaSettings};
use schemars::{JsonSchema, Schema};
use serde_json::{Map, Value, json};

use super::{Api, action};

/// How a request's method is spelled in the router and in the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    /// The document's spelling: `get`, `post`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
        }
    }

    const fn filter(self) -> MethodFilter {
        match self {
            Self::Get => MethodFilter::GET,
            Self::Post => MethodFilter::POST,
        }
    }
}

/// One kind of refusal, and the status it answers with.
///
/// Every refusal answers `{"error": "<sentence>"}`; the class decides only the
/// status. An operation's documented statuses are the classes every route can
/// answer, the classes its extractors can answer, and the ones its own entry
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorClass {
    /// An identifier that does not parse, a request whose content is wrong, or
    /// a body that is not JSON.
    BadRequest,
    /// No credential, or one the authenticator refused.
    Unauthenticated,
    /// The policy refused, the caller's tenant has no plane here, or the store
    /// refused this caller.
    Forbidden,
    /// The thing named does not exist.
    NotFound,
    /// The state of what was named refuses the request.
    Conflict,
    /// A decision named a version of the task that is no longer the stored one.
    PreconditionFailed,
    /// A body larger than the surface reads.
    PayloadTooLarge,
    /// A body sent without `Content-Type: application/json`.
    UnsupportedMediaType,
    /// A body that is JSON but not this operation's shape — an unknown member,
    /// a missing one, a wrong type — or a decision the plane cannot act on.
    Unprocessable,
    /// The store failed, the policy set could not be evaluated, or the
    /// authenticated identity cannot be recorded.
    Internal,
    /// This plane was built without the store the operation needs.
    NotWired,
    /// The store failed while delivering an event; a sender should retry.
    Unavailable,
}

impl ErrorClass {
    /// The HTTP status this class answers with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::PayloadTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::Unprocessable => 422,
            Self::Internal => 500,
            Self::NotWired => 501,
            Self::Unavailable => 503,
        }
    }

    /// The response description the document gives this class.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::BadRequest => {
                "An identifier does not parse, the request's content is wrong, or the body is not JSON."
            }
            Self::Unauthenticated => "No credential, or one the authenticator refused.",
            Self::Forbidden => "The policy refused, or the caller's tenant has no plane here.",
            Self::NotFound => "The named thing does not exist.",
            Self::Conflict => "The named thing's state refuses the request.",
            Self::PreconditionFailed => {
                "The decision named a version of the task that is no longer stored; read it again."
            }
            Self::PayloadTooLarge => "The body is larger than this surface reads.",
            Self::UnsupportedMediaType => "The body was not sent as application/json.",
            Self::Unprocessable => {
                "The body is JSON but not this operation's shape, or the plane cannot act on it."
            }
            Self::Internal => "The store failed, or the policy set could not be evaluated.",
            Self::NotWired => "This plane was built without the store this operation needs.",
            Self::Unavailable => "The store failed during delivery; retry.",
        }
    }
}

/// What every route can answer, before it reads anything of the request.
const GATE: &[ErrorClass] = &[
    ErrorClass::Unauthenticated,
    ErrorClass::Forbidden,
    ErrorClass::Internal,
];

/// What the JSON body extractor answers when it refuses.
const JSON_BODY: &[ErrorClass] = &[
    ErrorClass::BadRequest,
    ErrorClass::PayloadTooLarge,
    ErrorClass::UnsupportedMediaType,
    ErrorClass::Unprocessable,
];

/// What an event body answers when it refuses: it is read as bytes and parsed
/// by the shape its headers announce, so a parse failure is a 400.
const EVENT_BODY: &[ErrorClass] = &[ErrorClass::BadRequest, ErrorClass::PayloadTooLarge];

type SchemaFn = fn(&mut SchemaGenerator) -> Schema;
type Serve = fn(MethodFilter) -> MethodRouter<Api>;

/// The schema of `T`, by reference where it has a name.
fn schema<T: JsonSchema>(generator: &mut SchemaGenerator) -> Schema {
    generator.subschema_for::<T>()
}

/// A request body.
#[derive(Debug, Clone, Copy)]
pub enum Body {
    /// `application/json`, in this schema.
    Json(SchemaFn),
    /// An event: this plane's own shape as `application/json`, or a
    /// `CloudEvent` in structured or binary content mode.
    Event(SchemaFn),
}

/// One operation of the operator API.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub method: Method,
    /// The path, with each parameter in braces: `/runs/{run}`.
    pub path: &'static str,
    /// The `operationId`, and the name a generated client gives the call.
    pub operation: &'static str,
    pub summary: &'static str,
    /// The `api:` action the handler asks the policy engine.
    pub action: &'static str,
    pub query: Option<SchemaFn>,
    pub body: Option<Body>,
    /// The status of a successful answer.
    pub success: u16,
    /// The schema of a successful answer; `None` for an answer with no body.
    pub answer: Option<SchemaFn>,
    /// What this operation refuses with beyond the gate and its extractors.
    pub errors: &'static [ErrorClass],
    /// The cargo feature this operation needs to do anything but answer 501.
    pub feature: Option<&'static str>,
    serve: Serve,
}

impl Route {
    /// Every status this operation can refuse with, ascending, once each.
    #[must_use]
    pub fn refusals(&self) -> BTreeSet<ErrorClass> {
        let mut classes: BTreeSet<ErrorClass> = GATE.iter().copied().collect();
        classes.extend(self.errors.iter().copied());
        if self.query.is_some() {
            classes.insert(ErrorClass::BadRequest);
        }
        if self.path.contains('{') {
            classes.insert(ErrorClass::BadRequest);
        }
        match self.body {
            Some(Body::Json(_)) => classes.extend(JSON_BODY.iter().copied()),
            Some(Body::Event(_)) => classes.extend(EVENT_BODY.iter().copied()),
            None => {}
        }
        classes
    }

    /// The method router this build serves the operation with.
    pub(super) fn served(&self) -> MethodRouter<Api> {
        (self.serve)(self.method.filter())
    }
}

/// Every operation the operator API serves.
pub const ROUTES: &[Route] = &[
    Route {
        method: Method::Get,
        path: "/runs",
        operation: "list_runs",
        summary: "Runs that ended a given way; quarantined unless `outcome` names another.",
        action: action::RUN_LIST,
        query: Some(schema::<super::OutcomeQuery>),
        body: None,
        success: 200,
        answer: Some(schema::<super::RunList>),
        errors: &[],
        feature: None,
        serve: |m| on(m, super::runs_by_outcome),
    },
    Route {
        method: Method::Get,
        path: "/runs/live",
        operation: "list_live_runs",
        summary: "Runs holding an admission slot now, each with its agent and subject.",
        action: action::RUN_LIVE,
        query: Some(schema::<super::LiveQuery>),
        body: None,
        success: 200,
        answer: Some(schema::<super::LiveRuns>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::live_runs),
    },
    Route {
        method: Method::Get,
        path: "/runs/waiting",
        operation: "list_waiting_runs",
        summary: "Suspended runs and what each waits for, soonest due first.",
        action: action::RUN_WAITING,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::WaitingRuns>),
        errors: &[],
        feature: None,
        serve: |m| on(m, super::waiting_runs),
    },
    Route {
        method: Method::Get,
        path: "/attention",
        operation: "attention",
        summary: "Every condition on this plane that needs a person, by name.",
        action: action::ATTENTION,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::AttentionView>),
        errors: &[],
        feature: None,
        serve: |m| on(m, super::attention),
    },
    Route {
        method: Method::Get,
        path: "/drill",
        operation: "last_drill",
        summary: "When this plane last rehearsed recovery, and what it found.",
        action: action::DRILL_READ,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::DrillView>),
        errors: &[ErrorClass::NotFound],
        feature: None,
        serve: |m| on(m, super::last_drill),
    },
    Route {
        method: Method::Get,
        path: "/runs/{run}",
        operation: "get_run",
        summary: "One run: its status, why it is not finishing, and what is undecided.",
        action: action::RUN_READ,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::RunView>),
        errors: &[ErrorClass::NotFound],
        feature: None,
        serve: |m| on(m, super::run_view),
    },
    Route {
        method: Method::Get,
        path: "/runs/{run}/history",
        operation: "run_history",
        summary: "One run's journal, a page at a time from a sequence.",
        action: action::RUN_HISTORY,
        query: Some(schema::<super::HistoryQuery>),
        body: None,
        success: 200,
        answer: Some(schema::<super::HistoryPage>),
        errors: &[ErrorClass::NotFound],
        feature: None,
        serve: |m| on(m, super::run_history),
    },
    Route {
        method: Method::Post,
        path: "/runs/{run}/cancel",
        operation: "cancel_run",
        summary: "Stop a run at its next step boundary.",
        action: action::RUN_CANCEL,
        query: None,
        body: Some(Body::Json(schema::<super::CancelRequest>)),
        success: 202,
        answer: Some(schema::<super::CancelAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::Conflict],
        feature: None,
        serve: |m| on(m, super::cancel_run),
    },
    Route {
        method: Method::Post,
        path: "/runs/{run}/reopen",
        operation: "reopen_run",
        summary: "Hand a quarantined run back to the runtime, and answer what it reached.",
        action: action::RUN_REOPEN,
        query: None,
        body: Some(Body::Json(schema::<super::QuarantineRequest>)),
        success: 200,
        answer: Some(schema::<super::QuarantineAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::Conflict],
        feature: None,
        serve: |m| on(m, super::reopen_run),
    },
    Route {
        method: Method::Post,
        path: "/runs/{run}/abandon",
        operation: "abandon_run",
        summary: "Close a quarantined run whose outcome will never be established.",
        action: action::RUN_ABANDON,
        query: None,
        body: Some(Body::Json(schema::<super::QuarantineRequest>)),
        success: 200,
        answer: Some(schema::<super::QuarantineAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::Conflict],
        feature: None,
        serve: |m| on(m, super::abandon_run),
    },
    Route {
        method: Method::Post,
        path: "/runs/{run}/reconcile",
        operation: "reconcile_effect",
        summary: "Assert what happened to one effect the runtime could not decide.",
        action: action::EFFECT_RECONCILE,
        query: None,
        body: Some(Body::Json(schema::<super::ReconcileRequest>)),
        success: 200,
        answer: Some(schema::<super::ReconcileAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::Conflict],
        feature: None,
        serve: |m| on(m, super::reconcile_effect),
    },
    Route {
        method: Method::Get,
        path: "/tasks",
        operation: "list_tasks",
        summary: "The worklist the caller's roles entitle them to.",
        action: action::TASK_LIST,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::Worklist>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::worklist),
    },
    Route {
        method: Method::Get,
        path: "/tasks/{task}",
        operation: "get_task",
        summary: "One task, and whether this caller may decide it.",
        action: action::TASK_READ,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::TaskView>),
        errors: &[ErrorClass::NotFound, ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::task_view),
    },
    Route {
        method: Method::Post,
        path: "/tasks/{task}/claim",
        operation: "claim_task",
        summary: "Reserve a task so no other reviewer works it.",
        action: action::TASK_CLAIM,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::TaskView>),
        errors: &[
            ErrorClass::Forbidden,
            ErrorClass::NotFound,
            ErrorClass::Conflict,
            ErrorClass::NotWired,
        ],
        feature: None,
        serve: |m| on(m, super::claim),
    },
    Route {
        method: Method::Post,
        path: "/tasks/{task}/release",
        operation: "release_task",
        summary: "Give a claimed task back without deciding it.",
        action: action::TASK_RELEASE,
        query: None,
        body: None,
        success: 204,
        answer: None,
        errors: &[
            ErrorClass::Forbidden,
            ErrorClass::NotFound,
            ErrorClass::Conflict,
            ErrorClass::NotWired,
        ],
        feature: None,
        serve: |m| on(m, super::release),
    },
    Route {
        method: Method::Post,
        path: "/tasks/{task}/takeover",
        operation: "take_over_task",
        summary: "Take a task over from the holder named in the body.",
        action: action::TASK_TAKEOVER,
        query: None,
        body: Some(Body::Json(schema::<super::TakeOverBody>)),
        success: 200,
        answer: Some(schema::<super::TaskView>),
        errors: &[
            ErrorClass::Forbidden,
            ErrorClass::NotFound,
            ErrorClass::Conflict,
            ErrorClass::NotWired,
        ],
        feature: None,
        serve: |m| on(m, super::take_over),
    },
    Route {
        method: Method::Post,
        path: "/tasks/{task}/decide",
        operation: "decide_task",
        summary: "Approve or reject a task as the authenticated caller.",
        action: action::TASK_DECIDE,
        query: None,
        body: Some(Body::Json(schema::<super::DecisionRequest>)),
        success: 200,
        answer: Some(schema::<super::DecideAnswer>),
        errors: &[
            ErrorClass::Forbidden,
            ErrorClass::NotFound,
            ErrorClass::Conflict,
            ErrorClass::PreconditionFailed,
            ErrorClass::Unprocessable,
            ErrorClass::NotWired,
        ],
        feature: None,
        serve: |m| on(m, super::decide),
    },
    Route {
        method: Method::Get,
        path: "/cases",
        operation: "list_cases",
        summary: "Cases in a given state; escalated unless `status` names another.",
        action: action::CASE_LIST,
        query: Some(schema::<super::StatusQuery>),
        body: None,
        success: 200,
        answer: Some(schema::<super::CaseList>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::cases_by_status),
    },
    Route {
        method: Method::Get,
        path: "/obligations",
        operation: "list_breached_obligations",
        summary: "Missed obligations nobody has accounted for, longest overdue first.",
        action: action::OBLIGATION_LIST,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::ObligationList>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::breached_obligations),
    },
    Route {
        method: Method::Post,
        path: "/obligations/acknowledge",
        operation: "acknowledge_obligation",
        summary: "Account for a missed obligation, taking it off the listing.",
        action: action::OBLIGATION_ACKNOWLEDGE,
        query: None,
        body: Some(Body::Json(schema::<super::AcknowledgeRequest>)),
        success: 200,
        answer: Some(schema::<super::AcknowledgeAnswer>),
        errors: &[
            ErrorClass::NotFound,
            ErrorClass::Conflict,
            ErrorClass::NotWired,
        ],
        feature: None,
        serve: |m| on(m, super::acknowledge_obligation),
    },
    Route {
        method: Method::Get,
        path: "/cases/{case}",
        operation: "get_case",
        summary: "One case, its deadlines and its history.",
        action: action::CASE_READ,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::CaseAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::case_view),
    },
    Route {
        method: Method::Get,
        path: "/holds",
        operation: "list_holds",
        summary: "Every matter preserved against erasure, oldest hold first; or the recorded releases.",
        action: action::HOLD_LIST,
        query: Some(schema::<super::HoldStateQuery>),
        body: None,
        success: 200,
        answer: Some(schema::<super::HoldList>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::standing_holds),
    },
    Route {
        method: Method::Post,
        path: "/holds",
        operation: "place_hold",
        summary: "Preserve one matter against every erasure verb.",
        action: action::HOLD_PLACE,
        query: None,
        body: Some(Body::Json(schema::<super::PlaceHoldRequest>)),
        success: 200,
        answer: Some(schema::<super::PlaceHoldAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::place_hold),
    },
    Route {
        method: Method::Post,
        path: "/holds/release",
        operation: "release_hold",
        summary: "Lift a legal hold.",
        action: action::HOLD_RELEASE,
        query: None,
        body: Some(Body::Json(schema::<super::ReleaseHoldRequest>)),
        success: 200,
        answer: Some(schema::<super::ReleaseHoldAnswer>),
        errors: &[ErrorClass::NotFound, ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::release_hold),
    },
    Route {
        method: Method::Get,
        path: "/halts",
        operation: "list_halts",
        summary: "Every halt standing now, and why; or the recorded lifts.",
        action: action::HALT_LIST,
        query: Some(schema::<super::HaltStateQuery>),
        body: None,
        success: 200,
        answer: Some(schema::<super::HaltList>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::standing_halts),
    },
    Route {
        method: Method::Post,
        path: "/halts",
        operation: "place_halt",
        summary: "Throw the emergency stop for a scope, and answer how far it reaches.",
        action: action::HALT_PLACE,
        query: None,
        body: Some(Body::Json(schema::<super::PlaceHaltRequest>)),
        success: 200,
        answer: Some(schema::<super::PlaceHaltAnswer>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::place_halt),
    },
    Route {
        method: Method::Post,
        path: "/halts/lift",
        operation: "lift_halt",
        summary: "Lift a halt, and answer whether one was standing.",
        action: action::HALT_LIFT,
        query: None,
        body: Some(Body::Json(schema::<super::LiftHaltRequest>)),
        success: 200,
        answer: Some(schema::<super::LiftHaltAnswer>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::lift_halt),
    },
    Route {
        method: Method::Post,
        path: "/events",
        operation: "deliver_event",
        summary: "Deliver an inbound message to whichever run waits for it.",
        action: action::EVENT_DELIVER,
        query: None,
        body: Some(Body::Event(schema::<super::DeliverBody>)),
        success: 200,
        answer: Some(schema::<super::DeliveryAnswer>),
        errors: &[
            ErrorClass::Forbidden,
            ErrorClass::Conflict,
            ErrorClass::NotWired,
            ErrorClass::Unavailable,
        ],
        feature: None,
        serve: |m| on(m, super::deliver),
    },
    Route {
        method: Method::Get,
        path: "/dead-letters",
        operation: "list_dead_letters",
        summary: "Messages that matched no waiter and aged out.",
        action: action::DEADLETTER_LIST,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::DeadLetters>),
        errors: &[ErrorClass::NotWired],
        feature: None,
        serve: |m| on(m, super::dead_letters),
    },
    Route {
        method: Method::Get,
        path: "/push",
        operation: "list_parked_push",
        summary: "Webhook registrations a delivery worker gave up on.",
        action: action::PUSH_LIST,
        query: None,
        body: None,
        success: 200,
        answer: Some(schema::<super::ParkedPush>),
        errors: &[ErrorClass::NotWired],
        feature: Some("push"),
        serve: |m| on(m, super::parked_push),
    },
    Route {
        method: Method::Post,
        path: "/push/rearm",
        operation: "rearm_push",
        summary: "Re-arm a parked registration once its receiver answers again.",
        action: action::PUSH_REARM,
        query: None,
        body: Some(Body::Json(schema::<super::RearmRequest>)),
        success: 200,
        answer: Some(schema::<super::RearmAnswer>),
        errors: &[ErrorClass::Conflict, ErrorClass::NotWired],
        feature: Some("push"),
        serve: |m| on(m, super::rearm_push),
    },
];

/// The scope and standing of the document, as its `info.description`.
const DESCRIPTION: &str = "The operator API of an agentplane plane: the routes a person or their tooling \
uses to see what a plane is doing and to intervene — runs, tasks, cases, obligations, holds, halts, \
events and dead letters.\n\n\
**Scope.** This document describes the operator API only. The A2A surface is described by its own \
protocol and the Agent Card it serves; the MCP server by the tool listing MCP defines. Neither is here.\n\n\
**Tenant.** The tenant a request reaches comes from its credential, never from a path, query or body \
member; no operation takes one.\n\n\
**Refusals.** Every non-success answer is `{\"error\": \"<sentence>\"}`.\n\n\
**Compatibility.** This document is outside the project's compatibility promise, like the Rust API: \
an operation, a member or a status can change in any release. Pin the version your client was \
generated from.";

const BEARER: &str = "The token the shipped token authenticator reads (`agentplane serve --tokens`). \
Authentication is a seam: a deployment that embeds the API with its own authenticator may read \
something else, and then this scheme describes nothing.";

/// Every schema in a generated document follows JSON Schema 2020-12, with its
/// named schemas under `components/schemas`.
fn settings() -> SchemaSettings {
    SchemaSettings::draft2020_12().with(|s| {
        s.definitions_path = "/components/schemas".into();
        s.meta_schema = None;
    })
}

/// Remove the derive's prose — the Rust documentation, written for a reader of
/// the source — and keep what a member holds where its type is open.
fn plain(value: &mut Value) {
    let Value::Object(map) = value else {
        if let Value::Array(items) = value {
            items.iter_mut().for_each(plain);
        }
        return;
    };
    map.remove("description");
    if let Some(holds) = map.remove("x-agentplane-holds") {
        map.insert("description".to_owned(), holds);
    }
    for (key, child) in map.iter_mut() {
        match key.as_str() {
            // Maps from a name to a schema: the names are data.
            "properties" | "patternProperties" | "$defs" | "dependentSchemas" => {
                if let Value::Object(named) = child {
                    named.values_mut().for_each(plain);
                }
            }
            // Values, not schemas.
            "enum" | "const" | "default" | "examples" | "required" => {}
            _ => plain(child),
        }
    }
}

fn schema_value(schema: Schema) -> Value {
    let mut value = schema.to_value();
    plain(&mut value);
    value
}

/// An operation's path parameters, then its query parameters.
fn parameters(route: &Route, queries: &mut SchemaGenerator) -> Vec<Value> {
    let mut parameters: Vec<Value> = route
        .path
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| {
            json!({
                "name": name,
                "in": "path",
                "required": true,
                "schema": { "type": "string" },
            })
        })
        .collect();
    if let Some(query) = route.query {
        let shape = schema_value(query(queries));
        let required: BTreeSet<&str> = shape["required"]
            .as_array()
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(Value::Object(members)) = shape.get("properties") {
            for (name, member) in members {
                parameters.push(json!({
                    "name": name,
                    "in": "query",
                    "required": required.contains(name.as_str()),
                    "schema": member,
                }));
            }
        }
    }
    parameters
}

/// An operation's request body.
fn request_body(body: Body, requests: &mut SchemaGenerator) -> Value {
    match body {
        Body::Json(body) => json!({
            "required": true,
            "content": {
                "application/json": { "schema": schema_value(body(requests)) },
            },
        }),
        Body::Event(body) => json!({
            "required": true,
            "description": "This plane's own event shape as `application/json`, or a \
                CloudEvents 1.0 event: structured mode as \
                `application/cloudevents+json`, or binary mode with `ce-` headers.",
            "content": {
                "application/json": { "schema": schema_value(body(requests)) },
                "application/cloudevents+json": {
                    "schema": {
                        "type": "object",
                        "description": "A CloudEvents 1.0 event in structured content mode; `data` is the sender's.",
                    },
                },
            },
        }),
    }
}

/// The operator API, as an `OpenAPI` 3.1 document.
///
/// # Panics
///
/// If two types share a schema name and describe different shapes, which a
/// test of this function finds before a release does.
#[must_use]
pub fn document() -> Value {
    let mut requests = settings().for_deserialize().into_generator();
    let mut answers = settings().for_serialize().into_generator();
    let mut queries = settings()
        .with(|s| s.inline_subschemas = true)
        .for_deserialize()
        .into_generator();
    let error = schema_value(answers.subschema_for::<super::ErrorBody>());

    let mut paths = Map::new();
    for route in ROUTES {
        let mut operation = Map::new();
        operation.insert("operationId".into(), route.operation.into());
        operation.insert("summary".into(), route.summary.into());
        operation.insert("x-agentplane-action".into(), route.action.into());
        if let Some(feature) = route.feature {
            operation.insert("x-agentplane-feature".into(), feature.into());
        }

        let parameters = parameters(route, &mut queries);
        if !parameters.is_empty() {
            operation.insert("parameters".into(), parameters.into());
        }

        if let Some(body) = route.body {
            operation.insert("requestBody".into(), request_body(body, &mut requests));
        }

        let mut responses = Map::new();
        let success = match route.answer {
            Some(answer) => json!({
                "description": "The answer.",
                "content": { "application/json": { "schema": schema_value(answer(&mut answers)) } },
            }),
            None => json!({ "description": "Done; no body." }),
        };
        responses.insert(route.success.to_string(), success);
        for class in route.refusals() {
            responses.insert(
                class.status().to_string(),
                json!({
                    "description": class.meaning(),
                    "content": { "application/json": { "schema": error } },
                }),
            );
        }
        operation.insert("responses".into(), responses.into());

        let entry = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        entry[route.method.as_str()] = operation.into();
    }

    let mut schemas = Map::new();
    for (name, mut shape) in requests
        .take_definitions(true)
        .into_iter()
        .chain(answers.take_definitions(true))
    {
        plain(&mut shape);
        match schemas.get(&name) {
            Some(existing) => assert_eq!(
                existing, &shape,
                "two shapes are both named {name} in the operator API document"
            ),
            None => {
                schemas.insert(name, shape);
            }
        }
    }

    sorted(json!({
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "agentplane operator API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": DESCRIPTION,
        },
        "security": [{ "bearer": [] }],
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer", "description": BEARER },
            },
        },
    }))
}

/// Every object's members in name order, so the printed document is the same
/// bytes whether or not the build keeps insertion order.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut members: Vec<(String, Value)> = map.into_iter().collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(members.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}
