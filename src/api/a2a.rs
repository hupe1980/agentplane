//! Serving A2A: this plane, as an agent other agents can call.
//!
//! The client side ([`crate::peers::a2a`]) lets this plane *call* peers. This is
//! the other half — a peer calling us — and it is a different problem, because
//! everything arriving here came from somebody else.
//!
//! # Why this is not a route on the operator API
//!
//! Every route on [`crate::api::Api`] authenticates and then authorizes. An
//! Agent Card is public by design: it is what a caller reads *before* it has
//! credentials, and a card behind authentication cannot be discovered. Bolting
//! an unauthenticated path onto a surface whose invariant is "every route
//! authenticates" would delete that invariant for the one route nobody would
//! think to check.
//!
//! So this is its own router with its own rule: **the card is public, every
//! method call is authenticated and authorized**.
//!
//! # What arrives here is untrusted
//!
//! A message from a peer is data written by a party this plane does not control,
//! so it is admitted as `Tainted` with the sending
//! peer's identity as its provenance source — never as trusted input. A skill
//! that wants to act on it has to say so at a gate, and a protected sink field
//! can name the one counterparty it will accept an amount from.
//!
//! This is the same reason the operator API takes an event's `source` from the
//! authenticated caller rather than the body: a party describing itself is not
//! evidence about itself.
//!
//! # The capability is named, never inferred
//!
//! A2A messages do not carry a "call this skill" field — the protocol assumes an
//! agent works out what is being asked. This plane will not: choosing which
//! capability to run on the strength of an untrusted message is a dispatch
//! decision made by inference, and the thing doing the inferring would be a
//! model reading attacker-controlled text.
//!
//! The skill is taken from `message.metadata.skill`, matched against the card's
//! advertised skill ids. When the agent advertises exactly one there is nothing
//! to infer and it is used; when it advertises several and none was named, the
//! call is refused rather than guessed.
//!
//! # What is not implemented, and says so
//!
//! Streaming, task subscription and push notifications need machinery that does
//! not exist here. They are refused with the spec's own codes —
//! `UnsupportedOperationError` and `PushNotificationNotSupportedError`, not
//! "method not found" — because a caller has to be able to tell *this agent
//! cannot do that* from *you spelled it wrong*. The card advertises them as
//! false for the same reason.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::{PolicyDecision, PolicyRequest, RunId, SourceId, Tainted};
use crate::journal::RecordKind;
use crate::manifest::Manifest;
use crate::peers::{AgentCard, ExtendedAgentCard, WELL_KNOWN_PATH};
use crate::runtime::Runtime;

use super::{Authenticator, Caller};

/// JSON-RPC method names, exactly as A2A 1.0 spells them.
///
/// 1.0 renamed these: `message/send` was the 0.3 spelling, and a server
/// answering the old names would silently accept clients that have lost half the
/// protocol. Constants rather than inline literals so the dispatch table and the
/// refusal table cannot disagree.
pub mod method {
    pub const SEND_MESSAGE: &str = "SendMessage";
    pub const GET_TASK: &str = "GetTask";
    pub const CANCEL_TASK: &str = "CancelTask";
    pub const GET_EXTENDED_CARD: &str = "GetExtendedAgentCard";

    /// Defined by the protocol, not implemented here.
    pub const SEND_STREAMING: &str = "SendStreamingMessage";
    pub const SUBSCRIBE: &str = "SubscribeToTask";
    pub const LIST_TASKS: &str = "ListTasks";
    pub const CREATE_PUSH: &str = "CreateTaskPushNotificationConfig";
    pub const GET_PUSH: &str = "GetTaskPushNotificationConfig";
    pub const LIST_PUSH: &str = "ListTaskPushNotificationConfigs";
    pub const DELETE_PUSH: &str = "DeleteTaskPushNotificationConfig";
}

/// A2A-specific JSON-RPC error codes, from the spec's mapping table.
pub mod code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    pub const TASK_NOT_FOUND: i32 = -32001;
    pub const TASK_NOT_CANCELABLE: i32 = -32002;
    pub const PUSH_NOT_SUPPORTED: i32 = -32003;
    pub const UNSUPPORTED_OPERATION: i32 = -32004;
    pub const CONTENT_TYPE_NOT_SUPPORTED: i32 = -32005;
    pub const EXTENDED_CARD_NOT_CONFIGURED: i32 = -32007;
    pub const VERSION_NOT_SUPPORTED: i32 = -32009;
}

/// Actions this surface asks the policy engine about.
pub mod action {
    pub const MESSAGE_SEND: &str = "a2a:message.send";
    pub const TASK_READ: &str = "a2a:task.read";
    pub const TASK_CANCEL: &str = "a2a:task.cancel";
    pub const CARD_EXTENDED: &str = "a2a:card.extended";
    /// Registering, reading or removing a webhook for a task.
    pub const TASK_PUSH: &str = "a2a:task.push";

    /// Every action this surface can ask about, so a deployment can enumerate
    /// what it must write rules for.
    pub const ALL: &[&str] = &[
        MESSAGE_SEND,
        TASK_READ,
        TASK_CANCEL,
        CARD_EXTENDED,
        TASK_PUSH,
    ];
}

/// The `A2A-Version` service parameter.
const VERSION_HEADER: &str = "a2a-version";

/// A task's lifecycle state, as A2A names them.
///
/// `ProtoJSON` spelling — `TASK_STATE_WORKING`, not `working`. A client matching
/// on the enum gets nothing from a friendlier spelling.
///
/// # Why this is a subset
///
/// A2A also defines `SUBMITTED`, `REJECTED` and `AUTH_REQUIRED`, and this plane
/// never enters any of them. `SUBMITTED` means accepted but not yet started, and
/// there is no such moment here: a run starts inside the call that admits it.
/// The other two are refusals, and a refusal never becomes a task — a declined
/// request is answered with a `Message`, and an unauthenticated one never
/// reaches dispatch.
///
/// Declared and never produced would be worse than absent: a client writing a
/// branch for `SUBMITTED` would be writing dead code against a promise this
/// agent does not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    #[serde(rename = "TASK_STATE_WORKING")]
    Working,
    #[serde(rename = "TASK_STATE_COMPLETED")]
    Completed,
    #[serde(rename = "TASK_STATE_FAILED")]
    Failed,
    #[serde(rename = "TASK_STATE_CANCELED")]
    Canceled,
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
}

/// Where a run's status maps onto A2A's task states.
///
/// Two of these are worth stating because the obvious mapping is wrong.
///
/// A **suspended** run is `INPUT_REQUIRED`, not `WORKING`: it is stopped and
/// will not move until something external happens, and a caller polling a
/// `WORKING` task waits forever for a task that is not running.
///
/// A **quarantined** run is `FAILED`, not `REJECTED`. `REJECTED` means the agent
/// declined the work; quarantine means it accepted the work, started, and can no
/// longer be trusted to describe what it did. Reporting that as a refusal tells
/// the caller nothing happened, when something did.
fn state_of(status: &crate::runtime::RunStatus) -> TaskState {
    use crate::runtime::RunStatus;
    match status {
        RunStatus::Succeeded => TaskState::Completed,
        RunStatus::Suspended(_) => TaskState::InputRequired,
        RunStatus::Cancelled { .. } => TaskState::Canceled,
        RunStatus::Failed(_)
        | RunStatus::Exhausted(_)
        | RunStatus::Quarantined(_)
        | RunStatus::Replanning(_) => TaskState::Failed,
    }
}

/// A2A's `TaskStatus`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskStatus {
    pub state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// A2A's `Task` — what this plane calls a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTask {
    pub id: String,
    /// The case, when the run belongs to one.
    ///
    /// A2A's `contextId` is "the thing this conversation is part of", which is
    /// exactly a case: several runs, one matter, shared state. Mapping it to
    /// anything else would give a caller a correlation handle that does not
    /// correlate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<A2aArtifact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// One output produced by an A2A task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aArtifact {
    pub artifact_id: String,
    pub parts: Vec<Part>,
}

/// One piece of a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// A2A's `Message`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aMessage {
    pub message_id: String,
    pub role: String,
    pub parts: Vec<Part>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl A2aMessage {
    fn validate_parts(&self) -> Result<(), RpcError> {
        if self.parts.is_empty() {
            return Err(RpcError::new(
                code::CONTENT_TYPE_NOT_SUPPORTED,
                "the message has no parts this agent can read; it accepts text and data parts",
            ));
        }
        for (index, part) in self.parts.iter().enumerate() {
            let variants = usize::from(part.text.is_some())
                + usize::from(part.data.is_some())
                + usize::from(part.raw.is_some())
                + usize::from(part.url.is_some());
            if variants != 1 {
                return Err(RpcError::new(
                    code::INVALID_PARAMS,
                    format!(
                        "message.parts[{index}] must contain exactly one of text, data, raw, or url"
                    ),
                ));
            }
            if part.raw.is_some() || part.url.is_some() {
                return Err(RpcError::new(
                    code::CONTENT_TYPE_NOT_SUPPORTED,
                    format!(
                        "message.parts[{index}] is file content; this agent card advertises only text/plain and application/json"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// What the runtime receives as input.
    ///
    /// A stable shape, always the same two keys, rather than a clever unwrapping
    /// that hands a skill a bare string sometimes and an object other times. A
    /// skill parsing its own input should not have to branch on how many parts
    /// the caller happened to send.
    fn to_input(&self) -> Value {
        let text: Vec<&str> = self
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .collect();
        let data: Vec<Value> = self.parts.iter().filter_map(|p| p.data.clone()).collect();
        json!({ "text": text.join("\n"), "data": data })
    }

    /// The skill this message asks for, if it named one.
    fn requested_skill(&self) -> Option<&str> {
        self.metadata.as_ref()?.get("skill")?.as_str()
    }
}

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Deserialize)]
struct RpcRequest {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

/// The parts of `SendMessageConfiguration` this server acts on.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendConfiguration {
    /// Return as soon as the task exists, rather than when it finishes.
    ///
    /// Blocking is the spec's default and the default here: unset means wait.
    #[serde(default)]
    return_immediately: bool,
}

/// What every method's params may carry.
#[derive(Debug, Clone, Default, Deserialize)]
struct CommonParams {
    /// A2A's opaque routing identifier.
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    message: Option<A2aMessage>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    configuration: Option<SendConfiguration>,
    /// `TaskPushNotificationConfig` fields, flattened as the RPC sends them.
    #[serde(default, rename = "taskId")]
    push_task: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

/// A JSON-RPC error, carrying the HTTP status it should be served with.
#[derive(Debug, Clone)]
pub struct RpcError {
    code: i32,
    message: String,
    /// The id of the request being answered — `null` when it could not be read.
    id: Value,
}

impl RpcError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            id: Value::Null,
        }
    }

    fn with_id(mut self, id: Value) -> Self {
        self.id = id;
        self
    }
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        // Always HTTP 200 with a JSON-RPC error body. JSON-RPC carries its own
        // error channel, and a transport-level status for an application-level
        // refusal is how a client ends up retrying a permanent decline: an
        // A2A client reads `error.code`, and many treat a 5xx as retryable
        // without ever parsing the body.
        (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": self.id,
                "error": { "code": self.code, "message": self.message },
            })),
        )
            .into_response()
    }
}

/// This plane, served as an A2A agent.
#[derive(Clone)]
pub struct A2aServer {
    runtime: Arc<Runtime>,
    auth: Arc<dyn Authenticator>,
    policy: Arc<dyn crate::core::PolicyEngine>,
    card: AgentCard,
    extended: ExtendedAgentCard,
    /// The card's advertised skill ids — what a caller may ask for.
    skills: Vec<String>,
    /// Webhook storage and delivery, when this deployment wires them.
    push: Option<(Arc<dyn crate::push::PushStore>, crate::push::PushSender)>,
}

impl std::fmt::Debug for A2aServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aServer")
            .field("agent", &self.card.name)
            .field("skills", &self.skills)
            .finish_non_exhaustive()
    }
}

/// Why a server could not be built.
#[derive(Debug, thiserror::Error)]
pub enum ServerSetupError {
    #[error(
        "the runtime has no policy engine, so every A2A method would be \
         unauthorized. A surface reachable by other agents cannot be the one \
         place that skips the gate"
    )]
    NoPolicy,
    #[error("the agent card could not be derived: {0}")]
    Card(#[from] crate::manifest::ManifestError),
    #[error(
        "push cannot be enabled after Agent Cards are signed because the capability is part of \
         the signed payload; call `with_push` before `signing_cards_with`"
    )]
    CardAlreadySigned,
}

impl A2aServer {
    /// Serve `manifest`'s agent at `url`.
    ///
    /// `url` is where callers reach this plane, and it goes on the card — the
    /// same deployment-wiring split as everywhere else: an agent's declaration
    /// must not change when its address does.
    ///
    /// # Errors
    ///
    /// [`ServerSetupError::NoPolicy`] when the runtime has no policy engine, and
    /// [`ServerSetupError::Card`] when the manifest's digest cannot be computed.
    pub fn new(
        runtime: Arc<Runtime>,
        auth: Arc<dyn Authenticator>,
        security: &crate::peers::CardSecurity,
        manifest: &Manifest,
        url: impl Into<String>,
    ) -> Result<Self, ServerSetupError> {
        let policy = runtime.policy().ok_or(ServerSetupError::NoPolicy)?.clone();
        let url = url.into();
        let mut card = AgentCard::derive(manifest, url.clone())?;
        let mut extended = ExtendedAgentCard::derive(manifest, url)?;
        security.apply(&mut card);
        security.apply(&mut extended.public);

        // The card names the tenant only when there is one to route on. A2A's
        // rule is that a client echoes this value back in every request, so
        // advertising `default` would make every caller send a routing
        // identifier that routes nowhere.
        let tenant = runtime.tenant();
        if tenant.as_str() != crate::core::TenantId::DEFAULT {
            for iface in &mut card.supported_interfaces {
                iface.tenant = Some(tenant.to_string());
            }
            for iface in &mut extended.public.supported_interfaces {
                iface.tenant = Some(tenant.to_string());
            }
        }

        let skills = card.skills.iter().map(|s| s.id.clone()).collect();
        Ok(Self {
            runtime,
            auth,
            policy,
            card,
            extended,
            skills,
            push: None,
        })
    }

    /// Publish a **signed** card.
    ///
    /// The card is served unauthenticated from a host a caller may not control.
    /// TLS says the bytes came from that host; it says nothing about whether the
    /// host is the party whose capabilities the card describes. A signature says
    /// that, and it keeps saying it after the card has been copied into a
    /// registry, a cache, or somebody's repository.
    ///
    /// Signed here rather than at derivation because the signature covers the
    /// **published** card, interface URL and tenant included — those are
    /// deployment facts, and a signature taken before they were set would cover
    /// a document nobody serves.
    ///
    /// # Errors
    ///
    /// If the card cannot be canonicalized.
    pub fn signing_cards_with(
        mut self,
        signer: &dyn crate::peers::CardSigner,
    ) -> Result<Self, crate::peers::CardSignatureError> {
        self.card.sign(signer)?;
        self.extended.public.sign(signer)?;
        Ok(self)
    }

    /// Deliver push notifications for tasks peers register webhooks against.
    ///
    /// Without this the four `…PushNotificationConfig` methods refuse with the
    /// spec's code and the card advertises `pushNotifications: false` — so a
    /// deployment that has not made the egress decision is not quietly making
    /// outbound requests to addresses its callers chose.
    pub fn with_push(
        mut self,
        store: Arc<dyn crate::push::PushStore>,
        sender: crate::push::PushSender,
    ) -> Result<Self, ServerSetupError> {
        if !self.card.signatures.is_empty() || !self.extended.public.signatures.is_empty() {
            return Err(ServerSetupError::CardAlreadySigned);
        }
        self.card.capabilities.push_notifications = true;
        self.extended.public.capabilities.push_notifications = true;
        self.push = Some((store, sender));
        Ok(self)
    }

    /// Tell every webhook registered for this task what state it reached.
    ///
    /// Called when a task concludes. Best-effort by construction: a webhook is
    /// somebody else's endpoint, and its being down is ordinary rather than a
    /// failure of the run that finished. Outcomes are logged, not raised.
    ///
    /// The payload is a `StreamResponse` carrying the task's **state** and not
    /// its output — see [`crate::push`] for why an allowlist plus a body is an
    /// exfiltration channel.
    pub async fn notify(&self, task: RunId) {
        let Some((store, sender)) = self.push.as_ref() else {
            return;
        };
        let Ok(configs) = store.list(task).await else {
            tracing::warn!(%task, "could not read this task's webhooks");
            return;
        };
        if configs.is_empty() {
            return;
        }
        let Some((current, case, _)) = super::a2a_stream::current(&self.runtime, task).await else {
            return;
        };
        let payload = json!({
            "statusUpdate": {
                "taskId": task.to_string(),
                "contextId": case.unwrap_or_else(|| task.to_string()),
                "status": { "state": current.status.state },
            }
        });

        for config in &configs {
            match sender.deliver(config, &payload).await {
                Ok(crate::push::Delivered::Accepted) => {}
                Ok(other) => tracing::info!(
                    %task, config = %config.id, outcome = ?other,
                    "a webhook did not accept a notification"
                ),
                Err(why) => tracing::warn!(
                    %task, config = %config.id, %why,
                    "a webhook is registered but may no longer be delivered to"
                ),
            }
        }
    }

    /// The router.
    ///
    /// The card path is unauthenticated by design and everything else is not.
    pub fn router(self) -> Router {
        Router::new()
            .route(WELL_KNOWN_PATH, get(agent_card))
            .route("/a2a", post(rpc))
            .with_state(self)
    }

    /// Authenticate, then authorize.
    async fn gate(
        &self,
        headers: &HeaderMap,
        action: &str,
        resource: &str,
    ) -> Result<Caller, RpcError> {
        let caller = self.auth.authenticate(headers).await.map_err(|e| {
            // Refused, not "invalid request": a caller that cannot authenticate
            // must not be told its request was malformed and try again with a
            // different body.
            RpcError::new(code::INVALID_REQUEST, e.to_string())
        })?;
        // The caller's tenant is the second half of the check `check_tenant`
        // starts. That one compares what the *request* asked for against what
        // the card advertises; this compares it against what the *credential*
        // says. A peer that authenticates into one tenant must not be served
        // from another's runs by naming it in a field, and a peer holding a
        // valid credential for a different tenant is exactly who would try.
        if caller.tenant != *self.runtime.tenant() {
            return Err(RpcError::new(
                code::INVALID_PARAMS,
                "this endpoint does not serve your tenant",
            ));
        }

        let context = json!({
            "roles": caller.roles,
            "peer": caller.actor,
            "tenant": caller.tenant.as_str(),
        });
        match self.policy.authorize(&PolicyRequest {
            principal: &caller.actor,
            action,
            resource,
            context: &context,
        }) {
            PolicyDecision::Permit => Ok(caller),
            PolicyDecision::Deny { reason } => Err(RpcError::new(code::INVALID_REQUEST, reason)),
        }
    }

    /// Refuse a version this server does not speak.
    ///
    /// An **absent** header is a refusal, not a default. The spec says an empty
    /// value means 0.3, so a missing header is a 0.3 client — and answering it
    /// with 1.0 semantics is how a caller silently loses half the protocol.
    /// Matching is on `Major.Minor`, as the spec requires.
    fn check_version(headers: &HeaderMap) -> Result<(), RpcError> {
        let claimed = headers
            .get(VERSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let claimed_version = crate::peers::protocol_major_minor(claimed);
        if claimed_version == crate::peers::protocol_major_minor(crate::peers::PROTOCOL_VERSION)
            && claimed_version.is_some()
        {
            return Ok(());
        }
        let seen = if claimed.is_empty() {
            "0.3 (no A2A-Version header, which the spec reads as 0.3)".to_owned()
        } else {
            claimed.to_owned()
        };
        Err(RpcError::new(
            code::VERSION_NOT_SUPPORTED,
            format!(
                "this agent speaks A2A {}, and the request asked for {seen}",
                crate::peers::PROTOCOL_VERSION
            ),
        ))
    }

    /// Refuse a request routed to a different tenant.
    ///
    /// A2A's rule is that the client echoes the `tenant` from the interface it
    /// selected on the card, omitting it when the card omits it. So a value that
    /// does not match ours is a request meant for somebody else — plausibly
    /// another plane behind the same address — and answering it would serve one
    /// tenant's caller from another tenant's runs.
    fn check_tenant(&self, params: &CommonParams) -> Result<(), RpcError> {
        let ours = self.runtime.tenant().as_str();
        let advertised = if ours == crate::core::TenantId::DEFAULT {
            ""
        } else {
            ours
        };
        let sent = params.tenant.as_deref().unwrap_or("");
        if sent == advertised {
            return Ok(());
        }
        Err(RpcError::new(
            code::INVALID_PARAMS,
            format!(
                "this endpoint serves the tenant advertised on its card, and \
                 the request named '{sent}'. A2A clients echo the `tenant` from \
                 the interface they selected; a different value is a request \
                 for a different agent"
            ),
        ))
    }
}

/// The public Agent Card.
///
/// Unauthenticated on purpose — see the module docs. It is derived from the
/// manifest, so it cannot describe a capability the plane would refuse to
/// dispatch, which is what makes publishing it safe.
async fn agent_card(State(server): State<A2aServer>) -> Json<AgentCard> {
    Json(server.card.clone())
}

async fn rpc(
    State(server): State<A2aServer>,
    headers: HeaderMap,
    body: Result<Json<RpcRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(req)) = body else {
        return RpcError::new(code::PARSE_ERROR, "the request body is not valid JSON-RPC")
            .into_response();
    };
    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return RpcError::new(
            code::INVALID_REQUEST,
            format!("`jsonrpc` must be \"2.0\", not {:?}", req.jsonrpc),
        )
        .with_id(id)
        .into_response();
    }
    if let Err(e) = A2aServer::check_version(&headers) {
        return e.with_id(id).into_response();
    }

    // Streaming methods are dispatched first because they answer with a
    // different *kind* of response: an SSE body, not a JSON-RPC envelope. Folding
    // them into `dispatch` would mean a function whose return type is "a value
    // or an entire HTTP response", which is how one of the two paths quietly
    // stops setting its content type.
    if matches!(
        req.method.as_str(),
        method::SEND_STREAMING | method::SUBSCRIBE
    ) {
        return match stream_method(server, headers, req).await {
            Ok(sse) => sse.into_response(),
            Err(e) => e.with_id(id).into_response(),
        };
    }

    match dispatch(&server, &headers, &req).await {
        Ok(result) => Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response(),
        Err(e) => e.with_id(id).into_response(),
    }
}

/// `SendStreamingMessage` and `SubscribeToTask`.
///
/// Both are the same thing once the run exists: a view of the journal from a
/// point onward. The only difference is whether this call is what created it.
async fn stream_method(
    server: A2aServer,
    headers: HeaderMap,
    req: RpcRequest,
) -> Result<
    axum::response::sse::Sse<
        impl futures_util::stream::Stream<
            Item = Result<axum::response::sse::Event, std::convert::Infallible>,
        >,
    >,
    RpcError,
> {
    let params: CommonParams = serde_json::from_value(req.params.clone()).unwrap_or_default();
    server.check_tenant(&params)?;

    let run = if req.method == method::SUBSCRIBE {
        let id = task_id(&params)?;
        server
            .gate(&headers, action::TASK_READ, &id.to_string())
            .await?;
        id
    } else {
        let Some(message) = params.message.clone() else {
            return Err(RpcError::new(
                code::INVALID_PARAMS,
                "`message` is required by SendStreamingMessage",
            ));
        };
        let skill = resolve_skill(&server, &message)?;
        let caller = server.gate(&headers, action::MESSAGE_SEND, &skill).await?;
        if message.parts.is_empty() {
            return Err(RpcError::new(
                code::CONTENT_TYPE_NOT_SUPPORTED,
                "the message has no parts this agent can read",
            ));
        }

        // Admitted before the stream opens. A stream that begins and *then*
        // reports a refusal has already told the client the work started —
        // and an SSE body cannot carry a JSON-RPC error the client is looking
        // for at that point.
        let input = Tainted::from_source(
            message.to_input(),
            SourceId::new(format!("peer:{}", caller.actor)),
        );
        match server.runtime.spawn(&skill, input).await {
            Ok(run) => run,
            Err(crate::core::RuntimeError::PolicyDenied(_)) => {
                return Err(RpcError::new(
                    code::UNSUPPORTED_OPERATION,
                    "this agent declined the request",
                ));
            }
            Err(crate::core::RuntimeError::QuotaExceeded(why)) => {
                return Err(RpcError::new(code::UNSUPPORTED_OPERATION, why.to_string()));
            }
            Err(e) => return Err(RpcError::new(code::INTERNAL_ERROR, e.to_string())),
        }
    };

    let Some((task, case, from)) = super::a2a_stream::current(&server.runtime, run).await else {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {run}"),
        ));
    };

    Ok(super::a2a_stream::tail(
        Arc::clone(&server.runtime),
        run,
        case,
        req.id,
        task,
        from,
    ))
}

async fn dispatch(
    server: &A2aServer,
    headers: &HeaderMap,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let params: CommonParams = serde_json::from_value(req.params.clone()).unwrap_or_default();
    server.check_tenant(&params)?;

    match req.method.as_str() {
        method::SEND_MESSAGE => send_message(server, headers, params).await,
        method::GET_TASK => get_task(server, headers, params).await,
        method::CANCEL_TASK => cancel_task(server, headers, params).await,
        method::GET_EXTENDED_CARD => get_extended_card(server, headers).await,

        // Defined by the protocol and not implemented. The spec's own codes,
        // so a caller can tell "this agent cannot" from "you spelled it wrong"
        // — and these are exactly the operations the card advertises as false.
        // Streaming is handled before dispatch; reaching here means the router
        // changed and this arm did not.
        method::SEND_STREAMING | method::SUBSCRIBE => Err(RpcError::new(
            code::INTERNAL_ERROR,
            "a streaming method reached the non-streaming dispatcher",
        )),
        method::LIST_TASKS => Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "this agent does not implement ListTasks",
        )),
        method::CREATE_PUSH => push_create(server, headers, params).await,
        method::GET_PUSH => push_get(server, headers, &params).await,
        method::LIST_PUSH => push_list(server, headers, &params).await,
        method::DELETE_PUSH => push_delete(server, headers, &params).await,
        other => Err(RpcError::new(
            code::METHOD_NOT_FOUND,
            format!("no such A2A method: {other}"),
        )),
    }
}

async fn send_message(
    server: &A2aServer,
    headers: &HeaderMap,
    params: CommonParams,
) -> Result<Value, RpcError> {
    let Some(message) = params.message else {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "`message` is required by SendMessage",
        ));
    };
    message.validate_parts()?;
    if message.task_id.is_some() || message.context_id.is_some() {
        return Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "this server does not yet implement A2A multi-turn continuation; taskId/contextId \
             are refused rather than silently starting an unrelated run",
        ));
    }
    let skill = resolve_skill(server, &message)?;
    let caller = server.gate(headers, action::MESSAGE_SEND, &skill).await?;

    // Untrusted, and provenanced to the peer that sent it. A protected sink
    // field can then name the one counterparty it will take an amount from, and
    // a skill that wants to act on this has to pass a gate to do it.
    let input = Tainted::from_source(
        message.to_input(),
        SourceId::new(format!("peer:{}", caller.actor)),
    );

    // Non-blocking: the spec requires returning as soon as the task exists,
    // with an in-progress state, leaving the caller to poll `GetTask`. Admission
    // still happens synchronously, so a refusal is still an immediate answer —
    // returning a task id for a run the gate rejected would hand the caller a
    // handle to nothing and turn a decline into a task that never appears.
    if params
        .configuration
        .as_ref()
        .is_some_and(|c| c.return_immediately)
    {
        return match server.runtime.spawn(&skill, input).await {
            Ok(run) => Ok(json!({
                "task": task_of(run, TaskState::Working, "accepted", None)
            })),
            Err(crate::core::RuntimeError::PolicyDenied(_)) => {
                Ok(json!({ "message": declined(&skill) }))
            }
            Err(crate::core::RuntimeError::QuotaExceeded(why)) => {
                Err(RpcError::new(code::UNSUPPORTED_OPERATION, why.to_string()))
            }
            Err(e) => Err(RpcError::new(code::INTERNAL_ERROR, e.to_string())),
        };
    }

    let outcome = match server.runtime.run_tainted(&skill, input).await {
        Ok(outcome) => outcome,
        // A policy denial is the agent *declining*, not the agent breaking.
        // Reported as `-32603 Internal error` it reads as "this server is
        // faulty, retry later", and the caller retries a decision that will
        // never change.
        //
        // Answered as a `Message` rather than a rejected `Task` because no task
        // exists: nothing was admitted, so there is no id to poll and no
        // history to fetch. A2A's response is a oneof for exactly this.
        Err(crate::core::RuntimeError::PolicyDenied(_)) => {
            return Ok(json!({ "message": declined(&skill) }));
        }
        // Back-pressure, not a fault. `-32603` reads as "the far side is
        // broken, retry later" and a caller may well retry the same second;
        // this says *the agent cannot take this on right now*, which is what a
        // ceiling means and what a caller should back off from.
        Err(crate::core::RuntimeError::QuotaExceeded(why)) => {
            return Err(RpcError::new(code::UNSUPPORTED_OPERATION, why.to_string()));
        }
        Err(e) => return Err(RpcError::new(code::INTERNAL_ERROR, e.to_string())),
    };

    // The run is over by the time a blocking send returns, so any webhook
    // registered against it is told now. A caller that both blocks *and*
    // registers gets the answer twice, which is its choice — and cheaper than a
    // notification that never arrives because it registered a moment too late.
    server.notify(outcome.run_id).await;

    Ok(json!({ "task": task_of_outcome(&outcome) }))
}

fn task_of_outcome(outcome: &crate::runtime::RunOutcome) -> A2aTask {
    let part = match outcome.output.clone().unwrap_or(Value::Null) {
        Value::String(text) => Part {
            text: Some(text),
            data: None,
            raw: None,
            url: None,
            filename: None,
            media_type: Some("text/plain".to_owned()),
        },
        data => Part {
            text: None,
            data: Some(data),
            raw: None,
            url: None,
            filename: None,
            media_type: Some("application/json".to_owned()),
        },
    };
    A2aTask {
        id: outcome.run_id.to_string(),
        context_id: None,
        status: TaskStatus {
            state: state_of(&outcome.status),
            message: None,
            timestamp: None,
        },
        artifacts: matches!(outcome.status, crate::runtime::RunStatus::Succeeded).then(|| {
            vec![A2aArtifact {
                artifact_id: format!("{}-result", outcome.run_id),
                parts: vec![part],
            }]
        }),
        metadata: None,
    }
}

/// Which capability this message asks for.
///
/// Named or unambiguous — never inferred. See the module docs: picking a
/// capability from the content of an untrusted message is a dispatch decision
/// made by reading attacker-controlled text.
fn resolve_skill(server: &A2aServer, message: &A2aMessage) -> Result<String, RpcError> {
    if let Some(asked) = message.requested_skill() {
        if server.skills.iter().any(|s| s == asked) {
            return Ok(asked.to_owned());
        }
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            format!(
                "this agent has no skill '{asked}'. Its card advertises: {}",
                server.skills.join(", ")
            ),
        ));
    }
    match server.skills.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "this agent advertises no skills, so there is nothing to send a \
             message to",
        )),
        many => Err(RpcError::new(
            code::INVALID_PARAMS,
            format!(
                "this agent advertises {} skills, so `message.metadata.skill` \
                 must name one of: {}. It is not inferred from the message — \
                 choosing what to run by reading the text would let the sender \
                 pick the capability",
                many.len(),
                many.join(", ")
            ),
        )),
    }
}

async fn get_task(
    server: &A2aServer,
    headers: &HeaderMap,
    params: CommonParams,
) -> Result<Value, RpcError> {
    let id = task_id(&params)?;
    server
        .gate(headers, action::TASK_READ, &id.to_string())
        .await?;

    let records = server
        .runtime
        .journal()
        .read(id, 1)
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the journal could not be read"))?;
    let Some(last) = records.last() else {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {id}"),
        ));
    };

    // Read from the **last** record, not from whether a suspension appears
    // anywhere: a run that waited, was resumed and carried on has a suspension
    // in its history and is not suspended now.
    let (state, detail) = match last.kind() {
        RecordKind::RunSuspended { reason } => (TaskState::InputRequired, reason.to_string()),
        RecordKind::RunSealed { outcome, .. } => (sealed_state(outcome), outcome.clone()),
        _ => (TaskState::Working, "running".to_owned()),
    };
    let case = records
        .iter()
        .find_map(|r| r.body.case.map(|c| c.to_string()));

    Ok(json!({ "task": task_of(id, state, &detail, case) }))
}

/// A sealed run's outcome word, as an A2A state.
///
/// The outcome is the same string [`RunStatus::as_str`](crate::runtime::RunStatus::as_str)
/// produces, which is what the executor seals with.
pub(super) fn sealed_state(outcome: &str) -> TaskState {
    match outcome {
        "succeeded" => TaskState::Completed,
        "cancelled" => TaskState::Canceled,
        "suspended" => TaskState::InputRequired,
        _ => TaskState::Failed,
    }
}

async fn cancel_task(
    server: &A2aServer,
    headers: &HeaderMap,
    params: CommonParams,
) -> Result<Value, RpcError> {
    let id = task_id(&params)?;
    let caller = server
        .gate(headers, action::TASK_CANCEL, &id.to_string())
        .await?;

    let records = server
        .runtime
        .journal()
        .read(id, 1)
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the journal could not be read"))?;
    let Some(last) = records.last() else {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {id}"),
        ));
    };
    // A sealed run is finished, and A2A has a code for exactly this. Accepting
    // the request and reporting success would tell the caller a completed run
    // is about to stop.
    if let RecordKind::RunSealed { outcome, .. } = last.kind() {
        return Err(RpcError::new(
            code::TASK_NOT_CANCELABLE,
            format!("this task already finished as '{outcome}'"),
        ));
    }

    server
        .runtime
        .request_cancel(id, &caller.actor, "cancelled over A2A")
        .await
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;

    // Still `WORKING`, deliberately. The request is durable, and the run stops
    // at its next step boundary — reporting `CANCELED` here would claim it had
    // already stopped and unwound, which is exactly what has not happened yet.
    Ok(json!({
        "task": task_of(id, TaskState::Working, "cancellation requested", None)
    }))
}

async fn get_extended_card(server: &A2aServer, headers: &HeaderMap) -> Result<Value, RpcError> {
    server
        .gate(headers, action::CARD_EXTENDED, &server.card.name)
        .await?;
    serde_json::to_value(&server.extended)
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))
}

fn task_id(params: &CommonParams) -> Result<RunId, RpcError> {
    let Some(raw) = params.id.as_deref() else {
        return Err(RpcError::new(code::INVALID_PARAMS, "`id` is required"));
    };
    RunId::parse(raw).map_err(|_| {
        // Not found rather than invalid params: whether a string is a run id
        // this plane issued is not something a caller should learn from the
        // shape of the refusal.
        RpcError::new(code::TASK_NOT_FOUND, format!("no such task: {raw}"))
    })
}

/// The agent declining, with nothing about *why*.
///
/// The reason is deliberately absent. A denial reason describes the rule that
/// fired, and a rule describes the classification it protects — so a caller who
/// can send messages and read refusals can map the policy by probing it. The
/// operator sees the reason in the journal, where it belongs; the peer sees that
/// it was declined, which is all it can act on anyway.
fn declined(skill: &str) -> A2aMessage {
    A2aMessage {
        message_id: format!("declined-{skill}"),
        role: "ROLE_AGENT".to_owned(),
        parts: vec![Part {
            text: Some("this agent declined the request".to_owned()),
            data: None,
            raw: None,
            url: None,
            filename: None,
            media_type: Some("text/plain".to_owned()),
        }],
        context_id: None,
        task_id: None,
        metadata: None,
    }
}

pub(super) fn task_of(run: RunId, state: TaskState, detail: &str, case: Option<String>) -> A2aTask {
    A2aTask {
        id: run.to_string(),
        context_id: case,
        status: TaskStatus {
            state,
            message: Some(A2aMessage {
                message_id: format!("{run}-status"),
                role: "ROLE_AGENT".to_owned(),
                parts: vec![Part {
                    text: Some(detail.to_owned()),
                    data: None,
                    raw: None,
                    url: None,
                    filename: None,
                    media_type: Some("text/plain".to_owned()),
                }],
                context_id: None,
                task_id: Some(run.to_string()),
                metadata: None,
            }),
            timestamp: None,
        },
        artifacts: None,
        metadata: None,
    }
}

// ── Push notification configuration ─────────────────────────────────────────
//
// Every one of these authorizes against the **task**, not against the method.
// A webhook registration is permission to be told about somebody's work, so the
// question is "may this caller touch this task", and a caller that may not read
// a task must not be able to attach a URL to it either.

/// The push machinery, or the spec's refusal when this build has none.
fn push_parts(
    server: &A2aServer,
) -> Result<(&Arc<dyn crate::push::PushStore>, &crate::push::PushSender), RpcError> {
    server.push.as_ref().map(|p| (&p.0, &p.1)).ok_or_else(|| {
        RpcError::new(
            code::PUSH_NOT_SUPPORTED,
            "this agent does not implement push notifications; its card \
             advertises pushNotifications as false",
        )
    })
}

/// The task a push request names, refusing one that does not exist.
async fn push_task(server: &A2aServer, raw: Option<&str>) -> Result<RunId, RpcError> {
    let Some(raw) = raw else {
        return Err(RpcError::new(code::INVALID_PARAMS, "`taskId` is required"));
    };
    let id = RunId::parse(raw)
        .map_err(|_| RpcError::new(code::TASK_NOT_FOUND, format!("no such task: {raw}")))?;
    // Checked against the journal rather than taken on faith: registering a
    // webhook for a task that does not exist would let a caller park a
    // destination against an id somebody else is about to be issued.
    let records = server
        .runtime
        .journal()
        .read(id, 1)
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the journal could not be read"))?;
    if records.is_empty() {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {id}"),
        ));
    }
    Ok(id)
}

async fn push_create(
    server: &A2aServer,
    headers: &HeaderMap,
    params: CommonParams,
) -> Result<Value, RpcError> {
    let (store, _) = push_parts(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    server
        .gate(headers, action::TASK_PUSH, &task.to_string())
        .await?;

    let Some(url) = params.url else {
        return Err(RpcError::new(code::INVALID_PARAMS, "`url` is required"));
    };

    // Checked before anything is stored, so a caller learns now that its
    // webhook will never be called — rather than waiting for a notification
    // that silently never comes.
    let (_, sender) = push_parts(server)?;
    sender
        .policy()
        .check(&url)
        .map_err(|e| RpcError::new(code::INVALID_PARAMS, e.to_string()))?;

    let config = crate::push::PushConfig {
        id: params.id.unwrap_or_else(|| format!("push-{task}")),
        task,
        url,
        token: params.token.map(crate::core::Secret::new),
    };
    store
        .put(&config)
        .await
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
    Ok(config.redacted())
}

async fn push_get(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let (store, _) = push_parts(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    server
        .gate(headers, action::TASK_PUSH, &task.to_string())
        .await?;

    let id = params
        .id
        .as_deref()
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`id` is required"))?;
    store
        .get(task, id)
        .await
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?
        .map(|c| c.redacted())
        .ok_or_else(|| {
            RpcError::new(
                code::TASK_NOT_FOUND,
                format!("no push configuration '{id}' for task {task}"),
            )
        })
}

async fn push_list(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let (store, _) = push_parts(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    server
        .gate(headers, action::TASK_PUSH, &task.to_string())
        .await?;

    let configs = store
        .list(task)
        .await
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
    Ok(json!({
        "configs": configs.iter().map(crate::push::PushConfig::redacted).collect::<Vec<_>>()
    }))
}

async fn push_delete(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let (store, _) = push_parts(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    server
        .gate(headers, action::TASK_PUSH, &task.to_string())
        .await?;

    let id = params
        .id
        .as_deref()
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`id` is required"))?;
    store
        .delete(task, id)
        .await
        .map_err(|e| RpcError::new(code::INTERNAL_ERROR, e.to_string()))?;
    Ok(json!({}))
}
