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
//! # Optional capabilities say what is wired
//!
//! Streaming and non-terminal task subscription are durable journal views.
//! Push is advertised only after `with_push` supplies durable registration
//! storage and a retrying transport worker; without that wiring every push
//! method uses `PushNotificationNotSupportedError` and the card advertises
//! false.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::{PolicyDecision, PolicyRequest, RunId, Seq, SourceId, Tainted};
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

    /// Optional operations implemented by this server.
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
    pub const TASK_CONTINUE: &str = "a2a:task.continue";
    pub const TASK_CANCEL: &str = "a2a:task.cancel";
    pub const CARD_EXTENDED: &str = "a2a:card.extended";
    /// Registering, reading or removing a webhook for a task.
    pub const TASK_PUSH: &str = "a2a:task.push";

    /// Every action this surface can ask about, so a deployment can enumerate
    /// what it must write rules for.
    pub const ALL: &[&str] = &[
        MESSAGE_SEND,
        TASK_READ,
        TASK_CONTINUE,
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
    #[serde(rename = "TASK_STATE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "TASK_STATE_SUBMITTED")]
    Submitted,
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
    #[serde(rename = "TASK_STATE_REJECTED")]
    Rejected,
    #[serde(rename = "TASK_STATE_AUTH_REQUIRED")]
    AuthRequired,
}

/// The A2A state a live run's status surfaces as.
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
///
/// This and [`sealed_state`] are the **same question asked on two paths**: this
/// one answers the caller who receives the immediate `SendMessage` response, and
/// `sealed_state` answers everyone who reads the task back — `GetTask`,
/// `SubscribeToTask`, and every streamed status update. They must agree, and
/// `a_live_status_and_its_sealed_outcome_agree` holds them to it over every
/// variant.
///
/// **This is the exhaustive one, and that is the point.** The two were unified
/// once by making this function delegate to `sealed_state`, which reads as the
/// tidier direction and is the wrong one: `sealed_state` matches *strings*
/// behind a `_ => Failed`, so delegating to it deleted the only compile-time
/// check on the mapping while leaving a comment claiming the compiler still
/// enforced it. Adding a `RunStatus` variant for something that is **not** a
/// failure — an authorization wait, a rejection — would then have compiled
/// cleanly and reported `Failed` on both paths. That is not agreement; it is
/// the same wrong answer twice, which is strictly harder to notice than two
/// different ones.
///
/// So the enum match is the definition and the string match is checked against
/// it. A new variant fails to compile *here*, which is where the decision
/// belongs.
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
    pub history: Option<Vec<A2aMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// One output produced by an A2A task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aArtifact {
    pub artifact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parts: Vec<Part>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl Part {
    /// A text part.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            data: None,
            raw: None,
            url: None,
            filename: None,
            media_type: Some("text/plain".to_owned()),
            metadata: None,
        }
    }

    /// A structured-data part.
    #[must_use]
    pub fn data(data: Value) -> Self {
        Self {
            text: None,
            data: Some(data),
            raw: None,
            url: None,
            filename: None,
            media_type: Some("application/json".to_owned()),
            metadata: None,
        }
    }

    /// A file part carrying its bytes inline, base64-encoded per `ProtoJSON`.
    #[must_use]
    pub fn file_raw(
        raw_base64: impl Into<String>,
        media_type: impl Into<String>,
        filename: impl Into<String>,
    ) -> Self {
        Self {
            text: None,
            data: None,
            raw: Some(raw_base64.into()),
            url: None,
            filename: Some(filename.into()),
            media_type: Some(media_type.into()),
            metadata: None,
        }
    }

    /// A file part referring to bytes by URL.
    #[must_use]
    pub fn file_url(
        url: impl Into<String>,
        media_type: impl Into<String>,
        filename: impl Into<String>,
    ) -> Self {
        Self {
            text: None,
            data: None,
            raw: None,
            url: Some(url.into()),
            filename: Some(filename.into()),
            media_type: Some(media_type.into()),
            metadata: None,
        }
    }
}

/// How a skill shapes its A2A answer, when the default projection is not it.
///
/// The default stands for most skills: a string output becomes a text part and
/// anything else a data part, in one artifact. What that projection cannot say
/// is *file content* — inline bytes or a URL with a filename — or that the
/// answer is a quick, stateless `Message` rather than a task's artifact. Both
/// are ordinary A2A response shapes a peer may expect.
///
/// A skill opts in by returning this value (via [`A2aReply::into_value`]) as
/// its outcome. The runtime journals it as it journals any output — the shape
/// is a *projection instruction* read at the protocol boundary, not a second
/// channel around the journal.
///
/// ```no_run
/// # use agentplane::api::a2a::{A2aReply, Part};
/// # use agentplane::core::{Outcome, Tainted};
/// // A task whose artifact is a file reference:
/// let reply = A2aReply::artifact(vec![Part::file_url(
///     "https://example.com/report.pdf",
///     "application/pdf",
///     "report.pdf",
/// )]);
/// # let _ = Outcome::done(Tainted::trusted(reply.into_value()));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2aReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Vec<Part>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifacts: Option<Vec<Vec<Part>>>,
}

/// The output key an [`A2aReply`] travels under.
///
/// A `$`-prefixed marker, like `$a2a_message` on the inbound side: ordinary
/// skill output is domain data this runtime never interprets, so the one shape
/// it *does* interpret must be unmistakably deliberate rather than a field
/// name a domain object happens to share.
const REPLY_KEY: &str = "$a2a_reply";

impl A2aReply {
    /// Answer the blocking send with a direct `Message` instead of a task.
    ///
    /// Outside a blocking send — a spawned task, a stream, a later `GetTask` —
    /// there is no message to deliver, and the parts become the task's
    /// artifact instead: the content survives, only the envelope differs.
    #[must_use]
    pub const fn message(parts: Vec<Part>) -> Self {
        Self {
            message: Some(parts),
            artifacts: None,
        }
    }

    /// Answer with one artifact holding these parts.
    #[must_use]
    pub fn artifact(parts: Vec<Part>) -> Self {
        Self {
            message: None,
            artifacts: Some(vec![parts]),
        }
    }

    /// Answer with several artifacts.
    #[must_use]
    pub const fn artifacts(artifacts: Vec<Vec<Part>>) -> Self {
        Self {
            message: None,
            artifacts: Some(artifacts),
        }
    }

    /// The outcome value a skill returns.
    #[must_use]
    pub fn into_value(self) -> Value {
        json!({ REPLY_KEY: self })
    }

    /// Read a reply back out of a run's output, **if the run may declare one**.
    ///
    /// A projection instruction is authority: it decides whether the answer is
    /// a task artifact or a direct `Message`, and what parts it carries —
    /// including a file part naming a URL. Skill output routinely *contains*
    /// untrusted data: a summariser quotes its input, a declarative agent's
    /// answer is a model's words, and an echoing skill returns a peer's own
    /// bytes. So the marker is honoured only from a **trusted** output.
    ///
    /// This was not hypothetical. Before the check, a peer could put the
    /// marker in its message, have an ordinary echoing skill return it, and
    /// choose the envelope its own reply arrived in — a file URL of the
    /// attacker's naming, presented as the agent's answer. Model output is a
    /// proposal, never authority; so is a peer's message.
    ///
    /// An untrusted answer still reaches the caller — as the artifact content
    /// it is, rather than as an instruction about the envelope.
    pub(super) fn of_output(output: &crate::core::Tainted<Value>) -> Option<Self> {
        if output.label().is_untrusted() {
            return None;
        }
        serde_json::from_value(output.peek().get(REPLY_KEY)?.clone()).ok()
    }

    /// The message parts, when this reply is a direct `Message`.
    pub(super) fn message_parts(&self) -> Option<Vec<Part>> {
        self.message.clone()
    }

    /// Every part, for contexts that can only carry artifacts.
    pub(super) fn artifact_parts(&self) -> Vec<Vec<Part>> {
        match (&self.artifacts, &self.message) {
            (Some(artifacts), _) => artifacts.clone(),
            (None, Some(message)) => vec![message.clone()],
            (None, None) => Vec::new(),
        }
    }
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_task_ids: Vec<String>,
}

impl A2aMessage {
    fn validate_parts(&self) -> Result<(), RpcError> {
        if self.role != "ROLE_USER" {
            return Err(RpcError::new(
                code::INVALID_PARAMS,
                "an inbound Message role must be ROLE_USER",
            ));
        }
        if self.parts.is_empty() {
            return Err(RpcError::new(
                code::CONTENT_TYPE_NOT_SUPPORTED,
                "the message has no parts this agent can read; it accepts text and data parts",
            ));
        }
        for (index, part) in self.parts.iter().enumerate() {
            if part.raw.is_some() || part.url.is_some() {
                return Err(RpcError::new(
                    code::CONTENT_TYPE_NOT_SUPPORTED,
                    format!(
                        "message.parts[{index}] is file content; this agent card advertises only text/plain and application/json"
                    ),
                ));
            }
            let variants = usize::from(part.text.is_some()) + usize::from(part.data.is_some());
            if variants != 1 {
                return Err(RpcError::new(
                    code::INVALID_PARAMS,
                    format!("message.parts[{index}] must contain exactly one of text or data"),
                ));
            }
            let supported = match (part.text.is_some(), part.data.is_some()) {
                (true, false) => part
                    .media_type
                    .as_deref()
                    .is_none_or(|value| value == "text/plain"),
                (false, true) => part
                    .media_type
                    .as_deref()
                    .is_none_or(|value| value == "application/json"),
                _ => false,
            };
            if !supported {
                return Err(RpcError::new(
                    code::CONTENT_TYPE_NOT_SUPPORTED,
                    format!(
                        "message.parts[{index}] mediaType does not match this agent's text/plain and application/json inputs"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// What the runtime receives as input.
    ///
    /// A stable shape, always the same three keys, rather than a clever unwrapping
    /// that hands a skill a bare string sometimes and an object other times. A
    /// skill parsing its own input should not have to branch on how many parts
    /// the caller happened to send. `$a2a_message` preserves the exact protocol
    /// object for task-history reconstruction; `text` and `data` remain the
    /// ergonomic projections skills normally consume.
    fn to_input(&self) -> Value {
        let text: Vec<&str> = self
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .collect();
        let data: Vec<Value> = self.parts.iter().filter_map(|p| p.data.clone()).collect();
        json!({
            "text": text.join("\n"),
            "data": data,
            "$a2a_message": self,
        })
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
    #[serde(default)]
    accepted_output_modes: Vec<String>,
    #[serde(default)]
    history_length: Option<usize>,
    #[serde(default)]
    task_push_notification_config: Option<PushRequest>,
}

impl SendConfiguration {
    fn validate(&self) -> Result<(), RpcError> {
        if !self.accepted_output_modes.is_empty()
            && !self
                .accepted_output_modes
                .iter()
                .any(|mode| matches!(mode.as_str(), "text/plain" | "application/json"))
        {
            return Err(RpcError::new(
                code::CONTENT_TYPE_NOT_SUPPORTED,
                "acceptedOutputModes contains no mode this agent can produce",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushAuthenticationRequest {
    scheme: String,
    #[serde(default)]
    credentials: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    url: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    authentication: Option<PushAuthenticationRequest>,
}

impl PushRequest {
    /// Refuse an id in the namespace an operator destination owns.
    ///
    /// A caller and the deployment share one push store, and the two are told
    /// apart by an id prefix. A caller allowed to write into that namespace could
    /// point one of the deployment's own destinations at an address it chose —
    /// and operator destinations are deliberately exempt from the host
    /// allowlist, HTTPS and the public-address check, because there is supposed
    /// to be no caller involved. This is the check that keeps that supposition
    /// true.
    fn validate(&self) -> Result<(), RpcError> {
        if self.id.as_deref().is_some_and(crate::push::is_operator_id) {
            return Err(RpcError::new(
                code::INVALID_PARAMS,
                format!(
                    "a pushNotificationConfig id may not begin with '{}': that namespace \
                     belongs to destinations this deployment configured for itself",
                    crate::push::OPERATOR_PREFIX
                ),
            ));
        }
        Ok(())
    }

    fn config(&self, task: RunId) -> crate::push::PushConfig {
        crate::push::PushConfig {
            id: self.id.clone().unwrap_or_else(|| format!("push-{task}")),
            task,
            url: self.url.clone(),
            token: self.token.clone().map(crate::core::Secret::new),
            authentication: self.authentication.as_ref().map(|authentication| {
                crate::push::PushAuthentication {
                    scheme: authentication.scheme.clone(),
                    credentials: crate::core::Secret::new(
                        authentication.credentials.clone().unwrap_or_default(),
                    ),
                }
            }),
        }
    }
}

/// What every method's params may carry.
///
/// One struct for every method, which is the same shape the binary's arguments
/// had before they moved onto per-verb structs: a field belonging to one method
/// was **silently accepted** by another and did nothing. On the wire that reads
/// worse than at a command line, because the caller is a stranger who cannot
/// see the source. `ListTasks` was the case that mattered — a request naming
/// `contxtId`, or the `context_id` the protocol's own conformance kit sends,
/// parsed cleanly, dropped the filter, and answered with **every** task the
/// caller may see, shaped exactly like the scoped list that was asked for.
///
/// Two mechanisms close it, and they are different questions.
/// [`deny_unknown_fields`] refuses a name this surface does not know at all
/// (`contxtId`, `task_id`), which the A2A specification licenses
/// outright: A2A §5.5 says JSON field names **MUST** be camelCase, so `context_id` is not an
/// alternative spelling but a violation. [`FIELDS_BY_METHOD`] refuses a name
/// this surface knows and *this method* does not (`pageSize` on `CancelTask`).
///
/// Neither subsumes the other.
///
/// [`deny_unknown_fields`]: https://serde.rs/container-attrs.html
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// `SendMessageRequest.metadata`, accepted and not interpreted.
    ///
    /// Modelled rather than ignored because the two are different answers now
    /// that unknown fields are refused: the specification defines this field, so
    /// a conforming client may send it and must not meet `-32602`. It is
    /// deliberately not read — opaque caller data has no governed meaning here,
    /// and inventing one would be a control nothing enforces. What the runtime
    /// does record about an inbound message is its authenticated sender, which
    /// is provenance rather than a field the sender chose.
    ///
    /// `dead_code` is allowed here for the one case where it is the point: the
    /// field exists so that deserialization *accepts* the name, and reading it
    /// is what would be wrong.
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<Value>,
    #[serde(default, rename = "taskId")]
    push_task: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    authentication: Option<PushAuthenticationRequest>,
    #[serde(default, rename = "contextId")]
    context_id: Option<String>,
    #[serde(default)]
    status: Option<TaskState>,
    #[serde(default, rename = "pageSize")]
    page_size: Option<usize>,
    #[serde(default, rename = "pageToken")]
    page_token: Option<String>,
    #[serde(default, rename = "historyLength")]
    history_length: Option<usize>,
    #[serde(default, rename = "statusTimestampAfter")]
    status_timestamp_after: Option<String>,
    #[serde(default, rename = "includeArtifacts")]
    include_artifacts: bool,
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

    /// The machine-readable reason A2A 1.0's error-handling rules require
    /// beside an A2A-specific code, as a `google.rpc.ErrorInfo` in
    /// `error.data`.
    ///
    /// Derived from the code rather than declared per call site, because the
    /// two are one fact: the spec's table maps each code to exactly one reason
    /// token, and a site that could set them independently is a site that can
    /// disagree with itself. Standard JSON-RPC codes carry no reason — the
    /// spec assigns them none — so they return `None` and the error omits
    /// `data` rather than inventing a token.
    ///
    /// This adds no information a prober does not already have: the reason is
    /// a restatement of the code in the same response. The uniform-refusal
    /// rule governs what a *model* is told; this is the protocol channel to an
    /// authenticated peer.
    const fn reason(&self) -> Option<&'static str> {
        match self.code {
            code::TASK_NOT_FOUND => Some("TASK_NOT_FOUND"),
            code::TASK_NOT_CANCELABLE => Some("TASK_NOT_CANCELABLE"),
            code::PUSH_NOT_SUPPORTED => Some("PUSH_NOTIFICATION_NOT_SUPPORTED"),
            code::UNSUPPORTED_OPERATION => Some("UNSUPPORTED_OPERATION"),
            code::CONTENT_TYPE_NOT_SUPPORTED => Some("CONTENT_TYPE_NOT_SUPPORTED"),
            code::EXTENDED_CARD_NOT_CONFIGURED => Some("EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
            code::VERSION_NOT_SUPPORTED => Some("VERSION_NOT_SUPPORTED"),
            _ => None,
        }
    }

    /// The JSON-RPC error member, with the required `ErrorInfo` when one
    /// applies.
    fn body(&self) -> Value {
        match self.reason() {
            Some(reason) => json!({
                "code": self.code,
                "message": self.message,
                "data": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "domain": "a2a-protocol.org",
                    "reason": reason,
                }],
            }),
            None => json!({ "code": self.code, "message": self.message }),
        }
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
                "error": self.body(),
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
    /// Each agent's own card, by agent name.
    per_agent: std::collections::BTreeMap<String, crate::peers::AgentCard>,
    /// The card's advertised skill ids — what a caller may ask for.
    skills: Vec<String>,
    push: Option<PushRuntime>,
    /// How many candidate journals one content-filtered `ListTasks` may read.
    ///
    /// See [`Self::filter_scan_budget`] for why this is a ceiling and not a
    /// page size.
    filter_scan_budget: usize,
}

#[derive(Debug, Clone)]
struct PushRuntime {
    store: Arc<dyn crate::push::PushStore>,
    transport: Arc<dyn crate::push::PushTransport>,
}

/// Durable A2A webhook delivery, driven by an operator scheduler.
///
/// A thin binding of [`DeliveryWorker`](crate::push::DeliveryWorker) to the A2A
/// projection. The cursor discipline lives in `push` because it has nothing to
/// do with A2A — it lived here only because A2A was the first caller, which made
/// the one mechanism an operator most wants reachable only by speaking somebody
/// else's protocol.
#[derive(Debug, Clone)]
pub struct A2aPushWorker {
    inner: crate::push::DeliveryWorker,
}

/// Outcome of one bounded push sweep.
///
/// Re-exported from [`crate::push`], which owns the delivery loop now.
pub use crate::push::PushSweepReport;

/// `StreamResponse` payloads, for **caller-registered** webhooks only.
///
/// It claims exactly the registrations an operator destination does not — see
/// [`crate::push::Outbox`] on why the two share one store and must not serve
/// each other's rows.
#[derive(Clone)]
struct A2aProjection {
    runtime: Arc<Runtime>,
}

impl std::fmt::Debug for A2aProjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aProjection").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl crate::push::Projection for A2aProjection {
    async fn payloads(
        &self,
        record: &crate::journal::Record,
    ) -> Result<Vec<serde_json::Value>, crate::core::StoreError> {
        let case = record.body.case.map(|case| case.to_string());
        super::a2a_stream::payloads_for_record(&self.runtime, record, case.as_deref())
            .await
            // A projection failure is this plane's own bug and always transient
            // to the worker; the shape it travels in is the store's error type
            // because that is what the seam speaks.
            .map_err(|error| crate::core::StoreError::Backend(error.to_string()))
    }

    fn owns(&self, registration: &crate::push::PushRegistration) -> bool {
        !crate::push::is_operator_id(&registration.config.id)
    }
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
    #[error(
        "the runtime has no case layer, so this server cannot mint the \
         contextId A2A 1.0 requires on every task — a generated contextId \
         must be continuable, and continuation here is a case. Build the \
         runtime with `.cases(store)`"
    )]
    NoCases,
    #[error("the agent card could not be derived: {0}")]
    Card(#[from] crate::manifest::ManifestError),
    #[error("push changes the signed Agent Card; configure it before calling signing_cards_with")]
    CardAlreadySigned,
    #[error(
        "an A2A server serves at least one agent, and no manifest was given —          the well-known card path must answer with a card describing something"
    )]
    NoAgents,
    #[error(
        "agents '{first}' and '{second}' both advertise skill '{skill}', so a          request naming it would be a routing decision the caller did not make.          A2A dispatch is named, never inferred: give the skill distinct          capability names, or serve the two agents from separate planes"
    )]
    AmbiguousSkill {
        skill: String,
        first: String,
        second: String,
    },
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
        Self::hosting(runtime, auth, security, &[manifest], url)
    }

    /// Serve several declared agents from one plane.
    ///
    /// A2A's well-known card path is singular per host, so a plane hosting many
    /// agents could previously give each its own card only by running a server
    /// per agent. The first manifest is the one the **well-known card
    /// describes** — a room's orchestrator, in the shape the CLI already uses —
    /// and every agent additionally gets its own full card at
    /// [`agent_card_path`](crate::peers::agent_card_path), listed in the
    /// [`EXT_AGENT_DIRECTORY`](crate::peers::EXT_AGENT_DIRECTORY) extension so
    /// a caller can find them.
    ///
    /// Skill dispatch spans every agent, because they are all on the runtime
    /// already — what was missing was only discovery. Two agents advertising
    /// one skill id is **refused**: dispatch names a skill, and a name that
    /// resolves to two agents is a routing decision the caller did not make.
    ///
    /// # Errors
    ///
    /// [`ServerSetupError::NoPolicy`], [`ServerSetupError::NoCases`],
    /// [`ServerSetupError::NoAgents`] for an empty slice, or
    /// [`ServerSetupError::AmbiguousSkill`].
    pub fn hosting(
        runtime: Arc<Runtime>,
        auth: Arc<dyn Authenticator>,
        security: &crate::peers::CardSecurity,
        manifests: &[&Manifest],
        url: impl Into<String>,
    ) -> Result<Self, ServerSetupError> {
        let policy = runtime.policy().ok_or(ServerSetupError::NoPolicy)?.clone();
        if runtime.cases().is_none() {
            return Err(ServerSetupError::NoCases);
        }
        let [primary, rest @ ..] = manifests else {
            return Err(ServerSetupError::NoAgents);
        };
        let url = url.into();

        // Every agent's own card, derived exactly as a lone agent's would be —
        // same digest, same skills, same ceilings. A card that differed because
        // its agent shared a plane would make the plane part of the identity a
        // consumer pins, which the room work already refused for manifests.
        let mut directory = Vec::new();
        let mut per_agent = std::collections::BTreeMap::new();
        let mut owner_of_skill: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for m in manifests {
            let name = m.metadata.name.clone();
            let mut agent_card = AgentCard::derive(m, url.clone())?;
            security.apply(&mut agent_card);
            for skill in &agent_card.skills {
                if let Some(other) = owner_of_skill.insert(skill.id.clone(), name.clone())
                    && other != name
                {
                    return Err(ServerSetupError::AmbiguousSkill {
                        skill: skill.id.clone(),
                        first: other,
                        second: name,
                    });
                }
            }
            directory.push(serde_json::json!({
                "name": name,
                "version": m.metadata.version,
                "cardPath": crate::peers::agent_card_path(&name),
                "manifestDigest": m.digest()?.to_hex(),
                "skills": agent_card.skills.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            }));
            per_agent.insert(name, agent_card);
        }

        let mut card = AgentCard::derive(primary, url.clone())?;
        let mut extended = ExtendedAgentCard::derive(primary, url)?;
        security.apply(&mut card);
        security.apply(&mut extended.public);

        // Only when there is more than one, so a single-agent plane's card is
        // byte-for-byte what it was: an extension nobody needs is a claim a
        // verifier has to understand for nothing.
        if !rest.is_empty() {
            let ext = crate::peers::AgentExtension {
                uri: crate::peers::EXT_AGENT_DIRECTORY.to_owned(),
                description: Some(
                    "Every agent this plane serves, and where each agent's own card is.".to_owned(),
                ),
                required: false,
                params: Some(serde_json::json!({ "agents": directory })),
            };
            card.capabilities.extensions.push(ext.clone());
            extended.public.capabilities.extensions.push(ext);
        }

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

        // The union, because every agent is already on the runtime and a skill
        // that dispatches but is not accepted here would be a refusal the plane
        // could have answered.
        let skills = owner_of_skill.keys().cloned().collect();
        Ok(Self {
            runtime,
            auth,
            policy,
            card,
            extended,
            per_agent,
            skills,
            push: None,
            filter_scan_budget: FILTER_SCAN_BUDGET,
        })
    }

    /// Bound what one content-filtered `ListTasks` may cost.
    ///
    /// A `status` or `contextId` filter can only be evaluated by reading a
    /// candidate task's journal, and the spec's `totalSize` is the exact total
    /// — so a filtered listing over a large tenant is a request whose cost the
    /// *caller* chooses. Unbounded, that is the same scan the paged index
    /// removed, reachable by any authenticated peer who adds one field.
    ///
    /// Over budget, the request is refused with the narrowing lever named —
    /// `statusTimestampAfter` is answered from the index, so tightening it
    /// shrinks the candidate set without reading anything. A refusal is honest
    /// where a truncated total would be a lie shaped like an answer: the spec
    /// requires the exact count, and a bound that quietly stopped counting
    /// would report a smaller tenant, not a bounded scan.
    #[must_use]
    pub fn filter_scan_budget(mut self, budget: usize) -> Self {
        self.filter_scan_budget = budget.max(1);
        self
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

    /// Enable A2A push configuration and expose a durable delivery worker.
    ///
    /// The worker uses the task journal itself as its outbox. A registration's
    /// cursor advances only after a receiver returns 2xx, so a crash between
    /// POST and acknowledgement persistence repeats an event and never loses
    /// one. Call [`A2aServer::push_worker`] before consuming the server into its
    /// router and schedule [`A2aPushWorker::run_once`] from every instance.
    pub fn with_push(
        mut self,
        store: Arc<dyn crate::push::PushStore>,
        transport: Arc<dyn crate::push::PushTransport>,
    ) -> Result<Self, ServerSetupError> {
        if !self.card.signatures.is_empty() || !self.extended.public.signatures.is_empty() {
            return Err(ServerSetupError::CardAlreadySigned);
        }
        self.card.capabilities.push_notifications = true;
        self.extended.public.capabilities.push_notifications = true;
        self.push = Some(PushRuntime { store, transport });
        Ok(self)
    }

    /// A cloneable worker handle, when push is configured.
    #[must_use]
    pub fn push_worker(&self) -> Option<A2aPushWorker> {
        self.push.clone().map(|push| A2aPushWorker {
            inner: crate::push::DeliveryWorker::new(
                Arc::clone(self.runtime.journal()),
                push.store,
                push.transport,
                Arc::new(A2aProjection {
                    runtime: Arc::clone(&self.runtime),
                }),
            ),
        })
    }

    /// The router.
    ///
    /// The card path is unauthenticated by design and everything else is not.
    ///
    /// The RPC endpoint answers with and without a trailing slash, and that is
    /// an interoperability fact rather than a courtesy: mainstream HTTP clients
    /// that take a base URL — httpx among them, which is what the official A2A
    /// conformance kit and the reference Python SDK are built on — resolve a
    /// request for `"/"` against the card's interface URL per RFC 3986, so the
    /// wire carries `POST {interface}/`. A router that 404s the slash form
    /// passes every test written here and fails the first real peer. Exactness
    /// elsewhere (method names, version headers) guards protocol *semantics*;
    /// a trailing slash is a client-side join artifact with none.
    pub fn router(self) -> Router {
        Router::new()
            .route(WELL_KNOWN_PATH, get(agent_card))
            // Unauthenticated like the well-known card, and for the same
            // reason: a card a caller must already be trusted to read is a card
            // that cannot be discovered.
            .route("/agents/{agent}/agent-card.json", get(one_agent_card))
            .route("/a2a", post(rpc))
            .route("/a2a/", post(rpc))
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
            PolicyDecision::Deny { reason } => {
                // The determining policy and its reason stay operator-side. A
                // Cedar denial names the action, the resource, and the policy
                // ids that fired; returned to an external caller that is a
                // probe-able map of the authorization vocabulary. A decline
                // carries no reason on the wire — the runtime's own denial
                // already names the action and resource the gate keyed on. The
                // caller learns only that it was declined; the reason reaches
                // whoever runs the plane.
                tracing::warn!(
                    target: "agentplane::a2a",
                    action,
                    resource,
                    reason,
                    "A2A request denied at admission"
                );
                Err(RpcError::new(
                    code::INVALID_REQUEST,
                    "this request was not permitted",
                ))
            }
        }
    }

    fn permits(&self, caller: &Caller, action: &str, resource: &str) -> bool {
        let context = json!({
            "roles": caller.roles,
            "peer": caller.actor,
            "tenant": caller.tenant.as_str(),
        });
        matches!(
            self.policy.authorize(&PolicyRequest {
                principal: &caller.actor,
                action,
                resource,
                context: &context,
            }),
            PolicyDecision::Permit
        )
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

impl A2aPushWorker {
    /// How many consecutive failures a receiver gets before it is abandoned.
    ///
    /// The delivery loop's own default, named here too because it is part of
    /// this type's contract and a reader should not have to follow a link to
    /// find out what happens to a webhook that stops answering.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = crate::push::DeliveryWorker::DEFAULT_MAX_ATTEMPTS;

    /// Change the ceiling above.
    ///
    /// Zero is refused, for the reason [`WitnessQuorum`] refuses an empty
    /// quorum: it would spell *never deliver anything* as if it were a retry
    /// policy.
    ///
    /// # Panics
    ///
    /// If `attempts` is zero.
    ///
    /// [`WitnessQuorum`]: crate::journal::WitnessQuorum
    #[must_use]
    pub fn max_attempts(self, attempts: u32) -> Self {
        Self {
            inner: self.inner.max_attempts(attempts),
        }
    }

    /// Deliver at most `limit` due registrations once.
    ///
    /// `at` is Unix time in seconds and is explicit to make backoff tests
    /// deterministic. The operator owns scheduling and the clock.
    /// Multiple workers may race and produce duplicates, which A2A receivers
    /// must tolerate; cursor updates use monotonic advancement, so they cannot
    /// lose an event.
    ///
    /// Rows belonging to an operator [`Outbox`](crate::push::Outbox) are left
    /// alone: they share this store, and delivering one with the A2A projection
    /// would post a `StreamResponse` to a deployment's own bus.
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::core::StoreError) when the push store or a
    /// journal cannot be read.
    pub async fn run_once(
        &self,
        at: u64,
        limit: usize,
    ) -> Result<PushSweepReport, crate::core::StoreError> {
        self.inner.run_once(at, limit).await
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

/// One agent's own card.
///
/// A 404 for an unknown name, deliberately naming nothing: the directory
/// extension on the well-known card is how a caller learns which names exist,
/// and answering an unknown one with the list would make this path a way to
/// enumerate a plane without reading the card that governs it.
async fn one_agent_card(
    State(server): State<A2aServer>,
    axum::extract::Path(agent): axum::extract::Path<String>,
) -> Response {
    server.per_agent.get(&agent).map_or_else(
        || (StatusCode::NOT_FOUND, "no such agent on this plane").into_response(),
        |card| Json(card.clone()).into_response(),
    )
}

async fn rpc(
    State(server): State<A2aServer>,
    headers: HeaderMap,
    body: Result<Json<RpcRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(req)) => req,
        // The two refusals are different spec rows and must not share a code:
        // a body that is not `application/json` is `ContentTypeNotSupported`
        // (-32005) in A2A's own mapping table, while a body that *claims* JSON
        // and is not is JSON-RPC's ParseError. Collapsing them tells a caller
        // with a wrong header that its serializer is broken.
        Err(rejection) => {
            let error = match &rejection {
                axum::extract::rejection::JsonRejection::MissingJsonContentType(_) => {
                    RpcError::new(
                        code::CONTENT_TYPE_NOT_SUPPORTED,
                        "the request body must be application/json",
                    )
                }
                _ => RpcError::new(code::PARSE_ERROR, "the request body is not valid JSON-RPC"),
            };
            return error.into_response();
        }
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
    let params = parse_params(&req.method, &req.params)?;
    server.check_tenant(&params)?;
    if req.method == method::SEND_STREAMING
        && let Some(configuration) = &params.configuration
    {
        configuration.validate()?;
    }

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
        message.validate_parts()?;
        if message.task_id.is_some() {
            continue_task(&server, &headers, &message).await?
        } else {
            let skill = resolve_skill(&server, &message)?;
            let caller = server.gate(&headers, action::MESSAGE_SEND, &skill).await?;
            if let Some(push) = params
                .configuration
                .as_ref()
                .and_then(|configuration| configuration.task_push_notification_config.as_ref())
            {
                validate_inline_push(&server, &headers, &skill, push).await?;
            }
            // Admitted before the stream opens. A stream that begins and *then*
            // reports a refusal has already told the client the work started —
            // and an SSE body cannot carry a JSON-RPC error the client is looking
            // for at that point.
            let input = Tainted::from_source(
                message.to_input(),
                SourceId::new(format!("peer:{}", caller.actor)),
            );
            match spawn_a2a(&server, &skill, input, &message).await {
                Ok(run) => {
                    if let Some(push) = params.configuration.as_ref().and_then(|configuration| {
                        configuration.task_push_notification_config.as_ref()
                    }) {
                        register_push(&server, push, run, 1).await?;
                    }
                    run
                }
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
        }
    };

    let Some((task, case, from)) = super::a2a_stream::current(&server.runtime, run).await else {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {run}"),
        ));
    };
    // `closes` and not a second `matches!` with the same four states: this
    // decides whether a subscription is *refused*, and `closes` decides whether
    // a stream *ends*. Two spellings of one rule disagree the day somebody adds
    // a terminal state to one of them, and the result is either a subscription
    // accepted that shuts immediately or one refused that would have streamed.
    if req.method == method::SUBSCRIBE && super::a2a_stream::closes(task.status.state) {
        return Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "SubscribeToTask requires a non-terminal task",
        ));
    }

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
    let params = parse_params(&req.method, &req.params)?;
    server.check_tenant(&params)?;

    match req.method.as_str() {
        method::SEND_MESSAGE => send_message(server, headers, params).await,
        method::GET_TASK => get_task(server, headers, params).await,
        method::CANCEL_TASK => cancel_task(server, headers, params).await,
        method::GET_EXTENDED_CARD => get_extended_card(server, headers).await,

        // Streaming is handled before dispatch; reaching here means the router
        // changed and this arm did not.
        method::SEND_STREAMING | method::SUBSCRIBE => Err(RpcError::new(
            code::INTERNAL_ERROR,
            "a streaming method reached the non-streaming dispatcher",
        )),
        method::LIST_TASKS => list_tasks(server, headers, &params).await,
        method::CREATE_PUSH => push_create(server, headers, &params).await,
        method::GET_PUSH => push_get(server, headers, &params).await,
        method::LIST_PUSH => push_list(server, headers, &params).await,
        method::DELETE_PUSH => push_delete(server, headers, &params).await,
        other => Err(RpcError::new(
            code::METHOD_NOT_FOUND,
            format!("no such A2A method: {other}"),
        )),
    }
}

/// Which parameter names each method actually reads.
///
/// `tenant` is on every row rather than special-cased: A2A's routing identifier
/// is orthogonal to the method, and leaving it out of one row would refuse a
/// correctly-routed request for that method alone — the kind of hole a table
/// exists to make visible.
const FIELDS_BY_METHOD: &[(&str, &[&str])] = &[
    (
        method::SEND_MESSAGE,
        &["tenant", "message", "configuration", "metadata"],
    ),
    (
        method::SEND_STREAMING,
        &["tenant", "message", "configuration", "metadata"],
    ),
    (method::GET_TASK, &["tenant", "id", "historyLength"]),
    (method::CANCEL_TASK, &["tenant", "id"]),
    (method::SUBSCRIBE, &["tenant", "id"]),
    (method::GET_EXTENDED_CARD, &["tenant"]),
    (
        method::LIST_TASKS,
        &[
            "tenant",
            "contextId",
            "status",
            "pageSize",
            "pageToken",
            "historyLength",
            "statusTimestampAfter",
            "includeArtifacts",
        ],
    ),
    (
        method::CREATE_PUSH,
        &["tenant", "taskId", "id", "url", "token", "authentication"],
    ),
    (method::GET_PUSH, &["tenant", "taskId", "id"]),
    (
        method::LIST_PUSH,
        &["tenant", "taskId", "pageSize", "pageToken"],
    ),
    (method::DELETE_PUSH, &["tenant", "taskId", "id"]),
];

fn parse_params(method: &str, value: &Value) -> Result<CommonParams, RpcError> {
    if value.is_null() {
        return Ok(CommonParams::default());
    }
    let Some(object) = value.as_object() else {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "A2A method parameters must be a JSON object",
        ));
    };

    // Before deserializing, because the union struct would accept the field and
    // the method would then ignore it. An unknown method falls through to the
    // dispatcher's own `METHOD_NOT_FOUND`, which is a better answer than a
    // parameter complaint about a method that does not exist.
    if let Some((_, allowed)) = FIELDS_BY_METHOD.iter().find(|(m, _)| *m == method)
        && let Some(stray) = object.keys().find(|k| !allowed.contains(&k.as_str()))
    {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            format!(
                "'{stray}' is not a parameter of {method}; it takes {}",
                allowed.join(", ")
            ),
        ));
    }

    serde_json::from_value(value.clone()).map_err(|error| {
        RpcError::new(
            code::INVALID_PARAMS,
            format!("request parameters do not match the A2A method schema: {error}"),
        )
    })
}

/// Continue one interrupted A2A task with a client message.
///
/// The run remains append-only: the message becomes the output of the exact
/// `event.await` effect on which the task stopped, then ordinary resume replay
/// carries execution forward. `EventStore::deliver_to` is task-addressed and
/// atomic, so another run sharing the same business correlation key cannot
/// consume this message.
async fn continue_task(
    server: &A2aServer,
    headers: &HeaderMap,
    message: &A2aMessage,
) -> Result<RunId, RpcError> {
    let raw = message
        .task_id
        .as_deref()
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`taskId` is required"))?;
    let run = RunId::parse(raw)
        .map_err(|_| RpcError::new(code::TASK_NOT_FOUND, format!("no such task: {raw}")))?;
    let caller = server
        .gate(headers, action::TASK_CONTINUE, &run.to_string())
        .await?;
    let records = server
        .runtime
        .journal()
        .read(run, 1)
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the journal could not be read"))?;
    let Some(last) = records.last() else {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {run}"),
        ));
    };
    if matches!(
        last.kind(),
        RecordKind::RunSuspended {
            reason: crate::core::SuspendReason::AwaitingTime { .. }
        }
    ) {
        return Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "this task is sleeping until a timer fires and cannot accept input",
        ));
    }
    if !matches!(
        last.kind(),
        RecordKind::RunSuspended { .. } | RecordKind::RunSealed { .. }
    ) {
        return Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "this task is not waiting for input",
        ));
    }
    // Search history rather than only the last record so a transport retry of
    // the message that completed a task can still be recognized as the same
    // `(source, messageId)` and return the current task instead of a spurious
    // terminal-task error. A different message id finds no live subscription
    // and remains refused.
    let (kind, correlation) = records
        .iter()
        .rev()
        .find_map(|record| match record.kind() {
            RecordKind::RunSuspended {
                reason:
                    crate::core::SuspendReason::AwaitingEvent {
                        kind, correlation, ..
                    },
            } => Some((kind.clone(), correlation.clone())),
            _ => None,
        })
        .ok_or_else(|| {
            RpcError::new(
                code::UNSUPPORTED_OPERATION,
                "this task has no input wait to continue",
            )
        })?;
    let context = records
        .iter()
        .find_map(|record| record.body.case.map(|case| case.to_string()));
    if let Some(sent) = message.context_id.as_deref()
        && context.as_deref() != Some(sent)
    {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "message.contextId does not match the referenced task",
        ));
    }

    let event = crate::core::InboundEvent {
        source: format!("a2a:peer:{}", caller.actor),
        id: message.message_id.clone(),
        kind,
        correlation,
        payload: message.to_input(),
    };
    match server.runtime.deliver_to(run, &event).await {
        Ok(crate::core::Delivery::Resumed { .. } | crate::core::Delivery::Duplicate) => Ok(run),
        Ok(crate::core::Delivery::Buffered) => Err(RpcError::new(
            code::INTERNAL_ERROR,
            "targeted task input was unexpectedly buffered",
        )),
        Err(crate::core::RuntimeError::PlanContract(_)) => Err(RpcError::new(
            code::UNSUPPORTED_OPERATION,
            "this task is no longer waiting for input",
        )),
        Err(error) => Err(RpcError::new(code::INTERNAL_ERROR, error.to_string())),
    }
}

#[allow(clippy::too_many_lines)]
async fn send_message(
    server: &A2aServer,
    headers: &HeaderMap,
    params: CommonParams,
) -> Result<Value, RpcError> {
    if let Some(configuration) = &params.configuration {
        configuration.validate()?;
    }
    let inline_push = params
        .configuration
        .as_ref()
        .and_then(|configuration| configuration.task_push_notification_config.clone());
    let Some(message) = params.message else {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "`message` is required by SendMessage",
        ));
    };
    message.validate_parts()?;
    if message.task_id.is_some() {
        let history_length = params
            .configuration
            .as_ref()
            .and_then(|configuration| configuration.history_length);
        let run = continue_task(server, headers, &message).await?;
        return get_task(
            server,
            headers,
            CommonParams {
                id: Some(run.to_string()),
                history_length,
                ..CommonParams::default()
            },
        )
        .await
        .map(|task| json!({ "task": task }));
    }
    let skill = resolve_skill(server, &message)?;
    let caller = server.gate(headers, action::MESSAGE_SEND, &skill).await?;
    if let Some(push) = &inline_push {
        validate_inline_push(server, headers, &skill, push).await?;
    }

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
        return match spawn_a2a(server, &skill, input, &message).await {
            Ok(run) => {
                if let Some(push) = &inline_push {
                    register_push(server, push, run, 1).await?;
                }
                let case = task_context(server, run).await?;
                Ok(json!({
                    "task": task_of(run, TaskState::Working, "accepted", case)
                }))
            }
            Err(crate::core::RuntimeError::PolicyDenied(_)) => {
                Ok(json!({ "message": declined(&skill) }))
            }
            Err(crate::core::RuntimeError::QuotaExceeded(why)) => {
                Err(RpcError::new(code::UNSUPPORTED_OPERATION, why.to_string()))
            }
            Err(crate::core::RuntimeError::PlanContract(why)) if message.context_id.is_some() => {
                Err(RpcError::new(code::TASK_NOT_FOUND, why))
            }
            Err(e) => Err(RpcError::new(code::INTERNAL_ERROR, e.to_string())),
        };
    }

    let outcome = match run_a2a(server, &skill, input, &message).await {
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
        Err(crate::core::RuntimeError::PlanContract(why)) if message.context_id.is_some() => {
            return Err(RpcError::new(code::TASK_NOT_FOUND, why));
        }
        Err(e) => return Err(RpcError::new(code::INTERNAL_ERROR, e.to_string())),
    };

    let case = task_context(server, outcome.run_id).await?;
    // A declared `Message` reply answers the blocking send directly — A2A's
    // response is a oneof for exactly this, and it is the only path with a
    // caller still waiting to hand a message to. Returned before push
    // registration, because a response with no task has no task to push about;
    // the run and its journal exist either way.
    if matches!(outcome.status, crate::runtime::RunStatus::Succeeded)
        && let Some(reply) = outcome.output.as_ref().and_then(A2aReply::of_output)
        && let Some(parts) = reply.message_parts()
    {
        return Ok(json!({
            "message": A2aMessage {
                message_id: format!("reply-{}", outcome.run_id),
                role: "ROLE_AGENT".to_owned(),
                parts,
                context_id: case,
                task_id: None,
                metadata: None,
                extensions: Vec::new(),
                reference_task_ids: Vec::new(),
            }
        }));
    }
    if let Some(push) = &inline_push {
        register_push(server, push, outcome.run_id, 1).await?;
    }
    let mut task = task_of_outcome(&outcome);
    task.context_id = case;
    if let Some(history_length) = params
        .configuration
        .as_ref()
        .and_then(|configuration| configuration.history_length)
    {
        let records = server
            .runtime
            .journal()
            .read(outcome.run_id, 1)
            .await
            .map_err(|_| {
                RpcError::new(code::INTERNAL_ERROR, "the task journal could not be read")
            })?;
        task.history = task_history(
            outcome.run_id,
            &records,
            Some(history_length),
            task.context_id.as_deref(),
        );
    }
    Ok(json!({ "task": task }))
}

async fn run_a2a(
    server: &A2aServer,
    skill: &str,
    input: Tainted<Value>,
    message: &A2aMessage,
) -> Result<crate::runtime::RunOutcome, crate::core::RuntimeError> {
    if let Some(context) = message.context_id.as_deref() {
        let case = crate::core::CaseId::parse(context).map_err(|_| {
            crate::core::RuntimeError::PlanContract("contextId is not a case issued here".into())
        })?;
        return server.runtime.run_in_case(skill, input, case).await;
    }
    // Always correlated: `A2aServer::new` refuses a runtime without a case
    // layer, so every task gets a real, continuable context — the contextId
    // returned is one a client can send back, not a string that satisfies a
    // schema and continues nothing.
    server
        .runtime
        .run_correlated(
            skill,
            input,
            "a2a.context",
            &[crate::core::CorrelationKey::new(
                "a2a-message",
                message.message_id.clone(),
            )],
        )
        .await
}

async fn spawn_a2a(
    server: &A2aServer,
    skill: &str,
    input: Tainted<Value>,
    message: &A2aMessage,
) -> Result<RunId, crate::core::RuntimeError> {
    if let Some(context) = message.context_id.as_deref() {
        let case = crate::core::CaseId::parse(context).map_err(|_| {
            crate::core::RuntimeError::PlanContract("contextId is not a case issued here".into())
        })?;
        return server.runtime.spawn_in_case(skill, input, case).await;
    }
    // Always correlated, for the reason `run_a2a` states.
    server
        .runtime
        .spawn_correlated(
            skill,
            input,
            "a2a.context",
            &[crate::core::CorrelationKey::new(
                "a2a-message",
                message.message_id.clone(),
            )],
        )
        .await
}

async fn task_context(server: &A2aServer, run: RunId) -> Result<Option<String>, RpcError> {
    server
        .runtime
        .journal()
        .read(run, 1)
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the task journal could not be read"))
        .map(|records| {
            records
                .iter()
                .find_map(|record| record.body.case.map(|case| case.to_string()))
        })
}

pub(super) fn task_of_outcome(outcome: &crate::runtime::RunOutcome) -> A2aTask {
    // A declared reply carries its own parts; otherwise the default projection
    // stands — a string is a text part, anything else a data part.
    let artifacts_parts: Vec<Vec<Part>> =
        match outcome.output.as_ref().and_then(A2aReply::of_output) {
            Some(reply) => reply.artifact_parts(),
            None => vec![vec![match outcome
                .output
                .as_ref()
                .map_or(Value::Null, |o| o.peek().clone())
            {
                Value::String(text) => Part::text(text),
                data => Part::data(data),
            }]],
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
            artifacts_parts
                .into_iter()
                .enumerate()
                .map(|(i, parts)| A2aArtifact {
                    artifact_id: format!("{}-result-{i}", outcome.run_id),
                    name: None,
                    description: None,
                    parts,
                    metadata: None,
                    extensions: Vec::new(),
                })
                .collect()
        }),
        history: None,
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

    load_task(server, id, params.history_length).await
}

async fn load_task(
    server: &A2aServer,
    id: RunId,
    history_length: Option<usize>,
) -> Result<Value, RpcError> {
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

    let mut task = task_of(id, state, &detail, case.clone());
    task.history = task_history(id, &records, history_length, case.as_deref());
    task.artifacts = task_artifacts(&server.runtime, id, state)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
    serde_json::to_value(task)
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskCursor {
    updated_at: u64,
    run: String,
    context_id: Option<String>,
    status: Option<TaskState>,
    status_timestamp_after: Option<String>,
}

/// How many index rows `list_tasks` pulls per store round trip.
///
/// Bounded so no path holds the tenant's whole index in memory — which is what
/// the unbounded read this replaced did on *every* call, before going on to
/// read the complete journal of every run it returned.
const TASK_SCAN: usize = 256;

/// Default for [`A2aServer::filter_scan_budget`]: the most candidate journals
/// one content-filtered `ListTasks` may read before being refused as too broad.
///
/// The number is a cost ceiling, not a result limit — results are bounded by
/// `pageSize` already. At the default, the worst request a peer can make costs
/// on the order of a thousand journal reads, once, and is told how to narrow;
/// without it the cost was every run the tenant ever wrote, per request,
/// forever.
const FILTER_SCAN_BUDGET: usize = 1024;

#[allow(clippy::too_many_lines)]
async fn list_tasks(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let caller = server.gate(headers, action::TASK_READ, "tasks").await?;
    let page_size = params.page_size.unwrap_or(50);
    if !(1..=100).contains(&page_size) {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "pageSize must be between 1 and 100",
        ));
    }
    let after = params
        .status_timestamp_after
        .as_deref()
        .map(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .map_err(|_| {
                    RpcError::new(
                        code::INVALID_PARAMS,
                        "statusTimestampAfter must be an RFC 3339 timestamp",
                    )
                })
        })
        .transpose()?;
    let cursor = params
        .page_token
        .as_deref()
        .map(decode_task_cursor)
        .transpose()?;
    if let Some(cursor) = &cursor
        && (cursor.context_id != params.context_id
            || cursor.status != params.status
            || cursor.status_timestamp_after != params.status_timestamp_after)
    {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "pageToken was issued for different ListTasks filters",
        ));
    }

    // Whether the caller asked anything that can only be answered by reading a
    // run's journal. `statusTimestampAfter` is not one of those — it compares
    // against the activity index's own timestamp — and neither is the
    // permission check, which sees only the run id.
    //
    // That split is the whole performance story. The expensive operation is
    // `read`, which pulls a run's complete journal; everything else here is
    // index data the store hands back beside the id. So an unfiltered listing
    // reads exactly the journals that appear on the page, and a content-filtered
    // one reads the candidates it must examine to answer honestly.
    let content_filtered = params.context_id.is_some() || params.status.is_some();

    let mut cursor_pos = cursor
        .as_ref()
        .and_then(|c| RunId::parse(&c.run).ok().map(|run| (c.updated_at, run)));
    let mut page: Vec<(RunId, u64, A2aTask)> = Vec::new();
    let mut matched: u64 = 0;
    let mut has_more = false;
    let mut reads: usize = 0;

    loop {
        let batch = server
            .runtime
            .journal()
            .recent_runs(cursor_pos, TASK_SCAN)
            .await
            .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the task index could not be read"))?;
        if batch.is_empty() {
            break;
        }
        cursor_pos = batch.last().map(|(run, updated)| (*updated, *run));

        for (run, updated) in batch {
            // Both of these read the index only, and the first is load-bearing
            // for more than cost: a run the caller may not read must not reach
            // the total either, or `totalSize` discloses the existence of tasks
            // the policy just refused to show them.
            if !server.permits(&caller, action::TASK_READ, &run.to_string()) {
                continue;
            }
            if after.is_some_and(|cutoff| {
                i64::try_from(updated)
                    .ok()
                    .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
                    .is_none_or(|value| value < cutoff)
            }) {
                continue;
            }

            // Read only when the answer needs it: to evaluate a content filter,
            // or to build a task that will actually be returned.
            let wanted = page.len() < page_size;
            if !content_filtered && !wanted {
                matched += 1;
                has_more = true;
                continue;
            }

            // The ceiling on what one filtered listing may cost. A `status` or
            // `contextId` filter is answerable only by reading the candidate's
            // journal, and the spec's `totalSize` is the exact pre-pagination
            // total — so without a bound, one authenticated request costs every
            // run the tenant ever wrote, which is the scan the paged index
            // exists to prevent. Refused rather than truncated: a total that
            // quietly stopped counting is a smaller tenant, not a bounded scan,
            // and the refusal names the lever that narrows without reading —
            // `statusTimestampAfter` is answered from the index.
            reads += 1;
            if content_filtered && reads > server.filter_scan_budget {
                return Err(RpcError::new(
                    code::INVALID_PARAMS,
                    format!(
                        "this filter would require examining more than {} tasks to answer \
                         exactly — narrow it with statusTimestampAfter and page from there",
                        server.filter_scan_budget
                    ),
                ));
            }
            let records = server.runtime.journal().read(run, 1).await.map_err(|_| {
                RpcError::new(code::INTERNAL_ERROR, "a task journal could not be read")
            })?;
            let task = task_from_records(run, &records, updated, params.history_length);
            if params
                .context_id
                .as_ref()
                .is_some_and(|context| task.context_id.as_ref() != Some(context))
                || params
                    .status
                    .as_ref()
                    .is_some_and(|status| &task.status.state != status)
            {
                continue;
            }
            matched += 1;
            if wanted {
                page.push((run, updated, task));
            } else {
                has_more = true;
            }
        }
    }

    // Exact, and counted over the same rows the caller was allowed to see. The
    // easy mistake is reporting the page's length, which tells every caller the
    // total is whatever fits on a screen; the dangerous one is counting the
    // store's index directly, which is cheaper and reveals the tasks policy
    // just hid.
    let total_size = matched;

    let visible = &page[..];
    let next_page_token = if has_more {
        let (run, updated, _) = visible.last().expect("a page with more has a last item");
        encode_task_cursor(&TaskCursor {
            updated_at: *updated,
            run: run.to_string(),
            context_id: params.context_id.clone(),
            status: params.status,
            status_timestamp_after: params.status_timestamp_after.clone(),
        })?
    } else {
        String::new()
    };
    let mut tasks = Vec::with_capacity(visible.len());
    for (run, _, task) in visible {
        let mut task = task.clone();
        if params.include_artifacts {
            task.artifacts = task_artifacts(&server.runtime, *run, task.status.state)
                .await
                .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
        }
        tasks.push(task);
    }
    Ok(json!({
        "tasks": tasks,
        "nextPageToken": next_page_token,
        "pageSize": page_size,
        "totalSize": total_size,
    }))
}

fn encode_task_cursor(cursor: &TaskCursor) -> Result<String, RpcError> {
    crate::core::canon::to_bytes(cursor)
        .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the task cursor could not be encoded"))
}

fn decode_task_cursor(token: &str) -> Result<TaskCursor, RpcError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "pageToken is not a valid task cursor"))
}

fn task_from_records(
    run: RunId,
    records: &[crate::journal::Record],
    updated: u64,
    history_length: Option<usize>,
) -> A2aTask {
    let (state, detail) = records.last().map_or(
        (TaskState::Working, "unknown".to_owned()),
        |record| match record.kind() {
            RecordKind::RunSuspended { reason } => (TaskState::InputRequired, reason.to_string()),
            RecordKind::RunSealed { outcome, .. } => (sealed_state(outcome), outcome.clone()),
            _ => (TaskState::Working, "running".to_owned()),
        },
    );
    let case = records
        .iter()
        .find_map(|record| record.body.case.map(|case| case.to_string()));
    let timestamp = i64::try_from(updated)
        .ok()
        .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        });
    let history = task_history(run, records, history_length, case.as_deref());
    let mut task = task_of(run, state, &detail, case);
    task.status.timestamp = timestamp;
    task.history = history;
    task
}

fn task_history(
    run: RunId,
    records: &[crate::journal::Record],
    history_length: Option<usize>,
    case: Option<&str>,
) -> Option<Vec<A2aMessage>> {
    history_length.and_then(|limit| {
        if limit == 0 {
            return None;
        }
        let mut history = Vec::new();
        for record in records {
            let input = match record.kind() {
                RecordKind::RunAdmitted { input, .. } => Some(input),
                RecordKind::EffectDone { output, .. } if output.get("$a2a_message").is_some() => {
                    Some(output)
                }
                _ => None,
            };
            let Some(input) = input else { continue };
            if let Some(message) = input.get("$a2a_message")
                && let Ok(mut message) = serde_json::from_value::<A2aMessage>(message.clone())
            {
                message.task_id = Some(run.to_string());
                if message.context_id.is_none() {
                    message.context_id = case.map(ToOwned::to_owned);
                }
                history.push(message);
                continue;
            }
            // Non-A2A admission retained for old/directly-created tasks.
            if history.is_empty() {
                let text = input
                    .get("text")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                let media_type = if text.is_some() {
                    "text/plain"
                } else {
                    "application/json"
                };
                history.push(A2aMessage {
                    message_id: format!("{run}-input"),
                    role: "ROLE_USER".to_owned(),
                    parts: vec![Part {
                        data: text.is_none().then(|| input.clone()),
                        text,
                        raw: None,
                        url: None,
                        filename: None,
                        media_type: Some(media_type.to_owned()),
                        metadata: None,
                    }],
                    context_id: case.map(ToOwned::to_owned),
                    task_id: Some(run.to_string()),
                    metadata: None,
                    extensions: Vec::new(),
                    reference_task_ids: Vec::new(),
                });
            }
        }
        let keep_from = history.len().saturating_sub(limit);
        (!history.is_empty()).then(|| history.split_off(keep_from))
    })
}

pub(super) async fn task_artifacts(
    runtime: &Runtime,
    run: RunId,
    state: TaskState,
) -> Result<Option<Vec<A2aArtifact>>, crate::core::RuntimeError> {
    if state != TaskState::Completed {
        return Ok(None);
    }
    runtime
        .replay(run, crate::runtime::Mode::Strict)
        .await
        .map(|outcome| task_of_outcome(&outcome).artifacts)
}

/// A sealed run's outcome word, as an A2A state.
///
/// The outcome is the same string [`RunStatus::as_str`](crate::runtime::RunStatus::as_str)
/// produces, which is what the executor seals with — so this is [`state_of`]
/// reached through a string, and the two are held to agreement by
/// `a_live_status_and_its_sealed_outcome_agree`.
///
/// The `_` arm is a *wire* decision rather than a modelling shortcut: an A2A
/// client must be told some state, and a word this build cannot interpret is not
/// something it may describe as completed or waiting. It is deliberately **not**
/// how the runtime itself treats an unrecognised outcome — `resume_is_closed`
/// quarantines on one, because refusing to guess is available there and is not
/// available here. The agreement test is what keeps this arm from quietly
/// swallowing a variant somebody added and forgot to map.
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
    serde_json::to_value(task_of(
        id,
        TaskState::Working,
        "cancellation requested",
        None,
    ))
    .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))
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
            metadata: None,
        }],
        context_id: None,
        task_id: None,
        metadata: None,
        extensions: Vec::new(),
        reference_task_ids: Vec::new(),
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
                    metadata: None,
                }],
                context_id: None,
                task_id: Some(run.to_string()),
                metadata: None,
                extensions: Vec::new(),
                reference_task_ids: Vec::new(),
            }),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

fn push_runtime(server: &A2aServer) -> Result<&PushRuntime, RpcError> {
    server.push.as_ref().ok_or_else(push_not_supported_error)
}

fn push_not_supported_error() -> RpcError {
    RpcError::new(
        code::PUSH_NOT_SUPPORTED,
        "this agent does not implement push notifications; its card advertises pushNotifications as false",
    )
}

async fn push_task(server: &A2aServer, raw: Option<&str>) -> Result<RunId, RpcError> {
    let raw = raw.ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`taskId` is required"))?;
    let task = RunId::parse(raw)
        .map_err(|_| RpcError::new(code::TASK_NOT_FOUND, format!("no such task: {raw}")))?;
    let records = server
        .runtime
        .journal()
        .read(task, 1)
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "the journal could not be read"))?;
    if records.is_empty() {
        return Err(RpcError::new(
            code::TASK_NOT_FOUND,
            format!("no such task: {task}"),
        ));
    }
    Ok(task)
}

fn push_request(params: &CommonParams) -> Result<PushRequest, RpcError> {
    let url = params
        .url
        .clone()
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`url` is required"))?;
    Ok(PushRequest {
        id: params.id.clone(),
        task_id: params.push_task.clone(),
        url,
        token: params.token.clone(),
        authentication: params.authentication.clone(),
    })
}

fn validate_push_request(server: &A2aServer, request: &PushRequest) -> Result<(), RpcError> {
    let push = push_runtime(server)?;
    request.validate()?;
    let config = request.config(RunId::generate());
    if let Some(authentication) = &config.authentication {
        authentication
            .validate()
            .map_err(|error| RpcError::new(code::INVALID_PARAMS, error.to_string()))?;
    }
    push.transport
        .validate(&config)
        .map_err(|error| RpcError::new(code::INVALID_PARAMS, error.to_string()))
}

async fn validate_inline_push(
    server: &A2aServer,
    headers: &HeaderMap,
    skill: &str,
    request: &PushRequest,
) -> Result<(), RpcError> {
    if request
        .task_id
        .as_deref()
        .is_some_and(|task| !task.is_empty())
    {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "taskPushNotificationConfig.taskId must be empty in SendMessage",
        ));
    }
    server
        .gate(headers, action::TASK_PUSH, &format!("new:{skill}"))
        .await?;
    validate_push_request(server, request)
}

async fn register_push(
    server: &A2aServer,
    request: &PushRequest,
    task: RunId,
    next_seq: Seq,
) -> Result<crate::push::PushConfig, RpcError> {
    let push = push_runtime(server)?;
    if request
        .task_id
        .as_deref()
        .is_some_and(|configured| !configured.is_empty() && configured != task.to_string())
    {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            "push configuration taskId does not match its task",
        ));
    }
    request.validate()?;
    let config = request.config(task);
    if let Some(authentication) = &config.authentication {
        authentication
            .validate()
            .map_err(|error| RpcError::new(code::INVALID_PARAMS, error.to_string()))?;
    }
    push.transport
        .validate(&config)
        .map_err(|error| RpcError::new(code::INVALID_PARAMS, error.to_string()))?;
    push.store
        .put(&config, next_seq)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
    Ok(config)
}

async fn push_create(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let resource = params.push_task.as_deref().unwrap_or("push");
    server.gate(headers, action::TASK_PUSH, resource).await?;
    push_runtime(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    let request = push_request(params)?;
    let head = server
        .runtime
        .journal()
        .head(task)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
    let tail = server
        .runtime
        .journal()
        .read(task, head.seq)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
    let next_seq = if tail
        .last()
        .is_some_and(|record| matches!(record.kind(), RecordKind::RunSealed { .. }))
    {
        head.seq
    } else {
        head.seq.saturating_add(1)
    };
    Ok(register_push(server, &request, task, next_seq)
        .await?
        .redacted())
}

async fn push_get(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let resource = params.push_task.as_deref().unwrap_or("push");
    server.gate(headers, action::TASK_PUSH, resource).await?;
    let push = push_runtime(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    let id = params
        .id
        .as_deref()
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`id` is required"))?;
    push.store
        .get(task, id)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?
        .map(|config| config.redacted())
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
    let resource = params.push_task.as_deref().unwrap_or("push");
    server.gate(headers, action::TASK_PUSH, resource).await?;
    let push = push_runtime(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    let configs = push
        .store
        .list(task)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
    Ok(json!({
        "configs": configs.iter().map(crate::push::PushConfig::redacted).collect::<Vec<_>>(),
        "nextPageToken": "",
    }))
}

async fn push_delete(
    server: &A2aServer,
    headers: &HeaderMap,
    params: &CommonParams,
) -> Result<Value, RpcError> {
    let resource = params.push_task.as_deref().unwrap_or("push");
    server.gate(headers, action::TASK_PUSH, resource).await?;
    let push = push_runtime(server)?;
    let task = push_task(server, params.push_task.as_deref()).await?;
    let id = params
        .id
        .as_deref()
        .ok_or_else(|| RpcError::new(code::INVALID_PARAMS, "`id` is required"))?;
    push.store
        .delete(task, id)
        .await
        .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?;
    Ok(json!({}))
}

#[cfg(test)]
mod state_agreement_tests {
    use super::{TaskState, sealed_state, state_of};

    /// The same task must not have two states depending on which path a client took.
    ///
    /// `state_of` answers the caller holding the immediate `SendMessage`
    /// response; `sealed_state` answers `GetTask`, `SubscribeToTask` and every
    /// streamed status update. They read the same run.
    ///
    /// The check runs over the crate's one `RunStatus` list, so adding a variant
    /// fails to compile in `state_of` (the match is exhaustive) and, once
    /// somebody maps it there, fails *here* until `sealed_state` is taught the
    /// same answer. That is the ordering the defect needs: the enum decides, the
    /// string agrees. Unifying them the other way — `state_of` delegating to
    /// `sealed_state` — makes both paths return the `_ => Failed` fallback for a
    /// new variant, with nothing to notice, and that is what this test exists to
    /// stop being reintroduced as a tidy-up.
    #[test]
    fn a_live_status_and_its_sealed_outcome_agree() {
        let statuses = crate::runtime::every_status();
        assert_eq!(
            statuses.len(),
            7,
            "a RunStatus variant was added or removed — decide which A2A state it \
             surfaces as, in `state_of` and in `sealed_state` both"
        );
        for status in &statuses {
            assert_eq!(
                state_of(status),
                sealed_state(status.as_str()),
                "'{}' surfaces as one state live and another once sealed",
                status.as_str()
            );
        }
    }

    /// And the mapping is not one answer for everything.
    ///
    /// Without this, `sealed_state` and `state_of` could both be changed to
    /// return `Failed` unconditionally and the agreement test above would pass
    /// perfectly — every A2A client would see every task as failed.
    #[test]
    fn the_mapping_distinguishes_more_than_failure() {
        let seen: std::collections::BTreeSet<_> = crate::runtime::every_status()
            .iter()
            .map(|status| format!("{:?}", state_of(status)))
            .collect();
        assert!(
            seen.len() >= 4,
            "the run-status mapping collapsed to {seen:?}; a client cannot tell \
             completed from cancelled from waiting"
        );
        assert_eq!(
            state_of(&crate::runtime::RunStatus::Succeeded),
            TaskState::Completed
        );
    }
}
