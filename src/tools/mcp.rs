//! MCP as a transport for tool calls.
//!
//! The catalogue in [`super`] decides what a tool is *allowed* to do. This file
//! only carries the call, and its one hard job is to say — for every way a call
//! can fail — whether the request reached the far side.
//!
//! # Why the error mapping is the whole of it
//!
//! [`Disposition`] is what the retry gate reads. Classify a timeout as
//! `DidNotHappen` and a mutating tool gets called twice; classify a rejected
//! request as `InDoubt` and every malformed argument escalates to a human. The
//! transport is the only layer that knows which happened, so getting this table
//! right *is* the integration:
//!
//! | `ServiceError` | Disposition | Why |
//! |---|---|---|
//! | `McpError` (`METHOD_NOT_FOUND`, `INVALID_PARAMS`, `INVALID_REQUEST`, parse, legacy `RESOURCE_NOT_FOUND`) | `DidNotHappen` | the server judged the request unrunnable and declined it; the tool never ran |
//! | `McpError` (anything else) | `InDoubt` | the server errored, possibly mid-execution |
//! | `Timeout` | `InDoubt` | sent, no answer — a timeout is not evidence |
//! | `Cancelled` | `InDoubt` | *we* gave up; the server may still be running it |
//! | `TransportSend`, `TransportClosed` | `InDoubt` | a send that failed partway is indistinguishable from one that never left |
//! | `UnexpectedResponse` | `Landed` | it answered, so it processed |
//! | `SubscriptionLagged`, `InputRequiredRoundsExceeded` | `InDoubt` | the exchange was abandoned mid-flight |
//!
//! Two of those deserve their reasoning stated rather than assumed.
//!
//! **`Cancelled` is not `DidNotHappen`.** Cancelling a request cancels *our*
//! interest in the answer. Whether the server stops executing is entirely up to
//! the server, and for a tool that moves money the honest answer is that we do
//! not know.
//!
//! **`TransportSend` is not `DidNotHappen`.** It is tempting: the send failed, so
//! surely nothing left. But a framed message can fail *partway* through the
//! write, and from here a partial write and a refused connection are the same
//! error. The crate's rule for an error that does not say what it did is to treat
//! it as dangerous, and this is that rule applied.
//!
//! # Annotations are read, recorded, and disobeyed
//!
//! [`McpClient::discover`] returns what each server advertises so it can be put
//! beside the operator's catalogue. It deliberately does not build a catalogue:
//! that would be the server deciding what it is allowed to do, which is the one
//! thing this whole module exists to prevent.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CancelTaskParams, ClientInfo, ErrorCode,
    ExtensionCapabilities, GetPromptRequestParams, GetPromptResponse, GetTaskParams,
    InputResponses, JsonObject, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
    TASKS_EXTENSION_ID, UpdateTaskParams,
};
use rmcp::service::{
    ClientLifecycleMode, ClientServiceExt as _, RoleClient, RunningService, ServiceError,
};
use rmcp::transport::IntoTransport;
use serde_json::Value;

use super::{Advertised, ToolClient, ToolError, ToolId};
use crate::core::{Effect, EffectDescriptor, EffectError, Recovery, Sensitivity, Trust};

/// Data-flow limits for one MCP prompt or resource grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpDataSafety {
    pub max_input_sensitivity: Sensitivity,
    pub output_sensitivity: Sensitivity,
}

impl McpDataSafety {
    #[must_use]
    pub const fn public() -> Self {
        Self {
            max_input_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
        }
    }

    #[must_use]
    pub const fn max_input(mut self, sensitivity: Sensitivity) -> Self {
        self.max_input_sensitivity = sensitivity;
        self
    }

    #[must_use]
    pub const fn output(mut self, sensitivity: Sensitivity) -> Self {
        self.output_sensitivity = sensitivity;
        self
    }
}

/// Operator grants for MCP context capabilities.
///
/// Discovery never populates this value. A server describing a prompt or
/// resource proves that it exists, not that an agent may read it.
#[derive(Debug, Clone, Default)]
pub struct McpAccess {
    prompts: BTreeMap<String, McpDataSafety>,
    resources: BTreeMap<String, McpDataSafety>,
    task_input: Option<McpDataSafety>,
}

impl McpAccess {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn prompt(mut self, name: impl Into<String>, safety: McpDataSafety) -> Self {
        self.prompts.insert(name.into(), safety);
        self
    }

    #[must_use]
    pub fn resource(mut self, uri: impl Into<String>, safety: McpDataSafety) -> Self {
        self.resources.insert(uri.into(), safety);
        self
    }

    /// Permit answering this server's outstanding input requests, up to a
    /// ceiling.
    ///
    /// One grant for the whole server rather than one per task, because a task
    /// id is minted by the server at runtime and an operator cannot review a
    /// name that does not exist yet. Only [`max_input`](McpDataSafety::max_input)
    /// is read — `tasks/update` returns nothing to label.
    ///
    /// Ungranted, `update_task` refuses. That is the same rule prompts and
    /// resources follow and it is the important half here: an elicitation is a
    /// server *asking this plane for data*, which is the direction an operator
    /// most needs to have said yes to.
    #[must_use]
    pub fn task_input(mut self, safety: McpDataSafety) -> Self {
        self.task_input = Some(safety);
        self
    }

    /// Derive this server's access catalogue from one reviewed manifest.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn from_manifest(server: &str, manifest: &crate::manifest::Manifest) -> Self {
        let mut access = Self::new();
        for grant in &manifest.spec.context.prompts {
            if grant.server == server {
                access = access.prompt(
                    grant.name.clone(),
                    McpDataSafety::public()
                        .max_input(grant.max_input_sensitivity)
                        .output(grant.output_sensitivity),
                );
            }
        }
        for grant in &manifest.spec.context.resources {
            if grant.server == server {
                access = access.resource(
                    grant.uri.clone(),
                    McpDataSafety::public().output(grant.output_sensitivity),
                );
            }
        }
        if let Some(grant) = manifest.task_input_grant(server) {
            access =
                access.task_input(McpDataSafety::public().max_input(grant.max_input_sensitivity));
        }
        access
    }
}

/// A connected MCP server.
#[derive(Debug)]
pub struct McpClient {
    /// The name this plane knows the server by.
    ///
    /// Local, not something the server chose: the catalogue keys on it, and a
    /// server able to rename itself could step into another's entry.
    server: String,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
    access: McpAccess,
    /// The whole-request deadline for every call through this client.
    ///
    /// The transport itself waits forever: a wedged server — child process
    /// alive, never answering — would otherwise hang the dispatching step with
    /// nothing journaled and nothing for the sweeper to sweep. Every other
    /// dereference in this crate carries a whole-request timeout; this is MCP
    /// held to the same rule. Expiry is classified through the same table as a
    /// transport timeout: `InDoubt`, because a deadline is not evidence about
    /// what the server did.
    timeout: Duration,
    /// Where this client's transport goes, for the plane's egress allowlist.
    ///
    /// It has to be **declared** rather than derived. The transport is the
    /// caller's — [`new`](Self::new) takes an already-initialised rmcp service
    /// precisely so stdio, a child process and streamable HTTP stay a
    /// deployment's choice — and an initialised `RunningService` does not
    /// disclose the URL it dialled. So this client cannot discover its own
    /// destination, and a control that guessed at one would be worse than the
    /// absent one it replaced.
    destination: crate::tools::Destination,
}

impl McpClient {
    /// The capabilities this host implements.
    ///
    /// Tasks are advertised because task handles and `tasks/get` are surfaced
    /// as journaled effects. Elicitation, sampling, roots, and subscriptions
    /// are deliberately absent: advertising them would invite a server to open
    /// an interaction that has no governed runtime path.
    #[must_use]
    pub fn host_info() -> ClientInfo {
        let mut info = ClientInfo::default();
        // The protocol baseline is pinned here rather than inherited from
        // rmcp's `ClientInfo::default()`, whose `LATEST` constant lags the
        // 2026-07-28 spec this host is written against — the tasks extension
        // and structured tool responses this module relies on are defined
        // there. Pinning also means a future rmcp bump cannot silently move
        // the negotiated dialect in either direction; the wire test asserts
        // the negotiated string byte-for-byte. What this does NOT do is
        // reject a server that negotiates the connection down to an older
        // version — rmcp's handshake accepts the server's answer, and
        // [`new`](Self::new) refuses only a version this host has never heard
        // of, because an unknown dialect cannot even be downgraded to.
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        // The identity a server's logs and allowlists see. rmcp's default
        // names the SDK it was compiled from, which is the wrong party: the
        // server is talking to this plane, not to its HTTP library.
        info.client_info =
            rmcp::model::Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        let mut extensions = ExtensionCapabilities::new();
        extensions.insert(TASKS_EXTENSION_ID.to_owned(), JsonObject::new());
        info.capabilities.extensions = Some(extensions);
        info
    }

    /// Every protocol revision this host knows how to speak.
    ///
    /// Negotiating *down* within this set is the protocol working and stays
    /// legible through [`negotiated_version`](Self::negotiated_version).
    /// Negotiating *outside* it is refused at construction: rmcp deserializes
    /// any string into a version, so without this check a server answering
    /// `2099-01-01` would proceed on a dialect nobody implements — and the
    /// spec's own instruction for an unsupported answer is to disconnect.
    pub const KNOWN_VERSIONS: [ProtocolVersion; 5] = [
        ProtocolVersion::V_2024_11_05,
        ProtocolVersion::V_2025_03_26,
        ProtocolVersion::V_2025_06_18,
        ProtocolVersion::V_2025_11_25,
        ProtocolVersion::V_2026_07_28,
    ];

    /// Open a transport and run the MCP lifecycle this host is written for.
    ///
    /// # Why the lifecycle lives here and not at the caller
    ///
    /// `2026-07-28` replaced the `initialize` handshake with `server/discover`
    /// and per-request metadata, and rmcp answers a plain `initialize` naming
    /// that revision with its newest *legacy* dialect instead. So a caller
    /// that starts the client with `.serve(transport)` negotiates down every
    /// time, silently: `tools/call` keeps working, the tasks extension and
    /// structured results this module is written against simply never appear,
    /// and nothing anywhere names the cause. Three call sites each choosing a
    /// lifecycle are three chances to make that mistake; this method makes it
    /// once.
    ///
    /// The lifecycle is *discover first, legacy fallback*: `server/discover`
    /// preferring `2026-07-28`, and the `initialize` handshake at
    /// `2025-11-25` when the server answers discover with a legacy refusal
    /// or not at all. A downgrade is still the protocol working and stays
    /// readable through [`negotiated_version`](Self::negotiated_version); a
    /// version outside [`KNOWN_VERSIONS`](Self::KNOWN_VERSIONS) is refused
    /// exactly as [`new`](Self::new) refuses it.
    ///
    /// Takes the transport rather than a URL for the reason `new` takes a
    /// running service: dialling is the caller's, and `destination` says what
    /// was dialled. A server that never answers `server/discover` costs the
    /// SDK's ten-second probe before the fallback — the price of a legacy
    /// server that cannot say so.
    ///
    /// # Errors
    ///
    /// [`ToolError::Unreachable`] when neither lifecycle completes, or when
    /// the handshake settled on a version this host does not speak.
    pub async fn connect<T, E, A>(
        server: impl Into<String>,
        transport: T,
        destination: crate::tools::Destination,
    ) -> Result<Self, ToolError>
    where
        T: IntoTransport<RoleClient, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let server = server.into();
        let service = Self::host_info()
            .serve_with_lifecycle(
                transport,
                ClientLifecycleMode::Auto {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                    legacy_version: Some(ProtocolVersion::V_2025_11_25),
                },
            )
            .await
            .map_err(|e| ToolError::Unreachable {
                tool: ToolId::new(&server, "initialize"),
                detail: format!("the MCP server did not initialise: {e}"),
            })?;
        Self::new(server, Arc::new(service), destination)
    }

    /// Wrap an already-initialised rmcp client.
    ///
    /// Taking the running service rather than a connection string keeps every
    /// transport — stdio, a child process, streamable HTTP — a caller's choice.
    /// Prefer [`connect`](Self::connect), which also chooses the lifecycle;
    /// this is for an embedder whose transport is already running.
    ///
    /// # Why the destination is a parameter and not an inference
    ///
    /// That choice is also why `destination` is asked for. This crate never
    /// dereferences an MCP URL: the transport is dialled by the caller, and an
    /// initialised `RunningService` does not disclose the host it reached. So
    /// there is nothing here to parse, and the plane's egress allowlist —
    /// which does set membership on a host — has nothing to judge unless the
    /// wiring says what it dialled.
    ///
    /// A child process or a stdio pipe is
    /// [`Destination::Local`](crate::tools::Destination::Local). A streamable
    /// HTTP connection is
    /// [`Destination::remote(host)`](crate::tools::Destination::remote), and
    /// naming a host other than the one dialled makes the allowlist judge the
    /// wrong string — which is why this is a required argument rather than a
    /// builder method somebody can forget.
    ///
    /// # Errors
    ///
    /// If the handshake settled on a protocol version this host does not
    /// speak. Nothing was called: the refusal exists precisely so that no
    /// request is ever issued in an unknown dialect.
    pub fn new(
        server: impl Into<String>,
        service: Arc<RunningService<RoleClient, ClientInfo>>,
        destination: crate::tools::Destination,
    ) -> Result<Self, ToolError> {
        let server = server.into();
        if let Some(info) = service.peer_info() {
            let negotiated = &info.protocol_version;
            if !Self::KNOWN_VERSIONS.contains(negotiated) {
                return Err(ToolError::Unreachable {
                    tool: ToolId::new(&server, "initialize"),
                    detail: format!(
                        "the server negotiated MCP protocol version '{}', which this \
                         host does not speak — proceeding would issue requests in a \
                         dialect nobody here implements",
                        negotiated.as_str()
                    ),
                });
            }
        }
        Ok(Self {
            server,
            service,
            access: McpAccess::default(),
            timeout: Self::DEFAULT_TIMEOUT,
            destination,
        })
    }

    /// The default whole-request deadline; see the field's reasoning.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

    /// Bound every call through this client by a different deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The protocol version the handshake actually settled on.
    ///
    /// `None` only before the handshake completes, which a constructed client
    /// is past.
    ///
    /// [`host_info`](Self::host_info) *offers* `2026-07-28`, and MCP's
    /// negotiation is a designed downgrade: a server answers with a version it
    /// speaks, and the connection proceeds on that. That is the protocol
    /// working, not a fault — unlike A2A, where a mismatched version is refused
    /// because its negotiation asserts rather than negotiates, so the two are
    /// deliberately not treated alike here.
    ///
    /// What a downgrade does mean is that features defined by the offered
    /// version are simply absent: the tasks extension and structured tool
    /// responses this module is written against. Nothing errors — an older
    /// server answers `tools/call` correctly and just never returns a task —
    /// so the symptom is a long-running tool that behaves synchronously and a
    /// governed suspension that never happens, with nothing anywhere saying
    /// why.
    ///
    /// So the version is readable rather than assumed. `agentplane serve`
    /// prints it beside each wired server, because the declarative tier has no
    /// Rust in which to ask, and an operator who cannot see what was negotiated
    /// cannot know which half of the protocol their server declined.
    #[must_use]
    pub fn negotiated_version(&self) -> Option<String> {
        self.service
            .peer_info()
            .map(|info| info.protocol_version.as_str().to_owned())
    }

    /// Grant exact prompt names and resource URIs this host may retrieve.
    #[must_use]
    pub fn with_access(mut self, access: McpAccess) -> Self {
        self.access = access;
        self
    }

    /// Prepare a governed `prompts/get` effect.
    pub fn prompt(
        &self,
        name: impl Into<String>,
        arguments: Value,
    ) -> Result<McpPrompt, ToolError> {
        let name = name.into();
        let Some(safety) = self.access.prompts.get(&name).copied() else {
            return Err(ToolError::Refused {
                tool: ToolId::new(&self.server, format!("prompt/{name}")),
                detail: "the operator did not grant this MCP prompt".to_owned(),
            });
        };
        if !arguments.is_object() && !arguments.is_null() {
            return Err(ToolError::Refused {
                tool: ToolId::new(&self.server, format!("prompt/{name}")),
                detail: "MCP prompt arguments must be an object or null".to_owned(),
            });
        }
        Ok(McpPrompt {
            server: self.server.clone(),
            name,
            arguments,
            safety,
            service: Arc::clone(&self.service),
            timeout: self.timeout,
        })
    }

    /// Prepare a governed `resources/read` effect.
    pub fn resource(&self, uri: impl Into<String>) -> Result<McpResource, ToolError> {
        let uri = uri.into();
        let Some(safety) = self.access.resources.get(&uri).copied() else {
            return Err(ToolError::Refused {
                tool: ToolId::new(&self.server, format!("resource/{uri}")),
                detail: "the operator did not grant this MCP resource".to_owned(),
            });
        };
        Ok(McpResource {
            server: self.server.clone(),
            uri,
            safety,
            service: Arc::clone(&self.service),
            timeout: self.timeout,
        })
    }

    /// Prepare a journaled poll of an MCP task returned by this server.
    ///
    /// `output_sensitivity` is the declared ceiling for the snapshot this poll
    /// returns — pass the originating tool's declared output sensitivity, the
    /// same value the synchronous `tools/call` answer would have carried. The
    /// poll cannot derive it: a task handle names a server and an id, not the
    /// tool whose result it will eventually deliver.
    pub fn task(
        &self,
        task: McpTask,
        output_sensitivity: Sensitivity,
    ) -> Result<McpTaskPoll, ToolError> {
        self.check_task_server(&task)?;
        Ok(McpTaskPoll {
            task,
            service: Arc::clone(&self.service),
            timeout: self.timeout,
            output_sensitivity,
        })
    }

    /// Prepare a `tasks/update` effect carrying answers to outstanding input
    /// requests. Dispatch it through [`StepCtx::sink`](crate::runtime::StepCtx::sink)
    /// so field labels are checked against the exact responses sent.
    pub fn update_task(
        &self,
        task: McpTask,
        input_responses: InputResponses,
    ) -> Result<McpTaskUpdate, ToolError> {
        self.check_task_server(&task)?;
        let Some(safety) = self.access.task_input else {
            return Err(ToolError::Refused {
                tool: ToolId::new(&self.server, format!("task/{}", task.id)),
                detail: "the operator did not grant this server input responses — an \
                         elicitation is a server asking this plane for data, and nothing \
                         about the server raising one says it may have an answer"
                    .to_owned(),
            });
        };
        // The serialized responses are what `sink_arguments` exposes to the
        // egress gate, while `perform` sends the typed value itself. Falling
        // back to `Null` on a serialization failure would fail *open*: the
        // gate would inspect nothing while the wire carried everything. So a
        // value that cannot be rendered for inspection is refused before any
        // effect exists — nothing was sent, and the refusal says why. This
        // does NOT validate the responses against the server's declared input
        // schema; the server still judges them on `tasks/update`.
        let arguments =
            serde_json::to_value(&input_responses).map_err(|error| ToolError::Refused {
                tool: ToolId::new(&self.server, format!("task/{}", task.id)),
                detail: format!(
                    "the input responses could not be serialized for policy \
                     inspection, so they were not sent: {error}"
                ),
            })?;
        Ok(McpTaskUpdate {
            task,
            input_responses,
            arguments,
            safety,
            service: Arc::clone(&self.service),
            timeout: self.timeout,
        })
    }

    /// Prepare an idempotent cooperative `tasks/cancel` effect.
    pub fn cancel_task(&self, task: McpTask) -> Result<McpTaskCancel, ToolError> {
        self.check_task_server(&task)?;
        Ok(McpTaskCancel {
            task,
            service: Arc::clone(&self.service),
            timeout: self.timeout,
        })
    }

    fn check_task_server(&self, task: &McpTask) -> Result<(), ToolError> {
        if task.server == self.server {
            return Ok(());
        }
        Err(ToolError::Unreachable {
            tool: ToolId::new(&task.server, format!("task/{}", task.id)),
            detail: format!(
                "this client is connected to MCP server '{}', not '{}'",
                self.server, task.server
            ),
        })
    }

    /// What this server says its tools are.
    ///
    /// Returned for comparison against the operator's catalogue, never to build
    /// one. See the module docs.
    ///
    /// # Errors
    ///
    /// If the server cannot be listed.
    pub async fn discover(&self) -> Result<Vec<(ToolId, Advertised)>, ToolError> {
        let listed = bounded(self.timeout, self.service.list_all_tools())
            .await
            .map_err(|e| Self::classify(&ToolId::new(&self.server, "tools/list"), &e))?;

        Ok(listed
            .into_iter()
            .map(|t| {
                let annotations = t.annotations.as_ref();
                (
                    ToolId::new(&self.server, t.name.to_string()),
                    Advertised {
                        read_only: annotations.and_then(|a| a.read_only_hint),
                        destructive: annotations.and_then(|a| a.destructive_hint),
                        idempotent: annotations.and_then(|a| a.idempotent_hint),
                    },
                )
            })
            .collect())
    }

    /// Turn a transport failure into a statement about whether the call landed.
    //
    // The arms below are deliberately not merged, though several share a body.
    // Each is a separate judgement about what a failure implies, and they agree
    // today by coincidence rather than by definition — collapsing them would
    // delete the reasoning and make a future divergence a silent edit.
    #[allow(clippy::match_same_arms)]
    fn classify(tool: &ToolId, e: &ServiceError) -> ToolError {
        let detail = e.to_string();
        match e {
            // The server judged the request unrunnable — unknown method, bad
            // params, unparseable frame, or not a valid request object — and
            // declined it before executing anything. The only genuinely
            // safe-to-repeat class. `RESOURCE_NOT_FOUND` (`-32002`) belongs
            // here because negotiation downgrades: 2026-07-28 folded it into
            // `INVALID_PARAMS`, but a server on an earlier revision still
            // answers a `resources/read` for a URI it does not have with the
            // old code, and the spec tells clients to keep accepting it. Left
            // in the fall-through it reads as *outcome unknown* and a read of
            // a resource that does not exist is retried forever.
            ServiceError::McpError(err)
                if matches!(
                    err.code,
                    ErrorCode::METHOD_NOT_FOUND
                        | ErrorCode::INVALID_PARAMS
                        | ErrorCode::INVALID_REQUEST
                        | ErrorCode::PARSE_ERROR
                        | ErrorCode::RESOURCE_NOT_FOUND
                ) =>
            {
                ToolError::Refused {
                    tool: tool.clone(),
                    detail,
                }
            }
            // Any other protocol error may have arrived mid-execution.
            ServiceError::McpError(_) => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            ServiceError::Timeout { .. } => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            // We stopped waiting. The server did not necessarily stop working.
            ServiceError::Cancelled { .. } => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            // A send that failed partway is indistinguishable from one that
            // never left.
            ServiceError::TransportSend(_) | ServiceError::TransportClosed => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            // It answered, so it processed; the answer was simply not usable.
            ServiceError::UnexpectedResponse => ToolError::Malformed {
                tool: tool.clone(),
                detail,
            },
            // Abandoned mid-exchange.
            _ => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
        }
    }
}

/// A stable asynchronous task handle returned by an MCP operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpTask {
    server: String,
    id: String,
}

impl McpTask {
    /// Parse the result of a tool call that returned `resultType: "task"`.
    pub fn from_result(server: impl Into<String>, value: &Value) -> Result<Self, String> {
        if value.get("resultType").and_then(Value::as_str) != Some("task") {
            return Err("MCP result is not a task handle".to_owned());
        }
        let id = value
            .get("taskId")
            .and_then(Value::as_str)
            .ok_or_else(|| "MCP task handle has no taskId".to_owned())?;
        Ok(Self {
            server: server.into(),
            id: id.to_owned(),
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum McpTaskState {
    Working,
    InputRequired,
    Completed,
    Failed,
    Cancelled,
}

impl McpTaskState {
    fn parse(value: &Value) -> Result<Self, String> {
        match value.get("status").and_then(Value::as_str) {
            Some("working") => Ok(Self::Working),
            Some("input_required") => Ok(Self::InputRequired),
            Some("completed") => Ok(Self::Completed),
            Some("failed") => Ok(Self::Failed),
            Some("cancelled") => Ok(Self::Cancelled),
            Some(other) => Err(format!("unknown MCP task state '{other}'")),
            None => Err("MCP task result has no status".to_owned()),
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct McpTaskSnapshot {
    pub task: McpTask,
    pub state: McpTaskState,
    pub value: Value,
}

impl McpTaskSnapshot {
    /// How many milliseconds from creation the server retains this task, when
    /// it says. A poll loop that sleeps past it finds the task discarded — and
    /// the answer to a discarded id is indistinguishable from "never existed",
    /// so the deadline is worth reading before choosing a cadence.
    #[must_use]
    pub fn ttl_ms(&self) -> Option<u64> {
        self.value.get("ttlMs").and_then(Value::as_u64)
    }

    /// The polling cadence the server asks for, in milliseconds, when it says.
    /// Each poll is a journaled effect; a loop that ignores this hammers the
    /// server and the journal alike.
    #[must_use]
    pub fn poll_interval_ms(&self) -> Option<u64> {
        self.value.get("pollIntervalMs").and_then(Value::as_u64)
    }
}

/// One exact, operator-granted `prompts/get` request.
#[derive(Debug)]
pub struct McpPrompt {
    server: String,
    name: String,
    arguments: Value,
    safety: McpDataSafety,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
    timeout: Duration,
}

#[async_trait]
impl Effect for McpPrompt {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        // The grant's sensitivities are deliberately absent. They are what the
        // operator will *allow*, not what this call asks the server for, and an
        // effect key is what was asked — so a catalogue edit would otherwise
        // recompute a different key for a call that never changed, and every
        // historical run through this prompt would fail its audit replay as
        // divergence. The declaration a replayed value carries is read back
        // from its own record instead; see `core::DeclaredOutput`.
        EffectDescriptor::new(
            "mcp.prompt/get",
            serde_json::json!({
                "server": self.server,
                "name": self.name,
                "arguments": self.arguments,
            }),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.safety.max_input_sensitivity
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.safety.output_sensitivity
    }

    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        let mut params = GetPromptRequestParams::new(&self.name);
        if let Value::Object(arguments) = &self.arguments {
            params = params.with_arguments(arguments.clone());
        }
        match bounded(self.timeout, self.service.get_prompt_once(params)).await {
            Ok(GetPromptResponse::Complete(result)) => serde_json::to_value(result)
                .map_err(|error| EffectError::Other(error.to_string())),
            Ok(GetPromptResponse::InputRequired(_)) => Err(EffectError::Interrupted {
                driver: self.server.clone(),
                detail: "MCP prompt retrieval requested elicitation; this host does not allow a server to open an ungoverned human-input loop"
                    .to_owned(),
            }),
            Ok(_) => Err(EffectError::Interrupted {
                driver: self.server.clone(),
                detail: "MCP prompt retrieval returned an unknown response variant".to_owned(),
            }),
            Err(error) => Err(mcp_effect_error(&self.server, &self.name, &error)),
        }
    }
}

/// One exact, operator-granted `resources/read` request.
#[derive(Debug)]
pub struct McpResource {
    server: String,
    uri: String,
    safety: McpDataSafety,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
    timeout: Duration,
}

#[async_trait]
impl Effect for McpResource {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        // Without the grant's ceiling, for the reason `McpPrompt` states: a
        // reviewed allowance is not part of what a read asks for.
        EffectDescriptor::new(
            "mcp.resource/read",
            serde_json::json!({
                "server": self.server,
                "uri": self.uri,
            }),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.safety.output_sensitivity
    }

    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        match bounded(
            self.timeout,
            self.service
                .read_resource_once(ReadResourceRequestParams::new(&self.uri)),
        )
        .await
        {
            Ok(ReadResourceResponse::Complete(result)) => serde_json::to_value(result)
                .map_err(|error| EffectError::Other(error.to_string())),
            Ok(ReadResourceResponse::InputRequired(_)) => Err(EffectError::Interrupted {
                driver: self.server.clone(),
                detail: "MCP resource retrieval requested elicitation; this host does not allow a server to open an ungoverned human-input loop"
                    .to_owned(),
            }),
            Ok(_) => Err(EffectError::Interrupted {
                driver: self.server.clone(),
                detail: "MCP resource retrieval returned an unknown response variant".to_owned(),
            }),
            Err(error) => Err(mcp_effect_error(&self.server, &self.uri, &error)),
        }
    }
}

/// One journaled `tasks/get` observation.
#[derive(Debug)]
pub struct McpTaskPoll {
    task: McpTask,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
    timeout: Duration,
    /// The ceiling for the snapshot this poll returns.
    ///
    /// A task is a tool call answered later: the completed snapshot carries
    /// the same payload the synchronous path would have returned, so it must
    /// carry the same declared ceiling. Left to the trait default the payload
    /// would arrive `Public` — the asynchronous path quietly declassifying
    /// what the synchronous path protects.
    output_sensitivity: Sensitivity,
}

/// Answers outstanding input requests on an MCP task.
#[derive(Debug)]
pub struct McpTaskUpdate {
    task: McpTask,
    input_responses: InputResponses,
    arguments: Value,
    safety: McpDataSafety,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
    timeout: Duration,
}

#[async_trait]
impl Effect for McpTaskUpdate {
    type Output = ();

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "mcp.task/update",
            serde_json::json!({
                "server": self.task.server,
                "task_id": self.task.id,
                "input_responses": self.input_responses,
            }),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        // The acknowledgement is eventual and does not prove whether the
        // server consumed the responses. Never submit human input twice by
        // guessing after a severed connection.
        Recovery::RequiresOperator
    }

    /// The operator's ceiling for this server, as
    /// [`McpPrompt`] takes for a prompt's arguments. Answering an elicitation
    /// sends data to the same server by the same connection, so a plane that
    /// may hand it internal data one way and not the other is drawing a line
    /// nobody outside could defend.
    ///
    /// What this does **not** relax is the whole-value taint gate below it:
    /// `tasks/update` mutates, and it declares no protected fields, so an
    /// untrusted response is refused whatever this ceiling says. A model's
    /// answer reaches an MCP server through a release or not at all.
    fn max_sensitivity(&self) -> Sensitivity {
        self.safety.max_input_sensitivity
    }

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }

    async fn perform(&self) -> Result<(), EffectError> {
        bounded(
            self.timeout,
            self.service.update_task(UpdateTaskParams::new(
                &self.task.id,
                self.input_responses.clone(),
            )),
        )
        .await
        .map_err(|error| mcp_effect_error(&self.task.server, &self.task.id, &error))
    }
}

/// Cooperative cancellation of an MCP task.
#[derive(Debug)]
pub struct McpTaskCancel {
    task: McpTask,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
    timeout: Duration,
}

#[async_trait]
impl Effect for McpTaskCancel {
    type Output = ();

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "mcp.task/cancel",
            serde_json::json!({"server": self.task.server, "task_id": self.task.id}),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        // SEP-2663 cancellation is cooperative and idempotent. The ack means
        // intent was accepted, not that work has stopped; callers poll to
        // observe the eventual state.
        Recovery::Retry
    }

    async fn perform(&self) -> Result<(), EffectError> {
        bounded(
            self.timeout,
            self.service
                .cancel_task(CancelTaskParams::new(&self.task.id)),
        )
        .await
        .map_err(|error| mcp_effect_error(&self.task.server, &self.task.id, &error))
    }
}

#[async_trait]
impl Effect for McpTaskPoll {
    type Output = McpTaskSnapshot;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "mcp.task/get",
            serde_json::json!({"server": self.task.server, "task_id": self.task.id}),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.output_sensitivity
    }

    async fn perform(&self) -> Result<McpTaskSnapshot, EffectError> {
        let result = bounded(
            self.timeout,
            self.service.get_task(GetTaskParams::new(&self.task.id)),
        )
        .await
        .map_err(|error| mcp_effect_error(&self.task.server, &self.task.id, &error))?;
        let value =
            serde_json::to_value(result).map_err(|error| EffectError::Other(error.to_string()))?;
        let state = McpTaskState::parse(&value).map_err(EffectError::Other)?;
        Ok(McpTaskSnapshot {
            task: self.task.clone(),
            state,
            value,
        })
    }
}

/// Run one MCP request under the client's whole-request deadline.
///
/// Expiry is synthesized as [`ServiceError::Timeout`] so the classification
/// table has exactly one row for "sent, no answer", however the waiting ended.
async fn bounded<T>(
    timeout: Duration,
    call: impl std::future::Future<Output = Result<T, ServiceError>> + Send,
) -> Result<T, ServiceError> {
    match tokio::time::timeout(timeout, call).await {
        Ok(result) => result,
        Err(_) => Err(ServiceError::Timeout { timeout }),
    }
}

fn mcp_effect_error(server: &str, operation: &str, error: &ServiceError) -> EffectError {
    let tool = ToolId::new(server, operation);
    let error = McpClient::classify(&tool, error);
    match error {
        ToolError::Unreachable { .. } | ToolError::Refused { .. } => {
            EffectError::Rejected(error.to_string())
        }
        ToolError::TimedOut { .. } => EffectError::Interrupted {
            driver: server.to_owned(),
            detail: error.to_string(),
        },
        ToolError::Malformed { .. } | ToolError::ToolFailed { .. } => {
            EffectError::Performed(error.to_string())
        }
    }
}

#[async_trait]
impl ToolClient for McpClient {
    async fn call(
        &self,
        tool: &ToolId,
        arguments: &Value,
        provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, ToolError> {
        // A `ToolId` names a server precisely so two servers offering
        // `transfer` stay two tools. This client speaks to exactly one, and
        // until it checked, it executed whatever name it was handed against
        // whatever it was connected to — so a plane granting `tool://ledger/read`
        // and wiring the `tickets` connection got an answer, from the wrong
        // server, under the ledger's operator safety. `Unreachable`, because
        // nothing was attempted and nothing could have been.
        if tool.server != self.server {
            return Err(ToolError::Unreachable {
                tool: tool.clone(),
                detail: format!(
                    "this client is connected to MCP server '{}', not '{}'",
                    self.server, tool.server
                ),
            });
        }
        let object = match arguments {
            Value::Object(map) => Some(map.clone()),
            Value::Null => None,
            other => {
                return Err(ToolError::Refused {
                    tool: tool.clone(),
                    detail: format!(
                        "MCP tool arguments must be a JSON object, got {}",
                        kind_of(other)
                    ),
                });
            }
        };

        let mut params = match object {
            Some(args) => CallToolRequestParams::new(tool.tool.clone()).with_arguments(args),
            None => CallToolRequestParams::new(tool.tool.clone()),
        };

        // `_meta` is where MCP puts caller context, and this is the whole reason
        // the block is signed: the fields let a server correlate, and the
        // signature is what lets it *check* them instead of believing whatever
        // the last hop wrote. Sent under a namespaced prefix because `_meta` is
        // shared with every other extension.
        if let Some(p) = provenance {
            use rmcp::model::RequestParamsMeta;
            params.set_meta(rmcp::model::RequestMetaObject(rmcp::model::MetaObject(
                p.to_meta(),
            )));
        }

        let result = match bounded(self.timeout, self.service.call_tool_once(params))
            .await
            .map_err(|e| Self::classify(tool, &e))?
        {
            CallToolResponse::Complete(result) => result,
            CallToolResponse::Task(task) => {
                // The tool call itself is already journaled. Returning the
                // stable handle lets a coded agent poll it through
                // `McpTaskPoll`, each observation becoming its own effect.
                return serde_json::to_value(task).map_err(|error| ToolError::Malformed {
                    tool: tool.clone(),
                    detail: format!("MCP task handle could not be represented: {error}"),
                });
            }
            CallToolResponse::InputRequired(_) => {
                // The server may already have performed partial work before it
                // asked. This is not a clean refusal. A future governed
                // elicitation bridge must suspend outside this call rather than
                // letting the server open an invisible human loop inside it.
                return Err(ToolError::TimedOut {
                    tool: tool.clone(),
                    detail: "the MCP server requested elicitation, which this host does not advertise or answer inside a tool call"
                        .to_owned(),
                });
            }
            _ => {
                return Err(ToolError::TimedOut {
                    tool: tool.clone(),
                    detail: "the MCP server returned an unknown tool response variant".to_owned(),
                });
            }
        };

        // `isError` means the server ran the tool and the tool failed. That is a
        // landed call: repeating it is a second invocation, whatever it did
        // before it failed.
        if result.is_error == Some(true) {
            return Err(ToolError::ToolFailed {
                tool: tool.clone(),
                detail: render(&result),
            });
        }

        // Structured content when the server provides it, otherwise preserve
        // every protocol block. Flattening to text silently discarded images,
        // audio and resources — a successful multimodal tool call became an
        // empty string, which is corruption rather than graceful degradation.
        // Both forms are labelled untrusted by the effect layer.
        if let Some(structured) = result.structured_content {
            return Ok(structured);
        }
        serde_json::to_value(&result.content).map_err(|error| ToolError::Malformed {
            tool: tool.clone(),
            detail: format!("MCP tool result content could not be represented: {error}"),
        })
    }

    /// What the wiring declared, unchanged.
    fn destination(&self, _tool: &ToolId) -> crate::tools::Destination {
        self.destination.clone()
    }
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn render(result: &rmcp::model::CallToolResult) -> String {
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        return text;
    }
    // A failing tool whose only explanation lives in `structuredContent` (or
    // in non-text blocks) would otherwise report an empty string — an error
    // with nothing after the colon.
    if let Some(structured) = &result.structured_content {
        return structured.to_string();
    }
    serde_json::to_string(&result.content).unwrap_or_default()
}

#[cfg(test)]
mod classify_tests {
    use super::*;
    use crate::core::Disposition;

    /// A legacy server's `-32002` is a judgement, not an unknown outcome.
    ///
    /// The current revision folded resource-not-found into `INVALID_PARAMS`,
    /// but negotiation downgrades by design and an older server still answers
    /// with the old code — which the spec tells clients to keep accepting. In
    /// the in-doubt fall-through, a read of a resource that does not exist
    /// classifies as *may have executed* and is retried under policy forever;
    /// nothing ran, and the honest class is a refusal.
    #[test]
    fn a_legacy_resource_not_found_is_a_refusal_not_an_unknown_outcome() {
        let tool = ToolId::new("kb", "resource/read");
        let error = ServiceError::McpError(rmcp::model::ErrorData::resource_not_found(
            "no such resource",
            None,
        ));
        let classified = McpClient::classify(&tool, &error);
        assert!(
            matches!(classified, ToolError::Refused { .. }),
            "-32002 classified as: {classified}"
        );
        assert_eq!(classified.disposition(), Disposition::DidNotHappen);
    }
}
