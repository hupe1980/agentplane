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
//! | `McpError` (`METHOD_NOT_FOUND`, `INVALID_PARAMS`, parse) | `DidNotHappen` | the server parsed the request and declined it; the tool never ran |
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

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CancelTaskParams, ClientInfo, ErrorCode,
    ExtensionCapabilities, GetPromptRequestParams, GetPromptResponse, GetTaskParams,
    InputResponses, JsonObject, ReadResourceRequestParams, ReadResourceResponse,
    TASKS_EXTENSION_ID, UpdateTaskParams,
};
use rmcp::service::{RoleClient, RunningService, ServiceError};
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
        let mut extensions = ExtensionCapabilities::new();
        extensions.insert(TASKS_EXTENSION_ID.to_owned(), JsonObject::new());
        info.capabilities.extensions = Some(extensions);
        info
    }

    /// Wrap an already-initialised rmcp client.
    ///
    /// Taking the running service rather than a connection string keeps every
    /// transport — stdio, a child process, streamable HTTP — a caller's choice.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        service: Arc<RunningService<RoleClient, ClientInfo>>,
    ) -> Self {
        Self {
            server: server.into(),
            service,
            access: McpAccess::default(),
        }
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
        })
    }

    /// Prepare a journaled poll of an MCP task returned by this server.
    pub fn task(&self, task: McpTask) -> Result<McpTaskPoll, ToolError> {
        self.check_task_server(&task)?;
        Ok(McpTaskPoll {
            task,
            service: Arc::clone(&self.service),
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
        let arguments = serde_json::to_value(&input_responses).unwrap_or(Value::Null);
        Ok(McpTaskUpdate {
            task,
            input_responses,
            arguments,
            service: Arc::clone(&self.service),
        })
    }

    /// Prepare an idempotent cooperative `tasks/cancel` effect.
    pub fn cancel_task(&self, task: McpTask) -> Result<McpTaskCancel, ToolError> {
        self.check_task_server(&task)?;
        Ok(McpTaskCancel {
            task,
            service: Arc::clone(&self.service),
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
        let listed = self
            .service
            .list_all_tools()
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
            // The server parsed the request and declined it without running
            // anything. The only genuinely safe-to-repeat class.
            ServiceError::McpError(err)
                if matches!(
                    err.code,
                    ErrorCode::METHOD_NOT_FOUND
                        | ErrorCode::INVALID_PARAMS
                        | ErrorCode::PARSE_ERROR
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

/// One exact, operator-granted `prompts/get` request.
#[derive(Debug)]
pub struct McpPrompt {
    server: String,
    name: String,
    arguments: Value,
    safety: McpDataSafety,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
}

#[async_trait]
impl Effect for McpPrompt {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "mcp.prompt/get",
            serde_json::json!({
                "server": self.server,
                "name": self.name,
                "arguments": self.arguments,
                "max_input_sensitivity": self.safety.max_input_sensitivity,
                "output_sensitivity": self.safety.output_sensitivity,
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
        match self.service.get_prompt_once(params).await {
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
}

#[async_trait]
impl Effect for McpResource {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "mcp.resource/read",
            serde_json::json!({
                "server": self.server,
                "uri": self.uri,
                "output_sensitivity": self.safety.output_sensitivity,
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
        match self
            .service
            .read_resource_once(ReadResourceRequestParams::new(&self.uri))
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
}

/// Answers outstanding input requests on an MCP task.
#[derive(Debug)]
pub struct McpTaskUpdate {
    task: McpTask,
    input_responses: InputResponses,
    arguments: Value,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
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

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }

    async fn perform(&self) -> Result<(), EffectError> {
        self.service
            .update_task(UpdateTaskParams::new(
                &self.task.id,
                self.input_responses.clone(),
            ))
            .await
            .map_err(|error| mcp_effect_error(&self.task.server, &self.task.id, &error))
    }
}

/// Cooperative cancellation of an MCP task.
#[derive(Debug)]
pub struct McpTaskCancel {
    task: McpTask,
    service: Arc<RunningService<RoleClient, ClientInfo>>,
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
        self.service
            .cancel_task(CancelTaskParams::new(&self.task.id))
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

    async fn perform(&self) -> Result<McpTaskSnapshot, EffectError> {
        let result = self
            .service
            .get_task(GetTaskParams::new(&self.task.id))
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

        let result = match self
            .service
            .call_tool_once(params)
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
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}
