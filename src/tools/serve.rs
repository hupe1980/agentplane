//! Serving MCP.
//!
//! This plane's agents as tools, and their reviewed instructions as prompts.
//!
//! The other direction from this crate as an MCP *host*. A host calls in, this
//! plane admits and dispatches through the same funnel an A2A message takes,
//! and the gate stays where it always is — inside effect dispatch. That is what
//! separates serving from the oversight wires, which sit beside work this plane
//! does not execute and can honestly produce only a record.
//!
//! # What is served, and what deliberately is not
//!
//! **Tools** — one per capability a manifest declares. **Prompts** — the
//! reviewed system prompt of each agent that has one.
//!
//! **Resources — the declaration, and nothing that carries a payload.** A
//! resource read is an egress into a model's context, not an operator reading
//! their own journal: sensitivity governs what may leave a *run*, so a read
//! verb that answers for an operator answers the wrong question for a model.
//! The protocol's caching directives compound it — a cached payload is a copy
//! no erasure reaches. A manifest raises neither question: it is the reviewed,
//! content-addressed document `agentplane card` already publishes, served with
//! its digest. Journals, cases and audit reports are not served.
//!
//! # An offered schema is a reviewed artifact, in both directions
//!
//! This crate refuses to consume a server's own tool schemas: the shape a model
//! is offered is the manifest's declaration. Serving holds the same rule from
//! the other end, and enforces it — an agent with no `spec.input` cannot be
//! served, because `Tool::input_schema` is required and the only honest thing
//! to put there is something somebody reviewed.

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;

use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResult, CancelTaskParams, ContentBlock,
    CreateTaskResult, DetailedTask, GetPromptRequestParams, GetPromptResult, GetTaskParams,
    GetTaskResult, Implementation, InitializeResult, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, Prompt, PromptMessage, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, Role,
    ServerCapabilities, Task, TaskPayload, TaskStatus, Tool,
};
use rmcp::model::{CallToolResponse, GetPromptResponse, ReadResourceResponse};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};

use crate::core::RunId;
use crate::core::{RuntimeError, SourceId, Tainted};
use crate::manifest::{Identity, Manifest};
use crate::runtime::{Admission, RunStatus, RunTerms, Runtime};

/// Why a plane could not be served over MCP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServeError {
    /// An agent declares a capability and no argument shape.
    ///
    /// Refused at construction rather than at the first call, because the
    /// alternative is discovering at `tools/list` that a model is being offered
    /// an unreviewed shape — and by then the catalogue has been published.
    #[error(
        "agent '{agent}' provides '{capability}' and declares no `spec.input`, so there is \
         no reviewed argument shape to offer a model. Declare one, or leave the agent off \
         this catalogue"
    )]
    NoInputSchema { agent: String, capability: String },
    /// Two agents offer the same tool name.
    #[error("'{name}' is offered by two agents, so a call to it names no agent in particular")]
    Duplicate { name: String },
    /// A manifest declares a capability this plane has no skill for.
    #[error(
        "agent '{agent}' declares '{capability}' and nothing on this plane provides it, so \
         the tool would be offered to a model and refused at every call"
    )]
    NoProvider { agent: String, capability: String },
    /// The runtime has no [`PolicyEngine`](crate::core::PolicyEngine).
    ///
    /// Refused at build, as the operator API and the A2A server refuse it: a
    /// catalogue offered to any host that connects, admitting runs under no
    /// rule at all, is a plane somebody believes is governed.
    #[error("this plane has no policy engine, so nothing would govern what a host may run")]
    NoPolicy,
    /// The policy engine cannot evaluate a request this surface's runs make.
    ///
    /// A host acts under no chain, so every run this catalogue admits asks
    /// the engine under a context with no identity in it — a shape a plane
    /// holding a chain of its own never builds for itself.
    #[error("the policy set cannot evaluate a run a host admits: {problems}")]
    PolicyUnevaluable { problems: String },
}

/// The `source` every admission this surface makes is keyed under.
///
/// What makes a run this surface's: `tasks/get` and `tasks/cancel` act only on
/// runs whose admission key carries it, so a task id is not a handle on
/// whatever the plane happens to be running.
const ADMISSION_SOURCE: &str = "mcp/client";

/// The request `_meta` key a host sets to make a retried `tools/call` one run.
///
/// The protocol carries no idempotency key of its own, and a JSON-RPC request
/// id is unique only within one session — a host that retries after a lost
/// response sends a new one. A host that wants a retry to be the same call
/// names the call here; the same value answers with the run it already
/// admitted.
///
/// **Within the session that sent it.** This surface authenticates no host, so
/// the session is the only thing that says whose key it is; a key honoured
/// across sessions would hand one host another's run for the price of
/// guessing its key. A host that reconnects before retrying makes a new call.
pub const IDEMPOTENCY_META_KEY: &str = "io.agentplane/idempotencyKey";

/// One agent, as this catalogue offers it.
#[derive(Debug, Clone)]
struct Served {
    /// The capability `run_under` is called with — and the tool's name, because
    /// a second spelling is a second thing to keep in step.
    capability: String,
    agent: String,
    description: Option<String>,
    input_schema: Arc<rmcp::model::JsonObject>,
    output_schema: Option<Arc<rmcp::model::JsonObject>>,
    /// The reviewed instruction, served verbatim. `None` where the agent has
    /// none to serve.
    prompt: Option<String>,
    /// The declaration itself, as the canonical JSON its digest covers.
    document: String,
    digest: Option<String>,
}

/// This plane, as an MCP server.
///
/// Built from the manifests whose agents are wired into `runtime`; an agent the
/// runtime cannot serve is a build-time refusal rather than a call-time one.
#[derive(Debug)]
pub struct McpServer {
    runtime: Arc<Runtime>,
    served: Vec<Served>,
    /// This session, so neither a request id nor a host's key collides with
    /// another session's.
    ///
    /// Minted per value, and **fresh on every clone**: a transport serving
    /// several sessions clones the server once per session, and a clone that
    /// copied the id would key two hosts' calls into one run — the second
    /// host handed the first one's output.
    session: String,
}

impl Clone for McpServer {
    fn clone(&self) -> Self {
        Self {
            runtime: Arc::clone(&self.runtime),
            served: self.served.clone(),
            session: RunId::generate().to_string(),
        }
    }
}

impl McpServer {
    /// Offer these agents.
    ///
    /// # Errors
    ///
    /// [`ServeError::NoPolicy`] for a runtime with no policy engine,
    /// [`ServeError::PolicyUnevaluable`] for one whose rules cannot evaluate a
    /// run admitted under no chain,
    /// [`ServeError::NoInputSchema`] for an agent with no reviewed argument
    /// shape, and [`ServeError::Duplicate`] where two agents would answer to
    /// one tool name.
    pub fn new(runtime: Arc<Runtime>, manifests: &[Manifest]) -> Result<Self, ServeError> {
        if runtime.policy().is_none() {
            return Err(ServeError::NoPolicy);
        }
        let problems = runtime.served_policy_problems();
        if !problems.is_empty() {
            return Err(ServeError::PolicyUnevaluable {
                problems: problems.join("; "),
            });
        }
        let mut served: Vec<Served> = Vec::new();
        for manifest in manifests {
            // The description a model reads is the *reviewed* one: `role` is
            // "what the agent is for, in one line", declared in the manifest and
            // covered by its digest. Anything composed here would be this crate
            // putting words in an agent's mouth that no reviewer saw.
            let identity = manifest.spec.identity.as_ref();
            let description = identity.map(|i| i.role.clone());
            let prompt = identity
                .map(Identity::system_prompt)
                .filter(|p| !p.trim().is_empty());
            for capability in &manifest.spec.capabilities.provides {
                let Some(schema) = manifest.input_schema() else {
                    return Err(ServeError::NoInputSchema {
                        agent: manifest.metadata.name.clone(),
                        capability: capability.clone(),
                    });
                };
                if served.iter().any(|s| &s.capability == capability) {
                    return Err(ServeError::Duplicate {
                        name: capability.clone(),
                    });
                }
                // Refused here rather than at the first call. A catalogue is
                // published once and read by a model that cannot tell an
                // unwired capability from a working one — it composes a call,
                // the call fails at admission, and the error names the plane
                // instead of the declaration that offered it.
                if !runtime.provides(capability) {
                    return Err(ServeError::NoProvider {
                        agent: manifest.metadata.name.clone(),
                        capability: capability.clone(),
                    });
                }
                served.push(Served {
                    document: serde_json::to_string_pretty(manifest)
                        .unwrap_or_else(|_| String::new()),
                    digest: manifest.digest().ok().map(crate::core::Digest::to_hex),
                    capability: capability.clone(),
                    agent: manifest.metadata.name.clone(),
                    description: description.clone(),
                    input_schema: Arc::new(object(schema)),
                    output_schema: manifest.output_schema().map(|s| Arc::new(object(s))),
                    prompt: prompt.clone(),
                });
            }
        }
        Ok(Self {
            runtime,
            served,
            session: RunId::generate().to_string(),
        })
    }

    fn find(&self, name: &str) -> Option<&Served> {
        self.served.iter().find(|s| s.capability == name)
    }

    /// The admission key for one call: the host's own, when it named one, or
    /// the request id — either one scoped to this session.
    fn admission_key(
        &self,
        request: &CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> String {
        let named = request
            .meta
            .as_ref()
            .and_then(|meta| meta.get(IDEMPOTENCY_META_KEY))
            .or_else(|| context.meta.get(IDEMPOTENCY_META_KEY))
            .and_then(serde_json::Value::as_str)
            .filter(|key| !key.trim().is_empty());
        let id = named.map_or_else(
            || format!("request:{}/{}", self.session, context.id),
            |key| format!("host:{}/{key}", self.session),
        );
        crate::core::origin_key(ADMISSION_SOURCE, &id)
    }

    /// The run a task id names, if this surface admitted it.
    ///
    /// A run another surface admitted — a peer's A2A task, the embedder's own
    /// — answers exactly as one that does not exist.
    async fn our_run(
        &self,
        task_id: &str,
    ) -> Result<(RunId, Vec<crate::journal::Record>), McpError> {
        let run =
            RunId::parse(task_id).map_err(|_| McpError::invalid_params("no such task", None))?;
        let records = self
            .runtime
            .journal()
            .read(run, 1)
            .await
            .map_err(|e| internal("reading a task's journal", &e))?;
        if records
            .first()
            .and_then(crate::journal::Record::admission_source)
            != Some(ADMISSION_SOURCE)
        {
            return Err(McpError::invalid_params("no such task", None));
        }
        Ok((run, records))
    }
}

/// A fault on this plane's side, told to the host in one fixed sentence —
/// see [`withheld_fault`](crate::core::withheld_fault).
fn internal(doing: &str, error: &dyn std::fmt::Display) -> McpError {
    McpError::internal_error(crate::core::withheld_fault("mcp", doing, error), None)
}

/// What a finished call answers with, for `tools/call` and `tasks/get` alike.
///
/// Every non-success is `isError`, and the reason is the run's status word —
/// a refusal, an exhausted ceiling and a quarantine are different facts to an
/// operator, and to a calling model they are all *this did not happen*. What
/// must not happen is a failure rendered as an empty success.
fn finished(
    run: RunId,
    status: &RunStatus,
    output: Option<&Tainted<serde_json::Value>>,
) -> CallToolResult {
    match status {
        RunStatus::Succeeded => {
            CallToolResult::structured(output.map_or(serde_json::Value::Null, |o| o.peek().clone()))
        }
        other => CallToolResult::error(vec![ContentBlock::text(format!(
            "run {run} did not succeed: {}",
            other.as_str()
        ))]),
    }
}

/// The URI an agent's declaration is served at.
fn manifest_uri(agent: &str) -> String {
    format!("agentplane://manifest/{agent}")
}

/// A JSON-RPC error object for a task that did not complete.
fn error_object(message: &str) -> rmcp::model::JsonObject {
    let mut out = serde_json::Map::new();
    out.insert("code".to_owned(), serde_json::json!(-32603));
    out.insert("message".to_owned(), serde_json::json!(message));
    out
}

/// The wall clock, for the protocol's own timestamps.
///
/// A `Task` carries ISO 8601 `createdAt` and `lastUpdatedAt` so a client can
/// pace its polling. They are chrome about the *response*, not evidence about
/// the run — what happened and when it happened are journaled as effects, under
/// the run's own clock. So this reads the host clock, and nothing derived from
/// it is ever written down.
#[allow(clippy::disallowed_methods)]
fn protocol_now() -> String {
    crate::core::format_timestamp(crate::core::Timestamp::now_utc())
}

/// A declared schema as the wire's object type.
///
/// What every cacheable result says, and the only thing this plane can stand
/// behind.
///
/// `private`, because everything served derives from an operator's reviewed
/// manifests under one tenant's authority: a shared intermediary holding it for
/// a second principal is a copy no erasure reaches.
///
/// `0` — immediately stale — because a freshness window is a promise to
/// *invalidate*, and nothing here reaches a copy it does not hold. A lifetime
/// this plane cannot honour would be a declared control enforced by the party
/// it binds. Zero says *ask again*, which is true.
const CACHE_SCOPE: CacheScope = CacheScope::Private;
const CACHE_TTL_MS: u64 = 0;

/// Both schemas reached here through `Manifest::validate`, which refuses
/// anything that is not a non-empty object — so the fallback is unreachable and
/// is an empty object rather than a panic, because a catalogue is not worth
/// aborting a process over.
fn object(schema: &serde_json::Value) -> rmcp::model::JsonObject {
    schema.as_object().cloned().unwrap_or_default()
}

impl ServerHandler for McpServer {
    /// **Only the revision this server implements.**
    ///
    /// The SDK's `ProtocolVersion::LATEST` is an *older* revision than the one
    /// this plane is written against, so a server that left this to the default
    /// would advertise every version the SDK knows and negotiate down to
    /// whatever a client offered — silently, with nothing failing. That is the
    /// same downgrade this crate guards against as a client, arriving from the
    /// other side.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![crate::tools::MCP_REVISION])
    }

    /// **Refuse an unsupported revision here, rather than on the next call.**
    ///
    /// A client opening with the legacy `initialize` handshake negotiates in
    /// this method; the SDK's default would answer with this server's own
    /// version and let the session continue, and the refusal would then arrive
    /// on the *first real request* — as a protocol error about a version, long
    /// after the handshake a reader would look at. Refusing at the handshake
    /// puts the failure where its cause is, and names the revision this plane
    /// speaks so the far end can act on it.
    fn initialize(
        &self,
        request: rmcp::model::InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, McpError>> + Send + '_ {
        let supported = self.supported_protocol_versions();
        std::future::ready(if supported.contains(&request.protocol_version) {
            context.peer.set_peer_info(request);
            Ok(self.get_info())
        } else {
            Err(McpError::unsupported_protocol_version(
                request.protocol_version,
                &supported,
            ))
        })
    }

    fn get_info(&self) -> InitializeResult {
        // Tools and prompts only. `resources` is absent rather than empty: a
        // declared capability with nothing behind it is the advisory shape this
        // design refuses everywhere else.
        let mut info = InitializeResult::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                // The Tasks extension, because a governed suspension has no
                // other expression on this wire — and refusing revisions that
                // lack it is only honest if this one declares it.
                .enable_tasks()
                .build(),
        )
        .with_server_info(Implementation::new("agentplane", env!("CARGO_PKG_VERSION")))
        .with_instructions(
            "Each tool runs one governed agent: the call is admitted, journaled and \
             dispatched under the agent's declared authority and budget. A refusal is \
             an answer, not an outage.",
        );
        info.protocol_version = crate::tools::MCP_REVISION;
        info
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult {
            tools: self
                .served
                .iter()
                .map(|s| {
                    let mut tool = Tool::new_with_raw(
                        Cow::Owned(s.capability.clone()),
                        s.description.clone().map(Cow::Owned),
                        Arc::clone(&s.input_schema),
                    );
                    tool.title = Some(s.agent.clone());
                    tool.output_schema.clone_from(&s.output_schema);
                    tool
                })
                .collect(),
            ttl_ms: Some(CACHE_TTL_MS),
            cache_scope: Some(CACHE_SCOPE),
            ..ListToolsResult::default()
        }))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(served) = self.find(&request.name) else {
            return Err(McpError::invalid_params(
                format!("no agent provides '{}'", request.name),
                None,
            ));
        };

        // Untrusted, and named for what composed it. A model's arguments get
        // the same admission any other caller's input gets, which is why the
        // sink gates downstream are not decorative.
        let key = self.admission_key(&request, &context);
        let input = Tainted::from_source(
            serde_json::Value::Object(request.arguments.unwrap_or_default()),
            SourceId::new("mcp://client"),
        );
        // Keyed, so a host's retry of one call is one run; and acting under no
        // chain, because a host on this surface presents none and the plane's
        // own is for the runs its embedder starts.
        let terms = RunTerms::default().once(&key).served(None);
        let admission = match self
            .runtime
            .run_under(&served.capability, input, terms)
            .await
        {
            Ok(admission) => admission,
            // The agent declining is an answer, not an outage, and its reason
            // stays on the operator's side.
            Err(RuntimeError::PolicyDenied(_) | RuntimeError::Delegation(_)) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    "this agent declined the request",
                )])
                .into());
            }
            Err(e) => return Err(internal("admitting a tool call", &e)),
        };

        let outcome = match admission {
            // A retry of a call that already rested. The journal answers what
            // happened, not the value, so a success is re-derived by strict
            // replay — no effect is performed — and the retry gets the answer
            // the first call got rather than an empty success.
            Admission::Replayed(outcome) if matches!(outcome.status, RunStatus::Succeeded) => self
                .runtime
                .replay(outcome.run_id, crate::runtime::Mode::Strict)
                .await
                .map_err(|e| internal("replaying a retried call", &e))?,
            Admission::Fresh(outcome) | Admission::Replayed(outcome) => outcome,
            // The same call is executing right now, here or on another
            // instance: a task the host can poll, never a failure it retries.
            Admission::InFlight(run) => {
                let now = protocol_now();
                return Ok(CreateTaskResult::new(
                    Task::new(run.to_string(), TaskStatus::Working, &now, &now)
                        .with_status_message("already in flight"),
                )
                .into());
            }
        };

        Ok(match outcome.status {
            // A suspension is a task, and the id is the run's own — never a
            // generated handle. See `get_task` for what that buys.
            RunStatus::Suspended(ref why) => {
                let now = protocol_now();
                CreateTaskResult::new(
                    Task::new(outcome.run_id.to_string(), TaskStatus::Working, &now, &now)
                        .with_status_message(why.to_string()),
                )
                .into()
            }
            ref status => finished(outcome.run_id, status, outcome.output.as_ref()).into(),
        })
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListPromptsResult {
            prompts: self
                .served
                .iter()
                .filter(|s| s.prompt.is_some())
                // **No arguments, deliberately.** A declared argument is a
                // string spliced into reviewed text, and the digest then covers
                // bytes nobody approved. The instruction is served as it was
                // reviewed or not at all.
                .map(|s| Prompt::new(s.agent.clone(), s.description.clone(), None))
                .collect(),
            ttl_ms: Some(CACHE_TTL_MS),
            cache_scope: Some(CACHE_SCOPE),
            ..ListPromptsResult::default()
        }))
    }

    /// **Only what carries no labelled payload.**
    ///
    /// One resource per agent: the declaration itself, which is the reviewed,
    /// content-addressed document `agentplane card` already publishes.
    ///
    /// **The line is the kind, not the request.** A resource read is an egress
    /// into a model's context, and a kind may cross only where the runtime can
    /// bound what crosses *without reading it* — where it cannot carry a
    /// caller's payload by construction. Deciding per request would need a
    /// sink gate, and a sink gate needs a declared ceiling for the
    /// destination; a resource read names no agent, so there is none to apply.
    ///
    /// Journals and cases are refused by that rule: records and case state
    /// exist to carry the caller's data. An **audit report** passes it —
    /// identifiers, checkpoints, digests and this runtime's own findings — and
    /// is still not here, which is a different sentence. A model reads a
    /// resource to do its work, and *did this history check out* is an
    /// operator's question asked of `audit` on a store; serving it would buy
    /// reach and no capability, over an artifact that grows with the plane.
    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        let mut seen = std::collections::BTreeSet::new();
        std::future::ready(Ok(ListResourcesResult {
            resources: self
                .served
                .iter()
                .filter(|s| seen.insert(s.agent.clone()))
                .map(|s| {
                    let resource = Resource::new(manifest_uri(&s.agent), s.agent.clone())
                        .with_mime_type("application/json");
                    match &s.description {
                        Some(role) => resource.with_description(role.clone()),
                        None => resource,
                    }
                })
                .collect(),
            ttl_ms: Some(CACHE_TTL_MS),
            cache_scope: Some(CACHE_SCOPE),
            ..ListResourcesResult::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, McpError>> + Send + '_ {
        std::future::ready(
            self.served
                .iter()
                .find(|s| manifest_uri(&s.agent) == request.uri)
                .map_or_else(
                    || {
                        Err(McpError::invalid_params(
                            format!("no resource at '{}'", request.uri),
                            None,
                        ))
                    },
                    |s| {
                        let mut contents =
                            ResourceContents::text(s.document.clone(), request.uri.clone())
                                .with_mime_type("application/json");
                        // The digest travels with the document, so a reader can
                        // say *which* declaration they were shown rather than
                        // only what it said.
                        if let Some(digest) = &s.digest {
                            let mut meta = rmcp::model::MetaObject::new();
                            meta.insert("digest".to_owned(), serde_json::json!(digest));
                            contents = contents.with_meta(meta);
                        }
                        let mut result = ReadResourceResult::new(vec![contents]);
                        result.ttl_ms = Some(CACHE_TTL_MS);
                        result.cache_scope = Some(CACHE_SCOPE);
                        Ok(result.into())
                    },
                ),
        )
    }

    /// **`tasks/get` answers by reading the run.**
    ///
    /// There is no table of tasks. The id a caller holds is the run id, so the
    /// answer comes from the journal — which means it survives a restart,
    /// reads the same from any instance sharing the store, and cannot drift
    /// from what the run actually did. A task table beside the journal would be
    /// a second account of one run, and the first one to go stale would be the
    /// one nobody checks against the records.
    async fn get_task(
        &self,
        request: GetTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        let (run, records) = self.our_run(&request.task_id).await?;

        // A run with records and no conclusion is still working. `None` here is
        // *in flight*, not *unknown*: the records exist, so the run does.
        let status = crate::runtime::observed_status(&records);
        let payload = match &status {
            // The call's own result, as `tools/call` would have answered it:
            // a completed task that hands back an empty object has lost the
            // answer the host suspended for. Recovered by strict replay — the
            // output is a projection of the journal, and nothing is re-run.
            Some(RunStatus::Succeeded) => {
                let outcome = self
                    .runtime
                    .replay(run, crate::runtime::Mode::Strict)
                    .await
                    .map_err(|e| internal("replaying a completed task", &e))?;
                let result =
                    serde_json::to_value(finished(run, &outcome.status, outcome.output.as_ref()))
                        .map_err(|e| internal("encoding a task's result", &e))?;
                TaskPayload::Completed {
                    result: result.as_object().cloned().unwrap_or_default(),
                }
            }
            Some(RunStatus::Cancelled { .. }) => TaskPayload::Cancelled,
            // A suspension is not a conclusion. The run is parked on a timer,
            // an event or somebody's decision, and *working* is what that is to
            // a caller polling it — the alternative reports a run that will
            // finish as one that failed.
            Some(RunStatus::Suspended(_)) | None => TaskPayload::Working,
            // Everything else that has concluded is a failure *to the caller* —
            // exhausted, quarantined, abandoned and failed are four different
            // facts to an operator and one fact to a model: it did not happen.
            // The distinction is not lost, it is in the journal, which is where
            // somebody who can act on it looks.
            Some(other) => TaskPayload::Failed {
                error: error_object(&format!("the run did not succeed: {}", other.as_str())),
            },
        };
        let now = protocol_now();
        Ok(GetTaskResult::new(DetailedTask::new(
            Task::new(request.task_id, TaskStatus::Working, &now, &now),
            payload,
        )))
    }

    /// **`tasks/cancel` is the runtime's own cancellation**, recorded in the
    /// journal and honoured at the next step boundary. Cooperative, as the
    /// specification asks and as this runtime already works: nothing is
    /// interrupted mid-effect.
    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let (run, _) = self.our_run(&request.task_id).await?;
        self.runtime
            // The actor is the *channel*, not a person: an MCP host cancelling
            // the task it started is identified by the connection this runtime
            // accepted and by nothing else. Recorded as `Connected` so a reader
            // is not told a credential named anybody.
            .request_cancel(
                run,
                &crate::core::Operator::connected("mcp://client")
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                "cancelled by the calling host",
            )
            .await
            .map(|_| ())
            .map_err(|e| match e {
                RuntimeError::Store(_) => internal("requesting a cancellation", &e),
                other => McpError::invalid_params(other.to_string(), None),
            })
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, McpError>> + Send + '_ {
        std::future::ready(self.prompt_for(request))
    }
}

impl McpServer {
    /// The reviewed instruction for one agent, or a refusal naming why.
    fn prompt_for(&self, request: GetPromptRequestParams) -> Result<GetPromptResponse, McpError> {
        let Some(served) = self
            .served
            .iter()
            .find(|s| s.agent == request.name && s.prompt.is_some())
        else {
            return Err(McpError::invalid_params(
                format!("no agent named '{}' serves a prompt", request.name),
                None,
            ));
        };
        if request.arguments.is_some_and(|a| !a.is_empty()) {
            return Err(McpError::invalid_params(
                "this prompt takes no arguments: it is a reviewed instruction, and a \
                 value spliced into it would be text nobody approved under a digest that \
                 covers text somebody did",
                None,
            ));
        }
        let text = served.prompt.clone().unwrap_or_default();
        let mut result = GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)]);
        result.description.clone_from(&served.description);
        Ok(result.into())
    }
}
