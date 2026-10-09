//! Serving MCP: a real client, over a real `rmcp` session, against this plane.
//!
//! In-process over a duplex pipe rather than a fixture, for the reason the
//! consuming side is tested the same way: a hand-written expectation of what a
//! server sends is a test of the author's reading of the specification, and the
//! SDK on the other end is what an adopter actually runs.
//!
//! Four properties carry this file, and each has a failure that looks like
//! success:
//!
//! * **The advertised revision is the one this plane implements.** The SDK's
//!   own `LATEST` is an *older* revision, so a server that left the default
//!   alone would negotiate down to whatever a client offered, silently, with
//!   nothing failing — the downgrade this crate guards against as a client,
//!   arriving from the other side.
//! * **A tool's `inputSchema` is the reviewed one**, so a model composes
//!   arguments against a shape somebody approved under a digest.
//! * **An agent with no declared input cannot be offered at all.** The failure
//!   otherwise is a permissive stand-in that reads, to a model and to a
//!   reviewer, exactly like a declaration.
//! * **A prompt is the reviewed instruction, verbatim, and takes no
//!   arguments.** A value spliced into it is text nobody approved, carried
//!   under the digest of text somebody did.

#![cfg(all(feature = "mcp-server", feature = "redb", feature = "testkit"))]

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::tools::serve::{McpServer, ServeError};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, GetPromptRequestParams, ProtocolVersion};
use serde_json::{Value, json};

const AGENT: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: pattern-compliance-auditor
  version: "2.0.0"
spec:
  identity:
    role: Finds anomalies in a ledger and says which rule each one breaks.
    constraints: Never state a conclusion the evidence does not carry.
  capabilities:
    provides: [audit.anomaly-detection]
  input:
    schema:
      type: object
      additionalProperties: false
      required: [ledger]
      properties:
        ledger:
          type: string
  budgets:
    max_tokens: 120000
    max_steps: 25
"#;

#[derive(Debug)]
struct Auditor;

#[async_trait::async_trait]
impl Skill for Auditor {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("auditor").provides("audit.anomaly-detection")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let ledger = input
            .peek()
            .get("ledger")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(Outcome::done(input.map(|_| json!({ "audited": ledger }))))
    }
}

/// Permits everything: a served plane must be governed, and these tests are
/// about the wire rather than the rules.
#[derive(Debug)]
struct Permit;

impl agentplane::core::PolicyEngine for Permit {
    fn authorize(
        &self,
        _request: &agentplane::core::PolicyRequest<'_>,
    ) -> agentplane::core::PolicyDecision {
        agentplane::core::PolicyDecision::Permit
    }

    fn bundle(&self) -> agentplane::core::PolicyBundleIdentity {
        agentplane::core::PolicyBundleIdentity::new(
            agentplane::core::Digest::of(b"mcp-permit"),
            "agentplane-test/mcp-permit",
        )
    }
}

fn plane() -> Arc<Runtime> {
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn JournalStore>;
    Runtime::builder(store)
        .owner("mcp")
        .policy(Arc::new(Permit))
        .skill(Auditor)
        .build()
}

/// A client that asks for the revision this plane implements.
///
/// Spelled out rather than taking the SDK's default, because the default is an
/// *older* revision — see
/// [`an_older_revision_is_refused_rather_than_negotiated_down`].
#[derive(Debug, Clone, Default)]
struct Caller;

impl rmcp::ClientHandler for Caller {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        let mut info = rmcp::model::ClientConfig::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        // A client that does not declare tasks is one the server may not hand a
        // task handle to, so a caller of a plane whose agents suspend declares
        // it.
        info.capabilities = rmcp::model::ClientCapabilities::builder()
            .enable_tasks()
            .build();
        info
    }
}

fn pipe(server: McpServer) -> (tokio::io::DuplexStream, ()) {
    let (client_side, server_side) = tokio::io::duplex(16 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        // Boxed: the server future carries the catalogue and the runtime handle,
        // which is more than clippy will let sit on a task's stack.
        if let Ok(running) = Box::pin(rmcp::serve_server(server, (sr, sw))).await {
            let _ = running.waiting().await;
        }
    });
    (client_side, ())
}

/// A client talking to this plane over an in-process pipe.
async fn connect(server: McpServer) -> rmcp::service::RunningService<rmcp::RoleClient, Caller> {
    use rmcp::service::{ClientLifecycleMode, ClientServiceExt};

    let (client_side, ()) = pipe(server);
    let (cr, cw) = tokio::io::split(client_side);
    // The **modern** lifecycle: `server/discover` with self-contained
    // per-request metadata. `ServiceExt::serve` is the legacy `initialize`
    // handshake, which is what a client built on the SDK's defaults does — and
    // what the test below asserts this plane refuses.
    Caller
        .serve_with_lifecycle(
            (cr, cw),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("client initialises")
}

/// **A revision older than the ones this plane speaks is refused, not
/// quietly served** — with the supported set in the error, so the far end can
/// tell an unsupported version from an outage.
#[tokio::test]
async fn an_older_revision_is_refused_rather_than_negotiated_down() {
    #[derive(Debug, Clone, Default)]
    struct Old;
    impl rmcp::ClientHandler for Old {
        fn get_info(&self) -> rmcp::model::ClientConfig {
            let mut info = rmcp::model::ClientConfig::default();
            info.protocol_version = ProtocolVersion::V_2025_06_18;
            info
        }
    }

    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let server = McpServer::new(plane(), &[manifest]).expect("served");
    let (client_side, ()) = pipe(server);
    let (cr, cw) = tokio::io::split(client_side);

    let refused = Old.serve((cr, cw)).await;
    let Err(error) = refused else {
        panic!("a client asking for 2025-06-18 was served");
    };
    let said = error.to_string();
    assert!(
        said.contains("2026-07-28") && said.contains("2025-11-25"),
        "the refusal does not name the revisions this plane speaks, so the far end \
         cannot tell an unsupported version from an outage: {said}"
    );
}

const LOOKUP: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: lookup, version: "1.0.0" }
spec:
  identity: { role: Look up a customer record. }
  capabilities: { provides: [crm.lookup] }
  input:
    schema:
      type: object
      additionalProperties: false
      required: [id]
      properties:
        id: { type: string }
  tools:
    - ref: tool://crm/lookup
      mutates: false
      # A served host's arguments arrive `Internal`: they came from outside.
      max_sensitivity: internal
  execution: { kind: call }
  budgets: {}
"#;

/// Answers every call with its arguments.
#[derive(Debug)]
struct Echo;

#[async_trait::async_trait]
impl agentplane::tools::ToolClient for Echo {
    async fn call(
        &self,
        _tool: &agentplane::tools::ToolId,
        arguments: &Value,
        _p: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, agentplane::tools::ToolError> {
        Ok(json!({ "found": arguments }))
    }

    fn destination(&self, _tool: &agentplane::tools::ToolId) -> agentplane::tools::Destination {
        agentplane::tools::Destination::Local
    }
}

/// A coded agent (which may suspend: nothing can see into it) beside a `call`
/// agent (which cannot).
fn mixed_plane() -> (Arc<Runtime>, Vec<Manifest>) {
    let lookup = Manifest::parse(LOOKUP).expect("lookup");
    let auditor = Manifest::parse(AGENT).expect("auditor");
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn JournalStore>;
    let plane = Runtime::builder(store)
        .owner("mcp")
        .policy(Arc::new(Permit))
        .tools(
            Arc::new(agentplane::tools::ToolCatalog::from_manifest(&lookup)),
            Arc::new(Echo) as Arc<dyn agentplane::tools::ToolClient>,
        )
        .agent(agentplane::runtime::Agent::new(&lookup))
        .skill(Auditor)
        .build();
    (plane, vec![lookup, auditor])
}

/// **A host that cannot hold a task is offered only what never needs one.**
///
/// A `2025-11-25` host, and a `2026-07-28` host that does not declare the
/// Tasks extension, are both served — and both see the `call` tool and not
/// the agent that may wait on a person or a timer. Calling that one by name is
/// refused before anything is admitted, naming what the host lacks.
#[tokio::test]
async fn a_host_without_tasks_is_offered_only_tools_that_cannot_suspend() {
    use rmcp::service::{ClientLifecycleMode, ClientServiceExt};

    #[derive(Debug, Clone, Default)]
    struct NoTasks;
    impl rmcp::ClientHandler for NoTasks {
        fn get_info(&self) -> rmcp::model::ClientConfig {
            let mut info = rmcp::model::ClientConfig::default();
            info.protocol_version = ProtocolVersion::V_2026_07_28;
            info
        }
    }

    let (plane, manifests) = mixed_plane();
    let server = McpServer::new(Arc::clone(&plane), &manifests).expect("served");

    let (legacy_side, ()) = pipe(server.clone());
    let (cr, cw) = tokio::io::split(legacy_side);
    let legacy = ().serve((cr, cw)).await.expect("a 2025-11-25 host is served");
    assert_eq!(
        legacy.peer_info().expect("server info").protocol_version,
        ProtocolVersion::V_2025_11_25,
        "the handshake did not settle on the host's revision"
    );

    let (modern_side, ()) = pipe(server);
    let (cr, cw) = tokio::io::split(modern_side);
    let modern = NoTasks
        .serve_with_lifecycle(
            (cr, cw),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("a host without the extension is served");

    for (host, label) in [(legacy.peer(), "2025-11-25"), (modern.peer(), "no tasks")] {
        let names: Vec<String> = host
            .list_all_tools()
            .await
            .expect("tools/list")
            .into_iter()
            .map(|t| t.name.into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["crm.lookup".to_owned()],
            "{label}: a tool that may suspend was offered to a host that cannot hold a task"
        );
        let answer = host
            .call_tool(
                CallToolRequestParams::new("crm.lookup")
                    .with_arguments(json!({ "id": "C-7" }).as_object().cloned().expect("object")),
            )
            .await
            .expect("the call tool answers");
        assert_eq!(
            answer.structured_content,
            Some(json!({ "found": { "id": "C-7" } })),
            "{label}"
        );
        let before = plane
            .journal()
            .recent_runs(None, 10)
            .await
            .expect("index")
            .len();
        let refused = host
            .call_tool(
                CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
                    json!({ "ledger": "GL" })
                        .as_object()
                        .cloned()
                        .expect("object"),
                ),
            )
            .await;
        let said = format!("{refused:?}");
        let Err(rmcp::service::ServiceError::McpError(error)) = refused else {
            panic!("{label}: calling a may-suspend tool by name was not refused: {said}");
        };
        assert_eq!(
            error.code,
            rmcp::model::ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY,
            "{label}: the Tasks extension answers a call it cannot serve without a task \
             with -32021, not as a bad argument: {said}"
        );
        assert!(
            said.contains("io.modelcontextprotocol/tasks"),
            "{label}: the refusal does not name the extension it requires: {said}"
        );
        assert_eq!(
            plane
                .journal()
                .recent_runs(None, 10)
                .await
                .expect("index")
                .len(),
            before,
            "{label}: the refused call admitted a run"
        );
    }
    legacy.cancel().await.expect("shutdown");
    modern.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn the_catalogue_offers_the_reviewed_shape_and_the_reviewed_revision() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let server = McpServer::new(plane(), std::slice::from_ref(&manifest)).expect("served");
    let client = connect(server).await;

    // The revision this plane implements, not whatever the SDK defaults to.
    assert_eq!(
        client.peer_info().expect("server info").protocol_version,
        ProtocolVersion::V_2026_07_28,
        "the server negotiated a revision it was not written against, which is the \
         downgrade a client cannot see"
    );

    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 1, "one capability, one tool");
    let tool = &tools[0];
    assert_eq!(tool.name, "audit.anomaly-detection");
    assert_eq!(
        tool.description.as_deref(),
        Some("Finds anomalies in a ledger and says which rule each one breaks."),
        "the description a model reads must be the reviewed `identity.role`, not one \
         this crate composed"
    );

    // The offered schema is the declared one, byte for byte.
    let offered = serde_json::to_value(&*tool.input_schema).expect("schema");
    assert_eq!(
        offered,
        manifest.input_schema().cloned().expect("declared"),
        "the shape a model composes arguments against is not the shape somebody \
         reviewed under the manifest digest"
    );

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn a_tool_call_runs_the_agent_and_returns_its_answer() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let server = McpServer::new(plane(), &[manifest]).expect("served");
    let client = connect(server).await;

    let result = client
        .call_tool(
            CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
                json!({ "ledger": "GL-2026" })
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await
        .expect("tools/call");

    assert_ne!(
        result.is_error,
        Some(true),
        "the run did not succeed: {result:?}"
    );
    assert_eq!(
        result.structured_content,
        Some(json!({ "audited": "GL-2026" })),
        "the tool returned something other than the run's own output"
    );

    client.cancel().await.expect("shutdown");
}

/// **A plane with no policy engine is not served.**
///
/// A catalogue any connecting host may call, admitting runs under no rule at
/// all, is a plane somebody believes is governed. Refused at build, as the
/// operator API and the A2A server refuse it.
#[test]
fn a_plane_without_a_policy_engine_is_not_served() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn JournalStore>;
    let ungoverned = Runtime::builder(store).owner("mcp").skill(Auditor).build();
    assert_eq!(
        McpServer::new(ungoverned, &[manifest]).err(),
        Some(ServeError::NoPolicy),
        "an ungoverned plane was offered as a tool catalogue"
    );
}

/// **A host's retry of one call is one run.**
///
/// The protocol has no idempotency key and a request id is unique only within
/// a session, so a host that resends a call after losing the response would
/// otherwise run the agent twice — twice the effects, twice the spend. A host
/// that names the call in `_meta` gets the run it already admitted back.
#[tokio::test]
async fn a_retried_call_with_the_same_key_is_one_run() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let plane = plane();
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let client = connect(server).await;

    let call = || {
        let mut meta = rmcp::model::MetaObject::new();
        meta.insert(
            agentplane::tools::serve::IDEMPOTENCY_META_KEY.to_owned(),
            json!("host-call-7"),
        );
        let mut request = CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
            json!({ "ledger": "GL-2026" })
                .as_object()
                .cloned()
                .expect("object"),
        );
        request.meta = Some(rmcp::model::RequestMetaObject(meta));
        request
    };
    let first = client.call_tool(call()).await.expect("first call");
    let second = client.call_tool(call()).await.expect("retried call");
    assert_eq!(first.structured_content, second.structured_content);
    let runs = plane.journal().recent_runs(None, 10).await.expect("index");
    assert_eq!(
        runs.len(),
        1,
        "a retried call admitted a second run: {runs:?}"
    );

    client.cancel().await.expect("shutdown");
}

/// **Two sessions are two callers, whatever their request ids and keys.**
///
/// A server is cloned once per session by an HTTP transport. A request id is
/// unique only within its session, and a host's key is the host's own: two
/// sessions sending the same id — or the same key — are two calls, and the
/// second must not be handed the first one's run.
#[tokio::test]
async fn two_sessions_with_the_same_request_id_and_key_are_two_runs() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let plane = plane();
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let call = |key: Option<&str>| {
        let mut request = CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
            json!({ "ledger": "GL-2026" })
                .as_object()
                .cloned()
                .expect("object"),
        );
        if let Some(key) = key {
            let mut meta = rmcp::model::MetaObject::new();
            meta.insert(
                agentplane::tools::serve::IDEMPOTENCY_META_KEY.to_owned(),
                json!(key),
            );
            request.meta = Some(rmcp::model::RequestMetaObject(meta));
        }
        request
    };

    for key in [None, Some("host-call-7")] {
        let before = plane
            .journal()
            .recent_runs(None, 10)
            .await
            .expect("index")
            .len();
        let a = connect(server.clone()).await;
        let b = connect(server.clone()).await;
        // Each session's first call carries the same request id.
        a.call_tool(call(key)).await.expect("session a");
        b.call_tool(call(key)).await.expect("session b");
        let runs = plane.journal().recent_runs(None, 10).await.expect("index");
        assert_eq!(
            runs.len() - before,
            2,
            "a second session was handed the first one's run (key {key:?}): {runs:?}"
        );
        a.cancel().await.expect("shutdown");
        b.cancel().await.expect("shutdown");
    }
}

/// **A task id is not a handle on whatever the plane is running.**
///
/// `tasks/get` and `tasks/cancel` act on runs this surface admitted. A run the
/// embedder started, or a peer's A2A task, is not an MCP host's to read or
/// stop, and answers as a task that does not exist.
#[tokio::test]
async fn a_run_this_surface_did_not_admit_is_no_task_of_its_own() {
    use rmcp::model::{CancelTaskParams, GetTaskParams};

    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let plane = waiting_plane();
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let client = connect(server).await;

    let embedded = plane
        .spawn(
            "audit.anomaly-detection",
            Tainted::trusted(json!({ "ledger": "internal" })),
        )
        .await
        .expect("an in-process run");
    let task_id = embedded.to_string();

    let read = client
        .peer()
        .get_task(GetTaskParams::new(task_id.clone()))
        .await;
    assert!(
        read.is_err(),
        "tasks/get read a run the host never started: {read:?}"
    );
    let cancelled = client
        .peer()
        .cancel_task(CancelTaskParams::new(task_id.clone()))
        .await;
    assert!(
        cancelled.is_err(),
        "tasks/cancel reached a run the host never started"
    );
    assert!(
        plane
            .cancellation(embedded)
            .await
            .expect("read the cancellation")
            .is_none(),
        "a host stopped the embedder's run"
    );

    client.cancel().await.expect("shutdown");
}

/// **A completed task hands back the call's result.**
///
/// The Tasks extension's completed payload is the original request's result.
/// An empty object in its place is a host that suspended for an answer and
/// was handed nothing when it came.
#[tokio::test]
async fn a_completed_task_returns_the_calls_result() {
    use rmcp::model::{GetTaskParams, TaskPayload};

    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let plane = plane();
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let client = connect(server).await;
    client
        .call_tool(
            CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
                json!({ "ledger": "GL-2026" })
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await
        .expect("tools/call");
    let task_id = plane.journal().recent_runs(None, 1).await.expect("index")[0]
        .0
        .to_string();

    let detailed = client
        .peer()
        .get_task(GetTaskParams::new(task_id))
        .await
        .expect("tasks/get");
    let TaskPayload::Completed { result } = &detailed.task.payload else {
        panic!("a finished call did not read as completed: {detailed:?}");
    };
    assert_eq!(
        result.get("structuredContent"),
        Some(&json!({ "audited": "GL-2026" })),
        "the completed task lost the call's answer: {result:?}"
    );

    client.cancel().await.expect("shutdown");
}

/// An unknown capability is a protocol error rather than a run that fails.
#[tokio::test]
async fn a_call_to_an_unoffered_capability_is_refused_before_admission() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let server = McpServer::new(plane(), &[manifest]).expect("served");
    let client = connect(server).await;

    let answer = client
        .call_tool(CallToolRequestParams::new("audit.something-else"))
        .await;
    assert!(
        answer.is_err(),
        "a capability this plane does not provide was admitted"
    );

    client.cancel().await.expect("shutdown");
}

/// **An agent with no reviewed argument shape cannot be offered.**
///
/// Refused at construction, not at the first call: by the time a catalogue has
/// been published, a model has already been handed the shape.
#[test]
fn an_agent_with_no_declared_input_is_not_servable() {
    let without = AGENT.replace(
        "  input:\n    schema:\n      type: object\n      additionalProperties: false\n      required: [ledger]\n      properties:\n        ledger:\n          type: string\n",
        "",
    );
    let manifest = Manifest::parse(&without).expect("a valid manifest without an input block");
    assert!(
        manifest.input_schema().is_none(),
        "the fixture still declares an input, so this proves nothing"
    );

    match McpServer::new(plane(), &[manifest]) {
        Err(ServeError::NoInputSchema { agent, capability }) => {
            assert_eq!(agent, "pattern-compliance-auditor");
            assert_eq!(capability, "audit.anomaly-detection");
        }
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!(
            "an agent with no reviewed argument shape was offered to a model — a \
             permissive stand-in reads exactly like a declaration"
        ),
    }
}

/// The reviewed instruction, verbatim, and nothing spliced into it.
#[tokio::test]
async fn a_prompt_is_the_reviewed_instruction_and_takes_no_arguments() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let expected = manifest
        .spec
        .identity
        .as_ref()
        .expect("an identity")
        .system_prompt();
    let server = McpServer::new(plane(), &[manifest]).expect("served");
    let client = connect(server).await;

    let prompts = client.list_all_prompts().await.expect("prompts/list");
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "pattern-compliance-auditor");
    assert!(
        prompts[0].arguments.is_none(),
        "a declared argument is a value spliced into reviewed text"
    );

    let got = client
        .get_prompt(GetPromptRequestParams::new("pattern-compliance-auditor"))
        .await
        .expect("prompts/get");
    let text = serde_json::to_value(&got.messages[0].content).expect("content");
    assert_eq!(
        text.get("text").and_then(Value::as_str),
        Some(expected.as_str()),
        "the served instruction is not the one the manifest declares"
    );

    // And an argument is refused rather than ignored.
    let spliced = client
        .get_prompt(
            GetPromptRequestParams::new("pattern-compliance-auditor").with_arguments(
                json!({ "tone": "terse" })
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await;
    assert!(
        spliced.is_err(),
        "an argument was accepted for a reviewed instruction, so the digest now \
         covers text nobody approved"
    );

    client.cancel().await.expect("shutdown");
}

/// A skill that parks the run on a timer, so the call suspends.
#[derive(Debug)]
struct Waits;

#[async_trait::async_trait]
impl Skill for Waits {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("waits").provides("audit.anomaly-detection")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.sleep(std::time::Duration::from_secs(3600)).await?;
        Ok(Outcome::done(input))
    }
}

fn waiting_plane() -> Arc<Runtime> {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("mcp")
        .policy(Arc::new(Permit))
        .timers(store as Arc<dyn agentplane::case::TimerStore>)
        .skill(Waits)
        .build()
}

/// **A suspended run is a task, and the task id is the run id.**
///
/// The claim the Tasks extension makes for a task — durable, observable whether
/// or not the client is connected — is one the journal already satisfies and an
/// in-memory table does not. So there is no table: `tasks/get` reads the run.
/// The failure this rules out is a handle that means something only to the
/// process that minted it, which stops meaning anything after a restart and
/// disagrees with the records the moment the two are asked separately.
#[tokio::test]
async fn a_suspended_run_is_a_task_that_reads_from_the_journal() {
    use rmcp::model::{GetTaskParams, TaskStatus};

    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let plane = waiting_plane();
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let client = connect(server).await;

    // A suspension answers as a task handle, so the typed `call_tool` helper —
    // which expects a completed result — cannot parse it. That refusal is the
    // first half of the assertion: a suspended run did not come back as a
    // result, empty or otherwise.
    let answer = client
        .call_tool(
            CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
                json!({ "ledger": "GL-2026" })
                    .as_object()
                    .cloned()
                    .expect("object"),
            ),
        )
        .await;
    assert!(
        answer.is_err(),
        "a suspended run answered as a completed tool call: {answer:?}"
    );

    let task_id = plane
        .journal()
        .recent_runs(None, 10)
        .await
        .expect("the run was journaled")
        .first()
        .map(|(run, _)| run.to_string())
        .expect("one run");

    let detailed = client
        .peer()
        .get_task(GetTaskParams::new(task_id.clone()))
        .await
        .expect("tasks/get");
    assert_eq!(
        detailed.task.task.task_id, task_id,
        "the task id is not the run id, so the handle means nothing to the journal"
    );
    assert_eq!(
        detailed.task.status(),
        TaskStatus::Working,
        "a suspended run must read as working: it has not concluded"
    );

    // Cancelling through the wire is the runtime's own cancellation.
    client
        .peer()
        .cancel_task(rmcp::model::CancelTaskParams::new(task_id.clone()))
        .await
        .expect("tasks/cancel");
    let run = agentplane::core::RunId::parse(&task_id).expect("a run id");
    assert!(
        plane
            .cancellation(run)
            .await
            .expect("read the cancellation")
            .is_some(),
        "cancelling the task recorded nothing in the journal, so a restart would \
         not honour it"
    );

    // And a cancelled run reads as cancelled — a status the protocol has — not
    // as a failure the host would report as the agent breaking.
    let detailed = client
        .peer()
        .get_task(GetTaskParams::new(task_id.clone()))
        .await
        .expect("tasks/get after cancel");
    assert_eq!(
        detailed.task.status(),
        TaskStatus::Cancelled,
        "a cancelled run read as {:?}",
        detailed.task.status()
    );

    client.cancel().await.expect("shutdown");
}

/// **A resource is the declaration, and nothing that carries a payload.**
///
/// A resource read is an egress into a model's context: sensitivity governs
/// what may leave a *run*, so the read verb that answers for an operator
/// answers a different question here. A declaration has no payload to answer it
/// about — it is the reviewed, content-addressed document `agentplane card`
/// already publishes — so it is the one thing served. Journals, cases and audit
/// reports are absent, and the assertion below is that they are *absent* rather
/// than merely undocumented.
#[tokio::test]
async fn resources_serve_the_declaration_and_nothing_with_a_payload() {
    use rmcp::model::ReadResourceRequestParams;

    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let digest = manifest.digest().expect("a digest").to_hex();
    let server = McpServer::new(plane(), std::slice::from_ref(&manifest)).expect("served");
    let client = connect(server).await;

    let resources = client.list_all_resources().await.expect("resources/list");
    assert_eq!(
        resources.len(),
        1,
        "exactly one resource — the declaration; anything else here carries a \
         payload somebody would have to decide a model may see: {resources:?}"
    );
    assert_eq!(
        resources[0].uri,
        "agentplane://manifest/pattern-compliance-auditor"
    );

    let read = client
        .read_resource(ReadResourceRequestParams::new(&resources[0].uri))
        .await
        .expect("resources/read");
    let rmcp::model::ResourceContents::TextResourceContents { text, meta, .. } = &read.contents[0]
    else {
        panic!("the declaration came back as a blob");
    };
    let document: Value = serde_json::from_str(text).expect("the declaration parses");
    assert_eq!(
        document,
        serde_json::to_value(&manifest).expect("the manifest serializes"),
        "the served document is not the declaration"
    );
    assert_eq!(
        meta.as_ref()
            .and_then(|m| m.get("digest"))
            .and_then(Value::as_str),
        Some(digest.as_str()),
        "the digest does not travel with the document, so a reader cannot say \
         which declaration they were shown"
    );

    // A journal is not reachable by asking for one.
    assert!(
        client
            .read_resource(ReadResourceRequestParams::new(
                "agentplane://run/run_01ARZ3NDEKTSV4RRFFQ69G5FAV"
            ))
            .await
            .is_err(),
        "a run's journal was served as a resource"
    );

    client.cancel().await.expect("shutdown");
}

/// **A capability nothing provides is not offered.**
///
/// A catalogue is published once and read by a model that cannot tell an
/// unwired capability from a working one: it composes a call against the
/// declared shape, the call fails at admission, and the error names the plane
/// rather than the declaration that offered it. Refused at construction, where
/// the person who wired the plane is looking.
#[test]
fn a_capability_the_plane_does_not_provide_is_not_offered() {
    let orphan = AGENT.replace(
        "provides: [audit.anomaly-detection]",
        "provides: [audit.anomaly-detection, audit.nobody-wired-this]",
    );
    let manifest = Manifest::parse(&orphan).expect("a valid manifest");
    assert_eq!(
        manifest.spec.capabilities.provides.len(),
        2,
        "the fixture declares one capability, so this proves nothing"
    );

    match McpServer::new(plane(), &[manifest]) {
        Err(ServeError::NoProvider { agent, capability }) => {
            assert_eq!(agent, "pattern-compliance-auditor");
            assert_eq!(capability, "audit.nobody-wired-this");
        }
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!("a tool nothing can answer was offered to a model"),
    }
}

/// **Every cacheable result carries the directives, and they say `private` and
/// stale.**
///
/// The revision this server speaks requires `ttlMs` and `cacheScope` on each
/// result a client may cache, and the protocol's default for a missing scope is
/// `public`. So an omitted field is not a neutral silence — it is a server
/// telling a shared intermediary it may hold a governed declaration and serve
/// it to somebody else, which is a copy no erasure reaches.
///
/// The negative half is the point: flip either constant and this fails. A
/// freshness window this plane cannot invalidate would be a declared control
/// enforced by the party it binds, and that is I12.
#[tokio::test]
async fn every_cacheable_result_refuses_a_shared_cache_and_a_freshness_window() {
    use rmcp::model::{CacheScope, ReadResourceRequestParams};

    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let server = McpServer::new(plane(), std::slice::from_ref(&manifest)).expect("served");
    let client = connect(server).await;

    // Each of the four is checked by hand rather than through the `list_all_*`
    // helpers, because those page and discard the envelope the directives ride
    // on — and the envelope is the whole subject here.
    let tools = client
        .list_tools(Option::default())
        .await
        .expect("tools/list");
    let prompts = client
        .list_prompts(Option::default())
        .await
        .expect("prompts/list");
    let resources = client
        .list_resources(Option::default())
        .await
        .expect("resources/list");
    let read = client
        .read_resource(ReadResourceRequestParams::new(&resources.resources[0].uri))
        .await
        .expect("resources/read");

    for (what, ttl, scope) in [
        ("tools/list", tools.ttl_ms, tools.cache_scope),
        ("prompts/list", prompts.ttl_ms, prompts.cache_scope),
        ("resources/list", resources.ttl_ms, resources.cache_scope),
        ("resources/read", read.ttl_ms, read.cache_scope),
    ] {
        assert_eq!(
            scope,
            Some(CacheScope::Private),
            "{what} left `cacheScope` unset or public: a shared intermediary may \
             now hold this and serve it to another principal"
        );
        assert_eq!(
            ttl,
            Some(0),
            "{what} advertised a freshness window this plane cannot invalidate"
        );
    }

    client.cancel().await.expect("shutdown");
}

/// Answers two capabilities, so one agent serves two tools.
#[derive(Debug)]
struct TwoHats;

#[async_trait::async_trait]
impl Skill for TwoHats {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("two-hats")
            .provides("audit.anomaly-detection")
            .provides("audit.reconcile")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(input))
    }
}

/// **One prompt per agent**, however many capabilities it serves — as one
/// resource per agent. The instruction is the agent's, and listing it once per
/// tool offers a host the same reviewed text under one name twice.
#[tokio::test]
async fn an_agent_serving_two_capabilities_is_one_prompt() {
    let two = AGENT.replace(
        "provides: [audit.anomaly-detection]",
        "provides: [audit.anomaly-detection, audit.reconcile]",
    );
    let manifest = Manifest::parse(&two).expect("a valid manifest");
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn JournalStore>;
    let plane = Runtime::builder(store)
        .owner("mcp")
        .policy(Arc::new(Permit))
        .skill(TwoHats)
        .build();
    let server = McpServer::new(plane, &[manifest]).expect("served");
    let client = connect(server).await;

    let tools = client
        .list_tools(Option::default())
        .await
        .expect("tools/list");
    assert_eq!(tools.tools.len(), 2, "the fixture serves two tools");
    let prompts = client
        .list_prompts(Option::default())
        .await
        .expect("prompts/list");
    let names: Vec<_> = prompts.prompts.iter().map(|p| p.name.clone()).collect();
    assert_eq!(
        names,
        vec!["pattern-compliance-auditor".to_owned()],
        "an agent was listed once per capability"
    );
    client.cancel().await.expect("shutdown");
}
