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

fn plane() -> Arc<Runtime> {
    let store = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn JournalStore>;
    Runtime::builder(store).owner("mcp").skill(Auditor).build()
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

/// **An older revision is refused, not quietly served.**
///
/// The SDK's own `ProtocolVersion::LATEST` is `2025-11-25`, so a client built
/// on the defaults asks for a revision this plane is not written against. What
/// it must not get is a working session: that revision has no Tasks extension,
/// so a run that suspends for an approval would have no way to say so — the
/// long-running call would simply behave synchronously and no error would name
/// the cause. That is the downgrade this crate refuses as a *client*, and it is
/// refused here from the other side, with the supported set in the error so the
/// operator on the far end can read what happened.
#[tokio::test]
async fn an_older_revision_is_refused_rather_than_negotiated_down() {
    let manifest = Manifest::parse(AGENT).expect("a valid manifest");
    let server = McpServer::new(plane(), &[manifest]).expect("served");
    let (client_side, ()) = pipe(server);
    let (cr, cw) = tokio::io::split(client_side);

    let refused = ().serve((cr, cw)).await;
    let Err(error) = refused else {
        panic!(
            "a client asking for {} was served — a suspension has no expression on that \
             revision, so the session would work right up to the first governed wait",
            ProtocolVersion::LATEST
        );
    };
    let said = error.to_string();
    assert!(
        said.contains("2026-07-28"),
        "the refusal does not name the revision this plane speaks, so the far end \
         cannot tell an unsupported version from an outage: {said}"
    );
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
