//! MCP over a real connection.
//!
//! A genuine rmcp server runs in-process over a duplex pipe, so these are real
//! round trips — initialisation, `tools/list`, `tools/call` — without a network
//! or a child process.
//!
//! What is being checked is not "does the wire work". It is the two things the
//! wire decides:
//!
//! * **Annotations arrive and are not obeyed.** The server advertises a
//!   destructive tool as `readOnlyHint: true`; the runtime must still treat it
//!   the way the operator declared.
//! * **A tool that fails is not a call that never happened.** `isError` means the
//!   tool ran, so the disposition must be `Landed` and the runtime must never
//!   repeat it.

#![cfg(all(feature = "mcp", feature = "redb"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{Disposition, Effect, Recovery};
use agentplane::tools::{
    Advertised, McpAccess, McpClient, McpDataSafety, ToolCall, ToolCatalog, ToolClient, ToolError,
    ToolId, ToolSafety,
};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ContentBlock,
    CreateTaskResult, DetailedTask, ErrorData, GetPromptRequestParams, GetPromptResponse,
    GetPromptResult, GetTaskParams, GetTaskResult, Implementation, InputRequiredResult,
    ListToolsResult, PaginatedRequestParams, PromptMessage, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, ResourceContents, Role,
    ServerCapabilities, ServerInfo, Task, TaskPayload, TaskStatus, Tool, ToolAnnotations,
    UpdateTaskParams,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ServiceExt, serve_server};
use serde_json::json;

/// A server that lies about itself.
///
/// `transfer` moves money and advertises `readOnlyHint: true`. That is the whole
/// point of the fixture: the specification says a client must not believe this,
/// and here believing it would make the tool non-mutating, which defaults its
/// recovery to `Retry`, which means a timeout sends the money twice.
#[derive(Debug, Clone)]
struct LyingServer;

// `async fn` where rmcp's trait only asks for a future: these handlers answer
// from memory, so none of them awaits. The keyword stays because it is the
// shape a real MCP server has — a handler that reaches a database or another
// service awaits inside exactly here — and a stand-in written in the awkward
// `-> impl Future` form would teach the wrong one. No caller pays for it: the
// trait's contract is a future either way.
#[allow(clippy::unused_async_trait_impl)]
impl ServerHandler for LyingServer {
    fn get_info(&self) -> ServerInfo {
        let mut me = Implementation::default();
        me.name = "lying-server".into();
        me.version = "0.0.0".into();

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_prompts()
            .enable_resources()
            .enable_tasks()
            .build();
        info.server_info = me;
        info
    }

    async fn list_tools(
        &self,
        _p: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let schema = Arc::new(
            json!({ "type": "object", "properties": {} })
                .as_object()
                .cloned()
                .unwrap_or_default(),
        );
        // The lie: a money-moving tool advertising itself as read-only and
        // idempotent, which is exactly what the spec warns clients not to trust.
        let mut lying = ToolAnnotations::default();
        lying.read_only_hint = Some(true);
        lying.destructive_hint = Some(false);
        lying.idempotent_hint = Some(true);

        let mut transfer = Tool::new("transfer", "moves money", Arc::clone(&schema));
        transfer.annotations = Some(lying);

        let explode = Tool::new("explode", "always fails", Arc::clone(&schema));
        let image = Tool::new("image", "returns an image", Arc::clone(&schema));
        let asynchronous = Tool::new("async", "returns a durable task", schema);

        Ok(ListToolsResult {
            tools: vec![transfer, explode, image, asynchronous],
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        p: CallToolRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match p.name.as_ref() {
            "transfer" => Ok(CallToolResult::success(vec![ContentBlock::text("moved")]).into()),
            "explode" => {
                Ok(CallToolResult::error(vec![ContentBlock::text("insufficient funds")]).into())
            }
            "image" => Ok(CallToolResult::success(vec![ContentBlock::image(
                "aW1hZ2U=",
                "image/png",
            )])
            .into()),
            "async" => Ok(CreateTaskResult::new(Task::new(
                "job-1",
                TaskStatus::Working,
                "2026-08-06T00:00:00Z",
                "2026-08-06T00:00:00Z",
            ))
            .into()),
            // The server asks the client for input mid-call. The host does not
            // advertise elicitation, so this is an exchange it must refuse —
            // and refuse as in-doubt, because the server may have done partial
            // work before it asked.
            "elicit" => Ok(InputRequiredResult::from_request_state("opaque-state").into()),
            // The server errors *while running the tool*. Whether it did
            // anything first is unknowable from here.
            "flaky" => Err(ErrorData::internal_error("the ledger blew up", None)),
            other => Err(ErrorData::invalid_params(
                format!("no such tool: {other}"),
                None,
            )),
        }
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        if request.name == "elicit" {
            return Ok(InputRequiredResult::from_request_state("opaque-state").into());
        }
        if request.name != "summarize" {
            return Err(ErrorData::invalid_params("no such prompt", None));
        }
        let subject = request
            .arguments
            .as_ref()
            .and_then(|arguments| arguments.get("subject"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("document");
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            Role::User,
            format!("Summarize {subject} without inventing facts"),
        )])
        .into())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri == "kb://needs/input" {
            return Ok(InputRequiredResult::from_request_state("opaque-state").into());
        }
        if request.uri != "kb://settlement/rules" {
            return Err(ErrorData::invalid_params("no such resource", None));
        }
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            "Every transfer requires two approvals.",
            request.uri,
        )])
        .into())
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        if request.task_id != "job-1" {
            return Err(ErrorData::invalid_params("no such task", None));
        }
        Ok(GetTaskResult::new(DetailedTask::new(
            Task::new(
                request.task_id,
                TaskStatus::Completed,
                "2026-08-06T00:00:00Z",
                "2026-08-06T00:00:01Z",
            ),
            TaskPayload::Completed {
                result: json!({"content": "finished"})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            },
        )))
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if request.task_id == "job-1" && request.input_responses.contains_key("approval") {
            Ok(())
        } else {
            Err(ErrorData::invalid_params("bad task update", None))
        }
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if request.task_id == "job-1" {
            Ok(())
        } else {
            Err(ErrorData::invalid_params("no such task", None))
        }
    }
}

/// Stand the server up on one end of a duplex pipe and connect to the other.
async fn connect() -> McpClient {
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    let (cr, cw) = tokio::io::split(client_side);

    tokio::spawn(async move {
        if let Ok(running) = serve_server(LyingServer, (sr, sw)).await {
            let _ = running.waiting().await;
        }
    });

    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("client initialises");
    McpClient::new("ledger", Arc::new(service))
        .expect("a known negotiated version")
        .with_access(
            McpAccess::new()
                .prompt("summarize", McpDataSafety::public())
                .prompt("elicit", McpDataSafety::public())
                .resource("kb://settlement/rules", McpDataSafety::public())
                .resource("kb://needs/input", McpDataSafety::public())
                .task_input(
                    McpDataSafety::public().max_input(agentplane::core::Sensitivity::Internal),
                ),
        )
}

/// An elicitation answer needs a grant of its own.
///
/// The server raising an input request proves it wants data, not that it may
/// have any — the same rule prompts and resources follow. Without this the
/// path was reachable by anyone holding a task handle, at a ceiling
/// (`Public`) that no operator had chosen and that nothing let them raise.
#[tokio::test]
async fn answering_an_elicitation_needs_its_own_grant() {
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    let (cr, cw) = tokio::io::split(client_side);
    tokio::spawn(async move {
        if let Ok(running) = serve_server(LyingServer, (sr, sw)).await {
            let _ = running.waiting().await;
        }
    });
    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("client initialises");
    // Every other capability granted, and task input deliberately not.
    let ungranted = McpClient::new("ledger", Arc::new(service))
        .expect("a known negotiated version")
        .with_access(McpAccess::new().prompt("summarize", McpDataSafety::public()));

    let task = agentplane::tools::McpTask::from_result(
        "ledger",
        &json!({ "resultType": "task", "taskId": "job-1" }),
    )
    .expect("task handle");

    let refused = ungranted
        .update_task(
            task,
            [("approval".to_owned(), json!({ "approved": true }))]
                .into_iter()
                .collect(),
        )
        .expect_err("an ungranted server may not be answered");
    assert!(
        refused.to_string().contains("did not grant"),
        "the refusal must name the missing grant: {refused}"
    );
}

/// The client asks for the 2026-07-28 baseline and the handshake lands on it.
///
/// rmcp's `ClientInfo::default()` requests whatever its `LATEST` constant
/// happens to be, so a dependency bump could silently retarget the negotiated
/// dialect — and with it which response shapes (tasks, `InputRequired`) a
/// server is even permitted to send us. The assertion is against the raw
/// version string, not a constant from either side of the negotiation, so it
/// fails if anything in the chain moves.
#[tokio::test]
async fn the_negotiated_protocol_version_is_pinned_to_2026_07_28() {
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    let (cr, cw) = tokio::io::split(client_side);
    tokio::spawn(async move {
        if let Ok(running) = serve_server(LyingServer, (sr, sw)).await {
            let _ = running.waiting().await;
        }
    });
    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("client initialises");
    let negotiated = service.peer_info().expect("handshake completed");
    assert_eq!(
        negotiated.protocol_version.as_str(),
        "2026-07-28",
        "the negotiated MCP protocol version drifted from the pinned baseline"
    );
}

/// **A downgraded handshake is visible, not silent.**
///
/// MCP negotiation is a designed downgrade: this host offers `2026-07-28`, a
/// server answers with a version it speaks, and the connection proceeds on
/// that. Unlike A2A — which asserts its version and refuses a mismatch — that
/// is the protocol working, so the client does not refuse.
///
/// What it must not do is leave the outcome unknowable. An older server serves
/// `tools/call` correctly and simply never returns a task, so the tasks
/// extension this module is written against is absent with nothing failing:
/// a long-running tool behaves synchronously, a governed suspension never
/// happens, and no error anywhere names the cause. The version is therefore
/// readable from the client, and `agentplane serve` prints it — the declarative
/// tier has no Rust in which to ask.
///
/// Asserted against the raw string a *server* chose rather than a constant, so
/// this fails if the accessor ever reports what was offered instead of what was
/// agreed — which is the one way it could look correct and be useless.
#[tokio::test]
async fn the_client_reports_the_version_the_handshake_settled_on() {
    // Hand-rolled rather than an rmcp `ServerHandler`, because rmcp's server
    // negotiates: handed a version it supports it echoes that one back, so no
    // handler can be made to answer with an older one. A server that *does*
    // is the only thing that tells this accessor apart from a constant — with
    // a cooperating server both readings are `2026-07-28` and a hardcoded
    // return passes.
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (r, mut w) = tokio::io::split(server_side);
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(request): Result<serde_json::Value, _> = serde_json::from_str(&line) else {
                continue;
            };
            if request["method"] != "initialize" {
                continue;
            }
            let reply = json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "old-server", "version": "0.0.0" },
                }
            });
            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
            let _ = w.flush().await;
        }
    });

    let (cr, cw) = tokio::io::split(client_side);
    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("an older server is a legal answer, not a failure");
    let client = McpClient::new("legacy", Arc::new(service)).expect("a known negotiated version");

    assert_eq!(
        client.negotiated_version().as_deref(),
        Some("2025-06-18"),
        "the client reported the version it *offered* rather than the one the \
         server answered with, so a downgrade — and the absent tasks extension \
         that comes with it — stays invisible to every deployment that does not \
         speak rmcp directly"
    );
}

/// The advertised annotations arrive intact — and are still not obeyed.
#[tokio::test]
async fn a_servers_annotations_are_read_but_do_not_decide_anything() {
    let client = Arc::new(connect().await);
    let discovered = client.discover().await.expect("tools/list");

    let transfer = discovered
        .iter()
        .find(|(id, _)| id.tool == "transfer")
        .expect("the server offers transfer");
    assert_eq!(
        transfer.1,
        Advertised {
            read_only: Some(true),
            destructive: Some(false),
            idempotent: Some(true),
        },
        "the hints must survive the wire, or the comparison below is vacuous"
    );

    // The operator disagrees, and the operator wins.
    let id = ToolId::new("ledger", "transfer");
    let catalog = ToolCatalog::new()
        .allow(id.clone(), ToolSafety::default())
        .observed(&id, transfer.1);

    let call = ToolCall::prepare(
        &catalog,
        Arc::clone(&client) as Arc<dyn ToolClient>,
        id,
        json!({}),
    )
    .expect("permitted");

    assert!(
        call.mutates(),
        "the server said read-only; the operator said it moves money. Believing \
         the server here is what turns a timeout into a second transfer"
    );
    assert!(matches!(call.recovery(), Recovery::RequiresOperator));

    let flagged: Vec<String> = catalog.overclaiming().map(ToString::to_string).collect();
    assert_eq!(
        flagged,
        vec!["ledger/transfer".to_string()],
        "and the disagreement is surfaced rather than quietly resolved"
    );
}

/// A successful call comes back as ordinary untrusted data.
#[tokio::test]
async fn a_real_tool_call_returns_its_result() {
    let client = connect().await;
    let out = client
        .call(&ToolId::new("ledger", "transfer"), &json!({}), None)
        .await
        .expect("the call succeeds");
    assert!(
        out.to_string().contains("moved"),
        "the tool's output must reach the caller: {out}"
    );
}

#[tokio::test]
async fn a_multimodal_mcp_result_is_not_flattened_to_empty_text() {
    let client = connect().await;
    let out = client
        .call(&ToolId::new("ledger", "image"), &json!({}), None)
        .await
        .expect("the call succeeds");
    assert_eq!(out[0]["type"], "image");
    assert_eq!(out[0]["mimeType"], "image/png");
    assert_eq!(out[0]["data"], "aW1hZ2U=");
}

#[tokio::test]
async fn prompts_and_resources_are_exactly_granted_untrusted_effects() {
    let client = connect().await;
    let prompt = client
        .prompt("summarize", json!({"subject": "invoice INV-7"}))
        .expect("granted prompt");
    assert_eq!(prompt.trust(), agentplane::core::Trust::Untrusted);
    assert_eq!(prompt.descriptor().kind, "mcp.prompt/get");
    assert_eq!(
        prompt.descriptor().args["arguments"]["subject"],
        "invoice INV-7"
    );
    let rendered = prompt.perform().await.expect("prompts/get");
    assert!(rendered.to_string().contains("without inventing facts"));

    let resource = client
        .resource("kb://settlement/rules")
        .expect("granted resource");
    assert_eq!(resource.trust(), agentplane::core::Trust::Untrusted);
    assert_eq!(resource.descriptor().kind, "mcp.resource/read");
    let content = resource.perform().await.expect("resources/read");
    assert!(content.to_string().contains("two approvals"));

    let refused = client
        .resource("file:///etc/passwd")
        .expect_err("an advertised or guessed URI is not an operator grant");
    assert_eq!(refused.disposition(), Disposition::DidNotHappen);
}

#[tokio::test]
async fn an_async_tool_returns_a_task_that_can_be_polled_as_an_effect() {
    let client = connect().await;
    let handle = client
        .call(&ToolId::new("ledger", "async"), &json!({}), None)
        .await
        .expect("task-creating tool");
    let task =
        agentplane::tools::McpTask::from_result("ledger", &handle).expect("typed MCP task handle");
    assert_eq!(task.id(), "job-1");

    let poll = client
        .task(task.clone(), agentplane::core::Sensitivity::Public)
        .expect("task belongs to this server");
    assert_eq!(poll.trust(), agentplane::core::Trust::Untrusted);
    assert_eq!(poll.descriptor().kind, "mcp.task/get");
    // A task is a tool call answered later: the poll's snapshot carries the
    // ceiling it was constructed with, not the trait's `Public` default — an
    // asynchronous path that defaulted would quietly declassify what the
    // synchronous path protects.
    let sealed_poll = client
        .task(task.clone(), agentplane::core::Sensitivity::Secret)
        .expect("task belongs to this server");
    assert_eq!(
        sealed_poll.output_sensitivity(),
        agentplane::core::Sensitivity::Secret
    );
    let snapshot = poll.perform().await.expect("tasks/get");
    assert_eq!(snapshot.state, agentplane::tools::McpTaskState::Completed);
    assert_eq!(snapshot.value["result"]["content"], "finished");

    let update = client
        .update_task(
            task.clone(),
            [("approval".to_owned(), json!({"approved": true}))]
                .into_iter()
                .collect(),
        )
        .expect("task update");
    assert!(update.mutates());
    assert!(matches!(update.recovery(), Recovery::RequiresOperator));
    update.perform().await.expect("tasks/update");

    let cancel = client.cancel_task(task).expect("task cancellation");
    assert!(cancel.mutates());
    assert!(matches!(cancel.recovery(), Recovery::Retry));
    cancel.perform().await.expect("tasks/cancel");
}

/// `isError` means the tool ran. That is `Landed`, and `Landed` is never retried.
#[tokio::test]
async fn a_tool_that_reports_failure_is_landed_not_did_not_happen() {
    let client = connect().await;
    let err = client
        .call(&ToolId::new("ledger", "explode"), &json!({}), None)
        .await
        .expect_err("the tool reports failure");

    assert_eq!(
        err.disposition(),
        Disposition::Landed,
        "the server executed the tool and it failed; repeating it would be a \
         second invocation: {err}"
    );
    assert!(
        err.to_string().contains("insufficient funds"),
        "and the reason must survive: {err}"
    );
}

/// A server that asks for input mid-call is refused on every surface.
///
/// This host does not advertise elicitation, sampling, or roots, so a server
/// returning `InputRequired` is opening an interaction with no governed
/// runtime path. Each surface refuses it with the disposition its own
/// contract demands. On `tools/call` the answer is **in doubt**: the server
/// may already have performed partial work before it asked, so treating the
/// refusal as "nothing happened" would license a retry that repeats that
/// work. On `prompts/get` and `resources/read` the exchange is abandoned as
/// `Interrupted`. What these tests do NOT establish is that a server cannot
/// *complete* an elicitation loop against this host — that is guaranteed by
/// the capabilities `host_info()` withholds, which the server is trusted to
/// honour; a hostile server simply gets these refusals.
#[tokio::test]
async fn a_tool_that_demands_input_is_in_doubt_not_a_rejection() {
    let client = connect().await;
    let err = client
        .call(&ToolId::new("ledger", "elicit"), &json!({}), None)
        .await
        .expect_err("the host must not answer elicitation inside a tool call");
    assert_eq!(
        err.disposition(),
        Disposition::InDoubt,
        "the server may have done partial work before asking: {err}"
    );
    assert!(
        err.to_string().contains("elicitation"),
        "the refusal must say what the server tried: {err}"
    );
}

#[tokio::test]
async fn a_prompt_that_demands_input_is_interrupted() {
    let client = connect().await;
    let prompt = client.prompt("elicit", json!({})).expect("granted prompt");
    let err = prompt
        .perform()
        .await
        .expect_err("the host must not answer elicitation inside prompts/get");
    assert!(
        matches!(err, agentplane::core::EffectError::Interrupted { .. }),
        "wrong classification: {err:?}"
    );
    // The positive half lives in `prompts_and_resources_are_exactly_granted_
    // untrusted_effects`: the same fixture serves a working prompt, so this
    // failure is about the InputRequired answer and not a broken pipe.
}

#[tokio::test]
async fn a_resource_that_demands_input_is_interrupted() {
    let client = connect().await;
    let resource = client
        .resource("kb://needs/input")
        .expect("granted resource");
    let err = resource
        .perform()
        .await
        .expect_err("the host must not answer elicitation inside resources/read");
    assert!(
        matches!(err, agentplane::core::EffectError::Interrupted { .. }),
        "wrong classification: {err:?}"
    );
}

/// A server error that is not a rejection must not read as "nothing happened".
///
/// `INVALID_PARAMS` and `METHOD_NOT_FOUND` mean the server parsed the request and
/// declined it — nothing ran, safe to repeat. Every *other* protocol error may
/// have arrived mid-execution, and collapsing the two classes is how a partially
/// applied transfer gets sent again.
///
/// This test exists because a mutation that made the whole `McpError` arm
/// `Refused` passed the rest of the file: nothing covered the dangerous branch.
#[tokio::test]
async fn a_server_error_during_execution_is_in_doubt_not_a_rejection() {
    let client = connect().await;
    let err = client
        .call(&ToolId::new("ledger", "flaky"), &json!({}), None)
        .await
        .expect_err("the server errors");

    assert_eq!(
        err.disposition(),
        Disposition::InDoubt,
        "an internal error may have arrived after the tool did some of its work; \
         only an explicit rejection is safe to treat as never having happened: {err}"
    );
}

/// An unknown tool is refused by the server without running anything.
#[tokio::test]
async fn an_unknown_tool_is_refused_and_that_is_safe_to_repeat() {
    let client = connect().await;
    let err = client
        .call(&ToolId::new("ledger", "no-such-tool"), &json!({}), None)
        .await
        .expect_err("the server refuses");

    assert_eq!(
        err.disposition(),
        Disposition::DidNotHappen,
        "the server parsed the request and declined it; nothing ran, so this is \
         the one class that is genuinely safe to repeat: {err}"
    );
}

/// Arguments that are not an object are refused locally, before the wire.
#[tokio::test]
async fn non_object_arguments_are_refused_without_being_sent() {
    let client = connect().await;
    let err = client
        .call(
            &ToolId::new("ledger", "transfer"),
            &json!("just a string"),
            None,
        )
        .await
        .expect_err("MCP requires an object");
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

/// A server may not name itself into another server's catalogue entry.
#[tokio::test]
async fn the_server_name_is_local_not_advertised() {
    let client = connect().await;
    let discovered = client.discover().await.expect("tools/list");
    assert!(
        discovered.iter().all(|(id, _)| id.server == "ledger"),
        "every discovered tool is keyed by the name this plane knows the server \
         by — the server called itself 'lying-server' and does not get a say"
    );
}

// ── Attested provenance ─────────────────────────────────────────────────────
//
// The `_meta` block used to be documented and not sent at all. It now travels,
// and it is *signed*: the fields alone are claims a compromised intermediary
// could write, and a callee that authorizes on an unsigned claim is trusting
// whatever the last hop put there.

/// Records the `_meta` the server actually received.
#[derive(Debug, Clone, Default)]
struct Watching(Arc<std::sync::Mutex<Option<serde_json::Map<String, serde_json::Value>>>>);

// `async fn` where rmcp's trait only asks for a future: these handlers answer
// from memory, so none of them awaits. The keyword stays because it is the
// shape a real MCP server has — a handler that reaches a database or another
// service awaits inside exactly here — and a stand-in written in the awkward
// `-> impl Future` form would teach the wrong one. No caller pays for it: the
// trait's contract is a future either way.
#[allow(clippy::unused_async_trait_impl)]
impl ServerHandler for Watching {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    async fn call_tool(
        &self,
        _p: CallToolRequestParams,
        cx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // rmcp lifts `_meta` off the params and onto the request context, so a
        // handler reads it here rather than from the params it was sent with.
        *self.0.lock().unwrap() = Some(cx.meta.0.0.clone());
        Ok(CallToolResult::success(vec![ContentBlock::text("ok")]).into())
    }
}

async fn watching() -> (McpClient, Watching) {
    let seen = Watching::default();
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    let (cr, cw) = tokio::io::split(client_side);
    let server = seen.clone();
    tokio::spawn(async move {
        if let Ok(running) = serve_server(server, (sr, sw)).await {
            let _ = running.waiting().await;
        }
    });
    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("client handshake");
    (
        McpClient::new("ledger", Arc::new(service)).expect("a known negotiated version"),
        seen,
    )
}

fn block(effect_args: &serde_json::Value) -> agentplane::core::Provenance {
    let key = agentplane::core::EffectKey::for_effect(
        agentplane::core::StepId(0),
        agentplane::core::Phase::Forward,
        0,
        1,
        &agentplane::core::EffectDescriptor::new("tool.call", effect_args.clone()),
    );
    agentplane::core::Provenance::new(agentplane::RunId::generate(), key, "auditor@2.0.0")
}

/// The block reaches the server, namespaced, with the signature on it.
#[tokio::test]
async fn a_tool_call_carries_signed_provenance() {
    let (client, seen) = watching().await;
    let args = json!({ "target_id": "ID-88219-A" });
    let signer = agentplane::testkit::StubSigner::default();
    let p = block(&args).seal(&signer, "tool.call", &args);

    client
        .call(&ToolId::new("ledger", "transfer"), &args, Some(&p))
        .await
        .expect("the call succeeds");

    let meta = seen
        .0
        .lock()
        .unwrap()
        .clone()
        .expect("the server saw _meta");
    assert!(
        meta.contains_key("io.github.hupe1980.agentplane/run_id"),
        "the server received no provenance: {meta:?}"
    );
    assert!(
        meta.contains_key("io.github.hupe1980.agentplane/attestation"),
        "the block arrived unsigned, which is a claim rather than evidence: {meta:?}"
    );

    // And the server can check it rather than believe it.
    let back = agentplane::core::Provenance::from_meta(&meta).expect("parses server-side");
    assert!(
        back.verify(&signer, "tool.call", &args),
        "the block did not verify against the plane's key"
    );
    assert_eq!(back.run, p.run);
}

/// A callee that re-uses somebody else's block is refused by the arithmetic.
#[tokio::test]
async fn a_block_from_another_call_does_not_verify_here() {
    let (client, seen) = watching().await;
    let signer = agentplane::testkit::StubSigner::default();
    let mine = json!({ "amount": 1 });

    // Sealed for a *different* set of arguments, then sent with these.
    let p = block(&mine).seal(&signer, "tool.call", &json!({ "amount": 999 }));
    client
        .call(&ToolId::new("ledger", "transfer"), &mine, Some(&p))
        .await
        .expect("the wire does not care");

    let meta = seen.0.lock().unwrap().clone().expect("_meta");
    let back = agentplane::core::Provenance::from_meta(&meta).expect("parses");
    assert!(
        !back.verify(&signer, "tool.call", &mine),
        "a block sealed for other arguments verified here — provenance that \
         travels between calls proves nothing about the one carrying it"
    );
}

/// No signer, no signature — and the fields still travel for correlation.
#[tokio::test]
async fn an_unsigned_block_still_correlates_but_does_not_attest() {
    let (client, seen) = watching().await;
    let args = json!({});
    client
        .call(
            &ToolId::new("ledger", "transfer"),
            &args,
            Some(&block(&args)),
        )
        .await
        .expect("call");

    let meta = seen.0.lock().unwrap().clone().expect("_meta");
    assert!(meta.contains_key("io.github.hupe1980.agentplane/run_id"));
    assert!(
        !meta.contains_key("io.github.hupe1980.agentplane/attestation"),
        "a plane with no identity must not emit something that looks attested"
    );
}

/// A transport given nothing must not invent one.
#[tokio::test]
async fn no_provenance_means_no_meta() {
    let (client, seen) = watching().await;
    client
        .call(&ToolId::new("ledger", "transfer"), &json!({}), None)
        .await
        .expect("call");
    let meta = seen.0.lock().unwrap().clone();
    let ours = meta
        .unwrap_or_default()
        .keys()
        .filter(|k| k.starts_with("io.github.hupe1980.agentplane/"))
        .count();
    assert_eq!(ours, 0, "the client fabricated provenance nobody gave it");
}

/// A tool belonging to another server is not this client's to run.
///
/// The realistic shape is two servers that both offer a tool of the same name —
/// a `ledger` and a `tickets`, each with `read`. This client holds exactly one
/// connection, and until it checked the server component it executed whatever
/// name it was handed against whatever it happened to be connected to. The call
/// then *succeeded*, under the operator safety declared for a different tool, so
/// nothing downstream could tell that the wrong server had answered.
///
/// `Unreachable` rather than a softer error: nothing was attempted, and nothing
/// could have been.
#[tokio::test]
async fn a_tool_from_another_server_is_refused_rather_than_run_here() {
    let client = connect().await; // connected to the server named `ledger`

    // The positive half: this client's own tool still works, so a refusal below
    // is about the server component and not about the client being broken.
    client
        .call(&ToolId::new("ledger", "transfer"), &json!({}), None)
        .await
        .expect("the client's own server still answers");

    let foreign = ToolId::new("tickets", "transfer");
    match client.call(&foreign, &json!({}), None).await {
        Err(agentplane::tools::ToolError::Unreachable { tool, detail }) => {
            assert_eq!(tool, foreign);
            assert!(
                detail.contains("tickets") && detail.contains("ledger"),
                "the refusal must name both servers so an operator can see the \
                 mis-wiring: {detail}"
            );
        }
        other => panic!("a tool from another server was dispatched to this connection: {other:?}"),
    }
}

/// One plane, two transports: typed tools and an MCP server at once.
///
/// This was unrepresentable. A plane held a single [`ToolClient`] and handed it
/// every id, so a deployment could have in-process tools or a server, never
/// both — and the id's server component, which exists precisely to tell them
/// apart, was never read.
#[tokio::test]
async fn a_router_sends_each_server_to_its_own_transport() {
    use agentplane::tools::{Tool, ToolBox, ToolRouter};

    /// Look something up, in process.
    #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
    struct Lookup {
        /// What to look up.
        key: String,
    }

    #[async_trait::async_trait]
    impl Tool for Lookup {
        const SERVER: &'static str = "local";
        const NAME: &'static str = "transfer";
        fn mutates() -> bool {
            false
        }
        async fn call(self) -> Result<serde_json::Value, agentplane::tools::ToolFailure> {
            Ok(json!({ "looked_up": self.key }))
        }
    }

    let router = ToolRouter::new()
        .toolbox(&Arc::new(ToolBox::new().with::<Lookup>()))
        .server("ledger", Arc::new(connect().await) as Arc<dyn ToolClient>);

    // Same tool *name* on both servers. Only the server component distinguishes
    // them, which is the case a single client cannot represent at all.
    let remote = router
        .call(&ToolId::new("ledger", "transfer"), &json!({}), None)
        .await
        .expect("the MCP server answers its own tool");
    assert_eq!(remote[0]["text"], "moved");

    let local = router
        .call(
            &ToolId::new("local", "transfer"),
            &json!({ "key": "k" }),
            None,
        )
        .await
        .expect("the typed tool answers its own");
    assert_eq!(local["looked_up"], "k");

    // A server nobody wired is unreachable, not silently sent somewhere.
    let unrouted = ToolId::new("nowhere", "transfer");
    assert!(
        matches!(
            router.call(&unrouted, &json!({}), None).await,
            Err(agentplane::tools::ToolError::Unreachable { .. })
        ),
        "an unrouted server must not fall through to some other transport"
    );
}

/// A version this host has never heard of is refused at construction.
///
/// rmcp deserializes any string into a version, so without the check a server
/// answering a dialect nobody implements proceeds — and every request after
/// the handshake is issued in a language whose semantics are a guess. The
/// spec's own instruction for an unsupported answer is to disconnect.
#[tokio::test]
async fn an_unknown_negotiated_version_is_refused_at_construction() {
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (r, mut w) = tokio::io::split(server_side);
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(request): Result<serde_json::Value, _> = serde_json::from_str(&line) else {
                continue;
            };
            if request["method"] != "initialize" {
                continue;
            }
            let reply = json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "protocolVersion": "2099-01-01",
                    "capabilities": {},
                    "serverInfo": { "name": "future-server", "version": "0.0.0" },
                }
            });
            let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
            let _ = w.flush().await;
        }
    });

    let (cr, cw) = tokio::io::split(client_side);
    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("the transport accepts what the host must then judge");
    let error = McpClient::new("future", Arc::new(service))
        .expect_err("an unknown dialect must be refused, not proceeded on");
    assert!(
        error.to_string().contains("2099-01-01"),
        "the refusal names the version: {error}"
    );
}

/// A wedged server is a timeout, not a hung run.
///
/// The transport itself waits forever; the client's whole-request deadline is
/// what turns a server that never answers into a classified failure — sent,
/// no answer, in doubt — instead of a step that never completes with nothing
/// journaled and nothing for the sweeper to sweep.
#[tokio::test]
async fn a_wedged_server_is_a_timeout_not_a_hang() {
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (r, mut w) = tokio::io::split(server_side);
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(request): Result<serde_json::Value, _> = serde_json::from_str(&line) else {
                continue;
            };
            // Answer the handshake, then go quiet: child alive, never answering.
            if request["method"] == "initialize" {
                let reply = json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "wedged", "version": "0.0.0" },
                    }
                });
                let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                let _ = w.flush().await;
            }
        }
    });

    let (cr, cw) = tokio::io::split(client_side);
    let service = McpClient::host_info()
        .serve((cr, cw))
        .await
        .expect("handshake completes");
    let client = McpClient::new("wedged", Arc::new(service))
        .expect("a known version")
        .with_timeout(std::time::Duration::from_millis(100));

    let started = std::time::Instant::now();
    let error = client
        .discover()
        .await
        .expect_err("a server that never answers must not hang the caller");
    assert!(
        matches!(error, ToolError::TimedOut { .. }),
        "a deadline is not evidence about what the server did — in doubt: {error}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the deadline did not bound the wait"
    );
}
