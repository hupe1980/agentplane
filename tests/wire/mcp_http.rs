//! Serving MCP over Streamable HTTP: the stock rmcp client, over a real
//! socket, against this plane's listener.
//!
//! What carries this file is that the HTTP door names its caller. A request
//! with no valid credential admits nothing; a call is admitted as the token's
//! actor, under its chain, with its input labelled as coming from it; a retry
//! is one run for that caller and another caller's run is no task of theirs;
//! policy is asked per action; and a rebinding request is refused before its
//! credential is read.

#![cfg(all(
    feature = "mcp-server-http",
    feature = "mcp-http",
    feature = "redb",
    feature = "testkit"
))]

use std::sync::{Arc, Mutex};

use agentplane::api::Authenticator;
use agentplane::api::tokens::TokenAuthenticator;
use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::manifest::Manifest;
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::tools::serve::McpServer;
use agentplane::tools::serve_http::{HttpConfig, McpHttp};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use rmcp::model::{CallToolRequestParams, ProtocolVersion};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, RunningService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};
use tower::ServiceExt;

const BOT: &str = "bot-token-0123456789abcdef0123456789abcdef";
const EVE: &str = "eve-token-0123456789abcdef0123456789abcdef";
const ELSEWHERE: &str = "far-token-0123456789abcdef0123456789abcdef";

fn tokens() -> Arc<dyn Authenticator> {
    Arc::new(
        TokenAuthenticator::from_yaml(&format!(
            "- token: {BOT}\n  actor: bot\n  roles: [framework]\n  scope: [audit.*, ledger.*]\n\
             - token: {EVE}\n  actor: eve\n  roles: [framework]\n\
             - token: {ELSEWHERE}\n  actor: far\n  roles: [framework]\n  tenant: elsewhere\n"
        ))
        .expect("tokens"),
    )
}

const AUDITOR: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: auditor, version: "1.0.0" }
spec:
  identity: { role: Finds anomalies in a ledger. }
  capabilities: { provides: [audit.anomaly-detection] }
  input:
    schema:
      type: object
      required: [ledger]
      properties:
        ledger: { type: string }
  budgets: {}
"#;

/// Answers with the ledger it was given — or waits an hour, when told to.
#[derive(Debug)]
struct Auditor;

#[async_trait::async_trait]
impl Skill for Auditor {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("auditor")
            .provides("audit.anomaly-detection")
            .provides("audit.reconcile")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        if input.peek()["ledger"] == "wait" {
            cx.sleep(std::time::Duration::from_secs(3600)).await?;
        }
        Ok(Outcome::done(input))
    }
}

/// Permits every action except the ones named.
#[derive(Debug)]
struct Except(&'static [&'static str]);

impl agentplane::core::PolicyEngine for Except {
    fn authorize(
        &self,
        request: &agentplane::core::PolicyRequest<'_>,
    ) -> agentplane::core::PolicyDecision {
        if self.0.contains(&request.action) {
            agentplane::core::PolicyDecision::Deny {
                reason: format!("{} is not permitted here", request.action),
            }
        } else {
            agentplane::core::PolicyDecision::Permit
        }
    }

    fn bundle(&self) -> agentplane::core::PolicyBundleIdentity {
        agentplane::core::PolicyBundleIdentity::new(
            agentplane::core::Digest::of(b"mcp-http-except"),
            "agentplane-test/mcp-http-except",
        )
    }
}

fn auditor_plane(policy: Except) -> Arc<Runtime> {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("mcp")
        .policy(Arc::new(policy))
        .timers(store as Arc<dyn agentplane::case::TimerStore>)
        .skill(Auditor)
        .build()
}

fn http(plane: &Arc<Runtime>, manifest: &str) -> McpHttp {
    let manifest = Manifest::parse(manifest).expect("manifest");
    let server = McpServer::new(Arc::clone(plane), &[manifest]).expect("served");
    McpHttp::new(server, tokens(), &HttpConfig::new()).expect("listener")
}

/// Serve on an ephemeral loopback port; the URL of its MCP endpoint.
async fn listen(http: &McpHttp) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = http.router();
    tokio::spawn(async move { axum::serve(listener, router).await });
    format!("http://{addr}/mcp")
}

/// A host on the current revision that can hold a task.
#[derive(Debug, Clone, Default)]
struct Host;

impl rmcp::ClientHandler for Host {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        let mut info = rmcp::model::ClientConfig::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = rmcp::model::ClientCapabilities::builder()
            .enable_tasks()
            .build();
        info
    }
}

async fn connect(url: &str, token: &str) -> RunningService<rmcp::RoleClient, Host> {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url).auth_header(token),
    );
    Host.serve_with_lifecycle(
        transport,
        ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        },
    )
    .await
    .expect("the host connects")
}

fn audit(ledger: &str, key: Option<&str>) -> CallToolRequestParams {
    let mut request = CallToolRequestParams::new("audit.anomaly-detection").with_arguments(
        json!({ "ledger": ledger })
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
}

async fn runs(plane: &Runtime) -> Vec<agentplane::core::RunId> {
    plane
        .journal()
        .recent_runs(None, 50)
        .await
        .expect("index")
        .into_iter()
        .map(|(run, _)| run)
        .collect()
}

/// One raw request to the router, as a framework's first POST.
async fn raw(http: &McpHttp, headers: &[(&str, &str)]) -> (StatusCode, String, String) {
    let mut request = Request::post("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "raw", "version": "0" }
        }
    });
    let response = http
        .router()
        .oneshot(request.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("infallible");
    let status = response.status();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        challenge,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// **No valid credential, no admission** — and one answer for missing, unknown
/// and another tenant's, so a prober learns nothing about what it held.
#[tokio::test]
async fn an_unauthenticated_mcp_request_is_refused_and_admits_nothing() {
    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);

    let host = ("host", "127.0.0.1:8081");
    let unknown = format!("Bearer {}", "x".repeat(40));
    let elsewhere = format!("Bearer {ELSEWHERE}");
    let mut bodies = Vec::new();
    for headers in [
        vec![host],
        vec![host, ("authorization", unknown.as_str())],
        vec![host, ("authorization", elsewhere.as_str())],
    ] {
        let (status, challenge, body) = raw(&http, &headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?} -> {body}");
        assert_eq!(
            challenge, "Bearer",
            "a static-bearer listener's challenge carries no metadata"
        );
        bodies.push(body);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "the refusals tell missing, unknown and wrong-tenant apart: {bodies:?}"
    );

    // And through the stock client, which must be refused at its handshake.
    let url = listen(&http).await;
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url.as_str()),
    );
    let refused = Host
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await;
    if let Ok(client) = refused {
        let called = client.call_tool(audit("GL-1", None)).await;
        assert!(called.is_err(), "an unauthenticated call was answered");
    }
    assert!(
        runs(&plane).await.is_empty(),
        "an unauthenticated host admitted a run"
    );
}

/// **A served call acts as its caller**: the admission names the actor, is
/// keyed under it, binds its chain, and labels the input as coming from it.
#[tokio::test]
async fn an_http_tool_call_is_admitted_as_its_caller() {
    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);
    let client = connect(&listen(&http).await, BOT).await;

    let answer = client
        .call_tool(audit("GL-2026", None))
        .await
        .expect("call");
    assert_ne!(answer.is_error, Some(true), "{answer:?}");

    let [run] = runs(&plane).await[..] else {
        panic!("one call, one run");
    };
    let records = plane.journal().read(run, 1).await.expect("journal");
    assert_eq!(
        records.first().and_then(|r| r.admission_source()),
        Some("mcp/peer:bot"),
        "the admission is not keyed under the caller"
    );
    let started = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted {
                admitted_by,
                input_label,
                ..
            } => Some((admitted_by.clone(), input_label.clone())),
            _ => None,
        })
        .expect("a RunAdmitted record");
    assert_eq!(
        started.0.as_deref(),
        Some("bot"),
        "admitted_by is not the actor"
    );
    assert_eq!(
        started.1.trust,
        agentplane::core::Trust::Untrusted,
        "a caller's input arrived trusted"
    );
    assert!(
        started
            .1
            .provenance
            .contains(&agentplane::core::SourceId::new("peer:bot")),
        "the input is not labelled as coming from the caller: {:?}",
        started.1
    );
    assert!(
        records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::IdentityBound { .. })),
        "the caller's chain was not bound to the run"
    );
    client.cancel().await.expect("shutdown");
}

/// **Another caller's task is no task**, read or cancel.
#[tokio::test]
async fn another_callers_task_is_no_such_task() {
    use rmcp::model::{CancelTaskParams, GetTaskParams};

    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);
    let url = listen(&http).await;
    let bot = connect(&url, BOT).await;
    let eve = connect(&url, EVE).await;

    // A suspension answers as a task, which the typed helper cannot parse.
    let _ = bot.call_tool(audit("wait", None)).await;
    let [run] = runs(&plane).await[..] else {
        panic!("one call, one run");
    };
    let task = run.to_string();

    bot.peer()
        .get_task(GetTaskParams::new(task.clone()))
        .await
        .expect("the owner reads its task");
    let read = eve.peer().get_task(GetTaskParams::new(task.clone())).await;
    let missing = eve
        .peer()
        .get_task(GetTaskParams::new(
            agentplane::core::RunId::generate().to_string(),
        ))
        .await;
    assert_eq!(
        format!("{:?}", read.as_ref().err()),
        format!("{:?}", missing.as_ref().err()),
        "another caller's task answered differently from no task at all"
    );
    assert!(read.is_err(), "another caller read the task: {read:?}");
    let cancelled = eve.peer().cancel_task(CancelTaskParams::new(task)).await;
    assert!(cancelled.is_err(), "another caller cancelled the task");
    assert!(
        plane.cancellation(run).await.expect("read").is_none(),
        "another caller's cancel reached the run"
    );
    bot.cancel().await.expect("shutdown");
    eve.cancel().await.expect("shutdown");
}

/// **A retry with the same key is one run on any request, for its caller** —
/// and the same key from another caller is another run.
#[tokio::test]
async fn an_http_retry_with_the_same_key_is_one_run() {
    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);
    let url = listen(&http).await;

    let first = connect(&url, BOT).await;
    first
        .call_tool(audit("GL-1", Some("call-7")))
        .await
        .expect("first");
    first.cancel().await.expect("shutdown");
    let again = connect(&url, BOT).await;
    again
        .call_tool(audit("GL-1", Some("call-7")))
        .await
        .expect("retry");
    assert_eq!(runs(&plane).await.len(), 1, "a retry admitted a second run");

    let other = connect(&url, EVE).await;
    other
        .call_tool(audit("GL-1", Some("call-7")))
        .await
        .expect("another caller");
    assert_eq!(
        runs(&plane).await.len(),
        2,
        "another caller's same key was handed the first caller's run"
    );
    again.cancel().await.expect("shutdown");
    other.cancel().await.expect("shutdown");
}

/// **Policy is asked per action.** A call it does not permit is declined and
/// admits nothing; a list it does not permit is an error, never an empty list
/// that reads as *nothing is offered*.
#[tokio::test]
async fn a_tool_call_the_policy_does_not_permit_is_declined_and_admits_nothing() {
    let plane = auditor_plane(Except(&[
        "mcp:tool.call",
        "mcp:prompt.read",
        "mcp:resource.read",
    ]));
    let http = http(&plane, AUDITOR);
    let client = connect(&listen(&http).await, BOT).await;

    let listed = client
        .list_tools(None)
        .await
        .expect("tools/list is permitted");
    assert_eq!(listed.tools.len(), 1);
    let answer = client
        .call_tool(audit("GL-1", None))
        .await
        .expect("answered");
    assert_eq!(
        answer.is_error,
        Some(true),
        "a declined call read as success"
    );
    assert!(
        runs(&plane).await.is_empty(),
        "a declined call admitted a run"
    );
    assert!(
        client.list_prompts(None).await.is_err(),
        "a denied prompts/list answered"
    );
    assert!(
        client.list_resources(None).await.is_err(),
        "a denied resources/list answered"
    );
    client.cancel().await.expect("shutdown");
}

/// **A rebinding request is refused before its credential is read**: a
/// present, unlisted `Origin` and a disallowed `Host` are `403`; a request
/// with no `Origin` reaches authentication.
#[tokio::test]
async fn a_foreign_origin_is_refused_before_authentication() {
    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);
    let bearer = format!("Bearer {BOT}");

    let (status, _, _) = raw(
        &http,
        &[
            ("host", "127.0.0.1:8081"),
            ("origin", "https://evil.example"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a foreign Origin was not refused"
    );
    let (status, _, _) = raw(
        &http,
        &[
            ("host", "127.0.0.1:8081"),
            ("origin", "https://evil.example"),
            ("authorization", bearer.as_str()),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a foreign Origin with a valid token was served"
    );
    let (status, _, _) = raw(&http, &[("host", "evil.example")]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a foreign Host was not refused"
    );
    let (status, _, _) = raw(&http, &[("host", "127.0.0.1:8081")]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a request with no Origin did not reach authentication"
    );
    assert!(runs(&plane).await.is_empty());
}

/// Records every call it receives.
#[derive(Debug, Default)]
struct Recorder {
    calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl agentplane::tools::ToolClient for Recorder {
    async fn call(
        &self,
        _tool: &agentplane::tools::ToolId,
        arguments: &Value,
        _p: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, agentplane::tools::ToolError> {
        self.calls.lock().expect("calls").push(arguments.clone());
        Ok(json!({ "moved": true }))
    }

    fn destination(&self, _tool: &agentplane::tools::ToolId) -> agentplane::tools::Destination {
        agentplane::tools::Destination::Local
    }
}

const TRANSFER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  identity: { role: Move funds. }
  capabilities: { provides: [ledger.transfer] }
  input:
    schema:
      type: object
      additionalProperties: false
      required: [recipient]
      properties:
        recipient: { type: string }
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      max_sensitivity: internal
      protected_fields:
        - path: /recipient
          FIELD_RULE
  execution: { kind: call }
  budgets: {}
"#;

fn transfer_plane(rule: &str) -> (Arc<Runtime>, Arc<Recorder>, McpHttp) {
    let manifest = Manifest::parse(&TRANSFER.replace("FIELD_RULE", rule)).expect("manifest");
    let recorder = Arc::new(Recorder::default());
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let plane = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("mcp")
        .policy(Arc::new(Except(&[])))
        .tools(
            Arc::new(agentplane::tools::ToolCatalog::from_manifest(&manifest)),
            Arc::clone(&recorder) as Arc<dyn agentplane::tools::ToolClient>,
        )
        .agent(agentplane::runtime::Agent::new(&manifest))
        .build();
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let http = McpHttp::new(server, tokens(), &HttpConfig::new()).expect("listener");
    (plane, recorder, http)
}

fn transfer() -> CallToolRequestParams {
    CallToolRequestParams::new("ledger.transfer").with_arguments(
        json!({ "recipient": "treasury" })
            .as_object()
            .cloned()
            .expect("object"),
    )
}

/// **A served caller's input stays untrusted at the field gate**: it cannot
/// fill a `require_trusted` field, and `allowed_sources` naming it admits that
/// caller and nobody else.
#[tokio::test]
async fn a_served_caller_cannot_fill_a_trusted_field() {
    let (_plane, recorder, http) = transfer_plane("require_trusted: true");
    let bot = connect(&listen(&http).await, BOT).await;
    let answer = bot.call_tool(transfer()).await.expect("answered");
    assert_eq!(answer.is_error, Some(true), "{answer:?}");
    assert!(
        recorder.calls.lock().expect("calls").is_empty(),
        "a served caller filled a field that requires trusted input"
    );
    bot.cancel().await.expect("shutdown");

    let (_plane, recorder, http) = transfer_plane("allowed_sources: [\"peer:bot\"]");
    let url = listen(&http).await;
    let bot = connect(&url, BOT).await;
    let eve = connect(&url, EVE).await;
    let answer = bot.call_tool(transfer()).await.expect("answered");
    assert_ne!(
        answer.is_error,
        Some(true),
        "the named caller was refused: {answer:?}"
    );
    let answer = eve.call_tool(transfer()).await.expect("answered");
    assert_eq!(
        answer.is_error,
        Some(true),
        "a caller the field does not name filled it"
    );
    assert_eq!(
        recorder.calls.lock().expect("calls").len(),
        1,
        "only the named caller's call ran"
    );
    bot.cancel().await.expect("shutdown");
    eve.cancel().await.expect("shutdown");
}

/// One request to the router, as a `2025-11-25` host sends it: the status, the
/// session the response names, and — for a finite response — the body.
async fn legacy(
    http: &McpHttp,
    method: &str,
    token: &str,
    session: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Option<String>) {
    let bearer = format!("Bearer {token}");
    let mut request = Request::builder()
        .method(method)
        .uri("/mcp")
        .header("host", "127.0.0.1:8081")
        .header("authorization", bearer)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json");
    if let Some(session) = session {
        request = request
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25");
    }
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let response = http
        .router()
        .oneshot(request.body(body).expect("request"))
        .await
        .expect("infallible");
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    (response.status(), session)
}

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "legacy", "version": "0" }
        }
    })
}

/// **A `2025-11-25` session is its creator's.** Another caller naming it —
/// to resume its stream, post into it, or close it — is answered as a session
/// that does not exist, and the owner's session survives the attempt.
#[tokio::test]
async fn another_callers_session_is_no_session() {
    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);

    let (status, session) = legacy(&http, "POST", BOT, None, Some(initialize())).await;
    assert_eq!(status, StatusCode::OK, "the legacy handshake was refused");
    let session = session.expect("a 2025-11-25 handshake names a session");
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let (status, _) = legacy(&http, "POST", BOT, Some(&session), Some(initialized)).await;
    assert!(
        status.is_success(),
        "the owner could not use its session: {status}"
    );

    let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    for (method, body) in [("GET", None), ("POST", Some(list)), ("DELETE", None)] {
        let (status, _) = legacy(&http, method, EVE, Some(&session), body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "another caller's {method} reached the session"
        );
    }
    let (status, _) = legacy(&http, "DELETE", BOT, Some(&session), None).await;
    assert!(
        status.is_success(),
        "the owner's session did not survive another caller: {status}"
    );
}

/// **One caller holds a bounded number of sessions**: an `initialize` past
/// the bound is refused and leaves no session behind, and closing one makes
/// room — for that caller, while another caller is not counted against it.
#[tokio::test]
async fn a_caller_holds_a_bounded_number_of_sessions() {
    use agentplane::tools::serve_http::MAX_SESSIONS_PER_CALLER;

    let plane = auditor_plane(Except(&[]));
    let http = http(&plane, AUDITOR);
    let mut held = Vec::new();
    for _ in 0..MAX_SESSIONS_PER_CALLER {
        let (status, session) = legacy(&http, "POST", BOT, None, Some(initialize())).await;
        assert_eq!(status, StatusCode::OK);
        held.push(session.expect("a session"));
    }
    let (status, session) = legacy(&http, "POST", BOT, None, Some(initialize())).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a caller opened more sessions than the bound"
    );
    assert!(
        session.is_none(),
        "a refused handshake still named a session"
    );

    let (status, _) = legacy(&http, "POST", EVE, None, Some(initialize())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another caller was counted against this one"
    );

    let (status, _) = legacy(&http, "DELETE", BOT, Some(&held[0]), None).await;
    assert!(status.is_success());
    let (status, _) = legacy(&http, "POST", BOT, None, Some(initialize())).await;
    assert_eq!(status, StatusCode::OK, "closing a session made no room");
}

/// **A request that arrived over HTTP with no caller is refused**, whoever
/// mounted the catalogue: served through rmcp's own HTTP service rather than
/// [`McpHttp`], a call is not admitted as the anonymous stdio host.
#[tokio::test]
async fn a_catalogue_mounted_over_http_without_its_guard_admits_nothing() {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    let plane = auditor_plane(Except(&[]));
    let manifest = Manifest::parse(AUDITOR).expect("manifest");
    let server = McpServer::new(Arc::clone(&plane), &[manifest]).expect("served");
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().route_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, router).await });

    let client = connect(&format!("http://{addr}/mcp"), BOT).await;
    let called = client.call_tool(audit("GL-1", None)).await;
    assert!(
        called.is_err(),
        "a call with no authenticated caller was answered: {called:?}"
    );
    assert!(
        runs(&plane).await.is_empty(),
        "an unauthenticated HTTP request was admitted as the stdio host"
    );
    client.cancel().await.expect("shutdown");
}

/// **One idempotency key sent to two tools is two calls**: the second is
/// never answered with a replay of the first tool's run.
#[tokio::test]
async fn one_key_sent_to_two_tools_is_two_calls() {
    let plane = auditor_plane(Except(&[]));
    let both = AUDITOR.replace(
        "provides: [audit.anomaly-detection]",
        "provides: [audit.anomaly-detection, audit.reconcile]",
    );
    let http = http(&plane, &both);
    let client = connect(&listen(&http).await, BOT).await;

    client
        .call_tool(audit("GL-1", Some("call-9")))
        .await
        .expect("first tool");
    let mut other = audit("GL-2", Some("call-9"));
    other.name = "audit.reconcile".into();
    let answer = client.call_tool(other).await.expect("second tool");
    assert_eq!(
        runs(&plane).await.len(),
        2,
        "the second tool was answered with the first tool's run"
    );
    assert!(
        format!("{answer:?}").contains("GL-2"),
        "the second tool's answer is not its own run's: {answer:?}"
    );
    client.cancel().await.expect("shutdown");
}
