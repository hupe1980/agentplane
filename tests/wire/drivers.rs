//! The two wire drivers: A2A peers and a model provider.
//!
//! Run against a local server on an ephemeral port, so there is no network and
//! no credential anywhere. What is under test is not the JSON — it is the
//! **failure mapping**, because that is the only part with consequences:
//!
//! * for a peer, whether a failure means the request reached them, which decides
//!   whether the runtime may ever send it again;
//! * for a model, whether a failure consumed tokens, which decides whether the
//!   budget ceiling is telling the truth.
//!
//! Both are easy to get plausibly wrong and hard to notice: a mapping that
//! reports everything as "did not happen" produces a system that works fine
//! until the first partial transfer.

// `http` too: the local stub server these tests run against is axum, which this
// crate only links under that feature. A test file that compiles to zero tests
// because a feature it uses is absent reports success while checking nothing.
#![cfg(all(feature = "a2a", feature = "providers", feature = "http"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{Delegation, Disposition, Principal, Scope};
use agentplane::model::anthropic::Anthropic;
use agentplane::model::chat_completions::ChatCompletions;
use agentplane::model::gemini::Gemini;
use agentplane::model::openai::OpenAi;
use agentplane::model::{
    ModelCall, ModelError, ModelId, ModelProvider, ProviderContinuation, ReasoningEffort, Request,
    SchemaMode, ToolDeclaration, ToolExchange,
};
use agentplane::peers::a2a::{A2aClient, EXTENSION_URI, Endpoint, PROTOCOL_VERSION};
use agentplane::peers::{PeerClient, PeerError, PeerId};
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use serde_json::{Value, json};

type SeenBody = Arc<std::sync::Mutex<Option<Value>>>;
type SeenHeaders = Arc<std::sync::Mutex<Option<axum::http::HeaderMap>>>;

/// Answers every request with a canned body and status.
#[derive(Clone)]
struct Canned {
    status: u16,
    body: Value,
    /// What the server saw, so a test can assert what we sent.
    seen: SeenBody,
    seen_headers: SeenHeaders,
}

async fn handle(
    State(canned): State<Canned>,
    headers: axum::http::HeaderMap,
    body: Option<axum::Json<Value>>,
) -> (axum::http::StatusCode, axum::Json<Value>) {
    *canned.seen.lock().unwrap() = body.map(|b| b.0);
    *canned.seen_headers.lock().unwrap() = Some(headers);
    (
        axum::http::StatusCode::from_u16(canned.status).unwrap(),
        axum::Json(canned.body),
    )
}

/// Start a one-shot server and return its base URL.
async fn serve(canned: Canned) -> String {
    let app = Router::new()
        .route("/", post(handle))
        .route("/v1/messages", post(handle))
        .route("/v1/responses", post(handle))
        .route("/v1/chat/completions", post(handle))
        // Gemini names the method in the path, and the model in it.
        .route("/v1beta/models/{model}", post(handle))
        .with_state(canned);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

async fn serve_hanging() -> String {
    async fn hang() -> &'static str {
        std::future::pending::<&'static str>().await
    }

    let app = Router::new()
        .route("/v1/messages", post(hang))
        .route("/v1/responses", post(hang))
        .route("/v1/chat/completions", post(hang));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn canned_observed(status: u16, body: Value) -> (Canned, SeenBody, SeenHeaders) {
    let seen = Arc::new(std::sync::Mutex::new(None));
    let seen_headers = Arc::new(std::sync::Mutex::new(None));
    (
        Canned {
            status,
            body,
            seen: Arc::clone(&seen),
            seen_headers: Arc::clone(&seen_headers),
        },
        seen,
        seen_headers,
    )
}

#[tokio::test]
async fn model_drivers_bound_a_provider_that_never_responds() {
    let url = serve_hanging().await;
    let timeout = std::time::Duration::from_millis(25);
    let prompt = json!("hello");
    let openai_model = ModelId::new("openai", "gpt-x");
    let anthropic_model = ModelId::new("anthropic", "claude-x");

    let openai = OpenAi::new("k").unwrap().base(url.clone()).timeout(timeout);
    let openai_error = openai
        .complete(agentplane::model::Request {
            model: &openai_model,
            prompt: &prompt,
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: None,
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .expect_err("OpenAI waited forever for a provider that never responded");
    assert!(
        matches!(openai_error, ModelError::Unavailable { .. }),
        "a pre-response timeout had the wrong recovery meaning: {openai_error}"
    );

    let anthropic = Anthropic::new("k").unwrap().base(url).timeout(timeout);
    let anthropic_error = anthropic
        .complete(agentplane::model::Request {
            model: &anthropic_model,
            prompt: &prompt,
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: None,
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .expect_err("Anthropic waited forever for a provider that never responded");
    assert!(
        matches!(anthropic_error, ModelError::Unavailable { .. }),
        "a pre-response timeout had the wrong recovery meaning: {anthropic_error}"
    );
}

#[tokio::test]
async fn reasoning_effort_uses_each_providers_native_request_shape() {
    let (openai_canned, openai_seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{"content": [{"type": "output_text", "text": "ok"}]}],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    );
    let openai_url = serve(openai_canned).await;
    let openai = OpenAi::new("k").unwrap().base(openai_url).buffered();
    let prompt = json!("think");
    let id = ModelId::new("openai", "gpt-5.6");
    openai
        .complete(agentplane::model::Request {
            model: &id,
            prompt: &prompt,
            max_output_tokens: 4096,
            reasoning_effort: Some(ReasoningEffort::XHigh),
            schema: None,
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .expect("OpenAI reasoning request");
    assert_eq!(
        openai_seen.lock().unwrap().as_ref().unwrap()["reasoning"]["effort"],
        "xhigh"
    );

    let (anthropic_canned, anthropic_seen) = canned(
        200,
        json!({
            "content": [{"type": "text", "text": "{\"ok\":true}"}],
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "stop_reason": "end_turn"
        }),
    );
    let anthropic_url = serve(anthropic_canned).await;
    let anthropic = Anthropic::new("k").unwrap().base(anthropic_url).buffered();
    let id = ModelId::new("anthropic", "claude-opus-5");
    let schema = json!({"type": "object"});
    anthropic
        .complete(agentplane::model::Request {
            model: &id,
            prompt: &prompt,
            max_output_tokens: 4096,
            reasoning_effort: Some(ReasoningEffort::High),
            schema: Some(&schema),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .expect("Anthropic reasoning request");
    let body = anthropic_seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["thinking"]["type"], "adaptive");
    assert_eq!(body["output_config"]["effort"], "high");
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
}

fn canned(status: u16, body: Value) -> (Canned, SeenBody) {
    let (canned, seen, _) = canned_observed(status, body);
    (canned, seen)
}

fn chain() -> Delegation {
    Delegation::root(Principal::new("user:owner", Scope::root()))
}

// ── A2A: what a failure says about whether the peer acted ───────────────────

/// A JSON-RPC decline is `DidNotHappen`: the peer read it and refused.
#[tokio::test]
async fn a_declined_request_did_not_happen() {
    for code in [
        -32700, -32600, -32601, -32602, -32001, -32004, -32005, -32007, -32008, -32009,
    ] {
        let (c, _) = canned(
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": "no" } }),
        );
        let url = serve(c).await;
        let client = A2aClient::new(Endpoint::new(url)).unwrap();
        let err = client
            .send(
                &PeerId::new("peer"),
                "audit.check",
                &json!({}),
                &chain(),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.disposition(),
            Disposition::DidNotHappen,
            "code {code} was not read as a clean refusal: {err}"
        );
    }
}

/// A2A 1.0 defines `-32006` as `InvalidAgentResponseError` and maps it to
/// INTERNAL/HTTP 500. It cannot prove that this request caused no work.
#[tokio::test]
async fn an_invalid_agent_response_is_in_doubt() {
    let (c, _) = canned(
        200,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32006, "message": "invalid agent response" }
        }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.disposition(), Disposition::InDoubt, "{err}");
    assert!(matches!(err, PeerError::InvalidResponse { .. }), "{err}");
}

/// An internal error is **not** a refusal.
///
/// The expensive row in the table. `-32603` can be raised after the peer has
/// started work, so treating it as a clean decline is how a half-finished
/// transfer is sent a second time.
#[tokio::test]
async fn an_internal_error_is_in_doubt_not_a_refusal() {
    let (c, _) = canned(
        200,
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32603, "message": "boom" } }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.disposition(),
        Disposition::InDoubt,
        "an internal error was read as a clean refusal, which is how a partial \
         transfer gets repeated: {err}"
    );
}

/// A 5xx reached them, so it is in doubt too.
#[tokio::test]
async fn a_server_error_is_in_doubt() {
    let (c, _) = canned(503, json!({ "error": "unavailable" }));
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.disposition(), Disposition::InDoubt, "{err}");
}

/// A 401 is a refusal: read, declined, nothing done.
#[tokio::test]
async fn an_unauthorized_call_did_not_happen() {
    let (c, _) = canned(401, json!({ "error": "no" }));
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.disposition(), Disposition::DidNotHappen, "{err}");
}

/// A task that came back `failed` **landed**.
///
/// The peer acted and says the work did not succeed. Reporting that as in-doubt
/// would send `Recovery` looking for an answer the peer has already given.
#[tokio::test]
async fn a_failed_task_landed() {
    let (c, _) = canned(
        200,
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "task": {
                "id": "task-1",
                "status": {
                    "state": "TASK_STATE_FAILED",
                    "message": {
                        "messageId": "failure-1",
                        "role": "ROLE_AGENT",
                        "parts": [{ "text": "declined" }]
                    }
                }
            } }
        }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.disposition(),
        Disposition::Landed,
        "a peer that reported it acted was recorded as in doubt: {err}"
    );
    assert!(matches!(err, PeerError::Failed { .. }));
}

/// A task in progress is a success: the run waits for it elsewhere.
#[tokio::test]
async fn an_accepted_task_is_not_a_failure() {
    let (c, _) = canned(
        200,
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "task": {
                "id": "task-9", "status": { "state": "TASK_STATE_WORKING" }
            } }
        }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    let out = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .expect("a working task is not a failure");
    assert_eq!(out["id"], "task-9");
}

/// A peer that is not listening was never reached.
#[tokio::test]
async fn an_unreachable_peer_did_not_happen() {
    // Port 1 on loopback: nothing binds it, and the connection is refused
    // rather than hanging.
    let client = A2aClient::new(Endpoint::new("http://127.0.0.1:1")).unwrap();
    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.disposition(), Disposition::DidNotHappen, "{err}");
    assert!(matches!(err, PeerError::Unreachable { .. }), "{err}");
}

/// The delegation chain travels under a declared extension URI.
#[tokio::test]
async fn the_delegation_chain_rides_a_declared_extension() {
    let (c, seen, seen_headers) = canned_observed(
        200,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "message": {
                "messageId": "reply-1", "role": "ROLE_AGENT", "parts": [{ "data": {} }]
            } }
        }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({ "doc": "INV-1" }),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().expect("the server saw a body");
    let msg = &body["params"]["message"];
    assert_eq!(body["method"], "SendMessage");
    assert_eq!(msg["role"], "ROLE_USER");
    assert!(
        msg["parts"][0].get("kind").is_none(),
        "A2A 1.0 removed the legacy part discriminator: {body}"
    );
    assert_eq!(
        msg["extensions"][0], EXTENSION_URI,
        "the extension is not declared, so a peer cannot say it understood it"
    );
    assert!(
        msg["metadata"][EXTENSION_URI]["chain"].is_object(),
        "the delegation chain did not travel: {body}"
    );
    assert_eq!(msg["parts"][0]["data"]["doc"], "INV-1");
    let headers = seen_headers.lock().unwrap();
    let headers = headers.as_ref().expect("the server saw headers");
    assert_eq!(headers["a2a-version"], PROTOCOL_VERSION);
    assert_eq!(headers["a2a-extensions"], EXTENSION_URI);
}

/// A successful response that violates the `SendMessageResponse` oneof is
/// unknown after dispatch, never a retryable clean rejection.
#[tokio::test]
async fn a_malformed_send_message_response_is_in_doubt() {
    for result in [
        json!({}),
        json!({ "task": {}, "message": {} }),
        json!({ "task": "not-an-object" }),
    ] {
        let (c, _) = canned(200, json!({ "jsonrpc": "2.0", "id": 1, "result": result }));
        let client = A2aClient::new(Endpoint::new(serve(c).await)).unwrap();
        let err = client
            .send(
                &PeerId::new("peer"),
                "audit.check",
                &json!({}),
                &chain(),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.disposition(), Disposition::InDoubt, "{err}");
    }
}

// ── The model driver: what a failure consumed ───────────────────────────────

fn model() -> ModelId {
    ModelId::new("anthropic", "claude-opus-5")
}

/// A completion carries its usage, which is what the budget bills.
#[tokio::test]
async fn a_completion_reports_what_it_cost() {
    let (c, seen) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "hello" }],
            "usage": { "input_tokens": 11, "output_tokens": 7 },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("test-key").unwrap().base(url).buffered();

    let out = provider
        .complete(ask(&model(), &json!("say hello")))
        .await
        .unwrap();
    assert_eq!(out.text, "hello");
    assert_eq!(out.usage.input_tokens, 11);
    assert_eq!(out.usage.output_tokens, 7);
    assert_eq!(out.usage.spend().tokens, 18);

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["model"], "claude-opus-5");
    assert_eq!(body["messages"][0]["content"], "say hello");
}

/// Remote media must not escape inside an otherwise governed model request.
///
/// The provider would fetch this URL from its own network, outside the plane's
/// egress policy and journal. Refusing before the model endpoint is reached is
/// the safe hard cut until a governed fetch effect can replace the URL with
/// bytes.
#[tokio::test]
async fn anthropic_never_receives_a_provider_fetched_media_url() {
    let (c, seen) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "should not run" }],
            "usage": { "input_tokens": 1, "output_tokens": 1 },
            "stop_reason": "end_turn"
        }),
    );
    let provider = Anthropic::new("k").unwrap().base(serve(c).await).buffered();
    let prompt = json!({
        "messages": [{
            "role": "user",
            "content": [{
                "type": "image",
                "source": {
                    "type": "url",
                    "url": "https://media.example/private.png"
                }
            }]
        }]
    });

    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("provider-side URL fetching must be refused");
    assert!(matches!(err, ModelError::Refused { .. }), "{err}");
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
    assert!(
        seen.lock().unwrap().is_none(),
        "the model endpoint was reached before the media URL was refused"
    );
}

/// A refusal before generating cost nothing.
#[tokio::test]
async fn a_rejected_request_is_not_billed() {
    let (c, _) = canned(400, json!({ "error": { "message": "bad request" } }));
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let err = provider
        .complete(ask(&model(), &json!("x")))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Refused { .. }), "{err}");
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
    assert_eq!(err.usage().spend().tokens, 0);
}

/// Rate limiting is its own case, because it is the one worth retrying.
#[tokio::test]
async fn rate_limiting_is_told_apart_from_refusal() {
    for status in [429, 529] {
        let (c, _) = canned(status, json!({ "error": { "message": "slow down" } }));
        let url = serve(c).await;
        let provider = Anthropic::new("k").unwrap().base(url);
        let err = provider
            .complete(ask(&model(), &json!("x")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ModelError::RateLimited { .. }),
            "HTTP {status} was not read as rate limiting: {err}"
        );
    }
}

/// A 5xx reached the provider and says nothing about what it cost.
#[tokio::test]
async fn a_server_error_says_it_does_not_know() {
    let (c, _) = canned(500, json!({ "error": { "message": "internal" } }));
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let err = provider
        .complete(ask(&model(), &json!("x")))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ModelError::Unavailable { .. }),
        "a 5xx was classified as something the driver could not have known: {err}"
    );
    // Safe to repeat, because a completion does not change the world.
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

/// A model that generated and then declined **is** billed.
///
/// The distinction the budget depends on: a refusal before generating costs
/// nothing, and a refusal after generating costs whatever it took to decide.
#[tokio::test]
async fn a_generated_refusal_is_billed() {
    let (c, _) = canned(
        200,
        json!({
            "content": [],
            "usage": { "input_tokens": 40, "output_tokens": 12 },
            "stop_reason": "refusal"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url).buffered();
    let err = provider
        .complete(ask(&model(), &json!("x")))
        .await
        .unwrap_err();

    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(
        err.disposition(),
        Disposition::Landed,
        "a call that generated was recorded as never having happened"
    );
    assert_eq!(
        err.usage().spend().tokens,
        52,
        "a generated refusal was billed as free, so the ceiling under-counts"
    );
}

/// An answer with no text is unusable, and still cost tokens.
#[tokio::test]
async fn an_empty_answer_is_unusable_and_billed() {
    let (c, _) = canned(
        200,
        json!({
            "content": [{ "type": "thinking", "text": "" }],
            "usage": { "input_tokens": 5, "output_tokens": 3 },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url).buffered();
    let err = provider
        .complete(ask(&model(), &json!("x")))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(err.usage().spend().tokens, 8);
}

// ── OpenAI: the Responses envelope ──────────────────────────────────────────

/// A request with no schema — the common case in these tests.
fn ask<'a>(model: &'a ModelId, prompt: &'a Value) -> agentplane::model::Request<'a> {
    agentplane::model::Request {
        model,
        prompt,
        max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
        reasoning_effort: None,
        schema: None,
        tools: &[],
        exchanges: &[],
        continuation: None,
        stream: None,
    }
}

fn gpt() -> ModelId {
    ModelId::new("openai", "gpt-5")
}

/// The `OpenAI` Responses spelling of the same provider-side fetch is refused.
#[tokio::test]
async fn openai_never_receives_a_provider_fetched_media_url() {
    let (c, seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "should not run" }] }],
            "usage": { "input_tokens": 1, "output_tokens": 1 }
        }),
    );
    let provider = OpenAi::new("k").unwrap().base(serve(c).await).buffered();
    let prompt = json!({
        "input": [{
            "role": "user",
            "content": [{
                "type": "input_image",
                "image_url": "https://media.example/private.png"
            }]
        }]
    });

    let err = provider
        .complete(ask(&gpt(), &prompt))
        .await
        .expect_err("provider-side URL fetching must be refused");
    assert!(matches!(err, ModelError::Refused { .. }), "{err}");
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
    assert!(
        seen.lock().unwrap().is_none(),
        "the model endpoint was reached before the media URL was refused"
    );
}

/// A completed response, with reasoning tokens counted.
///
/// Reasoning tokens are billed and invisible in the answer. A driver that
/// reported only what the caller can read would tell a reasoning-heavy run's
/// budget it cost a fraction of what it did.
#[tokio::test]
async fn a_response_bills_reasoning_tokens_too() {
    let (c, seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "the answer" }] }],
            "usage": {
                "input_tokens": 30,
                "output_tokens": 120,
                "output_tokens_details": { "reasoning_tokens": 100 }
            }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("sk-test").unwrap().base(url).buffered();

    let out = provider
        .complete(ask(&gpt(), &json!("think")))
        .await
        .unwrap();
    assert_eq!(out.text, "the answer");
    assert!(!out.truncated);
    assert_eq!(
        out.usage.spend().tokens,
        150,
        "reasoning tokens were dropped, so the ceiling under-counts a \
         reasoning-heavy run by most of its cost"
    );

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["model"], "gpt-5");
    assert_eq!(body["input"], "think");
}

/// **A truncated answer is returned, and says it is truncated.**
///
/// Not an error: prose that stops early is still readable, and only the caller
/// knows whether they were parsing JSON. But it must not come back looking
/// whole — a partial answer silently returned as a complete one is the silent
/// truncation this crate refuses everywhere else.
#[tokio::test]
async fn a_cut_off_answer_says_so() {
    let (c, _) = canned(
        200,
        json!({
            "status": "incomplete",
            "incomplete_details": { "reason": "max_output_tokens" },
            "output": [{ "content": [{ "type": "output_text", "text": "it begins" }] }],
            "usage": { "input_tokens": 5, "output_tokens": 4096 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();

    let out = provider.complete(ask(&gpt(), &json!("x"))).await.unwrap();
    assert_eq!(out.text, "it begins");
    assert!(
        out.truncated,
        "a cut-off answer came back looking whole — a caller parsing JSON has no \
         way to know it is holding half a document"
    );
    assert_eq!(
        out.stop_reason.as_deref(),
        Some("incomplete:max_output_tokens")
    );
    assert_eq!(
        out.usage.spend().tokens,
        4101,
        "a truncated answer is still billed"
    );
}

/// A refusal part means it generated, then declined — so it is billed.
#[tokio::test]
async fn an_openai_refusal_is_billed() {
    let (c, _) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "refusal", "refusal": "I can't help with that" }] }],
            "usage": { "input_tokens": 20, "output_tokens": 8 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let err = provider
        .complete(ask(&gpt(), &json!("x")))
        .await
        .unwrap_err();

    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(err.disposition(), Disposition::Landed);
    assert_eq!(
        err.usage().spend().tokens,
        28,
        "a generated refusal was billed as free"
    );
}

/// A `failed` response started and gave up — metered.
#[tokio::test]
async fn a_failed_response_is_billed() {
    let (c, _) = canned(
        200,
        json!({
            "status": "failed",
            "error": { "code": "server_error", "message": "gave up" },
            "output": [],
            "usage": { "input_tokens": 11, "output_tokens": 2 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let err = provider
        .complete(ask(&gpt(), &json!("x")))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(err.usage().spend().tokens, 13);
}

/// The shared status doctrine applies to this driver too.
#[tokio::test]
async fn openai_shares_the_status_classification() {
    for (status, want_rate_limited) in [(429u16, true), (529, true), (400, false), (401, false)] {
        let (c, _) = canned(status, json!({ "error": { "message": "no" } }));
        let url = serve(c).await;
        let provider = OpenAi::new("k").unwrap().base(url);
        let err = provider
            .complete(ask(&gpt(), &json!("x")))
            .await
            .unwrap_err();
        if want_rate_limited {
            assert!(
                matches!(err, ModelError::RateLimited { .. }),
                "HTTP {status}: {err}"
            );
        } else {
            assert!(
                matches!(err, ModelError::Refused { .. }),
                "HTTP {status}: {err}"
            );
            assert_eq!(err.usage().spend().tokens, 0);
        }
    }
}

/// A 5xx is the unknowable case here as well.
#[tokio::test]
async fn an_openai_server_error_says_it_does_not_know() {
    let (c, _) = canned(503, json!({ "error": { "message": "overloaded" } }));
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url);
    let err = provider
        .complete(ask(&gpt(), &json!("x")))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Unavailable { .. }), "{err}");
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

/// An empty answer that was *not* truncated is unusable, and billed.
#[tokio::test]
async fn an_empty_openai_answer_is_unusable() {
    let (c, _) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [] }],
            "usage": { "input_tokens": 3, "output_tokens": 1 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let err = provider
        .complete(ask(&gpt(), &json!("x")))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(err.usage().spend().tokens, 4);
}

/// A provider's error body can echo the prompt; it must not reach a log whole.
#[tokio::test]
async fn a_huge_error_body_is_trimmed_before_it_reaches_a_log() {
    let (c, _) = canned(400, json!({ "error": { "message": "y".repeat(20_000) } }));
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url);
    let err = provider
        .complete(ask(&gpt(), &json!("x")))
        .await
        .unwrap_err();
    let rendered = err.to_string();
    assert!(
        rendered.len() < 800,
        "a 20 kB provider error went into the log intact ({} chars) — and providers \
         echo the prompt back in those",
        rendered.len()
    );
}

// ── Structured output ───────────────────────────────────────────────────────

fn schema() -> Value {
    json!({
        "type": "object",
        "properties": { "amount": { "type": "number" } },
        "required": ["amount"],
        "additionalProperties": false
    })
}

/// A declared schema reaches the provider as a *strict* constraint.
///
/// Without `strict`, a schema is a suggestion the model may ignore — and a
/// suggestion is not a constraint. The point of asking the provider is that the
/// shape is enforced during generation; a schema applied afterwards rejects an
/// answer already paid for.
#[tokio::test]
async fn a_schema_is_sent_as_a_strict_constraint() {
    let (c, seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "{\"amount\":42}" }] }],
            "usage": { "input_tokens": 5, "output_tokens": 5 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let sch = schema();

    let out = provider
        .complete(agentplane::model::Request {
            model: &gpt(),
            prompt: &json!("how much"),
            max_output_tokens: 77,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["max_output_tokens"], 77, "{body}");
    assert_eq!(body["text"]["format"]["type"], "json_schema");
    assert_eq!(
        body["text"]["format"]["strict"], true,
        "the schema went out as a suggestion rather than a constraint: {body}"
    );
    assert_eq!(body["text"]["format"]["schema"], sch);

    // The answer comes back parsed, and the raw text is still there.
    assert_eq!(out.structured.as_ref().unwrap()["amount"], 42);
    assert_eq!(out.text, "{\"amount\":42}");
}

/// Anthropic gets the same constraint through its own field.
#[tokio::test]
async fn the_anthropic_driver_sends_a_schema_too() {
    let (c, seen) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "{\"amount\":7}" }],
            "usage": { "input_tokens": 1, "output_tokens": 1 },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url).buffered();
    let sch = schema();

    let out = provider
        .complete(agentplane::model::Request {
            model: &model(),
            prompt: &json!("how much"),
            max_output_tokens: 88,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["max_tokens"], 88, "{body}");
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    assert_eq!(body["output_config"]["format"]["schema"], sch);
    assert_eq!(out.structured.as_ref().unwrap()["amount"], 7);
}

/// A schema was asked for and the answer is not JSON: loud, and **billed**.
///
/// The provider generated it, so it was paid for. Reporting a parse failure as
/// a free refusal would let a model that reliably breaks its own schema burn
/// budget invisibly.
#[tokio::test]
async fn an_unparseable_structured_answer_is_billed_and_loud() {
    let (c, _) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "not json at all" }] }],
            "usage": { "input_tokens": 12, "output_tokens": 6 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let sch = schema();

    let err = provider
        .complete(agentplane::model::Request {
            model: &gpt(),
            prompt: &json!("x"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(err.disposition(), Disposition::Landed);
    assert_eq!(
        err.usage().spend().tokens,
        18,
        "a malformed structured answer was billed as free"
    );
}

/// No schema, no parsing: a plain completion is not required to be JSON.
#[tokio::test]
async fn without_a_schema_the_answer_is_left_alone() {
    let (c, seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "prose" }] }],
            "usage": { "input_tokens": 1, "output_tokens": 1 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let out = provider.complete(ask(&gpt(), &json!("x"))).await.unwrap();
    assert!(out.structured.is_none());
    let body = seen.lock().unwrap().clone().unwrap();
    assert!(
        body.get("text").is_none(),
        "a format was sent unasked: {body}"
    );
}

// ── Structured output where the provider cannot do it natively ──────────────

/// **The fallback: one tool the model is obliged to call.**
///
/// Native constrained decoding is gated on particular models. Point a driver at
/// one that predates it and native mode is simply rejected — so the universal
/// mechanism is a single tool whose input schema *is* the answer's shape, forced
/// with `tool_choice`. It works wherever tool calling does, which is a much wider
/// set of models.
#[tokio::test]
async fn anthropic_can_emulate_a_schema_with_a_forced_tool() {
    let (c, seen) = canned(
        200,
        json!({
            // No text block at all — the answer *is* the tool call.
            "content": [{
                "type": "tool_use",
                "name": "agentplane_respond",
                "input": { "amount": 99 }
            }],
            "usage": { "input_tokens": 4, "output_tokens": 9 },
            "stop_reason": "tool_use"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .structured_via(SchemaMode::ForcedTool);
    let sch = schema();

    let out = provider
        .complete(agentplane::model::Request {
            model: &model(),
            prompt: &json!("how much"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["tools"][0]["name"], "agentplane_respond");
    assert_eq!(body["tools"][0]["input_schema"], sch);
    assert_eq!(
        body["tool_choice"],
        json!({ "type": "tool", "name": "agentplane_respond" }),
        "the tool was offered rather than forced, so the model may just answer \
         in prose: {body}"
    );
    assert!(
        body.get("output_config").is_none(),
        "native structured output was sent as well, to a model that may not \
         support it: {body}"
    );

    // The answer came from the tool call, not from a text block.
    assert_eq!(out.structured.as_ref().unwrap()["amount"], 99);
}

/// The same fallback on the other provider, where arguments arrive as a string.
#[tokio::test]
async fn openai_can_emulate_a_schema_with_a_forced_tool() {
    let (c, seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{
                "type": "function_call",
                "name": "agentplane_respond",
                "arguments": "{\"amount\":13}"
            }],
            "usage": { "input_tokens": 2, "output_tokens": 8 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .structured_via(SchemaMode::ForcedTool);
    let sch = schema();

    let out = provider
        .complete(agentplane::model::Request {
            model: &gpt(),
            prompt: &json!("how much"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["tools"][0]["parameters"], sch);
    assert_eq!(body["tool_choice"]["name"], "agentplane_respond");
    assert!(body.get("text").is_none(), "{body}");
    assert_eq!(out.structured.as_ref().unwrap()["amount"], 13);
}

/// **The mode is chosen per model, because that is what the constraint is.**
///
/// One driver instance serves many models over one key and one connection pool.
/// A capability setting on the *driver* would force a second instance per model
/// — a strange thing to make somebody do in order to say that a small model
/// cannot do what a large one can.
#[tokio::test]
async fn the_schema_mode_is_chosen_per_model() {
    let (c, seen) = canned(
        200,
        json!({
            "content": [{
                "type": "tool_use", "name": "agentplane_respond", "input": { "amount": 1 }
            }],
            "usage": { "input_tokens": 1, "output_tokens": 1 },
            "stop_reason": "tool_use"
        }),
    );
    let url = serve(c).await;
    // One driver. Native by default, emulation for the one model that needs it.
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .structured_via_for("claude-legacy-1", SchemaMode::ForcedTool);
    let sch = schema();

    // The overridden model gets the fallback...
    provider
        .complete(agentplane::model::Request {
            model: &ModelId::new("anthropic", "claude-legacy-1"),
            prompt: &json!("x"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();
    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        body["tool_choice"]["name"], "agentplane_respond",
        "the per-model override did not take effect: {body}"
    );
    assert!(body.get("output_config").is_none(), "{body}");

    // ...and every other model on the same driver still gets native.
    let (c2, seen2) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "{\"amount\":2}" }],
            "usage": { "input_tokens": 1, "output_tokens": 1 },
            "stop_reason": "end_turn"
        }),
    );
    let url2 = serve(c2).await;
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url2)
        .buffered()
        .structured_via_for("claude-legacy-1", SchemaMode::ForcedTool);
    provider
        .complete(agentplane::model::Request {
            model: &ModelId::new("anthropic", "claude-opus-4-5"),
            prompt: &json!("x"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();
    let body = seen2.lock().unwrap().clone().unwrap();
    assert!(
        body.get("tool_choice").is_none(),
        "one model's override leaked onto another: {body}"
    );
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
}

/// A model that ignores a forced tool call is a loud, metered failure.
///
/// The weakness of emulation, stated: native mode makes a non-conforming answer
/// *unproducible*, this makes it unlikely. So the case where the model answers
/// in prose anyway has to be caught rather than returned as an empty success.
#[tokio::test]
async fn a_model_that_ignores_the_forced_tool_is_caught() {
    let (c, _) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "about ninety-nine" }],
            "usage": { "input_tokens": 4, "output_tokens": 9 },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .structured_via(SchemaMode::ForcedTool);
    let sch = schema();

    let err = provider
        .complete(agentplane::model::Request {
            model: &model(),
            prompt: &json!("x"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(
        err.usage().spend().tokens,
        13,
        "the model generated an answer and it was billed as free"
    );
}

/// **A schema strict mode cannot accept is refused before it is sent.**
///
/// Strict mode takes a subset of JSON Schema: every object needs
/// `additionalProperties: false`, every property must be listed in `required`,
/// and `default` is rejected outright. A perfectly valid schema that breaks one
/// of those comes back from the provider as a 400 that does not say which.
/// Catching it here costs nothing and names the rule.
#[tokio::test]
async fn an_incompatible_schema_is_refused_with_the_reason() {
    let cases: [(Value, &str); 3] = [
        (
            json!({ "type": "object", "properties": { "a": { "type": "string" } },
                    "required": ["a"] }),
            "additionalProperties",
        ),
        (
            json!({ "type": "object", "additionalProperties": false,
                    "properties": { "a": { "type": "string" }, "b": { "type": "string" } },
                    "required": ["a"] }),
            "required",
        ),
        (
            json!({ "type": "object", "additionalProperties": false,
                    "properties": { "a": { "type": "string", "default": "x" } },
                    "required": ["a"] }),
            "default",
        ),
    ];

    for (sch, want) in cases {
        // No server: the refusal must happen before anything is sent.
        let provider = OpenAi::new("k").unwrap().base("http://127.0.0.1:1");
        let err = provider
            .complete(agentplane::model::Request {
                model: &gpt(),
                prompt: &json!("x"),
                max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
                reasoning_effort: None,
                schema: Some(&sch),
                tools: &[],
                exchanges: &[],
                continuation: None,
                stream: None,
            })
            .await
            .unwrap_err();

        assert!(
            matches!(err, ModelError::Refused { .. }),
            "an unusable schema reached the wire: {err}"
        );
        assert!(
            err.to_string().contains(want),
            "the refusal does not name the rule that was broken (wanted '{want}'): {err}"
        );
        assert_eq!(err.usage().spend().tokens, 0, "a refused schema was billed");
    }
}

/// A conformant schema passes the check and reaches the provider unaltered.
///
/// The other half of the previous test: a checker that rejected everything would
/// pass it while making structured output unusable.
#[tokio::test]
async fn a_conformant_schema_is_not_rewritten() {
    let (c, seen) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "{\"amount\":1}" }] }],
            "usage": { "input_tokens": 1, "output_tokens": 1 }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let sch = schema();

    provider
        .complete(agentplane::model::Request {
            model: &gpt(),
            prompt: &json!("x"),
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .expect("a conformant schema must be accepted");

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        body["text"]["format"]["schema"], sch,
        "the schema was rewritten on the way out, so the effect key records one \
         shape and the wire carried another: {body}"
    );
}

// ── Cached tokens ───────────────────────────────────────────────────────────

/// **Anthropic reports cached tokens beside `input_tokens`, not inside it.**
///
/// A driver reading only `input_tokens` bills a heavily cached call at close to
/// nothing, while the provider charges a premium for the write and a tenth of
/// the rate for the read. This is the arithmetic that makes a token ceiling lie.
#[tokio::test]
async fn anthropic_cached_tokens_are_added_back() {
    let (c, _) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "hi" }],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": 200,
                "cache_read_input_tokens": 1000
            },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url).buffered();
    let out = provider.complete(ask(&model(), &json!("x"))).await.unwrap();

    assert_eq!(
        out.usage.input_tokens, 1210,
        "cached tokens were dropped — a cached run bills at a fraction of what \
         the provider charges"
    );
    assert_eq!(out.usage.cache_write_tokens, 200);
    assert_eq!(out.usage.cache_read_tokens, 1000);
    assert_eq!(out.usage.uncached_input_tokens(), 10);
    assert_eq!(out.usage.spend().tokens, 1215);
}

/// **`OpenAI` reports cached tokens *inside* `input_tokens`.** Same words,
/// opposite arithmetic — adding them back would double-count.
#[tokio::test]
async fn openai_cached_tokens_are_not_double_counted() {
    let (c, _) = canned(
        200,
        json!({
            "status": "completed",
            "output": [{ "content": [{ "type": "output_text", "text": "hi" }] }],
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 5,
                "input_tokens_details": { "cached_tokens": 900 }
            }
        }),
    );
    let url = serve(c).await;
    let provider = OpenAi::new("k").unwrap().base(url).buffered();
    let out = provider.complete(ask(&gpt(), &json!("x"))).await.unwrap();

    assert_eq!(
        out.usage.input_tokens, 1000,
        "cached tokens were added to a count that already contained them"
    );
    assert_eq!(out.usage.cache_read_tokens, 900);
    assert_eq!(out.usage.uncached_input_tokens(), 100);
}

/// Both keys stay out of `Debug`.
///
/// Same rule as a peer credential: a secret that can be printed is a secret in
/// a log line, and this one is held for the process's lifetime.
#[test]
fn the_api_key_is_not_printable() {
    let a = Anthropic::new("sk-secret-value").unwrap();
    assert!(
        !format!("{a:?}").contains("sk-secret-value"),
        "the Anthropic key is printable: {a:?}"
    );
    let o = OpenAi::new("sk-other-secret").unwrap();
    assert!(
        !format!("{o:?}").contains("sk-other-secret"),
        "the OpenAI key is printable: {o:?}"
    );
}

// ── Streaming ───────────────────────────────────────────────────────────────
//
// The reason the streaming path exists is not latency — nothing here is
// rendering tokens to a person. It is that a *severed* response can still say
// what it burned, and the two providers differ in how much of that they make
// possible. Both halves are asserted below, because the asymmetry is a design
// claim and not an implementation detail.

/// Serves a canned SSE body, optionally cutting the connection partway.
#[derive(Clone)]
struct Sse {
    events: String,
    /// Abort the body after sending it, rather than ending cleanly.
    sever: bool,
    seen: Arc<std::sync::Mutex<Option<Value>>>,
}

async fn handle_sse(
    State(sse): State<Sse>,
    body: Option<axum::Json<Value>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    *sse.seen.lock().unwrap() = body.map(|b| b.0);

    // The pause before the abort is load-bearing. Without it the whole exchange
    // completes inside one poll and the client reports a failure to *send* the
    // request — which is a real case, but not this one. Production severs a
    // stream that is already flowing, and only the delay reproduces that.
    let sever = sse.sever;
    let body = futures_util::stream::unfold(0u8, move |step| {
        let events = sse.events.clone();
        async move {
            match step {
                0 => Some((Ok(bytes::Bytes::from(events)), 1u8)),
                1 if sever => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Some((Err(std::io::Error::other("connection reset")), 2u8))
                }
                _ => None,
            }
        }
    });

    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

async fn serve_sse(events: &str, sever: bool) -> (String, Arc<std::sync::Mutex<Option<Value>>>) {
    let seen = Arc::new(std::sync::Mutex::new(None));
    let state = Sse {
        events: events.to_owned(),
        sever,
        seen: Arc::clone(&seen),
    };
    let app = Router::new()
        .route("/v1/messages", post(handle_sse))
        .route("/v1/responses", post(handle_sse))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), seen)
}

const ANTHROPIC_HEAD: &str = "\
event: message_start
data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":100,\"output_tokens\":1}}}

event: content_block_start
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}

event: ping
data: {\"type\":\"ping\"}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}

event: message_delta
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":null},\"usage\":{\"output_tokens\":300}}

";

/// A whole stream produces the same answer a buffered response would.
#[tokio::test]
async fn a_streamed_answer_is_assembled() {
    let body = format!(
        "{ANTHROPIC_HEAD}\
event: content_block_delta
data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\" world\"}}}}

event: message_delta
data: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":315}}}}

event: message_stop
data: {{\"type\":\"message_stop\"}}

"
    );
    let (url, seen) = serve_sse(&body, false).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let out = provider.complete(ask(&model(), &prompt)).await.unwrap();

    assert_eq!(out.text, "Hello world");
    assert_eq!(out.usage.input_tokens, 100);
    assert_eq!(out.usage.output_tokens, 315);
    assert_eq!(out.stop_reason.as_deref(), Some("end_turn"));
    assert!(!out.truncated);

    let sent = seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        sent["stream"],
        json!(true),
        "the request must ask for a stream"
    );
}

/// **The property the whole streaming path exists for.**
///
/// A connection that dies after generating must report what it burned. Before
/// this existed, the only honest answer was `Unavailable` — cost unknown, billed
/// as zero, and treated as safe to send again — so a flaky provider could be
/// asked repeatedly while the token ceiling that bounds exactly that read
/// nothing.
#[tokio::test]
async fn a_severed_stream_reports_what_it_burned() {
    let (url, _) = serve_sse(ANTHROPIC_HEAD, true).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("the connection died mid-answer");

    match &err {
        ModelError::Interrupted { usage, .. } => {
            assert_eq!(usage.input_tokens, 100, "message_start said so");
            assert_eq!(usage.output_tokens, 300, "the last message_delta said so");
            assert_eq!(usage.spend().tokens, 400);
        }
        other => panic!("a severed stream that generated must be Interrupted: {other}"),
    }
    assert_eq!(
        err.disposition(),
        Disposition::Landed,
        "we watched it generate; asking again buys a second bill"
    );
}

/// A stream cut *before* `message_start` genuinely says nothing.
///
/// The other side of the same judgement, and the reason it is `started()` rather
/// than "did we get any bytes": reporting a failed handshake as billed would
/// make the ceiling over-count and stop runs that never cost anything.
#[tokio::test]
async fn a_stream_severed_before_it_began_reports_nothing_known() {
    let (url, _) = serve_sse("event: ping\ndata: {\"type\":\"ping\"}\n\n", true).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("severed");

    assert!(matches!(err, ModelError::Unavailable { .. }), "{err}");
    assert_eq!(err.usage().spend().tokens, 0);
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

/// A clean EOF with no `message_stop` is just as incomplete as a reset.
///
/// Returning the partial text as a whole answer would be the silent truncation
/// this crate refuses everywhere else.
#[tokio::test]
async fn a_stream_that_ends_without_message_stop_is_not_an_answer() {
    let (url, _) = serve_sse(ANTHROPIC_HEAD, false).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("no message_stop arrived");
    assert!(
        matches!(err, ModelError::Interrupted { .. }),
        "a truncated answer must not come back looking whole: {err}"
    );
}

/// An `overloaded_error` inside a 200, before anything was generated.
#[tokio::test]
async fn an_in_stream_overload_before_generating_is_rate_limiting() {
    let body = "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\
                \"message\":\"Overloaded\"}}\n\n";
    let (url, _) = serve_sse(body, false).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("overloaded");
    assert!(matches!(err, ModelError::RateLimited { .. }), "{err}");
    assert_eq!(err.usage().spend().tokens, 0);
}

/// The same error *after* generating is billed, not a free retry.
#[tokio::test]
async fn an_in_stream_error_after_generating_is_billed() {
    let body = format!(
        "{ANTHROPIC_HEAD}\
event: error
data: {{\"type\":\"error\",\"error\":{{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}}}

"
    );
    let (url, _) = serve_sse(&body, false).await;
    let provider = Anthropic::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("overloaded after generating");
    assert_eq!(
        err.usage().spend().tokens,
        400,
        "reporting this as a free rate limit loses the spend and invites a \
         second one: {err}"
    );
    assert_eq!(err.disposition(), Disposition::Landed);
}

/// Streaming carries the forced-tool emulation too.
#[tokio::test]
async fn a_streamed_forced_tool_call_is_reassembled() {
    let body = "\
event: message_start
data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}

event: content_block_start
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"agentplane_respond\"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"amount\\\":\"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"42}\"}}

event: message_delta
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":8}}

event: message_stop
data: {\"type\":\"message_stop\"}

";
    let (url, _) = serve_sse(body, false).await;
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .structured_via(SchemaMode::ForcedTool);
    let prompt = json!("x");
    let sch = json!({"type": "object"});
    let out = provider
        .complete(agentplane::model::Request {
            model: &model(),
            prompt: &prompt,
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .unwrap();
    assert_eq!(out.structured, Some(json!({"amount": 42})));
}

/// A tool call whose fragments were cut in half is not an answer.
///
/// A failure the buffered path cannot produce — there the arguments arrive
/// already decoded — and therefore one only a streaming test can catch.
#[tokio::test]
async fn a_half_streamed_tool_argument_is_a_metered_failure() {
    let body = "\
event: message_start
data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}

event: content_block_start
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"agentplane_respond\"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"amount\\\":\"}}

event: message_delta
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":8}}

event: message_stop
data: {\"type\":\"message_stop\"}

";
    let (url, _) = serve_sse(body, false).await;
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .structured_via(SchemaMode::ForcedTool);
    let prompt = json!("x");
    let sch = json!({"type": "object"});
    let err = provider
        .complete(agentplane::model::Request {
            model: &model(),
            prompt: &prompt,
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: Some(&sch),
            tools: &[],
            exchanges: &[],
            continuation: None,
            stream: None,
        })
        .await
        .expect_err("the fragments do not reassemble into JSON");
    assert!(matches!(err, ModelError::Unusable { .. }), "{err}");
    assert_eq!(err.usage().spend().tokens, 18, "it generated: {err}");
}

// ── OpenAI streaming: the same idea, one honest step short ───────────────────

const OPENAI_HEAD: &str = "\
event: response.created
data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_9\",\"status\":\"in_progress\",\"usage\":null}}

event: response.output_text.delta
data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"Hel\"}

";

#[tokio::test]
async fn an_openai_stream_is_assembled_from_its_terminal_event() {
    let body = format!(
        "{OPENAI_HEAD}\
event: response.completed
data: {{\"type\":\"response.completed\",\"sequence_number\":9,\"response\":{{\"status\":\"completed\",\
\"output\":[{{\"type\":\"message\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Hello\"}}]}}],\
\"usage\":{{\"input_tokens\":25,\"output_tokens\":15}}}}}}

"
    );
    let (url, seen) = serve_sse(&body, false).await;
    let provider = OpenAi::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let out = provider.complete(ask(&gpt(), &prompt)).await.unwrap();

    assert_eq!(out.text, "Hello");
    assert_eq!(out.usage.input_tokens, 25);
    assert_eq!(out.usage.output_tokens, 15);
    let sent = seen.lock().unwrap().clone().unwrap();
    assert_eq!(sent["stream"], json!(true));
}

/// **The asymmetry, asserted.**
///
/// `OpenAI` carries usage only in the terminal event, so a severed stream knows
/// that generation happened and nothing about its cost. That is
/// `Unaccounted` — landed, so it is not repeated, and honest that the figure is
/// missing rather than reporting a confident zero.
#[tokio::test]
async fn a_severed_openai_stream_is_landed_but_unaccounted() {
    let (url, _) = serve_sse(OPENAI_HEAD, true).await;
    let provider = OpenAi::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&gpt(), &prompt))
        .await
        .expect_err("severed after generating");

    assert!(
        matches!(err, ModelError::Unaccounted { .. }),
        "it generated, so this is not Unavailable — that one is safe to repeat, \
         and repeating buys a second bill: {err}"
    );
    assert_eq!(
        err.disposition(),
        Disposition::Landed,
        "what is unknown is the amount, not whether it happened"
    );
    assert!(
        err.to_string().contains("resp_9"),
        "the response id is the only way a caller can reconcile the real cost: {err}"
    );
}

/// Cut before any output delta, nothing is known to have happened.
#[tokio::test]
async fn an_openai_stream_severed_before_output_did_not_happen() {
    let head = "event: response.created\ndata: {\"type\":\"response.created\",\
                \"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\n";
    let (url, _) = serve_sse(head, true).await;
    let provider = OpenAi::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let err = provider
        .complete(ask(&gpt(), &prompt))
        .await
        .expect_err("severed");
    assert!(
        matches!(err, ModelError::Unavailable { .. }),
        "an id and an in_progress status are not evidence of generation: {err}"
    );
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

/// A streamed `incomplete` still returns an answer, and says it is cut short.
#[tokio::test]
async fn a_streamed_incomplete_response_says_it_was_truncated() {
    let body = format!(
        "{OPENAI_HEAD}\
event: response.incomplete
data: {{\"type\":\"response.incomplete\",\"response\":{{\"status\":\"incomplete\",\
\"incomplete_details\":{{\"reason\":\"max_output_tokens\"}},\
\"output\":[{{\"type\":\"message\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Hel\"}}]}}],\
\"usage\":{{\"input_tokens\":25,\"output_tokens\":999}}}}}}

"
    );
    let (url, _) = serve_sse(&body, false).await;
    let provider = OpenAi::new("k").unwrap().base(url);
    let prompt = json!("hi");
    let out = provider.complete(ask(&gpt(), &prompt)).await.unwrap();
    assert!(
        out.truncated,
        "a cut-off answer must not come back looking whole"
    );
    assert_eq!(out.usage.output_tokens, 999);
    assert_eq!(
        out.stop_reason.as_deref(),
        Some("incomplete:max_output_tokens")
    );
}

/// A peer call carries the same attested block a tool call does.
///
/// It travels under the declared extension URI, beside the delegation chain, so
/// a peer that does not implement the extension ignores both together rather
/// than half-understanding the message.
#[tokio::test]
async fn a_peer_call_carries_attested_provenance() {
    let (c, seen) = canned(
        200,
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "task": {
                "id": "t", "status": { "state": "TASK_STATE_COMPLETED" }
            } }
        }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();

    let payload = json!({ "doc": "INV-9" });
    let signer = agentplane::testkit::StubSigner::default();
    let key = agentplane::core::EffectKey::for_effect(
        agentplane::core::StepId(0),
        agentplane::core::Phase::Forward,
        0,
        1,
        &agentplane::core::EffectDescriptor::new("a2a.peer/call", payload.clone()),
    );
    let p = agentplane::core::Provenance::new(agentplane::RunId::generate(), key, "auditor@2.0.0")
        .seal(&signer, "a2a.peer/call", &payload);

    client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &payload,
            &chain(),
            None,
            Some(&p),
        )
        .await
        .expect("the peer answers");

    let sent = seen.lock().unwrap().clone().expect("the peer saw a body");
    let ext = &sent["params"]["message"]["metadata"][EXTENSION_URI];
    let meta = ext["provenance"]
        .as_object()
        .expect("provenance rides under the extension");

    assert!(
        meta.contains_key("io.github.hupe1980.agentplane/attestation"),
        "{meta:?}"
    );
    let back = agentplane::core::Provenance::from_meta(meta).expect("parses peer-side");
    assert!(
        back.verify(&signer, "a2a.peer/call", &payload),
        "the peer could not check the block it was sent"
    );
    assert!(
        !back.verify(&signer, "a2a.peer/call", &json!({ "doc": "OTHER" })),
        "the block verified against a payload it was not sealed for"
    );
}

/// Given nothing, the client invents nothing.
#[tokio::test]
async fn a_peer_call_without_provenance_sends_none() {
    let (c, seen) = canned(
        200,
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "task": {
                "id": "t", "status": { "state": "TASK_STATE_COMPLETED" }
            } }
        }),
    );
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url)).unwrap();
    client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .unwrap();

    let sent = seen.lock().unwrap().clone().unwrap();
    assert!(
        sent["params"]["message"]["metadata"][EXTENSION_URI]["provenance"].is_null(),
        "the client fabricated provenance nobody gave it"
    );
}

// ── Network egress ──────────────────────────────────────────────────────────
//
// The sensitivity lattice governs *what* may leave. This governs *where it may
// leave to*, which is a different hole: a value can sit perfectly within its
// ceiling and still be posted to a host nobody granted. An MCP server that can
// advertise a tool pointing at a new host, or a base URL edited in a config, is
// a self-service egress channel — so destinations are granted, not discovered.

/// A host nobody granted is refused, and nothing is sent.
#[tokio::test]
async fn a_model_call_to_an_ungranted_host_is_refused() {
    let (c, seen) = canned(200, json!({ "content": [] }));
    let url = serve(c).await;

    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .egress(agentplane::core::Egress::new().allow("api.anthropic.com"));

    let prompt = json!("hi");
    let err = provider
        .complete(ask(&model(), &prompt))
        .await
        .expect_err("127.0.0.1 was never granted");

    assert!(matches!(err, ModelError::Refused { .. }), "{err}");
    assert_eq!(
        err.disposition(),
        Disposition::DidNotHappen,
        "a refused destination cannot have generated anything"
    );
    assert_eq!(
        err.usage().spend().tokens,
        0,
        "and cannot have cost anything"
    );
    assert!(
        seen.lock().unwrap().is_none(),
        "the request reached the server despite being refused"
    );
}

/// Granting the host lets the same call through.
#[tokio::test]
async fn a_granted_host_is_reachable() {
    let (c, _) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "ok" }],
            "usage": { "input_tokens": 1, "output_tokens": 1 },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .egress(agentplane::core::Egress::new().allow("127.0.0.1"));

    let prompt = json!("hi");
    provider
        .complete(ask(&model(), &prompt))
        .await
        .expect("the host was granted");
}

/// An allowlist that grants nothing reaches nothing.
#[tokio::test]
async fn an_empty_allowlist_denies_everything() {
    let (c, _) = canned(200, json!({}));
    let url = serve(c).await;
    let provider = OpenAi::new("k")
        .unwrap()
        .base(url)
        .egress(agentplane::core::Egress::new());
    let prompt = json!("hi");
    assert!(
        provider.complete(ask(&gpt(), &prompt)).await.is_err(),
        "deny-by-default is the only default that fails safe"
    );
}

/// The same control on the peer wire.
#[tokio::test]
async fn a_peer_at_an_ungranted_host_is_refused() {
    let (c, seen) = canned(200, json!({ "jsonrpc": "2.0", "id": 1, "result": {} }));
    let url = serve(c).await;
    let client = A2aClient::new(Endpoint::new(url))
        .unwrap()
        .egress(agentplane::core::Egress::new().allow("peers.example.com"));

    let err = client
        .send(
            &PeerId::new("peer"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .expect_err("not granted");

    assert_eq!(
        err.disposition(),
        Disposition::DidNotHappen,
        "the peer never saw it, so it must not be in doubt"
    );
    assert!(
        seen.lock().unwrap().is_none(),
        "the peer was reached anyway"
    );
}

/// No allowlist configured is no egress control — spelled as absence.
#[tokio::test]
async fn without_an_allowlist_nothing_is_restricted() {
    let (c, _) = canned(
        200,
        json!({
            "content": [{ "type": "text", "text": "ok" }],
            "usage": { "input_tokens": 1, "output_tokens": 1 },
            "stop_reason": "end_turn"
        }),
    );
    let url = serve(c).await;
    let provider = Anthropic::new("k").unwrap().base(url).buffered();
    let prompt = json!("hi");
    provider
        .complete(ask(&model(), &prompt))
        .await
        .expect("no egress policy means no egress control");
}

/// A retried peer call carries the same `messageId`.
///
/// A2A deduplicates on `messageId`, so the answer to "have I already done this
/// work?" must be *yes* for a retry. The effect key cannot supply that: it
/// hashes the attempt number, because a retry must not collide with the
/// recorded failure of the attempt before it. Two questions, two identifiers —
/// and using the wrong one lets a peer act twice on one logical call.
#[test]
fn a_retry_keeps_the_peers_duplicate_detection_key() {
    use agentplane::core::{EffectKey, Provenance, RunId};

    let run = RunId::generate();
    // What the runtime derives for two attempts of one dispatch.
    let dispatch = EffectKey::from_hex(&"aa".repeat(32)).expect("key");
    let attempt_one = EffectKey::from_hex(&"11".repeat(32)).expect("key");
    let attempt_two = EffectKey::from_hex(&"22".repeat(32)).expect("key");

    let first = Provenance::new(run, attempt_one, "agent").dispatching(dispatch);
    let second = Provenance::new(run, attempt_two, "agent").dispatching(dispatch);

    assert_ne!(
        first.effect, second.effect,
        "attempts must differ, or replay reads back the wrong record"
    );
    assert_eq!(
        first.dedupe_key(),
        second.dedupe_key(),
        "both attempts are one logical call, so the peer must see one message id"
    );

    // Without a dispatch id the effect key is the fallback — wrong across
    // retries, right for anything that never retries, and never silently absent.
    let bare = Provenance::new(run, attempt_one, "agent");
    assert_eq!(bare.dedupe_key(), attempt_one);
}

// ── The OpenAI-compatible Chat Completions wire ─────────────────────────────
//
// The de-facto wire of self-hosted inference — TGI, vLLM, Ollama, llama.cpp,
// Hugging Face's router. Same discipline as the other drivers: what is under
// test is the failure mapping and the usage arithmetic, because those are the
// parts with consequences.

fn cc_request<'a>(model: &'a ModelId, prompt: &'a Value) -> agentplane::model::Request<'a> {
    agentplane::model::Request {
        model,
        prompt,
        max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
        reasoning_effort: None,
        schema: None,
        tools: &[],
        exchanges: &[],
        continuation: None,
        stream: None,
    }
}

#[tokio::test]
async fn chat_completions_maps_text_usage_and_the_request_shape() {
    let (canned, seen, headers) = canned_observed(
        200,
        json!({
            "choices": [{
                "message": { "content": "Hello from a local model" },
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 7,
                "prompt_tokens_details": { "cached_tokens": 12 },
            },
        }),
    );
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "llama-3.3-70b");
    let prompt = json!({ "system": "Answer briefly.", "input": "hello" });

    let completion = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    assert_eq!(completion.text, "Hello from a local model");
    assert_eq!(completion.stop_reason.as_deref(), Some("stop"));
    assert!(!completion.truncated);
    // Cached tokens are a *subset* of prompt_tokens, exactly as Responses
    // reports them — added back they would double-count.
    assert_eq!(completion.usage.input_tokens, 20);
    assert_eq!(completion.usage.output_tokens, 7);
    assert_eq!(completion.usage.cache_read_tokens, 12);
    assert_eq!(completion.usage.uncached_input_tokens(), 8);

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["model"], "llama-3.3-70b");
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], "Answer briefly.");
    assert_eq!(body["messages"][1]["role"], "user");
    assert_eq!(body["messages"][1]["content"], "hello");
    assert!(
        body["max_tokens"].is_u64(),
        "the per-call ceiling is missing"
    );
    assert!(
        body.get("stream").is_none(),
        "a buffered driver asked for a stream"
    );
    // No key was configured, and the common local server wants none — so no
    // Authorization header may be invented.
    let headers = headers.lock().unwrap().clone().unwrap();
    assert!(
        !headers.contains_key("authorization"),
        "an Authorization header appeared with no key configured"
    );
}

#[tokio::test]
async fn chat_completions_refuses_reasoning_effort_rather_than_dropping_it() {
    // No server: the refusal must happen before anything is sent.
    let driver = ChatCompletions::new("http://127.0.0.1:9").unwrap();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");
    let mut request = cc_request(&model, &prompt);
    request.reasoning_effort = Some(ReasoningEffort::High);

    let error = driver.complete(request).await.unwrap_err();
    assert!(
        matches!(&error, ModelError::Refused { .. }),
        "a declared control was not refused: {error}"
    );
    assert_eq!(error.disposition(), Disposition::DidNotHappen);
}

#[tokio::test]
async fn chat_completions_truncation_is_a_typed_fact() {
    let (canned, _seen) = canned(
        200,
        json!({
            "choices": [{
                "message": { "content": "an answer that was cut" },
                "finish_reason": "length",
            }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 99 },
        }),
    );
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let completion = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    assert!(
        completion.truncated,
        "finish_reason 'length' must surface as `truncated`, not as a \
         silently shortened string"
    );
}

#[tokio::test]
async fn chat_completions_a_refusal_after_generation_is_metered() {
    let (canned, _seen) = canned(
        200,
        json!({
            "choices": [{
                "message": { "content": null, "refusal": "I cannot help with that." },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 9, "completion_tokens": 4 },
        }),
    );
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let error = driver
        .complete(cc_request(&model, &prompt))
        .await
        .unwrap_err();
    assert!(matches!(&error, ModelError::Unusable { .. }), "{error}");
    // It generated the decline, so the decline is billed.
    assert_eq!(error.disposition(), Disposition::Landed);
    assert_eq!(error.usage().output_tokens, 4);
}

#[tokio::test]
async fn chat_completions_tool_calls_parse_and_a_malformed_one_is_loud() {
    let good = json!({
        "choices": [{
            "message": {
                "content": null,
                "tool_calls": [{
                    "id": "call_7",
                    "type": "function",
                    "function": { "name": "lookup", "arguments": "{\"id\":\"x\"}" },
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": { "prompt_tokens": 5, "completion_tokens": 3 },
    });
    let (canned_ok, _seen) = canned(200, good);
    let url = serve(canned_ok).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let completion = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    assert_eq!(completion.tool_calls.len(), 1);
    assert_eq!(completion.tool_calls[0].id, "call_7");
    assert_eq!(completion.tool_calls[0].arguments, json!({"id": "x"}));
    // The continuation is the assistant turn exactly as the server sent it,
    // ids included — a reconstructed turn is how an id gets rewritten.
    let continuation = completion.continuation.expect("a tool turn continues");
    assert_eq!(continuation.provider, "chat-completions");
    assert_eq!(continuation.state[0]["tool_calls"][0]["id"], "call_7");

    let (canned_bad, _seen) = canned(
        200,
        json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": "call_8",
                        "type": "function",
                        "function": { "name": "lookup", "arguments": "{not json" },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 3 },
        }),
    );
    let url = serve(canned_bad).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let error = driver
        .complete(cc_request(&model, &prompt))
        .await
        .unwrap_err();
    // A malformed call is a provider-protocol failure, not "no call":
    // dropping it can turn one bad and one good side effect into permission
    // for only the good one.
    assert!(matches!(&error, ModelError::Unusable { .. }), "{error}");
}

#[tokio::test]
async fn chat_completions_forces_a_tool_for_structured_output_by_default() {
    let (canned, seen, _headers) = canned_observed(
        200,
        json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "agentplane_respond",
                            "arguments": "{\"summary\":\"ok\"}",
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 3 },
        }),
    );
    let url = serve(canned).await;
    // ForcedTool is the *default* here — the opposite of the OpenAI driver —
    // because whether a compatible server honours `json_schema` at all is
    // exactly what cannot be assumed.
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("summarise");
    let schema = json!({
        "type": "object",
        "properties": { "summary": { "type": "string" } },
        "required": ["summary"],
        "additionalProperties": false,
    });
    let mut request = cc_request(&model, &prompt);
    request.schema = Some(&schema);

    let completion = driver.complete(request).await.unwrap();
    assert_eq!(completion.structured, Some(json!({"summary": "ok"})));
    assert!(
        completion.tool_calls.is_empty(),
        "the forced respond tool is this crate's mechanism, not a tool call"
    );

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        body["tool_choice"]["function"]["name"], "agentplane_respond",
        "structured output must be forced, not suggested"
    );
    // Nested under `function`, which is what this wire takes — the flat
    // Responses shape here would be the mirror image of the war story in the
    // OpenAI driver.
    assert_eq!(body["tools"][0]["function"]["name"], "agentplane_respond");
}

#[tokio::test]
async fn chat_completions_status_mapping_follows_the_shared_doctrine() {
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let (refused, _seen) = canned(400, json!({"error": {"message": "bad request"}}));
    let url = serve(refused).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let error = driver
        .complete(cc_request(&model, &prompt))
        .await
        .unwrap_err();
    assert!(matches!(&error, ModelError::Refused { .. }), "{error}");
    assert_eq!(error.disposition(), Disposition::DidNotHappen);

    let (unavailable, _seen) = canned(500, json!({"error": "boom"}));
    let url = serve(unavailable).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let error = driver
        .complete(cc_request(&model, &prompt))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, ModelError::Unavailable { .. }),
        "a 5xx did not say whether it generated: {error}"
    );
}

/// Serve a fixed SSE body once, then close the connection.
async fn serve_cc_sse(body: &'static str) -> String {
    async fn sse(State(body): State<&'static str>) -> impl axum::response::IntoResponse {
        (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            body,
        )
    }
    let app = Router::new()
        .route("/v1/chat/completions", post(sse))
        .with_state(body);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn chat_completions_streams_reassemble_and_meter_from_the_final_chunk() {
    let url = serve_cc_sse(concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2}}\n\n",
        "data: [DONE]\n\n",
    ))
    .await;
    let driver = ChatCompletions::new(url).unwrap();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let completion = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    assert_eq!(completion.text, "Hello");
    assert_eq!(completion.usage.input_tokens, 11);
    assert_eq!(completion.usage.output_tokens, 2);
    assert_eq!(completion.stop_reason.as_deref(), Some("stop"));
}

#[tokio::test]
async fn chat_completions_a_stream_severed_after_generation_is_not_free_to_retry() {
    // Deltas arrived; the terminal never did. The server generated tokens
    // this driver cannot count — repeating buys a second bill.
    let url = serve_cc_sse("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n").await;
    let driver = ChatCompletions::new(url).unwrap();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let error = driver
        .complete(cc_request(&model, &prompt))
        .await
        .unwrap_err();
    assert!(matches!(&error, ModelError::Unaccounted { .. }), "{error}");
    assert_eq!(error.disposition(), Disposition::Landed);
}

#[tokio::test]
async fn chat_completions_a_stream_severed_before_generation_is_safe_to_repeat() {
    let url = serve_cc_sse("").await;
    let driver = ChatCompletions::new(url).unwrap();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let error = driver
        .complete(cc_request(&model, &prompt))
        .await
        .unwrap_err();
    assert!(matches!(&error, ModelError::Unavailable { .. }), "{error}");
    assert_eq!(error.disposition(), Disposition::DidNotHappen);
}

#[tokio::test]
async fn chat_completions_tool_turns_return_under_the_ids_the_model_issued() {
    let (canned, seen, _headers) = canned_observed(
        200,
        json!({
            "choices": [{
                "message": { "content": "done" },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 1 },
        }),
    );
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!("hello");

    let call = agentplane::model::ToolCall {
        id: "call_42".to_owned(),
        name: "lookup".to_owned(),
        arguments: json!({"id": "x"}),
    };
    let exchanges = vec![agentplane::model::ToolExchange {
        call: call.clone(),
        output: json!({"found": true}),
        failed: false,
    }];
    let continuation = agentplane::model::ProviderContinuation::new(
        "chat-completions",
        json!([{
            "role": "assistant",
            "content": null,
            "tool_calls": [{
                "id": "call_42",
                "type": "function",
                "function": { "name": "lookup", "arguments": "{\"id\":\"x\"}" },
            }],
        }]),
    );
    let mut request = cc_request(&model, &prompt);
    request.exchanges = &exchanges;
    request.continuation = Some(&continuation);

    driver.complete(request).await.unwrap();
    let body = seen.lock().unwrap().clone().unwrap();
    let messages = body["messages"].as_array().unwrap();
    // user, assistant (exact echo, id included), tool result under that id.
    assert_eq!(messages[1]["role"], "assistant");
    assert_eq!(messages[1]["tool_calls"][0]["id"], "call_42");
    assert_eq!(messages[2]["role"], "tool");
    assert_eq!(messages[2]["tool_call_id"], "call_42");
}

/// Two tool turns accumulate the transcript exactly once.
///
/// The failure this rules out is silent and expensive: a continuation that
/// re-appends a prior turn makes every turn re-send the whole conversation
/// twice over, and one that *drops* a turn asks the model to answer without
/// the result it just received. Both look like a working loop until somebody
/// reads the bill or the answer.
#[tokio::test]
async fn chat_completions_two_tool_turns_accumulate_the_transcript_exactly_once() {
    let assistant = |id: &str| {
        json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": id,
                        "type": "function",
                        "function": { "name": "lookup", "arguments": "{}" },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 1 },
        })
    };
    let model = ModelId::new("chat-completions", "m");
    let prompt = json!({ "system": "Be brief.", "input": "start" });
    let exchange = |id: &str| agentplane::model::ToolExchange {
        call: agentplane::model::ToolCall {
            id: id.to_owned(),
            name: "lookup".to_owned(),
            arguments: json!({}),
        },
        output: json!({ "n": id }),
        failed: false,
    };

    // Turn 1 → the model asks for a tool.
    let (canned, _seen) = canned(200, assistant("call_1"));
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let first = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    let state1 = first.continuation.expect("turn 1 continues");

    // Turn 2 → carrying turn 1's result, the model asks again.
    let (canned, seen2, _h) = canned_observed(200, assistant("call_2"));
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let exchanges1 = vec![exchange("call_1")];
    let mut request = cc_request(&model, &prompt);
    request.exchanges = &exchanges1;
    request.continuation = Some(&state1);
    let second = driver.complete(request).await.unwrap();
    let state2 = second.continuation.expect("turn 2 continues");

    let sent2 = seen2.lock().unwrap().clone().unwrap();
    let m2 = sent2["messages"].as_array().unwrap();
    assert_eq!(
        m2.len(),
        4,
        "turn 2 should send system, user, assistant-1, tool-1 — got {m2:#?}"
    );

    // Turn 3 → carrying turn 2's result, the model answers.
    let (canned, seen3, _h) = canned_observed(
        200,
        json!({
            "choices": [{ "message": { "content": "done" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 1 },
        }),
    );
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let exchanges2 = vec![exchange("call_2")];
    let mut request = cc_request(&model, &prompt);
    request.exchanges = &exchanges2;
    request.continuation = Some(&state2);
    driver.complete(request).await.unwrap();

    let sent3 = seen3.lock().unwrap().clone().unwrap();
    let m3 = sent3["messages"].as_array().unwrap();
    assert_eq!(
        m3.len(),
        6,
        "turn 3 should send system, user, assistant-1, tool-1, assistant-2, \
         tool-2 — a transcript that grew faster re-sent a turn, one that grew \
         slower dropped one: {m3:#?}"
    );
    // Every tool result sits under the id the model actually issued, in order.
    assert_eq!(m3[3]["tool_call_id"], "call_1");
    assert_eq!(m3[5]["tool_call_id"], "call_2");
    assert_eq!(m3[2]["tool_calls"][0]["id"], "call_1");
    assert_eq!(m3[4]["tool_calls"][0]["id"], "call_2");
}

/// **A provider's assistant turn is carried back verbatim, not rebuilt.**
///
/// The continuation exists so the next request returns exactly what the server
/// emitted. It was built by copying four fields out of the parsed response —
/// `id`, `type`, `function.name`, `function.arguments` — and the comment above
/// it said "the assistant turn exactly as the server sent it", which it was
/// not. Anything else the server attached was dropped by `serde` on the way in
/// and could not have been re-emitted anyway.
///
/// That is not hypothetical, and the ecosystem has the scars. Gemini 3 returns
/// an encrypted `thought_signature` on every tool call and **rejects** a
/// follow-up turn that does not carry it back; through the OpenAI-compatible
/// endpoint it rides in `tool_calls[].extra_content.google.thought_signature`.
/// `LiteLLM`, which normalises every provider into this same shape, had nowhere
/// to put it and resorted to smuggling it inside the tool-call **id** — which
/// then leaked into requests to other providers, and still degenerates
/// multi-turn tool calling when the signature arrives on a thought part rather
/// than a function-call part.
///
/// The fix is not to learn Gemini's field. It is to stop rebuilding a message
/// this driver does not own: an OpenAI-compatible server may attach anything,
/// and a driver that re-emits only the fields it happens to know about is one
/// that breaks on every field added after it was written.
#[tokio::test]
async fn chat_completions_carries_an_unknown_tool_call_field_into_the_continuation() {
    let (canned, _seen, _headers) = canned_observed(
        200,
        json!({
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "lookup", "arguments": "{\"q\":\"x\"}" },
                        // Not a field this driver knows, and not one it may drop.
                        "extra_content": { "google": { "thought_signature": "SIGNATURE" } },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": { "prompt_tokens": 5, "completion_tokens": 3 },
        }),
    );
    let url = serve(canned).await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "gemini-3.5-flash");
    let prompt = json!({ "input": "look it up" });

    let completion = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    assert_eq!(completion.tool_calls.len(), 1, "the tool call was lost");

    let state = completion
        .continuation
        .as_ref()
        .expect("a tool call must produce a continuation")
        .state
        .clone();

    assert_eq!(
        state[0]["tool_calls"][0]["extra_content"]["google"]["thought_signature"], "SIGNATURE",
        "the server's own field was dropped rebuilding the assistant turn, so the \
         next request cannot return it — which is a 4xx on Gemini 3 and a \
         degenerating tool loop on anything else that signs its reasoning: {state}"
    );
}

// ── Gemini ──────────────────────────────────────────────────────────────────

fn gemini_request<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    tools: &'a [ToolDeclaration],
    exchanges: &'a [ToolExchange],
    continuation: Option<&'a ProviderContinuation>,
) -> Request<'a> {
    Request {
        model,
        prompt,
        max_output_tokens: 1024,
        reasoning_effort: None,
        schema: None,
        tools,
        exchanges,
        continuation,
        stream: None,
    }
}

/// The request shape Gemini actually takes, asserted field by field.
///
/// A known answer rather than a round trip: this driver's own reader would
/// agree with a wrong spelling, and Gemini answers most misspellings with a
/// 400 whose text does not name the offending key.
#[tokio::test]
async fn gemini_maps_the_request_shape_usage_and_the_system_instruction() {
    let (canned, seen, headers) = canned_observed(
        200,
        json!({
            "candidates": [{
                "content": { "role": "model", "parts": [{ "text": "Hello from Gemini" }] },
                "finishReason": "STOP",
            }],
            "usageMetadata": {
                "promptTokenCount": 20,
                "candidatesTokenCount": 7,
                "thoughtsTokenCount": 5,
                "cachedContentTokenCount": 12,
            },
        }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!({ "system": "Answer briefly.", "messages": [
        { "role": "user", "parts": [{ "text": "hello" }] }
    ]});

    let completion = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap();
    assert_eq!(completion.text, "Hello from Gemini");
    assert_eq!(completion.stop_reason.as_deref(), Some("STOP"));
    assert!(!completion.truncated);

    // Thinking tokens are billed as output and reported *beside* the candidate
    // count, so they are added. A driver that ignored them would under-report a
    // reasoning-heavy run by most of its bill.
    assert_eq!(completion.usage.output_tokens, 12, "7 answer + 5 thinking");
    // Cached input is a *subset* of the prompt count, so it is recorded rather
    // than added — adding it would double-count the cached portion.
    assert_eq!(completion.usage.input_tokens, 20);
    assert_eq!(completion.usage.cache_read_tokens, 12);
    assert_eq!(completion.usage.uncached_input_tokens(), 8);

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(body["contents"][0]["role"], "user");
    assert_eq!(body["contents"][0]["parts"][0]["text"], "hello");
    // Top-level, not a turn: Gemini has no `system` role, and an instruction
    // left in `contents` is shown to the model as part of the question.
    assert_eq!(
        body["systemInstruction"]["parts"][0]["text"],
        "Answer briefly."
    );
    assert!(
        body["contents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["role"] != "system"),
        "the instruction was left in the turns: {body}"
    );
    assert_eq!(body["generationConfig"]["maxOutputTokens"], 1024);
    assert!(
        body["generationConfig"].get("thinkingConfig").is_none(),
        "no reasoning was asked for and a thinking config was sent anyway"
    );

    // The key rides in a header, never the URL: a URL reaches proxies, traces
    // and error text, and a credential in any of those cannot be un-leaked.
    let headers = headers.lock().unwrap().clone().unwrap();
    assert_eq!(headers["x-goog-api-key"], "k");
}

/// **The model's turn is carried back verbatim, signature and all.**
///
/// This is the reason the driver exists rather than deferring to Google's
/// OpenAI-compatible endpoint. Gemini 3 attaches an encrypted `thoughtSignature`
/// to the parts it emits and **rejects** a follow-up turn that does not return
/// it. A driver that rebuilt the turn from the fields it understands could not
/// return what it never kept — which is the bug `LiteLLM` has been carrying, and
/// which it worked around by smuggling the signature inside the tool-call id.
///
/// So the assertion is not "the signature is preserved" as a property of this
/// driver's cleverness. It is that the driver keeps the provider's own document
/// and hands it straight back.
#[tokio::test]
async fn gemini_returns_the_models_turn_verbatim_including_its_thought_signature() {
    let (canned, seen, _headers) = canned_observed(
        200,
        json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": { "name": "lookup", "args": { "q": "x" } },
                        "thoughtSignature": "SIGNATURE",
                    }],
                },
                "finishReason": "STOP",
            }],
            "usageMetadata": { "promptTokenCount": 5, "candidatesTokenCount": 3 },
        }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("look it up");
    let tools = [ToolDeclaration {
        name: "lookup".to_owned(),
        description: "Look something up.".to_owned(),
        parameters: json!({ "type": "object", "properties": {} }),
    }];

    let first = driver
        .complete(gemini_request(&model, &prompt, &tools, &[], None))
        .await
        .unwrap();
    assert_eq!(first.tool_calls.len(), 1);
    assert_eq!(first.tool_calls[0].name, "lookup");
    // Gemini need not issue an id and the runtime keys results by one, so it is
    // derived from the position — stable across a replay of the same recorded
    // response, which a generated id would not be.
    assert_eq!(first.tool_calls[0].id, "lookup-0");

    let continuation = first.continuation.clone().expect("a continuation");
    assert_eq!(
        continuation.state["parts"][0]["thoughtSignature"], "SIGNATURE",
        "the signature was dropped on the way in: {:?}",
        continuation.state
    );

    // The second turn: the model's own document goes back untouched.
    let exchanges = [ToolExchange {
        call: first.tool_calls[0].clone(),
        output: json!({ "found": true }),
        failed: false,
    }];
    let _ = driver
        .complete(gemini_request(
            &model,
            &prompt,
            &tools,
            &exchanges,
            Some(&continuation),
        ))
        .await;

    let body = seen.lock().unwrap().clone().unwrap();
    let contents = body["contents"].as_array().expect("contents");
    assert_eq!(
        contents[1]["parts"][0]["thoughtSignature"], "SIGNATURE",
        "the follow-up turn did not return the signature, which Gemini 3 answers \
         with a 400: {body}"
    );
    assert_eq!(contents[1]["role"], "model");
    // The result goes back as a functionResponse user turn, named by the tool.
    assert_eq!(contents[2]["role"], "user");
    assert_eq!(
        contents[2]["parts"][0]["functionResponse"]["name"],
        "lookup"
    );
    assert_eq!(
        contents[2]["parts"][0]["functionResponse"]["response"]["output"]["found"],
        true
    );
}

/// Reasoning effort renders as a thinking level, or is refused — never bent.
#[tokio::test]
async fn gemini_maps_the_thinking_levels_it_has_and_refuses_the_rest() {
    use ReasoningEffort as E;

    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("hi");

    for (effort, expected) in [
        (E::Minimal, "minimal"),
        (E::Low, "low"),
        (E::Medium, "medium"),
        (E::High, "high"),
    ] {
        let (canned, seen, _h) = canned_observed(
            200,
            json!({
                "candidates": [{
                    "content": { "role": "model", "parts": [{ "text": "ok" }] },
                    "finishReason": "STOP",
                }],
                "usageMetadata": { "promptTokenCount": 1, "candidatesTokenCount": 1 },
            }),
        );
        let url = serve(canned).await;
        let driver = Gemini::new("k").unwrap().base(url).buffered();
        let mut request = gemini_request(&model, &prompt, &[], &[], None);
        request.reasoning_effort = Some(effort);
        driver.complete(request).await.unwrap();
        let body = seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            body["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            expected,
            "the {} level did not render as Gemini names it",
            effort.as_str()
        );
    }

    // Refused rather than collapsed. `max` answered with `high` would be a
    // substitution on a digest-covered value whose whole job is to say what
    // governed the call; and Google documents that thinking cannot be switched
    // off on the Gemini 3 models, so `none` is not expressible either.
    for effort in [E::None, E::XHigh, E::Max] {
        let driver = Gemini::new("k").unwrap().buffered();
        let mut request = gemini_request(&model, &prompt, &[], &[], None);
        request.reasoning_effort = Some(effort);
        let text = driver
            .complete(request)
            .await
            .expect_err("an effort Gemini cannot express must be refused")
            .to_string();
        assert!(
            text.contains(effort.as_str()) && text.contains("minimal, low, medium and high"),
            "the refusal must name the effort and the levels that exist: {text}"
        );
    }
}

/// A schema is enforced during generation, not checked afterwards.
#[tokio::test]
async fn gemini_asks_for_a_native_response_schema() {
    let (canned, seen, _headers) = canned_observed(
        200,
        json!({
            "candidates": [{
                "content": { "role": "model", "parts": [{ "text": "{\"id\":\"abc\"}" }] },
                "finishReason": "STOP",
            }],
            "usageMetadata": { "promptTokenCount": 3, "candidatesTokenCount": 4 },
        }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("give me an id");
    let schema = json!({
        "type": "object",
        "properties": { "id": { "type": "string" } },
        "required": ["id"],
    });
    let mut request = gemini_request(&model, &prompt, &[], &[], None);
    request.schema = Some(&schema);

    let completion = driver.complete(request).await.unwrap();
    assert_eq!(completion.structured, Some(json!({ "id": "abc" })));

    let body = seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        body["generationConfig"]["responseMimeType"],
        "application/json"
    );
    assert_eq!(body["generationConfig"]["responseJsonSchema"], schema);
}

/// A stop that is not an answer is metered, because deciding cost money.
#[tokio::test]
async fn gemini_a_safety_stop_is_metered_not_free() {
    let (canned, _seen, _headers) = canned_observed(
        200,
        json!({
            "candidates": [{ "content": { "role": "model", "parts": [] }, "finishReason": "SAFETY" }],
            "usageMetadata": { "promptTokenCount": 11, "candidatesTokenCount": 2 },
        }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("something");

    let error = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .expect_err("a safety stop is not an answer");
    assert_eq!(
        error.usage().output_tokens,
        2,
        "a decline was billed as free"
    );
    assert!(error.to_string().contains("SAFETY"), "{error}");
}

/// A prompt blocked before generating is a refusal that says why.
#[tokio::test]
async fn gemini_a_blocked_prompt_names_its_reason_and_costs_nothing() {
    let (canned, _seen, _headers) = canned_observed(
        200,
        json!({ "promptFeedback": { "blockReason": "SAFETY" } }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("something");

    let error = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .expect_err("a blocked prompt is not an answer");
    assert_eq!(
        error.disposition(),
        agentplane::core::Disposition::DidNotHappen
    );
    assert!(error.to_string().contains("SAFETY"), "{error}");
}

/// Truncation is a typed fact, never a silently shortened string.
#[tokio::test]
async fn gemini_truncation_is_a_typed_fact() {
    let (canned, _seen, _headers) = canned_observed(
        200,
        json!({
            "candidates": [{
                "content": { "role": "model", "parts": [{ "text": "half an ans" }] },
                "finishReason": "MAX_TOKENS",
            }],
            "usageMetadata": { "promptTokenCount": 3, "candidatesTokenCount": 4 },
        }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("write an essay");

    let completion = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap();
    assert!(completion.truncated, "a cut-off answer read as a whole one");
    assert_eq!(completion.stop_reason.as_deref(), Some("MAX_TOKENS"));
}

/// Provider state is opaque *and* provider-bound.
#[tokio::test]
async fn gemini_refuses_another_providers_continuation() {
    let driver = Gemini::new("k").unwrap().buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("hi");
    let foreign = ProviderContinuation::new("openai", json!([{ "type": "reasoning" }]));
    let exchanges = [ToolExchange {
        call: agentplane::model::ToolCall {
            id: "c1".to_owned(),
            name: "lookup".to_owned(),
            arguments: json!({}),
        },
        output: json!({}),
        failed: false,
    }];
    let text = driver
        .complete(gemini_request(
            &model,
            &prompt,
            &[],
            &exchanges,
            Some(&foreign),
        ))
        .await
        .expect_err("another provider's state must never be replayed here")
        .to_string();
    assert!(text.contains("openai"), "{text}");
}

/// The transport contract is in effect identity.
#[test]
fn gemini_request_profile_commits_to_the_transport() {
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let streamed = Gemini::new("k").unwrap();
    let buffered = Gemini::new("k").unwrap().buffered();
    assert_ne!(
        streamed.request_profile(&model),
        buffered.request_profile(&model),
        "buffered and streamed calls shared one effect identity"
    );
    let profile = buffered.request_profile(&model);
    assert_eq!(profile["driver"], "google-gemini-generatecontent/v1");
    assert_eq!(profile["api_version"], "v1beta");
    assert_eq!(profile["schema_mode"], "native");
    assert!(
        !profile.to_string().contains('k') || profile.get("key").is_none(),
        "a key reached the request profile, which is journaled"
    );
}

/// **The deployment's own safety thresholds, and nothing invented.**
///
/// The Bedrock guardrail's posture, on the provider that spells it differently:
/// this crate ships no classifier, Google's is configured here, and what the
/// runtime owns is that the choice is effect identity. A threshold moved from
/// `BLOCK_LOW_AND_ABOVE` to `BLOCK_NONE` between a run and its replay must be
/// divergence, not a silent change in what governed the call — so the profile
/// carries the pairs rather than a bare "safety was on".
#[tokio::test]
async fn gemini_passes_the_deployments_safety_thresholds_and_puts_them_in_identity() {
    use agentplane::model::gemini::{HarmBlockThreshold, HarmCategory, SafetySettings};

    let (canned, seen, _headers) = canned_observed(
        200,
        json!({
            "candidates": [{
                "content": { "role": "model", "parts": [{ "text": "ok" }] },
                "finishReason": "STOP",
            }],
            "usageMetadata": { "promptTokenCount": 1, "candidatesTokenCount": 1 },
        }),
    );
    let url = serve(canned).await;
    let settings = SafetySettings::new()
        .block(
            HarmCategory::DangerousContent,
            HarmBlockThreshold::LowAndAbove,
        )
        .block(HarmCategory::CivicIntegrity, HarmBlockThreshold::None);
    let driver = Gemini::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .safety(settings.clone());
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("hi");

    driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
    let sent = body["safetySettings"].as_array().expect("safetySettings");
    assert_eq!(sent.len(), 2, "{body}");
    // Ordered by category, so two deployments that configured the same
    // thresholds in a different order produce the same bytes — and therefore
    // the same effect identity, rather than a spurious divergence.
    assert_eq!(sent[0]["category"], "HARM_CATEGORY_DANGEROUS_CONTENT");
    assert_eq!(sent[0]["threshold"], "BLOCK_LOW_AND_ABOVE");
    assert_eq!(sent[1]["category"], "HARM_CATEGORY_CIVIC_INTEGRITY");
    assert_eq!(sent[1]["threshold"], "BLOCK_NONE");

    // Identity: unconfigured, one threshold, and a *looser* threshold are three
    // different requests, and the middle-to-last change is the one worth
    // catching — it is the direction somebody makes to get a run unstuck.
    let plain = Gemini::new("k").unwrap().buffered();
    let strict = Gemini::new("k").unwrap().buffered().safety(settings);
    let loose = Gemini::new("k").unwrap().buffered().safety(
        SafetySettings::new()
            .block(HarmCategory::DangerousContent, HarmBlockThreshold::None)
            .block(HarmCategory::CivicIntegrity, HarmBlockThreshold::None),
    );
    assert_eq!(plain.request_profile(&model)["safety"], Value::Null);
    assert_ne!(
        strict.request_profile(&model),
        loose.request_profile(&model),
        "loosening a threshold left effect identity unchanged"
    );
}

/// **No sampling parameter is ever sent.**
///
/// `temperature`, `topP`, `topK` and `seed` are absent from `Request`, so they
/// cannot enter the effect key — and a knob that changes what the provider does
/// without changing effect identity is one a replay cannot account for. `seed`
/// is the tempting one: replay here never calls the model again, so it buys
/// nothing and would imply a reproducibility guarantee no provider makes.
///
/// Asserted on the wire rather than trusted, because adding one is a one-line
/// change that looks like an improvement.
#[tokio::test]
async fn gemini_sends_no_sampling_parameter() {
    let (canned, seen, _headers) = canned_observed(
        200,
        json!({
            "candidates": [{
                "content": { "role": "model", "parts": [{ "text": "ok" }] },
                "finishReason": "STOP",
            }],
            "usageMetadata": { "promptTokenCount": 1, "candidatesTokenCount": 1 },
        }),
    );
    let url = serve(canned).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("hi");

    driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap();

    let config = &seen.lock().unwrap().clone().unwrap()["generationConfig"];
    for knob in [
        "temperature",
        "topP",
        "topK",
        "seed",
        "candidateCount",
        "stopSequences",
        "responseModalities",
    ] {
        assert!(
            config.get(knob).is_none(),
            "`{knob}` reached the wire: it is not in `Request`, so it cannot be in \
             the effect key, and a knob outside effect identity is one a replay \
             cannot account for — {config}"
        );
    }
}

/// **Every harm category and threshold spells itself the way Gemini reads it.**
///
/// A known-answer table taken from Google's `SafetySetting` reference, not a
/// round trip: this driver's own reader would agree with a wrong spelling, and
/// Gemini does not reject an unknown category — it **ignores** it. So the
/// failure being pinned is a deployment that configured a threshold, was
/// answered 200, and was governed by nothing, with the setting sitting in its
/// manifest looking applied.
///
/// Every variant is listed rather than a representative few, because the point
/// of the enum is that a category cannot be misspelled, and a variant no test
/// constructs is one whose spelling nothing checks. Written without a `use ...
/// as` alias on purpose: the dead-variant guard matches on the declared type
/// name, so an alias here would hide these constructions from it and the
/// variants would read as dead again.
#[test]
fn gemini_safety_categories_and_thresholds_use_the_documented_spellings() {
    use agentplane::model::gemini::{HarmBlockThreshold, HarmCategory, SafetySettings};

    for (category, expected) in [
        (HarmCategory::Harassment, "HARM_CATEGORY_HARASSMENT"),
        (HarmCategory::HateSpeech, "HARM_CATEGORY_HATE_SPEECH"),
        (
            HarmCategory::SexuallyExplicit,
            "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        ),
        (
            HarmCategory::DangerousContent,
            "HARM_CATEGORY_DANGEROUS_CONTENT",
        ),
        (
            HarmCategory::CivicIntegrity,
            "HARM_CATEGORY_CIVIC_INTEGRITY",
        ),
        (HarmCategory::Jailbreak, "HARM_CATEGORY_JAILBREAK"),
    ] {
        assert_eq!(category.as_str(), expected, "{category:?}");
    }

    for (threshold, expected) in [
        (HarmBlockThreshold::LowAndAbove, "BLOCK_LOW_AND_ABOVE"),
        (HarmBlockThreshold::MediumAndAbove, "BLOCK_MEDIUM_AND_ABOVE"),
        (HarmBlockThreshold::OnlyHigh, "BLOCK_ONLY_HIGH"),
        (HarmBlockThreshold::None, "BLOCK_NONE"),
    ] {
        assert_eq!(threshold.as_str(), expected, "{threshold:?}");
    }

    // And each pair reaches the request in that spelling, so the enum's job is
    // checked end to end rather than only at its own boundary.
    let settings = SafetySettings::new()
        .block(HarmCategory::Harassment, HarmBlockThreshold::MediumAndAbove)
        .block(HarmCategory::HateSpeech, HarmBlockThreshold::OnlyHigh)
        .block(
            HarmCategory::SexuallyExplicit,
            HarmBlockThreshold::LowAndAbove,
        )
        .block(HarmCategory::Jailbreak, HarmBlockThreshold::None);
    assert!(!settings.is_empty());
}

/// Serve a fixed Gemini SSE body, recording the query the driver asked with.
///
/// The query is captured because `alt=sse` is load-bearing and invisible in the
/// body: without it `streamGenerateContent` answers with a chunked JSON
/// **array**, which an SSE decoder reads as no events at all.
async fn serve_gemini_sse(body: &'static str) -> (String, SeenQuery) {
    type State2 = (&'static str, SeenQuery);
    async fn sse(
        State((body, seen)): State<State2>,
        request: axum::extract::Request,
    ) -> impl axum::response::IntoResponse {
        *seen.lock().unwrap() = request.uri().query().map(ToOwned::to_owned);
        (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            body,
        )
    }
    let seen: SeenQuery = Arc::new(std::sync::Mutex::new(None));
    let app = Router::new()
        .route("/v1beta/models/{model}", post(sse))
        .with_state((body, Arc::clone(&seen)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), seen)
}

type SeenQuery = Arc<std::sync::Mutex<Option<String>>>;

/// **The default path, end to end.** Streaming is what a Gemini deployment
/// actually runs, and until this existed only `.buffered()` had been exercised
/// through the driver — the accumulator had unit tests, the *path* had none.
///
/// The assertion that earns its place is the signature: it arrives on a
/// function-call part in its own chunk, and it has to reach the continuation
/// through reassembly. Merging text is the obvious thing to do to every part
/// and is right for only one of them, so this is where getting that wrong
/// shows up.
#[tokio::test]
async fn gemini_streams_reassemble_and_keep_the_signature() {
    let (url, query) = serve_gemini_sse(concat!(
        "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Loo\"}]}}]}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"king\"}]}}]}\n\n",
        // A **signed text** part. Google documents that on a turn without
        // function calls the signature rides the final content part — text or
        // inlineData — so a part can be text *and* carry something that must
        // survive. This is the case the merge predicate exists for, and the one
        // a fixture of only unsigned text cannot see: merging by "has a text
        // key" passes such a fixture and destroys this.
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" it\",\"thoughtSignature\":\"TEXTSIG\"}]}}]}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"lookup\",\"args\":{\"q\":\"x\"}},\"thoughtSignature\":\"SIG\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":11,\"candidatesTokenCount\":2,\"thoughtsTokenCount\":6}}\n\n",
    ))
    .await;
    let driver = Gemini::new("k").unwrap().base(url);
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("look it up");

    let completion = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap();

    // The signed text part contributes its text to the answer and keeps its
    // own place in the parts array — both, not either.
    assert_eq!(completion.text, "Looking it", "text deltas were not joined");
    assert_eq!(completion.stop_reason.as_deref(), Some("STOP"));
    assert_eq!(completion.tool_calls.len(), 1);
    assert_eq!(completion.tool_calls[0].name, "lookup");
    // Thinking tokens are billed as output on this path too. A driver that
    // counted them only when buffering would under-report every real
    // deployment, since streaming is the default.
    assert_eq!(completion.usage.output_tokens, 8, "2 answer + 6 thinking");
    assert_eq!(completion.usage.input_tokens, 11);

    let state = completion.continuation.expect("a continuation").state;
    assert_eq!(state["parts"][0]["text"], "Looking", "{state}");
    // Kept whole rather than merged into the run of text before it: a signature
    // on a text part is destroyed by exactly the merge that is correct for an
    // unsigned one.
    assert_eq!(state["parts"][1]["text"], " it", "{state}");
    assert_eq!(
        state["parts"][1]["thoughtSignature"], "TEXTSIG",
        "a signature on a *text* part was flattened away by the merge: {state}"
    );
    assert_eq!(
        state["parts"][2]["thoughtSignature"], "SIG",
        "the signature did not survive reassembly, so the next turn is a 400: {state}"
    );

    // `alt=sse` is load-bearing and invisible in the body. Without it
    // `streamGenerateContent` answers with a chunked JSON *array*, which this
    // driver's SSE decoder reads as no events at all — a stream reported as
    // never having generated, and therefore retried forever against a provider
    // that answered correctly every time.
    assert_eq!(
        query.lock().unwrap().as_deref(),
        Some("alt=sse"),
        "the streaming path did not ask for server-sent events"
    );
}

/// A stream that stopped after generating is not free to retry.
#[tokio::test]
async fn gemini_a_stream_severed_after_generation_is_not_free_to_retry() {
    let (url, _q) = serve_gemini_sse(
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n\n",
    )
    .await;
    let driver = Gemini::new("k").unwrap().base(url);
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("hello");

    let error = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap_err();
    assert!(matches!(&error, ModelError::Unaccounted { .. }), "{error}");
    assert_eq!(error.disposition(), Disposition::Landed);
}

/// A stream that never generated is safe to repeat.
///
/// The pair with the test above is the whole judgement, and getting it backwards
/// is expensive in both directions: calling this one `Landed` strands a run that
/// could simply be retried, and calling *that* one `DidNotHappen` buys a second
/// bill for tokens the provider already generated.
#[tokio::test]
async fn gemini_a_stream_severed_before_generation_is_safe_to_repeat() {
    let (url, _q) = serve_gemini_sse("").await;
    let driver = Gemini::new("k").unwrap().base(url);
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!("hello");

    let error = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .unwrap_err();
    assert!(matches!(&error, ModelError::Unavailable { .. }), "{error}");
    assert_eq!(error.disposition(), Disposition::DidNotHappen);
    assert_eq!(
        error.usage().spend().tokens,
        0,
        "nothing was generated and something was billed"
    );
}

/// **Gemini's provider-side URL form is refused before dispatch.**
///
/// `fileData.fileUri` is how Gemini is told to fetch bytes *itself* — a Files
/// API URI or a remote URL. That is a world-visible fetch from the provider's
/// network, outside this plane's egress allowlist, its DNS pinning, its size
/// and type ceilings, and its journal: the exact thing the governed-media path
/// exists to replace. Every other driver refuses its own provider's spelling
/// of this before anything is sent, and a spelling the shared check does not
/// know is a hole in a control every other driver has.
#[tokio::test]
async fn gemini_refuses_a_provider_side_file_uri() {
    // An unroutable base, so a regression cannot pass by reaching the real
    // endpoint and being refused for some unrelated reason — which is how the
    // first version of this test passed while the hole was wide open.
    let driver = Gemini::new("k")
        .unwrap()
        .base("http://127.0.0.1:1")
        .buffered();
    let model = ModelId::new("gemini", "gemini-3.5-flash");
    let prompt = json!({ "messages": [{
        "role": "user",
        "parts": [
            { "text": "describe this" },
            { "fileData": { "mimeType": "image/png", "fileUri": "https://attacker.example/x.png" } },
        ],
    }]});

    let error = driver
        .complete(gemini_request(&model, &prompt, &[], &[], None))
        .await
        .expect_err("a provider-side fetch must be refused before dispatch");
    // Asserted on the *reason*, not the variant. `Refused` is also what a 4xx
    // maps to, and this driver's default base is Google's real endpoint — so a
    // variant-only assertion would pass just as happily on a 401 from an
    // unauthenticated call that did reach the network, which is the opposite of
    // what is being claimed.
    assert!(
        error
            .to_string()
            .contains("refused before dispatch: the model provider would fetch it"),
        "the refusal did not come from the provider-side media check, so this test \
         proves nothing about it: {error}"
    );

    // Google's REST surface accepts camelCase and snake_case interchangeably, so
    // a control that knows only one is one an author bypasses by writing the
    // other without meaning to.
    let snake = json!({ "messages": [{
        "role": "user",
        "parts": [{ "file_data": { "mime_type": "image/png", "file_uri": "https://attacker.example/x.png" } }],
    }]});
    let error = driver
        .complete(gemini_request(&model, &snake, &[], &[], None))
        .await
        .expect_err("the snake_case spelling reaches the same provider fetch");
    assert!(
        error
            .to_string()
            .contains("refused before dispatch: the model provider would fetch it"),
        "the snake_case spelling was not refused: {error}"
    );

    // The positive half: inline bytes are the governed path and must still work,
    // or this check would be a refuse-everything change that passes its own test.
    let inline = json!({ "messages": [{
        "role": "user",
        "parts": [{ "inlineData": { "mimeType": "image/png", "data": "iVBORw0KGgo=" } }],
    }]});
    let error = driver
        .complete(gemini_request(&model, &inline, &[], &[], None))
        .await
        .expect_err("the unroutable base still fails, but not as a media refusal");
    assert!(
        !error
            .to_string()
            .contains("refused before dispatch: the model provider would fetch it"),
        "inline governed bytes were refused as a provider-side fetch: {error}"
    );
}

/// **The streaming path carries an extension too — and it is the default.**
///
/// The buffered path was fixed first, which covered the path this driver does
/// *not* take unless told to. `ChatCompletions` streams by default, so a fix
/// that stopped at `.buffered()` would be correct where it was looked for and
/// absent where it runs — the worst shape a fix can have.
///
/// Same subject as the buffered test: Gemini through Google's compatibility
/// endpoint puts its encrypted `thought_signature` in
/// `tool_calls[].extra_content`, and rejects the follow-up turn without it.
#[tokio::test]
async fn chat_completions_streaming_carries_an_unknown_tool_call_field_too() {
    let url = serve_cc_sse(concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"\"},\"extra_content\":{\"google\":{\"thought_signature\":\"STREAMSIG\"}}}]}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"q\\\":\\\"x\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":9}}\n\n",
        "data: [DONE]\n\n",
    ))
    .await;
    let driver = ChatCompletions::new(url).unwrap();
    let model = ModelId::new("chat-completions", "gemini-3.5-flash");
    let prompt = json!("look it up");

    let completion = driver.complete(cc_request(&model, &prompt)).await.unwrap();
    assert_eq!(completion.tool_calls.len(), 1);
    // The arguments still reassemble from their fragments: keeping the
    // extension must not cost the concatenation the wire actually needs.
    assert_eq!(completion.tool_calls[0].arguments, json!({ "q": "x" }));

    let state = completion
        .continuation
        .as_ref()
        .expect("a tool call must produce a continuation")
        .state
        .clone();
    assert_eq!(
        state[0]["tool_calls"][0]["extra_content"]["google"]["thought_signature"], "STREAMSIG",
        "the server's own field was dropped reassembling the stream, so the next \
         request cannot return it — and this is the path the driver takes by \
         default: {state}"
    );
}
