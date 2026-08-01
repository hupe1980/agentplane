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
use agentplane::model::openai::OpenAi;
use agentplane::model::{ModelError, ModelId, ModelProvider, SchemaMode};
use agentplane::peers::a2a::{A2aClient, EXTENSION_URI, Endpoint};
use agentplane::peers::{PeerClient, PeerError, PeerId};
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use serde_json::{Value, json};

/// Answers every request with a canned body and status.
#[derive(Clone)]
struct Canned {
    status: u16,
    body: Value,
    /// What the server saw, so a test can assert what we sent.
    seen: Arc<std::sync::Mutex<Option<Value>>>,
}

async fn handle(
    State(canned): State<Canned>,
    body: Option<axum::Json<Value>>,
) -> (axum::http::StatusCode, axum::Json<Value>) {
    *canned.seen.lock().unwrap() = body.map(|b| b.0);
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
        .with_state(canned);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn canned(status: u16, body: Value) -> (Canned, Arc<std::sync::Mutex<Option<Value>>>) {
    let seen = Arc::new(std::sync::Mutex::new(None));
    (
        Canned {
            status,
            body,
            seen: Arc::clone(&seen),
        },
        seen,
    )
}

fn chain() -> Delegation {
    Delegation::root(Principal::new("user:owner", Scope::root()))
}

// ── A2A: what a failure says about whether the peer acted ───────────────────

/// A JSON-RPC decline is `DidNotHappen`: the peer read it and refused.
#[tokio::test]
async fn a_declined_request_did_not_happen() {
    for code in [-32700, -32600, -32601, -32602, -32001, -32004, -32006] {
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
            "result": { "id": "task-1", "status": { "state": "failed", "message": "declined" } }
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
            "result": { "id": "task-9", "status": { "state": "working" } }
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
    let (c, seen) = canned(200, json!({ "jsonrpc": "2.0", "id": 1, "result": {} }));
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
    assert_eq!(
        msg["extensions"][0], EXTENSION_URI,
        "the extension is not declared, so a peer cannot say it understood it"
    );
    assert!(
        msg["metadata"][EXTENSION_URI]["chain"].is_object(),
        "the delegation chain did not travel: {body}"
    );
    assert_eq!(msg["parts"][0]["data"]["doc"], "INV-1");
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
        schema: None,
    }
}

fn gpt() -> ModelId {
    ModelId::new("openai", "gpt-5")
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
            schema: Some(&sch),
        })
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
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
            schema: Some(&sch),
        })
        .await
        .unwrap();

    let body = seen.lock().unwrap().clone().unwrap();
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
                schema: Some(&sch),
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
            schema: Some(&sch),
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
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "id": "t", "status": { "state": "completed" } } }),
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

    assert!(meta.contains_key("agentplane.io/attestation"), "{meta:?}");
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
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "id": "t", "status": { "state": "completed" } } }),
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
