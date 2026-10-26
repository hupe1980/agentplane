//! A conversation over the drivers: what the model says beside its calls, a
//! person's turn after an answer, and compaction the provider performs.
//!
//! Run against a local server, so nothing reaches a provider.

#![cfg(all(feature = "providers", feature = "http"))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::Tainted;
use agentplane::model::anthropic::Anthropic;
use agentplane::model::chat_completions::ChatCompletions;
use agentplane::model::gemini::Gemini;
use agentplane::model::openai::OpenAi;
use agentplane::model::{
    Compaction, Completion, ModelError, ModelId, ModelProvider, ModelStreamEvent,
    ModelStreamObserver, Request,
};
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use serde_json::{Value, json};

type Seen = Arc<Mutex<Vec<Value>>>;

/// What the stub answers: a JSON body, or an event stream.
#[derive(Clone)]
enum Answer {
    Json(Value),
    Sse(String),
}

#[derive(Clone)]
struct Stub {
    answer: Answer,
    seen: Seen,
}

async fn handle(
    State(stub): State<Stub>,
    headers: axum::http::HeaderMap,
    body: axum::Json<Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut body = body.0;
    // The one header a test here asks about, kept beside the body it came with.
    if let Some(beta) = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()) {
        body["__anthropic_beta"] = json!(beta);
    }
    stub.seen.lock().unwrap().push(body);
    match stub.answer {
        Answer::Json(value) => axum::Json(value).into_response(),
        Answer::Sse(events) => (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            events,
        )
            .into_response(),
    }
}

async fn serve(answer: Answer) -> (String, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/messages", post(handle))
        .route("/v1/responses", post(handle))
        .route("/v1/chat/completions", post(handle))
        .route("/v1beta/models/{model}", post(handle))
        .with_state(Stub {
            answer,
            seen: Arc::clone(&seen),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), seen)
}

#[derive(Debug, Default)]
struct Capture(Mutex<Vec<ModelStreamEvent>>);

impl ModelStreamObserver for Capture {
    fn event(&self, event: Tainted<ModelStreamEvent>) {
        self.0.lock().unwrap().push(event.peek().clone());
    }
}

impl Capture {
    fn collect(&self, pick: impl Fn(&ModelStreamEvent) -> Option<String>) -> String {
        self.0.lock().unwrap().iter().filter_map(pick).collect()
    }
}

fn ask<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    stream: Option<(&'a dyn ModelStreamObserver, &'a agentplane::core::Label)>,
) -> Request<'a> {
    Request {
        model,
        prompt,
        max_output_tokens: 4096,
        reasoning_effort: None,
        reasoning_summary: false,
        schema: None,
        tools: &[],
        exchanges: &[],
        told: &[],
        continuation: None,
        compaction: None,
        stream,
    }
}

fn narrated() -> Value {
    json!({
        "status": "completed",
        "output": [
            { "type": "message", "role": "assistant", "phase": "commentary",
              "content": [{ "type": "output_text", "text": "Checking the ledger." }] },
            { "type": "function_call", "call_id": "call_1", "name": "ledger", "arguments": "{}" }
        ],
        "usage": { "input_tokens": 3, "output_tokens": 9 }
    })
}

/// Responses narration beside a call reaches the completion as commentary,
/// and stays out of the answer.
#[tokio::test]
async fn responses_keeps_the_words_beside_a_call() {
    let (url, _) = serve(Answer::Json(narrated())).await;
    let driver = OpenAi::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");
    let out = driver.complete(ask(&model, &prompt, None)).await.unwrap();
    assert_eq!(out.commentary.as_deref(), Some("Checking the ledger."));
    assert_eq!(out.text, "");
    assert_eq!(out.tool_calls.len(), 1);
}

/// The live stream agrees with the completion: narration arrives as
/// commentary, never as answer text.
#[tokio::test]
async fn responses_streams_the_words_beside_a_call_as_commentary() {
    let terminal = json!({ "type": "response.completed", "response": narrated() });
    let events = format!(
        "event: response.output_item.added
data: {{\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{{\"type\":\"message\",\"role\":\"assistant\",\"phase\":\"commentary\",\"content\":[]}}}}

event: response.output_text.delta
data: {{\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"Checking the ledger.\"}}

event: response.completed
data: {terminal}

"
    );
    let (url, _) = serve(Answer::Sse(events)).await;
    let driver = OpenAi::new("k").unwrap().base(url);
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");
    let capture = Capture::default();
    let label = agentplane::core::Label::trusted();
    let out = driver
        .complete(ask(&model, &prompt, Some((&capture, &label))))
        .await
        .unwrap();
    let commentary = capture.collect(|e| match e {
        ModelStreamEvent::CommentaryDelta(d) => Some(d.clone()),
        _ => None,
    });
    let text = capture.collect(|e| match e {
        ModelStreamEvent::TextDelta(d) => Some(d.clone()),
        _ => None,
    });
    assert_eq!(commentary, "Checking the ledger.");
    assert_eq!(text, "", "narration streamed as the answer");
    assert_eq!(out.commentary.as_deref(), Some("Checking the ledger."));
}

// ── A person's turn ─────────────────────────────────────────────────────────

/// A follow-up call: the person's message after the conversation so far.
fn follow<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    told: &'a [String],
    after: &'a Completion,
) -> Request<'a> {
    Request {
        told,
        continuation: after.continuation.as_ref(),
        ..ask(model, prompt, None)
    }
}

fn said(text: &str) -> Vec<String> {
    vec![text.to_owned()]
}

/// The two requests a driver made, after answering the first in text.
async fn two_turns(driver: &dyn ModelProvider, seen: &Seen, model: &ModelId) -> (Value, Value) {
    let prompt = json!("balance?");
    let first = driver.complete(ask(model, &prompt, None)).await.unwrap();
    assert!(
        first.continuation.is_some(),
        "a text answer left no history for a person to follow"
    );
    let told = said("and in euros?");
    driver
        .complete(follow(model, &prompt, &told, &first))
        .await
        .unwrap();
    let bodies = seen.lock().unwrap().clone();
    (bodies[0].clone(), bodies[1].clone())
}

/// Anthropic: the history, the model's answer, then the person — one user
/// message after the assistant turn.
#[tokio::test]
async fn anthropic_sends_the_persons_turn_after_the_history() {
    let (url, seen) = serve(Answer::Json(json!({
        "content": [{ "type": "text", "text": "42." }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 3, "output_tokens": 2 }
    })))
    .await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("anthropic", "claude-x");
    let (_, second) = two_turns(&driver, &seen, &model).await;
    let messages = second["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 3, "{messages:?}");
    assert_eq!(messages[1]["role"], "assistant");
    assert_eq!(messages[1]["content"][0]["text"], "42.");
    assert_eq!(messages[2]["role"], "user");
    assert_eq!(
        messages[2]["content"],
        json!([{ "type": "text", "text": "and in euros?" }])
    );
}

/// Responses: the answer's output items, then the person as a user message.
#[tokio::test]
async fn responses_sends_the_persons_turn_after_the_history() {
    let (url, seen) = serve(Answer::Json(json!({
        "status": "completed",
        "output": [{ "type": "message", "role": "assistant",
                     "content": [{ "type": "output_text", "text": "42." }] }],
        "usage": { "input_tokens": 3, "output_tokens": 2 }
    })))
    .await;
    let driver = OpenAi::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("openai", "gpt-5.6");
    let (_, second) = two_turns(&driver, &seen, &model).await;
    let input = second["input"].as_array().expect("input items");
    assert_eq!(input.len(), 3, "{input:?}");
    assert_eq!(input[1]["type"], "message");
    assert_eq!(input[2]["role"], "user");
    assert_eq!(input[2]["content"][0]["text"], "and in euros?");
}

/// Chat Completions: the assistant message, then the person.
#[tokio::test]
async fn chat_completions_sends_the_persons_turn_after_the_history() {
    let (url, seen) = serve(Answer::Json(json!({
        "choices": [{ "message": { "role": "assistant", "content": "42." }, "finish_reason": "stop" }],
        "usage": { "prompt_tokens": 3, "completion_tokens": 2 }
    })))
    .await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let (_, second) = two_turns(&driver, &seen, &model).await;
    let messages = second["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 3, "{messages:?}");
    assert_eq!(messages[1]["role"], "assistant");
    assert_eq!(
        messages[2],
        json!({ "role": "user", "content": "and in euros?" })
    );
}

/// Gemini: the model turn verbatim, signature included, then the person.
#[tokio::test]
async fn gemini_sends_the_persons_turn_after_the_history() {
    let (url, seen) = serve(Answer::Json(json!({
        "candidates": [{
            "content": { "role": "model", "parts": [{ "text": "42.", "thoughtSignature": "SIG" }] },
            "finishReason": "STOP"
        }],
        "usageMetadata": { "promptTokenCount": 3, "candidatesTokenCount": 2 }
    })))
    .await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3-pro");
    let (_, second) = two_turns(&driver, &seen, &model).await;
    let contents = second["contents"].as_array().expect("contents");
    assert_eq!(contents.len(), 3, "{contents:?}");
    assert_eq!(contents[1]["parts"][0]["thoughtSignature"], "SIG");
    assert_eq!(
        contents[2],
        json!({ "role": "user", "parts": [{ "text": "and in euros?" }] })
    );
}

/// A history that keeps growing: the third request still carries the first
/// person's message and both answers.
#[tokio::test]
async fn a_conversation_keeps_every_turn() {
    let (url, seen) = serve(Answer::Json(json!({
        "content": [{ "type": "text", "text": "ok" }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 3, "output_tokens": 2 }
    })))
    .await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("anthropic", "claude-x");
    let prompt = json!("hello");
    let first = driver.complete(ask(&model, &prompt, None)).await.unwrap();
    let one = said("one");
    let second = driver
        .complete(follow(&model, &prompt, &one, &first))
        .await
        .unwrap();
    let two = said("two");
    driver
        .complete(follow(&model, &prompt, &two, &second))
        .await
        .unwrap();
    let third = seen.lock().unwrap()[2].clone();
    let roles: Vec<_> = third["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(roles, ["user", "assistant", "user", "assistant", "user"]);
    assert_eq!(third["messages"][2]["content"][0]["text"], "one");
    assert_eq!(third["messages"][4]["content"][0]["text"], "two");
}

// ── Compaction ──────────────────────────────────────────────────────────────

fn compacting<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    compaction: &'a Compaction,
) -> Request<'a> {
    Request {
        compaction: Some(compaction),
        ..ask(model, prompt, None)
    }
}

/// Anthropic is asked under its beta, reports the compaction with its
/// summary, carries the block back, and bills the compaction pass.
#[tokio::test]
async fn anthropic_compacts_reports_and_bills_the_pass() {
    let (url, seen) = serve(Answer::Json(json!({
        "content": [
            { "type": "compaction", "content": "The user asked about balances." },
            { "type": "text", "text": "42." }
        ],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 10, "output_tokens": 5,
            "iterations": [
                { "type": "compaction", "input_tokens": 180_000, "output_tokens": 2_000 },
                { "type": "message", "input_tokens": 10, "output_tokens": 5 }
            ]
        }
    })))
    .await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("anthropic", "claude-x");
    let prompt = json!("balance?");
    let compaction = Compaction::at(150_000).instructions("keep the figures");
    let out = driver
        .complete(compacting(&model, &prompt, &compaction))
        .await
        .unwrap();
    let sent = seen.lock().unwrap()[0].clone();
    assert_eq!(sent["__anthropic_beta"], "compact-2026-01-12");
    assert_eq!(
        sent["context_management"],
        json!({ "edits": [{
            "type": "compact_20260112",
            "trigger": { "type": "input_tokens", "value": 150_000 },
            "instructions": "keep the figures"
        }] })
    );
    assert_eq!(
        out.compacted.and_then(|c| c.summary).as_deref(),
        Some("The user asked about balances.")
    );
    assert_eq!(
        out.usage.input_tokens, 180_010,
        "the compaction pass was not billed"
    );
    assert_eq!(out.usage.output_tokens, 2_005);
    let carried = out.continuation.expect("history").state;
    assert_eq!(carried[0]["content"][0]["type"], "compaction");
}

/// A trigger under Anthropic's floor is refused before any request.
#[tokio::test]
async fn anthropic_refuses_a_trigger_under_its_floor() {
    let (url, seen) = serve(Answer::Json(json!({}))).await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("anthropic", "claude-x");
    let prompt = json!("balance?");
    let compaction = Compaction::at(10_000);
    let refused = driver
        .complete(compacting(&model, &prompt, &compaction))
        .await;
    assert!(
        matches!(refused, Err(ModelError::Refused { .. })),
        "{refused:?}"
    );
    assert!(seen.lock().unwrap().is_empty(), "the request was sent");
}

/// Responses is asked through `context_management`, and an output
/// `compaction` item is reported — with no summary, since it is encrypted.
#[tokio::test]
async fn responses_compacts_and_reports_it() {
    let (url, seen) = serve(Answer::Json(json!({
        "status": "completed",
        "output": [
            { "type": "compaction", "id": "cmp_1", "encrypted_content": "OPAQUE" },
            { "type": "message", "content": [{ "type": "output_text", "text": "42." }] }
        ],
        "usage": { "input_tokens": 3, "output_tokens": 2 }
    })))
    .await;
    let driver = OpenAi::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");
    let compaction = Compaction::at(200_000);
    let out = driver
        .complete(compacting(&model, &prompt, &compaction))
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap()[0]["context_management"],
        json!([{ "type": "compaction", "compact_threshold": 200_000 }])
    );
    assert_eq!(out.compacted.expect("reported").summary, None);
}

/// Responses has no field for summary instructions, so asking is refused.
#[tokio::test]
async fn responses_refuses_summary_instructions() {
    let (url, seen) = serve(Answer::Json(json!({}))).await;
    let driver = OpenAi::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");
    let compaction = Compaction::at(200_000).instructions("keep the figures");
    let refused = driver
        .complete(compacting(&model, &prompt, &compaction))
        .await;
    assert!(
        matches!(refused, Err(ModelError::Refused { .. })),
        "{refused:?}"
    );
    assert!(seen.lock().unwrap().is_empty(), "the request was sent");
}

/// A wire that cannot compact refuses before sending, rather than letting
/// the conversation run into its window.
#[tokio::test]
async fn a_wire_that_cannot_compact_refuses() {
    let (url, seen) = serve(Answer::Json(json!({}))).await;
    let prompt = json!("balance?");
    let compaction = Compaction::at(200_000);
    let chat = ChatCompletions::new(url.clone()).unwrap().buffered();
    let model = ModelId::new("chat-completions", "m");
    let refused = chat
        .complete(compacting(&model, &prompt, &compaction))
        .await;
    assert!(
        matches!(refused, Err(ModelError::Refused { .. })),
        "{refused:?}"
    );
    let gemini = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3-pro");
    let refused = gemini
        .complete(compacting(&model, &prompt, &compaction))
        .await;
    assert!(
        matches!(refused, Err(ModelError::Refused { .. })),
        "{refused:?}"
    );
    assert!(seen.lock().unwrap().is_empty(), "a request was sent");
}
