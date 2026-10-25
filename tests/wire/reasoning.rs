//! The model's account of its reasoning.
//!
//! A summary is asked for on the wires that can ask, read from the shape each
//! provider returns it in, kept out of the answer, streamed as its own event,
//! journaled with the completion, and never volunteered to a call that did not
//! ask. Run against a local server, so nothing reaches a provider.

#![cfg(all(
    feature = "providers",
    feature = "http",
    feature = "redb",
    feature = "testkit"
))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{Effect, Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::model::anthropic::Anthropic;
use agentplane::model::chat_completions::ChatCompletions;
use agentplane::model::gemini::Gemini;
use agentplane::model::openai::OpenAi;
use agentplane::model::{
    Completion, ModelCall, ModelError, ModelId, ModelProvider, ModelStreamEvent,
    ModelStreamObserver, Request, SchemaMode, Usage,
};
use agentplane::runtime::{Mode, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use serde_json::{Value, json};

type Seen = Arc<Mutex<Option<Value>>>;

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

async fn handle(State(stub): State<Stub>, body: axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    *stub.seen.lock().unwrap() = Some(body.0);
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
    let seen = Arc::new(Mutex::new(None));
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

fn sent(seen: &Seen) -> Value {
    seen.lock()
        .unwrap()
        .clone()
        .expect("the provider was reached")
}

#[derive(Debug, Default)]
struct Capture(Mutex<Vec<ModelStreamEvent>>);

impl ModelStreamObserver for Capture {
    fn event(&self, event: Tainted<ModelStreamEvent>) {
        self.0.lock().unwrap().push(event.peek().clone());
    }
}

impl Capture {
    fn reasoning(&self) -> String {
        self.collect(|event| match event {
            ModelStreamEvent::ReasoningDelta(delta) => Some(delta.clone()),
            _ => None,
        })
    }

    fn text(&self) -> String {
        self.collect(|event| match event {
            ModelStreamEvent::TextDelta(delta) => Some(delta.clone()),
            _ => None,
        })
    }

    fn collect(&self, pick: impl Fn(&ModelStreamEvent) -> Option<String>) -> String {
        self.0.lock().unwrap().iter().filter_map(pick).collect()
    }
}

fn ask<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    summary: bool,
    stream: Option<(&'a dyn ModelStreamObserver, &'a agentplane::core::Label)>,
) -> Request<'a> {
    Request {
        model,
        prompt,
        max_output_tokens: 4096,
        reasoning_effort: None,
        reasoning_summary: summary,
        schema: None,
        tools: &[],
        exchanges: &[],
        continuation: None,
        stream,
    }
}

fn label() -> agentplane::core::Label {
    agentplane::core::Label::trusted()
}

// ── Anthropic ──────────────────────────────────────────────────────────────

fn anthropic_answer() -> Value {
    json!({
        "content": [
            { "type": "thinking", "thinking": "The ledger says 42.", "signature": "SIG" },
            { "type": "text", "text": "The balance is 42." }
        ],
        "usage": { "input_tokens": 3, "output_tokens": 9 },
        "stop_reason": "end_turn"
    })
}

/// A summary is asked for as summarized adaptive thinking and read from the
/// thinking blocks, never into the answer, and never from the signature.
#[tokio::test]
async fn anthropic_asks_for_a_summary_and_reads_it_apart_from_the_answer() {
    let (url, seen) = serve(Answer::Json(anthropic_answer())).await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("anthropic", "claude-opus-5-5");
    let prompt = json!("balance?");

    let out = driver
        .complete(ask(&model, &prompt, true, None))
        .await
        .unwrap();
    assert_eq!(
        sent(&seen)["thinking"],
        json!({ "type": "adaptive", "display": "summarized" }),
        "current models omit thinking text unless the display is summarized"
    );
    assert_eq!(out.reasoning.as_deref(), Some("The ledger says 42."));
    assert_eq!(out.text, "The balance is 42.");
}

/// A call that does not ask sends no thinking configuration at all.
#[tokio::test]
async fn anthropic_does_not_ask_unless_told() {
    let (url, seen) = serve(Answer::Json(anthropic_answer())).await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("anthropic", "claude-opus-5-5");
    let prompt = json!("balance?");
    driver
        .complete(ask(&model, &prompt, false, None))
        .await
        .unwrap();
    assert!(sent(&seen).get("thinking").is_none());
}

/// Streamed thinking is a reasoning delta, and the deltas reassemble the
/// summary the completion carries.
#[tokio::test]
async fn anthropic_streams_thinking_as_reasoning_not_as_text() {
    let events = "\
event: message_start
data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}}

event: content_block_start
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"The ledger \"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"says 42.\"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"SIG\"}}

event: content_block_start
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}

event: content_block_delta
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"42.\"}}

event: message_delta
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":9}}

event: message_stop
data: {\"type\":\"message_stop\"}

";
    let (url, _) = serve(Answer::Sse(events.to_owned())).await;
    let driver = Anthropic::new("k").unwrap().base(url);
    let model = ModelId::new("anthropic", "claude-opus-5-5");
    let prompt = json!("balance?");
    let capture = Capture::default();
    let label = label();

    let out = driver
        .complete(ask(&model, &prompt, true, Some((&capture, &label))))
        .await
        .unwrap();
    assert_eq!(capture.reasoning(), "The ledger says 42.");
    assert_eq!(
        capture.text(),
        "42.",
        "thinking reached the answer's stream"
    );
    assert_eq!(out.reasoning.as_deref(), Some("The ledger says 42."));
    assert_eq!(out.text, "42.");
}

/// Thinking cannot accompany a forced tool choice, so a summary beside the
/// forced-tool schema path is refused before dispatch, as an effort is.
#[tokio::test]
async fn anthropic_refuses_a_summary_beside_a_forced_tool() {
    let (url, seen) = serve(Answer::Json(anthropic_answer())).await;
    let driver = Anthropic::new("k")
        .unwrap()
        .base(url)
        .buffered()
        .structured_via(SchemaMode::ForcedTool);
    let model = ModelId::new("anthropic", "claude-opus-5-5");
    let prompt = json!("balance?");
    let schema = json!({
        "type": "object",
        "properties": { "balance": { "type": "integer" } },
        "required": ["balance"],
        "additionalProperties": false,
    });
    let mut request = ask(&model, &prompt, true, None);
    request.schema = Some(&schema);
    let error = driver
        .complete(request)
        .await
        .expect_err("thinking beside a forced tool");
    assert!(
        matches!(&error, ModelError::Refused { detail, .. } if detail.contains("reasoning summary")),
        "{error}"
    );
    assert!(
        seen.lock().unwrap().is_none(),
        "the request was sent anyway"
    );
}

// ── OpenAI Responses ───────────────────────────────────────────────────────

fn responses_answer() -> Value {
    json!({
        "status": "completed",
        "output": [
            {
                "type": "reasoning",
                "id": "rs_1",
                "encrypted_content": "OPAQUE",
                "summary": [
                    { "type": "summary_text", "text": "Read the ledger." },
                    { "type": "summary_text", "text": "It says 42." }
                ]
            },
            { "type": "message", "content": [{ "type": "output_text", "text": "42." }] }
        ],
        "usage": { "input_tokens": 3, "output_tokens": 9 }
    })
}

/// A summary is asked for as `reasoning.summary` and read from the reasoning
/// items' summary text; the encrypted content beside it is never read.
#[tokio::test]
async fn responses_asks_for_a_summary_and_reads_it_apart_from_the_answer() {
    let (url, seen) = serve(Answer::Json(responses_answer())).await;
    let driver = OpenAi::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");

    let out = driver
        .complete(ask(&model, &prompt, true, None))
        .await
        .unwrap();
    assert_eq!(sent(&seen)["reasoning"]["summary"], "auto");
    assert_eq!(
        out.reasoning.as_deref(),
        Some("Read the ledger.\n\nIt says 42.")
    );
    assert!(!out.reasoning.unwrap().contains("OPAQUE"));
    assert_eq!(out.text, "42.");
}

#[tokio::test]
async fn responses_does_not_ask_unless_told() {
    let (url, seen) = serve(Answer::Json(responses_answer())).await;
    let driver = OpenAi::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");
    driver
        .complete(ask(&model, &prompt, false, None))
        .await
        .unwrap();
    assert!(sent(&seen).get("reasoning").is_none());
}

/// Summary deltas stream as reasoning, and the terminal object is still what
/// the completion is read from.
#[tokio::test]
async fn responses_streams_the_summary_as_reasoning_not_as_text() {
    let terminal = json!({ "type": "response.completed", "response": responses_answer() });
    let events = format!(
        "event: response.created
data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_1\",\"status\":\"in_progress\"}}}}

event: response.reasoning_summary_text.delta
data: {{\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"Read the ledger.\"}}

event: response.output_text.delta
data: {{\"type\":\"response.output_text.delta\",\"delta\":\"42.\"}}

event: response.completed
data: {terminal}

"
    );
    let (url, _) = serve(Answer::Sse(events)).await;
    let driver = OpenAi::new("k").unwrap().base(url);
    let model = ModelId::new("openai", "gpt-5.6");
    let prompt = json!("balance?");
    let capture = Capture::default();
    let label = label();

    let out = driver
        .complete(ask(&model, &prompt, true, Some((&capture, &label))))
        .await
        .unwrap();
    assert_eq!(capture.reasoning(), "Read the ledger.");
    assert_eq!(capture.text(), "42.");
    assert!(out.reasoning.is_some());
}

// ── Gemini ─────────────────────────────────────────────────────────────────

fn gemini_answer() -> Value {
    json!({
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [
                    { "text": "Checking the ledger.", "thought": true },
                    { "text": "42.", "thoughtSignature": "SIG" }
                ]
            },
            "finishReason": "STOP"
        }],
        "usageMetadata": { "promptTokenCount": 3, "candidatesTokenCount": 2 }
    })
}

/// Thought summaries are asked for with `includeThoughts` and read from the
/// parts marked `thought`, never into the answer.
#[tokio::test]
async fn gemini_asks_for_thought_summaries_and_reads_them_apart_from_the_answer() {
    let (url, seen) = serve(Answer::Json(gemini_answer())).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3-pro");
    let prompt = json!("balance?");

    let out = driver
        .complete(ask(&model, &prompt, true, None))
        .await
        .unwrap();
    assert_eq!(
        sent(&seen)["generationConfig"]["thinkingConfig"]["includeThoughts"],
        true
    );
    assert_eq!(out.reasoning.as_deref(), Some("Checking the ledger."));
    assert_eq!(out.text, "42.");
}

#[tokio::test]
async fn gemini_does_not_ask_unless_told() {
    let (url, seen) = serve(Answer::Json(gemini_answer())).await;
    let driver = Gemini::new("k").unwrap().base(url).buffered();
    let model = ModelId::new("gemini", "gemini-3-pro");
    let prompt = json!("balance?");
    driver
        .complete(ask(&model, &prompt, false, None))
        .await
        .unwrap();
    assert!(
        sent(&seen)["generationConfig"]
            .get("thinkingConfig")
            .is_none()
    );
}

#[tokio::test]
async fn gemini_streams_thoughts_as_reasoning_not_as_text() {
    let events = "\
data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Checking \",\"thought\":true}]}}]}

data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"the ledger.\",\"thought\":true}]}}]}

data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"42.\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":2}}

";
    let (url, _) = serve(Answer::Sse(events.to_owned())).await;
    let driver = Gemini::new("k").unwrap().base(url);
    let model = ModelId::new("gemini", "gemini-3-pro");
    let prompt = json!("balance?");
    let capture = Capture::default();
    let label = label();

    let out = driver
        .complete(ask(&model, &prompt, true, Some((&capture, &label))))
        .await
        .unwrap();
    assert_eq!(capture.reasoning(), "Checking the ledger.");
    assert_eq!(capture.text(), "42.");
    assert_eq!(
        out.reasoning.as_deref(),
        Some("Checking the ledger."),
        "the journaled summary is not what streamed"
    );
}

// ── A wire with no way to ask ──────────────────────────────────────────────

/// Chat Completions has no spelling for the request: the call goes through
/// unchanged and carries no summary, even where the server volunteers its
/// reasoning in a dialect.
#[tokio::test]
async fn chat_completions_sends_nothing_and_reads_no_dialect() {
    let (url, seen) = serve(Answer::Json(json!({
        "choices": [{
            "message": { "role": "assistant", "content": "42.", "reasoning_content": "raw thoughts" },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 3, "completion_tokens": 2 }
    })))
    .await;
    let driver = ChatCompletions::new(url).unwrap().buffered();
    let model = ModelId::new("chat-completions", "deepseek-r2");
    let prompt = json!("balance?");

    let asked = driver
        .complete(ask(&model, &prompt, true, None))
        .await
        .unwrap();
    let body_asked = sent(&seen);
    driver
        .complete(ask(&model, &prompt, false, None))
        .await
        .unwrap();
    assert_eq!(
        body_asked,
        sent(&seen),
        "a summary changed the wire request"
    );
    assert_eq!(asked.reasoning, None);
    assert_eq!(asked.text, "42.");
}

// ── The effect boundary ────────────────────────────────────────────────────

/// Asking is provider-visible, so it is in the effect key — and only when set,
/// so a call that does not ask keys as it always has.
#[test]
fn a_summary_request_is_in_the_effect_key_only_when_made() {
    let provider = FakeProvider::new();
    let call = || {
        ModelCall::new(
            Arc::clone(&provider) as Arc<dyn ModelProvider>,
            ModelId::new("fake", "m"),
            json!("q"),
        )
    };
    let plain = call().descriptor().args;
    let asked = call().with_reasoning_summary().descriptor().args;
    assert!(plain.get("reasoning_summary").is_none());
    assert_eq!(asked["reasoning_summary"], true);
    assert_ne!(plain, asked);
}

/// Volunteers its reasoning whether or not it was asked, as a provider an
/// embedder writes may.
#[derive(Debug)]
struct Volunteers;

#[async_trait::async_trait]
impl ModelProvider for Volunteers {
    fn gen_ai_provider(&self) -> Option<&str> {
        None
    }

    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
        if let Some((observer, label)) = request.stream {
            observer.event(Tainted::with_label(
                ModelStreamEvent::ReasoningDelta("unasked".to_owned()),
                label.clone(),
            ));
        }
        Ok(Completion {
            text: "42.".to_owned(),
            model: None,
            tool_calls: Vec::new(),
            usage: Usage::default(),
            stop_reason: Some("stop".to_owned()),
            truncated: false,
            structured: None,
            continuation: None,
            reasoning: Some("unasked".to_owned()),
        })
    }
}

#[derive(Debug)]
struct Asks {
    provider: Arc<dyn ModelProvider>,
    summary: bool,
    capture: Arc<Capture>,
}

#[async_trait::async_trait]
impl Skill for Asks {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("asks").provides("asks")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let mut call = ModelCall::new(
            Arc::clone(&self.provider),
            ModelId::new("fake", "m"),
            input.peek().clone(),
        )
        .streaming_to(Arc::clone(&self.capture) as Arc<dyn ModelStreamObserver>);
        if self.summary {
            call = call.with_reasoning_summary();
        }
        let completion = cx.sink(call, &input).await?;
        Ok(Outcome::done(completion.map(
            |completion| json!({ "text": completion.text, "reasoning": completion.reasoning }),
        )))
    }
}

async fn run(provider: Arc<dyn ModelProvider>, summary: bool) -> (Value, Value, Arc<Capture>) {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let capture = Arc::new(Capture::default());
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Asks {
            provider,
            summary,
            capture: Arc::clone(&capture),
        })
        .build();
    let live = runtime
        .start("asks", Tainted::trusted(json!("balance?")))
        .run()
        .await
        .unwrap();
    let replay = runtime.replay(live.run_id, Mode::Strict).await.unwrap();
    let history = store.read(live.run_id, 0).await.unwrap();
    let turns = agentplane::model::turns(&history);
    assert_eq!(turns.len(), 1, "one call, one turn");
    let journaled = serde_json::to_value(turns[0].completion.as_ref().expect("readable")).unwrap();
    assert_eq!(
        replay.output, live.output,
        "replay read back a different answer"
    );
    (
        live.output.clone().expect("an answer").peek().clone(),
        journaled,
        capture,
    )
}

/// The summary a call asked for is journaled with its completion and read
/// back by a strict replay, which never asks the provider again.
#[tokio::test]
async fn an_asked_summary_is_journaled_and_replayed() {
    let provider = FakeProvider::new();
    provider
        .streaming()
        .will_say_with_reasoning("42.", "Read the ledger.");
    let (output, journaled, capture) =
        run(Arc::clone(&provider) as Arc<dyn ModelProvider>, true).await;
    assert_eq!(output["reasoning"], "Read the ledger.");
    assert_eq!(journaled["reasoning"], "Read the ledger.");
    assert_eq!(capture.reasoning(), "Read the ledger.");
    assert!(provider.asked()[0].reasoning_summary);
}

/// A provider that volunteers reasoning to a call that did not ask reaches
/// neither the completion, the journal nor the stream.
#[tokio::test]
async fn an_unasked_summary_reaches_neither_the_journal_nor_the_stream() {
    let (output, journaled, capture) = run(Arc::new(Volunteers), false).await;
    assert_eq!(output["reasoning"], Value::Null);
    assert!(journaled.get("reasoning").is_none());
    assert_eq!(capture.reasoning(), "");
}
