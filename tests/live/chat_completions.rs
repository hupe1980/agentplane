#![cfg(all(feature = "providers", feature = "redb", feature = "testkit"))]

//! The `OpenAI`-compatible **Chat Completions** wire, for real.
//!
//! This driver is how the crate reaches every self-hosted engine — TGI, vLLM,
//! Ollama, llama.cpp, LM Studio — and it had no live coverage at all, which is
//! the same gap that let two `OpenAI` defects ship. Hugging Face's router *is*
//! this endpoint and needs only a token, so the wire is testable without
//! standing a server up.
//!
//! Gated on `HF_TOKEN` beside `AGENTPLANE_LIVE=1`, and it skips loudly without
//! them. Point `CHAT_COMPLETIONS_BASE_URL` and `CHAT_COMPLETIONS_API_KEY`
//! elsewhere to run the same battery against a local engine, which is the more
//! useful thing to do before trusting one.

use std::sync::Arc;

use agentplane::model::chat_completions::ChatCompletions;
use agentplane::model::{ModelCall, ModelId, ModelProvider, Request, ToolDeclaration};
use serde_json::{Value, json};

/// Pinned, for the reason every model in this suite is: a test whose subject
/// changes underneath it reports the model's behaviour, not this crate's.
const MODEL: &str = "openai/gpt-oss-20b";

const ROUTER: &str = "https://router.huggingface.co/v1";

/// The two signals, or `None` and a loud skip.
fn live() -> Option<(Arc<dyn ModelProvider>, ModelId)> {
    if std::env::var("AGENTPLANE_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set AGENTPLANE_LIVE=1 to run tests that call a real provider");
        return None;
    }
    let base = std::env::var("CHAT_COMPLETIONS_BASE_URL").unwrap_or_else(|_| ROUTER.to_owned());
    let model = std::env::var("CHAT_COMPLETIONS_MODEL").unwrap_or_else(|_| MODEL.to_owned());
    let Ok(token) =
        std::env::var("CHAT_COMPLETIONS_API_KEY").or_else(|_| std::env::var("HF_TOKEN"))
    else {
        eprintln!("skipping: neither CHAT_COMPLETIONS_API_KEY nor HF_TOKEN is set");
        return None;
    };
    let driver = ChatCompletions::new(base)
        .expect("build the chat-completions driver")
        .bearer(token);
    Some((Arc::new(driver), ModelId::new("chat-completions", model)))
}

/// One call: `None` when the far side says this account may not make it.
///
/// Two conditions, both outside the crate's control and both handled the way
/// this suite handles a missing key — loudly, without failing a build.
///
/// A **cut stream** is retried once. These drivers stream by default,
/// deliberately: a response dying in transit is then an honest *unknown*
/// rather than a `may never have generated`. A shared public router drops a
/// connection now and then; retried once so a hiccup does not fail the build,
/// and only once so a server that truncates every time still does.
///
/// A **credential or quota refusal** skips. `401`, `402` and `403` say the
/// account cannot spend, which is the same fact as an absent key arriving
/// later — and a free router's monthly allowance running out must not read as
/// this crate breaking.
async fn complete_or_skip(
    provider: &Arc<dyn ModelProvider>,
    prompt: &Value,
    model: &ModelId,
    schema: Option<&Value>,
    tools: &[ToolDeclaration],
) -> Option<agentplane::model::Completion> {
    // Matched on the rendered status because that is where a driver puts it;
    // the alternative is a public status field on every model error, added for
    // one test helper.
    fn cannot_spend(error: &agentplane::model::ModelError) -> bool {
        let rendered = error.to_string();
        ["HTTP 401", "HTTP 402", "HTTP 403"]
            .iter()
            .any(|status| rendered.contains(status))
    }

    let first = match provider.complete(ask(model, prompt, schema, tools)).await {
        Ok(completion) => return Some(completion),
        Err(first) => first,
    };
    if cannot_spend(&first) {
        eprintln!("skipping: this account may not spend on the configured server: {first}");
        return None;
    }
    eprintln!("retrying once after: {first}");
    match provider.complete(ask(model, prompt, schema, tools)).await {
        Ok(completion) => Some(completion),
        Err(second) if cannot_spend(&second) => {
            eprintln!("skipping: this account may not spend on the configured server: {second}");
            None
        }
        Err(second) => panic!("the live completion failed twice: {first} / then {second}"),
    }
}

fn ask<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    schema: Option<&'a Value>,
    tools: &'a [ToolDeclaration],
) -> Request<'a> {
    Request {
        model,
        prompt,
        max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
        reasoning_effort: None,
        schema,
        tools,
        exchanges: &[],
        continuation: None,
        stream: None,
    }
}

/// A schema this crate emits is one the compatible wire accepts, and the
/// answer comes back parsed.
///
/// The wire has no native constrained decoding, so this driver emulates it with
/// a single forced tool whose parameters are the answer's shape — a mechanism
/// no fake can exercise, because a fake accepts whatever it is handed.
#[tokio::test]
async fn a_compatible_server_answers_in_the_declared_schema() {
    let Some((provider, model)) = live() else {
        return;
    };
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["severity"],
        "properties": { "severity": { "type": "string", "enum": ["low", "high"] } }
    });
    let prompt = json!({
        "system": "Classify the ticket. Answer only in the given schema.",
        "input": "The printer is on fire and the office is being evacuated."
    });
    let Some(completion) = complete_or_skip(&provider, &prompt, &model, Some(&schema), &[]).await
    else {
        return;
    };

    let answer = completion
        .structured
        .as_ref()
        .unwrap_or_else(|| panic!("no structured answer came back: {completion:?}"));
    assert!(
        matches!(answer["severity"].as_str(), Some("low" | "high")),
        "the emulated schema did not bind the answer: {answer}"
    );
    assert!(
        completion.usage.input_tokens > 0 && completion.usage.output_tokens > 0,
        "the server reported no usage, so every budget built on it bounds \
         nothing: {:?}",
        completion.usage
    );
}

/// A declared tool's name survives the round trip, and its call comes back
/// parsed.
///
/// Arguments arrive on this wire as a JSON **string** rather than an object —
/// the difference from the Responses wire that a stubbed provider cannot have,
/// and the one a driver is most likely to get wrong.
#[tokio::test]
async fn a_compatible_server_accepts_our_tool_declaration_and_asks_for_it() {
    let Some((provider, model)) = live() else {
        return;
    };
    let prompt = json!({
        "system": "Use the tool to answer. Do not guess.",
        "input": "What is the weather in Berlin?"
    });
    let tools = [ToolDeclaration::new(
        "weather_lookup",
        "Look up the current weather for a city.",
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["city"],
            "properties": { "city": { "type": "string" } }
        }),
    )];
    let Some(completion) = complete_or_skip(&provider, &prompt, &model, None, &tools).await else {
        return;
    };

    let asked = completion
        .tool_calls
        .first()
        .unwrap_or_else(|| panic!("the model asked for no tool: {completion:?}"));
    assert_eq!(
        asked.name, "weather_lookup",
        "the tool name came back as something other than the one declared, so \
         a dispatcher matching on it byte for byte would find nothing"
    );
    assert!(
        asked.arguments.get("city").is_some(),
        "the tool call's arguments did not parse out of the JSON string this \
         wire carries them in: {:?}",
        asked.arguments
    );
    assert!(
        !asked.id.is_empty(),
        "the call carries no id, so the result cannot be handed back on the \
         next turn"
    );
}

/// The plan format `execution.kind: planned` asks for is one this wire accepts.
///
/// It is the largest schema the crate ever sends, and the `OpenAI` driver
/// refused the old one outright — so the question is worth asking of every wire
/// that claims compatibility, not only the one that caught it.
#[tokio::test]
async fn a_compatible_server_accepts_the_plan_format() {
    let Some((provider, model)) = live() else {
        return;
    };
    // The shape `plan_schema` emits, which is private to the crate. Kept in
    // step by `the_plan_format_survives_constrained_decoding`, which holds the
    // real one to the same subset this literal is written in.
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["steps", "answer"],
        "properties": {
            "steps": {
                "type": "array",
                "minItems": 1,
                "maxItems": 4,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["tool", "args", "parse"],
                    "properties": {
                        "tool": { "type": ["string", "null"] },
                        "args": { "type": ["string", "null"] },
                        "parse": {
                            "type": ["object", "null"],
                            "additionalProperties": false,
                            "required": ["from", "schema"],
                            "properties": {
                                "from": { "type": "string" },
                                "schema": { "type": "string" }
                            }
                        }
                    }
                }
            },
            "answer": { "type": ["string", "null"] }
        }
    });
    let prompt = json!({
        "system": "Plan the steps. A tool step names `tool` and `args`; \
                   `args` is a JSON object written as text.",
        "input": { "customer": "AC-1" },
        "tools": [{
            "tool": "crm__lookup",
            "description": "Look up a customer record by id.",
            "parameters": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id"],
                "properties": { "id": { "type": "string" } }
            }
        }]
    });
    let Some(completion) = complete_or_skip(&provider, &prompt, &model, Some(&schema), &[]).await
    else {
        return;
    };

    let plan = completion
        .structured
        .as_ref()
        .unwrap_or_else(|| panic!("no plan came back: {completion:?}"));
    let steps = plan["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("the plan carries no steps: {plan}"));
    assert!(!steps.is_empty(), "an empty plan: {plan}");
}
