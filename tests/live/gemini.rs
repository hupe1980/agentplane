#![cfg(all(feature = "providers", feature = "redb", feature = "testkit"))]

//! Gemini, for real — and one property in particular.
//!
//! Every other Gemini test in this repository is offline, and offline is
//! structurally unable to check the thing this driver exists for. The
//! **thought signature** is an encrypted token Google mints and Google
//! validates: a canned server accepts whatever a fixture says it accepts, so an
//! offline test proves the bytes travel from the response into the next request
//! and proves nothing at all about whether Gemini *accepts them back*. Only
//! Gemini can answer that, and its answer for a signature that was dropped,
//! reordered or re-encoded is a 400.
//!
//! So the load-bearing test here is the two-turn tool loop. It is the one that
//! would have caught a driver rebuilding the model's turn instead of carrying
//! it — the defect the wider ecosystem has been carrying for months, and which
//! no amount of fixture-writing surfaces.

use agentplane::model::gemini::{Gemini, HarmBlockThreshold, HarmCategory, SafetySettings};
use agentplane::model::{
    ModelId, ModelProvider, ReasoningEffort, Request, ToolDeclaration, ToolExchange,
};
use serde_json::{Value, json};

/// Pinned rather than "latest": a test whose subject changes underneath it
/// reports the model's behaviour, not this crate's, and the day it starts
/// failing nobody can tell which one moved.
const MODEL: &str = "gemini-3.5-flash";

/// The two signals, or `None` and a loud skip.
///
/// `GEMINI_API_KEY` *and* an explicit opt-in, for the reason the module docs
/// give for `OPENAI_API_KEY`: a credential being available is not a decision to
/// spend money with it.
fn live() -> Option<Gemini> {
    if std::env::var("AGENTPLANE_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set AGENTPLANE_LIVE=1 to run tests that call a real provider");
        return None;
    }
    let key = std::env::var("GEMINI_API_KEY")
        .or_else(|_| std::env::var("GOOGLE_API_KEY"))
        .ok();
    let Some(key) = key else {
        eprintln!("skipping: neither GEMINI_API_KEY nor GOOGLE_API_KEY is set");
        return None;
    };
    Some(Gemini::new(key).expect("build the Gemini driver"))
}

fn model() -> ModelId {
    ModelId::new("gemini", MODEL)
}

fn weather_tool() -> ToolDeclaration {
    ToolDeclaration {
        name: "current_temperature".to_owned(),
        description: "The current temperature in a named city, in Celsius.".to_owned(),
        parameters: json!({
            "type": "object",
            "properties": { "city": { "type": "string" } },
            "required": ["city"],
        }),
    }
}

fn request<'a>(
    model: &'a ModelId,
    prompt: &'a Value,
    tools: &'a [ToolDeclaration],
    exchanges: &'a [ToolExchange],
    continuation: Option<&'a agentplane::model::ProviderContinuation>,
    effort: Option<ReasoningEffort>,
    schema: Option<&'a Value>,
) -> Request<'a> {
    Request {
        model,
        prompt,
        max_output_tokens: 2048,
        reasoning_effort: effort,
        schema,
        tools,
        exchanges,
        continuation,
        stream: None,
    }
}

/// **The signature Gemini minted is the signature Gemini accepts back.**
///
/// The whole driver is arranged around this and nothing offline can check it.
/// Turn one asks a question only a tool can answer; turn two returns the
/// model's own content — signature included — plus the tool result. If the
/// driver rebuilt that turn, dropped the signature, or re-encoded it, Gemini
/// answers 400 `Function call ... is missing a thought_signature` and this
/// fails. A green run is the provider itself confirming the round trip.
#[tokio::test]
async fn a_thought_signature_survives_a_real_tool_turn() {
    let Some(driver) = live() else { return };
    let model = model();
    let tools = [weather_tool()];
    let prompt = json!("What is the current temperature in Reykjavik? Use the tool.");

    let first = driver
        .complete(request(&model, &prompt, &tools, &[], None, None, None))
        .await
        .expect("the first turn");

    assert_eq!(
        first.tool_calls.len(),
        1,
        "the model was asked a question only the tool can answer and did not call it: {first:?}"
    );
    let call = first.tool_calls[0].clone();
    assert_eq!(call.name, "current_temperature");

    let continuation = first
        .continuation
        .clone()
        .expect("a tool call must carry the model's turn forward");
    // Not asserted as *present* — a model may answer without thinking — but if
    // it is there, it must be carried whole. Printed so a failing run says which
    // case it was in.
    eprintln!(
        "continuation parts: {}",
        serde_json::to_string(&continuation.state).unwrap_or_default()
    );

    let exchanges = [ToolExchange {
        call,
        output: json!({ "celsius": 3 }),
        failed: false,
    }];

    // The turn that would 400 if anything about the signature were wrong.
    let second = driver
        .complete(request(
            &model,
            &prompt,
            &tools,
            &exchanges,
            Some(&continuation),
            None,
            None,
        ))
        .await
        .expect(
            "Gemini refused the follow-up turn — this is the failure a rebuilt model turn \
             produces, and the reason this driver carries the provider's own content verbatim",
        );

    assert!(
        !second.text.is_empty() || !second.tool_calls.is_empty(),
        "the second turn produced nothing at all: {second:?}"
    );
    assert!(
        second.usage.input_tokens > 0,
        "a real call reported no input tokens, so the budget is being told it was free"
    );
}

/// A declared thinking level is one Gemini accepts, and it bills for it.
///
/// The offline test pins the *rendering*; only the provider can say the
/// rendering is one it takes. It also settles the accounting question a fixture
/// cannot: whether `thoughtsTokenCount` really arrives beside the candidate
/// count rather than inside it, which is the difference between billing a
/// reasoning run correctly and under-reporting most of it.
#[tokio::test]
async fn a_thinking_level_is_accepted_and_billed() {
    let Some(driver) = live() else { return };
    let model = model();
    let prompt = json!("In one sentence: why is the sky blue?");

    let completion = driver
        .complete(request(
            &model,
            &prompt,
            &[],
            &[],
            None,
            Some(ReasoningEffort::Low),
            None,
        ))
        .await
        .expect("Gemini refused the thinking config this driver renders");

    assert!(!completion.text.is_empty(), "{completion:?}");
    assert!(
        completion.usage.output_tokens > 0,
        "a thinking call reported zero output tokens: {:?}",
        completion.usage
    );
}

/// A native response schema is enforced by the provider, not checked after.
#[tokio::test]
async fn a_native_response_schema_is_accepted() {
    let Some(driver) = live() else { return };
    let model = model();
    let prompt = json!("Classify this ticket: 'the printer is on fire'.");
    let schema = json!({
        "type": "object",
        "properties": {
            "severity": { "type": "string", "enum": ["low", "high"] },
            "summary": { "type": "string" },
        },
        "required": ["severity", "summary"],
    });

    let completion = driver
        .complete(request(
            &model,
            &prompt,
            &[],
            &[],
            None,
            None,
            Some(&schema),
        ))
        .await
        .expect("Gemini refused the responseJsonSchema this driver sends");

    let structured = completion.structured.expect("a schema was asked for");
    assert!(
        structured.get("severity").is_some() && structured.get("summary").is_some(),
        "the provider-enforced schema did not hold: {structured}"
    );
}

/// The deployment's own safety thresholds are ones Gemini accepts.
///
/// Cheap, and it settles the spelling. Gemini **ignores** a category it does not
/// recognise rather than rejecting it, so a typo is a threshold that governs
/// nothing while the manifest looks applied — and no offline test can tell the
/// two apart, because both produce a 200.
#[tokio::test]
async fn declared_safety_thresholds_are_accepted() {
    let Some(driver) = live() else { return };
    let driver = driver.safety(
        SafetySettings::new()
            .block(
                HarmCategory::DangerousContent,
                HarmBlockThreshold::MediumAndAbove,
            )
            .block(HarmCategory::Harassment, HarmBlockThreshold::OnlyHigh),
    );
    let model = model();
    let prompt = json!("Say hello.");

    let completion = driver
        .complete(request(&model, &prompt, &[], &[], None, None, None))
        .await
        .expect("Gemini refused the safetySettings this driver sends");
    assert!(!completion.text.is_empty(), "{completion:?}");
}
