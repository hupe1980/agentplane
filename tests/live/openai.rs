#![cfg(all(feature = "providers", feature = "redb", feature = "testkit"))]

//! `OpenAI`, for real.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted, Trust};
use agentplane::journal::JournalStore;
use agentplane::model::openai::OpenAi;
use agentplane::model::{
    Completion, ModelCall, ModelError, ModelId, ModelProvider, Request, ToolDeclaration,
};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// The cheapest widely-available model that does structured output and tools.
///
/// Pinned rather than "latest": a test whose subject changes underneath it
/// reports the model's behaviour, not this crate's, and the day it starts
/// failing nobody can tell which moved.
const MODEL: &str = "gpt-4o-mini";

/// The two signals, or `None` and a loud skip.
///
/// See the module docs for why the API key alone is not enough: a credential
/// being *available* is not a decision to spend money with it.
fn live() -> Option<Arc<dyn ModelProvider>> {
    if std::env::var("AGENTPLANE_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set AGENTPLANE_LIVE=1 to run tests that call a real provider");
        return None;
    }
    let Ok(key) = std::env::var("OPENAI_API_KEY") else {
        eprintln!("skipping: OPENAI_API_KEY is not set");
        return None;
    };
    Some(Arc::new(OpenAi::new(key).expect("build the OpenAI driver")))
}

fn model() -> ModelId {
    ModelId::new("openai", MODEL)
}

/// Counts what the provider was actually asked, so "did not call again" is
/// observed rather than assumed.
#[derive(Debug)]
struct Counted {
    inner: Arc<dyn ModelProvider>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ModelProvider for Counted {
    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.complete(request).await
    }
}

/// Asks the model to classify a ticket, in a fixed shape.
#[derive(Debug)]
struct Triage {
    provider: Arc<dyn ModelProvider>,
}

fn schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["severity", "summary"],
        "properties": {
            "severity": { "type": "string", "enum": ["low", "high"] },
            "summary": { "type": "string" }
        }
    })
}

#[async_trait::async_trait]
impl Skill for Triage {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("triage").provides("triage")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let prompt = input.map(|t| {
            json!({
                "instruction": "Classify this support ticket. Answer only in the given schema.",
                "ticket": t
            })
        });
        let call = ModelCall::new(Arc::clone(&self.provider), model(), prompt.peek().clone())
            .expecting(schema());
        let completion = cx.sink(call, &prompt).await?;
        Ok(Outcome::done(completion.map(|c| {
            c.structured.unwrap_or_else(|| json!({ "text": c.text }))
        })))
    }
}

/// A real completion is journaled, and strict replay does not ask again.
///
/// The crate's headline claim, against a provider that can actually disagree
/// with it. The fake cannot prove this: it would return the recorded answer
/// either way, so a driver that re-dispatched on replay would look identical.
/// Here the call counter is the evidence.
#[tokio::test]
async fn a_real_completion_replays_without_calling_openai_again() {
    let Some(provider) = live() else { return };
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::new(Counted {
        inner: provider,
        calls: Arc::clone(&calls),
    }) as Arc<dyn ModelProvider>;

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store))
        .owner("live-test")
        .skill(Triage {
            provider: Arc::clone(&counted),
        })
        .build();

    let out = rt
        .run(
            "triage",
            json!({ "text": "The printer is on fire and the office is being evacuated." }),
        )
        .await
        .expect("the live run failed");
    assert_eq!(out.status, RunStatus::Succeeded, "{:?}", out.status);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the run did not call once");

    // A real provider charges for real tokens. A zero here would mean usage is
    // parsed from a field this driver is not reading.
    assert!(
        out.spend.tokens > 0,
        "the completion reported no tokens, so usage accounting is reading the \
         wrong field — and every budget built on it bounds nothing"
    );

    let replayed = rt
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("strict replay failed");
    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "strict replay called the provider again — the recorded completion is \
         not being read back, so every replay costs money and can differ from \
         the history it claims to reproduce"
    );
    assert_eq!(
        replayed.output, out.output,
        "replay produced a different answer than the run it replayed"
    );
}

/// A real provider accepts our structured-output request and honours the schema.
///
/// The fake cannot fail this: it generates whatever shape it is handed. Only a
/// real provider can reject the request, or answer outside the schema.
#[tokio::test]
async fn openai_returns_an_answer_in_the_declared_schema() {
    let Some(provider) = live() else { return };
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store))
        .owner("live-test")
        .skill(Triage {
            provider: Arc::clone(&provider),
        })
        .build();

    let out = rt
        .run("triage", json!({ "text": "The stapler is empty." }))
        .await
        .expect("the live run failed");

    let answer = out.output.expect("no output");
    let severity = answer["severity"]
        .as_str()
        .unwrap_or_else(|| panic!("the answer is not schema-shaped: {answer}"));
    assert!(
        severity == "low" || severity == "high",
        "the model answered outside its declared enum: {answer}"
    );
    assert!(
        answer["summary"].is_string(),
        "the answer is missing a required field: {answer}"
    );
}

/// The model's answer is **untrusted**, even though it is well-formed.
///
/// Schema conformance is not provenance. A value generated from a context window
/// that held a support ticket carries the ticket's trust, and a real provider
/// returning a perfectly valid object must not change that.
#[tokio::test]
async fn a_real_completion_is_still_untrusted() {
    let Some(provider) = live() else { return };

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store))
        .owner("live-test")
        .skill(Asserts {
            provider: Arc::clone(&provider),
        })
        .build();

    // The skill asserts the label on the value it received; a run that succeeds
    // is the assertion holding against a real provider's answer.
    let out = rt
        .run("asserts", json!({ "text": "anything" }))
        .await
        .expect("the live run failed");
    assert_eq!(out.status, RunStatus::Succeeded, "{:?}", out.status);
}

/// Checks the label a real completion arrives with.
#[derive(Debug)]
struct Asserts {
    provider: Arc<dyn ModelProvider>,
}

#[async_trait::async_trait]
impl Skill for Asserts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("asserts").provides("asserts")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let prompt = input.map(|_| json!({ "instruction": "Reply with the single word: ok" }));
        let call = ModelCall::new(Arc::clone(&self.provider), model(), prompt.peek().clone());
        let completion = cx.sink(call, &prompt).await?;

        assert_eq!(
            completion.label().trust,
            Trust::Untrusted,
            "a real provider's answer arrived trusted — schema conformance is \
             not provenance, and a value generated from a context window that \
             held untrusted input carries that input's trust"
        );
        assert!(
            completion.peek().usage.input_tokens > 0 && completion.peek().usage.output_tokens > 0,
            "a real call reported zero input or output tokens, so usage is \
             being parsed from a field this driver does not read — and every \
             budget built on it bounds nothing"
        );
        Ok(Outcome::done(completion.map(|c| json!({ "text": c.text }))))
    }
}

/// A declared tool's name is one the provider accepts, and a tool call comes
/// back parsed.
///
/// This is the test the fake provider structurally cannot be: `OpenAI` validates
/// function names against its own rules, so a crate that assembles a name the
/// API rejects fails here and passes every stubbed test ever written. This
/// crate has already had three spellings of one tool name in two formats, and
/// only a real API can say which of them is legal.
#[tokio::test]
async fn openai_accepts_our_tool_declaration_and_asks_for_it() {
    let Some(provider) = live() else { return };

    // Straight at the driver: this is about what the *provider* accepts, so a
    // runtime in the middle would only add ways for the test to pass for the
    // wrong reason.
    let id = model();
    let prompt = json!({ "instruction": "What is the weather in Berlin? Use the tool." });
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
    let completion = provider
        .complete(Request {
            model: &id,
            prompt: &prompt,
            schema: None,
            tools: &tools,
            exchanges: &[],
        })
        .await
        .expect("the live completion failed");
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
        "the tool call carried no arguments in the declared shape: {:?}",
        asked.arguments
    );
}
