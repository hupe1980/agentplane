//! A governed run against a **real** `OpenAI` model.
//!
//! ```sh
//! export OPENAI_API_KEY=...        # or put it in .env and use `just test-live`
//! cargo run --example openai_live --features redb,providers
//! ```
//!
//! **This costs money.** It is deliberately absent from `just examples`, which
//! runs on every CI pass — an example that bills the maintainer for a docs
//! change is one nobody keeps.
//!
//! `model_run` is the same story against `FakeProvider`: no key, no
//! network, runnable by anyone. Read that one first. This exists to show the
//! claim holding against a provider that can genuinely disagree — which is not
//! a hypothetical, because writing it found two bugs in the `OpenAI` driver that
//! every stubbed test had passed.
//!
//! What it shows:
//!
//! 1. A run asks a real model for a schema-shaped answer, and journals it.
//! 2. **Strict replay reproduces the answer without calling `OpenAI` again** —
//!    the counter proves it, so a driver that re-dispatched would be caught.
//! 3. The answer is `Untrusted`, however well-formed. Schema conformance is not
//!    provenance.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted, Trust};
use agentplane::journal::JournalStore;
use agentplane::model::openai::OpenAi;
use agentplane::model::{Completion, ModelCall, ModelError, ModelId, ModelProvider, Request};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Pinned, not "latest": an example whose subject changes underneath it
/// demonstrates the model's behaviour rather than this crate's.
const MODEL: &str = "gpt-4o-mini";

/// Counts calls, so "did not ask again" is observed rather than asserted.
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

#[derive(Debug)]
struct Triage {
    provider: Arc<dyn ModelProvider>,
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
        let prompt = input.map(|ticket| {
            json!({
                "instruction": "Classify this support ticket. Answer only in the given schema.",
                "ticket": ticket
            })
        });

        let call = ModelCall::new(
            Arc::clone(&self.provider),
            ModelId::new("openai", MODEL),
            prompt.peek().clone(),
        )
        .expecting(schema());

        // Through `cx.sink`, which binds the labelled value to the call the
        // policy gate checked. The completion comes back labelled: it was
        // generated from a context window that held the ticket, and the ticket
        // came from outside.
        let completion = cx.sink(call, &prompt).await?;
        assert_eq!(completion.label().trust, Trust::Untrusted);

        Ok(Outcome::done(completion.map(|c| {
            c.structured.unwrap_or_else(|| json!({ "text": c.text }))
        })))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(key) = std::env::var("OPENAI_API_KEY") else {
        eprintln!("OPENAI_API_KEY is not set — this example calls a real model.");
        eprintln!(
            "For a version that needs no key: cargo run --example model_run --features redb,testkit"
        );
        return Ok(());
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(Counted {
        inner: Arc::new(OpenAi::new(key)?),
        calls: Arc::clone(&calls),
    }) as Arc<dyn ModelProvider>;

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let rt = Runtime::builder(Arc::clone(&store))
        .owner("openai-live-example")
        .skill(Triage {
            provider: Arc::clone(&provider),
        })
        .build();

    // ── 1. A live run ───────────────────────────────────────────────────────
    let out = rt
        .run(
            "triage",
            json!({ "text": "The printer is on fire and the office is being evacuated." }),
        )
        .await?;
    println!("run      {} → {:?}", out.run_id, out.status);
    println!("answer   {}", out.output.clone().unwrap_or(Value::Null));
    println!(
        "spend    {} tokens, {} calls to OpenAI",
        out.spend.tokens,
        calls.load(Ordering::SeqCst)
    );
    assert_eq!(out.status, RunStatus::Succeeded);

    // ── 2. Strict replay, which must not ask again ──────────────────────────
    let before = calls.load(Ordering::SeqCst);
    let replayed = rt.replay(out.run_id, Mode::Strict).await?;
    let after = calls.load(Ordering::SeqCst);

    println!("replay   {:?}", replayed.status);
    println!("calls    {before} before, {after} after — the model was not asked again");
    assert_eq!(
        before, after,
        "strict replay called the provider, so replay costs money and can \
         differ from the history it claims to reproduce"
    );
    assert_eq!(replayed.output, out.output);

    println!("\nthe answer replayed from the journal, byte for byte, without a network call");
    Ok(())
}
