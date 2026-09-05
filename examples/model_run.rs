//! A model-backed run that replays without asking the model again.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example model_run --features redb,testkit
//! ```
//!
//! No API key, no network. `testkit::FakeProvider` stands in for the provider,
//! which is what makes this the one example that can demonstrate the crate's
//! headline claim end to end — a real driver would make it unrunnable for anyone
//! without an account, and the claim would stay in the README.
//!
//! What it demonstrates, in order:
//!
//! 1. A run asks a model for a schema-shaped answer and journals the completion.
//! 2. Strict replay reproduces the answer and **does not call the provider**.
//! 3. A completion that died partway is billed for what it generated, and the
//!    token ceiling stops the run before it asks again.
//!
//! Point 3 is the one that is easy to get backwards. Every other outward call
//! this crate makes either happened or did not; a model call has a third state,
//! and the provider bills for it.

use std::sync::Arc;

use agentplane::core::{Budget, Outcome, Skill, SkillDescriptor, SkillError, Tainted, Trust};
use agentplane::journal::JournalStore;
use agentplane::model::{ModelCall, ModelError, ModelId, ModelProvider, Usage};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

fn render(output: Option<&Value>) -> String {
    output.map_or_else(|| "—".to_owned(), Value::to_string)
}

fn model() -> ModelId {
    ModelId::new("fake", "triage-1")
}

/// The shape the answer must take.
///
/// Passed to the provider's structured-output mode, where the constraint is
/// enforced *during* generation. A schema applied afterwards rejects an answer
/// you have already paid for.
fn schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["severity", "summary"],
        "properties": {
            "severity": {"type": "string"},
            "summary":  {"type": "string"},
        },
    })
}

/// Reads a ticket, asks a model to triage it.
///
/// The field is the *driver interface*, not the fake: a skill that names the
/// concrete provider type couples itself to one deployment's wiring.
#[derive(Debug)]
struct Triage {
    provider: Arc<dyn ModelProvider>,
}

#[async_trait::async_trait]
impl Skill for Triage {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("triage").provides("support.triage")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let provider = Arc::clone(&self.provider);
        let prompt = input.map(|input| json!({ "task": "triage this ticket", "ticket": input }));
        // `sink_with` hands the labelled value to the effect and the gates in
        // one motion: the closure receives the inner value, so the bytes the
        // egress ceiling checks and the bytes the provider is sent cannot be
        // two versions of one prompt.
        let completion = cx
            .sink_with(&prompt, |value| {
                ModelCall::new(provider, model(), value).expecting(schema())
            })
            .await?;

        // Whatever came back is a plausible string produced from a context
        // window that held the ticket, and the ticket arrived from outside. The
        // label rides along with the value; nothing here has to remember to
        // re-apply it.
        assert_eq!(completion.label().trust, Trust::Untrusted);

        Ok(Outcome::done(completion.map(|c| {
            c.structured.unwrap_or_else(|| json!({ "text": c.text }))
        })))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);

    // ── 1. A live run ──────────────────────────────────────────────────────
    let provider = FakeProvider::new();
    let rt = Runtime::builder(Arc::clone(&store))
        .owner("example")
        .skill(Triage {
            // Coerces to `Arc<dyn ModelProvider>` at the field: the fake is a
            // detail of this example's wiring, not of the skill.
            provider: provider.clone(),
        })
        .build();

    let ticket = json!({ "id": "T-4711", "body": "checkout returns 500 for EU cards" });
    let live = rt
        .run("support.triage", Tainted::trusted(ticket.clone()))
        .await?;
    println!("1. live run       → {:?}", live.status);
    println!("   provider calls: {}", provider.calls());
    println!(
        "   answer:         {}",
        render(live.output.as_ref().map(agentplane::Tainted::peek))
    );
    println!("   spend:          {} tokens", live.spend().tokens);

    // ── 2. Replay reads the journal, not the model ─────────────────────────
    let before = provider.calls();
    let replayed = rt.replay(live.run_id, Mode::Strict).await?;
    println!("\n2. strict replay  → {:?}", replayed.status);
    println!(
        "   provider calls: {} (unchanged: {})",
        provider.calls(),
        provider.calls() == before
    );
    assert_eq!(
        provider.calls(),
        before,
        "a replay that asked the model again would pay twice and could get a \
         different answer — the completion is journaled precisely so it cannot"
    );
    assert_eq!(
        live.output, replayed.output,
        "the least deterministic thing a run touches replays exactly"
    );

    // ── 3. A failed completion is not a free one ───────────────────────────
    // The first call generates 400 tokens and the stream dies. The answer is
    // unusable; the tokens are billed. Against a 300-token ceiling the run must
    // stop *before* the retry, which only happens if the failure was counted.
    let provider = FakeProvider::new();
    provider.will_fail(ModelError::Interrupted {
        model: model(),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 300,
            ..Usage::default()
        },
        detail: "connection reset mid-stream".into(),
    });

    let rt = Runtime::builder(Arc::clone(&store))
        .owner("example")
        .budget(Budget::unlimited().tokens(300))
        .skill(Retries {
            provider: provider.clone(),
        })
        .build();

    let burned = rt.run("support.triage", Tainted::trusted(ticket)).await?;
    println!("\n3. metered failure → {:?}", burned.status);
    println!(
        "   provider calls: {} — the reworded retry never went out",
        provider.calls()
    );
    println!(
        "   spend:          {} tokens, on a call that returned nothing usable",
        burned.spend().tokens
    );
    assert!(!matches!(burned.status, RunStatus::Succeeded));
    assert_eq!(
        provider.calls(),
        1,
        "400 tokens burned against a 300-token ceiling must stop the run before \
         it asks again; a driver reporting the dead stream as free would let it \
         retry forever against a ceiling reading zero"
    );

    // ── 4. Both journals verify ────────────────────────────────────────────
    for run in [live.run_id, burned.run_id] {
        store.verify(run).await?;
    }
    println!("\n4. both journals verify — including the one that failed");

    Ok(())
}

/// Asks, and on failure rewords and asks again — as an agent would.
///
/// The retry is what makes case 3 meaningful. A skill that gave up after one
/// failure would make exactly one call whatever the billing did, and the test
/// would pass with the metering removed.
#[derive(Debug)]
struct Retries {
    provider: Arc<dyn ModelProvider>,
}

#[async_trait::async_trait]
impl Skill for Retries {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("triage").provides("support.triage")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let provider = Arc::clone(&self.provider);
        let ask = |provider: Arc<dyn ModelProvider>, prompt: Value| {
            ModelCall::new(provider, model(), prompt)
        };

        // Swallowed, as an agent rewording its prompt would.
        let first_prompt = input
            .clone()
            .map(|ticket| json!({ "task": "triage", "ticket": ticket }));
        let _ = cx
            .sink_with(&first_prompt, |value| ask(Arc::clone(&provider), value))
            .await;

        let second_prompt =
            input.map(|ticket| json!({ "task": "triage, briefly", "ticket": ticket }));
        let completion = cx
            .sink_with(&second_prompt, |value| ask(provider, value))
            .await?;
        Ok(Outcome::done(completion.map(|c| json!({ "text": c.text }))))
    }
}
