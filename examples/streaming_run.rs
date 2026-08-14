//! Live tokens for a human, one journaled answer for the machine.
//!
//! ```sh
//! cargo run --example streaming_run --features redb,testkit
//! ```
//!
//! No API key, no network.
//!
//! Streaming looks like it should be in tension with everything this runtime
//! promises. Replay is supposed to reproduce a run exactly; a stream is a
//! thousand partial states that no journal should be asked to hold. The
//! resolution is a split that is worth stating plainly, because getting it
//! backwards produces either a useless log or an unreplayable run:
//!
//! * **The completion is the truth.** One record, one effect key, read back on
//!   replay. Deltas are *not* journaled — a partial answer is not evidence of
//!   anything, and a journal holding a thousand of them still answers exactly
//!   the same questions while costing a thousand times more to verify.
//! * **The observer is a view.** It is not provider-visible, so it is not part
//!   of effect identity: attaching or removing one cannot change a run's
//!   history. Strict replay never calls it, because replay never performs the
//!   provider — and that is the point, not an omission. The tokens already
//!   reached the human the first time.
//!
//! What this prints, in order:
//!
//! 1. A live run, with deltas arriving as they would in a terminal or over a
//!    websocket, and the concatenation of every delta reproducing the answer
//!    **byte for byte**.
//! 2. The journal, holding one completion rather than the deltas.
//! 3. A strict replay: the same answer, zero model calls, and an observer that
//!    is never called.
//!
//! Point 3 is the one to read twice. A framework that streams from a cache on
//! replay would be *reconstructing* a live experience, which is a different
//! claim from reproducing a run. This one does not pretend: replay is not a
//! rerun, and the honest interface says so.

use std::io::Write as _;
use std::sync::{Arc, Mutex};

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted, Trust};
use agentplane::journal::JournalStore;
use agentplane::model::{ModelCall, ModelId, ModelProvider, ModelStreamEvent, ModelStreamObserver};
use agentplane::runtime::{Mode, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

/// Where the live tokens go.
///
/// A terminal here; a websocket, an SSE response or a channel in a real
/// deployment. What matters is that it is **advisory**: delivery must not block
/// the provider being consumed, so anything slow belongs behind the caller's own
/// bounded queue rather than inside `event`.
#[derive(Debug, Default)]
struct Printer {
    /// Every delta, so the example can prove the concatenation is exact.
    buffered: Mutex<String>,
    calls: Mutex<usize>,
}

impl ModelStreamObserver for Printer {
    fn event(&self, event: Tainted<ModelStreamEvent>) {
        *self.calls.lock().expect("not poisoned") += 1;

        // Untrusted, like anything else a model produced. A delta is model
        // output that has not even been finished yet, so treating it as more
        // trustworthy than the completion would be exactly backwards.
        assert_eq!(event.label().trust, Trust::Untrusted);

        match event.peek() {
            ModelStreamEvent::TextDelta(delta) => {
                print!("{delta}");
                // Flushed per delta: line buffering would hold the whole answer
                // until the newline, which is precisely the effect a reader is
                // here to see not happening.
                let _ = std::io::stdout().flush();
                self.buffered.lock().expect("not poisoned").push_str(delta);
            }
            ModelStreamEvent::Usage(usage) => {
                println!(
                    "\n     [usage: {} in, {} out]",
                    usage.input_tokens, usage.output_tokens
                );
            }
        }
    }
}

/// Asks one question, streaming the answer to whoever is watching.
#[derive(Debug)]
struct Answers {
    provider: Arc<FakeProvider>,
    printer: Arc<Printer>,
}

#[async_trait::async_trait]
impl Skill for Answers {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("desk.answer").provides("desk.answer")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let provider: Arc<dyn ModelProvider> = self.provider.clone();
        let printer: Arc<dyn ModelStreamObserver> = self.printer.clone();
        let answer = cx
            .sink_with(&input, |value| {
                ModelCall::new(provider, ModelId::new("fake", "scribe-1"), value)
                    // Not provider-visible, so not part of the effect key: the
                    // same run with and without a watcher has one history.
                    .streaming_to(printer)
            })
            .await?;
        Ok(Outcome::done(answer.map(|c| json!({ "answer": c.text }))))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const ANSWER: &str = "Settlement GB-4471 clears on Thursday, once the counterparty confirms.";

    let provider = FakeProvider::new();
    provider.streaming().will_say(ANSWER);

    let printer = Arc::new(Printer::default());
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let runtime = Runtime::builder(Arc::clone(&store))
        .skill(Answers {
            provider: Arc::clone(&provider),
            printer: Arc::clone(&printer),
        })
        .build();

    println!("1. live run — deltas as they arrive\n");
    print!("     ");
    let outcome = runtime
        .run(
            "desk.answer",
            Tainted::trusted(json!({"q": "when does GB-4471 clear?"})),
        )
        .await?;

    let streamed = printer.buffered.lock().expect("not poisoned").clone();
    // Bound once. `std::sync::Mutex` is not reentrant, so two locks in one
    // `println!` argument list deadlock on the same thread — which this example
    // did, and which is worth the comment because the failure looks like a hang
    // rather than an error.
    let live_calls = *printer.calls.lock().expect("not poisoned");
    println!("\n   observer calls: {live_calls}");
    println!(
        "   deltas concatenate to the completion, byte for byte: {}",
        streamed == ANSWER
    );

    // ── 2. What the journal kept ────────────────────────────────────────────
    let records = store.read(outcome.run_id, 1).await?;
    let effects = records
        .iter()
        .filter(|r| format!("{:?}", r.body.kind).contains("Effect"))
        .count();
    println!("\n2. the journal");
    println!("   records: {}, of which effects: {effects}", records.len());
    println!("   the deltas are not among them — a partial answer is not evidence");

    // ── 3. Replay ───────────────────────────────────────────────────────────
    let before = provider.calls();
    let replayed = runtime.replay(outcome.run_id, Mode::Strict).await?;
    let after_replay = *printer.calls.lock().expect("not poisoned");

    println!("\n3. strict replay");
    println!("   status:         {:?}", replayed.status);
    println!(
        "   model calls:    {} (unchanged: {})",
        provider.calls(),
        provider.calls() == before
    );
    println!(
        "   observer calls: {after_replay} (unchanged: {})",
        after_replay == live_calls
    );
    println!(
        "\n   Replay is not a rerun. The provider was not performed, so there was\n   \
         nothing to observe — and the answer came back from the journal anyway."
    );

    Ok(())
}
