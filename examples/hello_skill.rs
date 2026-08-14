//! The smallest thing this runtime does: one skill, one run, one replay.
//!
//! Every other example layers a real concern on top — crash recovery, cases,
//! plans, sagas, memory. This one is deliberately none of that. It exists so a
//! newcomer has a runnable file, not a doc snippet, that shows the whole shape:
//!
//! * a skill is one `invoke`, handed a `StepCtx` and a labelled input;
//! * the clock is an effect (`cx.now()`), so replay reads the recorded instant
//!   rather than reading the wall clock again;
//! * a strict replay re-runs the logic and reproduces the answer byte for byte
//!   without performing anything.
//!
//! Run it: `cargo run --example hello_skill`

use std::sync::Arc;

// The getting-started page calls this "this exact skill", so it imports the way
// that page does: one prelude line, which is the whole point of having one —
// `async_trait` included, so writing a skill starts here rather than in
// `Cargo.toml`.
use agentplane::prelude::*;
use serde_json::{Value, json};

#[derive(Debug)]
struct Greet;

#[async_trait]
impl Skill for Greet {
    // No `.provides(..)`: a skill that declares nothing answers its own name.
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("greet")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // A journaled effect: on replay this returns the recorded instant, not a
        // fresh reading of the clock. `input.map` carries the label along.
        let at = cx.now().await?;
        Ok(Outcome::done(
            input.map(|v| json!({ "greeted": v, "at": at.to_string() })),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let runtime = Runtime::builder(Arc::clone(&store)).skill(Greet).build();

    let outcome = runtime
        .run("greet", Tainted::trusted(json!({ "name": "world" })))
        .await?;

    // Re-executes the logic and reads every effect back from the journal.
    // Nothing is performed again — no clock is read, no answer is invented.
    let replayed = runtime.replay(outcome.run_id, Mode::Strict).await?;
    assert_eq!(outcome.output, replayed.output, "replay reproduced the run");

    // `.success()` turns "did it work, and what did it say" into one `?`:
    // the labelled answer, or a typed error naming the run and its status.
    let answer = outcome.success()?;
    println!("live:    {}", answer.peek());
    println!("replay:  {}", replayed.success()?.peek());

    println!("\nSame answer, and the second time nothing happened.");
    Ok(())
}
