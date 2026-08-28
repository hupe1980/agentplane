//! A ceiling is a pause, not a poison pill.
//!
//! ```sh
//! cargo run --example budget_pause
//! ```
//!
//! A run that hits its budget is **exhausted**, and exhaustion is not a fault:
//! the run did what it was told, and what it was told included a ceiling. The
//! completed work stands — journaled, replayable, never repeated — and the run
//! waits for a decision. That decision is the point: most frameworks stop a
//! runaway agent by killing it, which converts a cost control into lost work
//! and a retry into double spend. Here the ceiling produces a *recorded
//! refusal*, and what happens next is governed:
//!
//! 1. **The ceiling binds.** Two effects of budget, three postings to make —
//!    the third never starts, and the run pauses as `Exhausted`.
//! 2. **Resuming changes nothing by itself.** Under the same ceiling the
//!    ledger still refuses, the run concludes exhausted again, and the
//!    standing refusal is not duplicated — resuming is not a way to nag a
//!    ceiling into yielding.
//! 3. **A raise is a decision, and it is on the record.** A plane built with
//!    the raised ceiling resumes the run: the refused effect is re-asked
//!    against the ledger now in force, `BudgetReadmitted` is journaled beside
//!    the old refusal, and the run finishes — the first two postings read
//!    back from the journal, the third performed once.
//! 4. **The whole history verifies.** A strict replay walks refusal,
//!    re-admission and completion as one coherent record — a pause is
//!    history, not damage.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{Budget, Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Posts three settlement entries. How many actually reached the outside
/// world is the number every assertion below is about.
#[derive(Debug)]
struct Settle {
    world: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Settle {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("billing.settle")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        for entry in ["fees", "interest", "principal"] {
            let arguments = Tainted::trusted(json!(null));
            cx.sink(
                Recorded::new(format!("post-{entry}")).counter(Arc::clone(&self.world)),
                &arguments,
            )
            .await?;
        }
        Ok(Outcome::done(input))
    }
}

fn plane(store: &Arc<dyn JournalStore>, world: &Arc<AtomicUsize>, budget: Budget) -> Arc<Runtime> {
    Runtime::builder(Arc::clone(store))
        .owner("billing")
        .budget(budget)
        .skill(Settle {
            world: Arc::clone(world),
        })
        .build()
}

/// How often a record kind appears in the run's journal.
async fn count(store: &Arc<dyn JournalStore>, run: agentplane::core::RunId, kind: &str) -> usize {
    store
        .read(run, 1)
        .await
        .expect("journal readable")
        .iter()
        .filter(|r| r.kind().kind_str() == kind)
        .count()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let world = Arc::new(AtomicUsize::new(0));

    // ── 1. The ceiling binds ───────────────────────────────────────────────
    let capped = plane(&store, &world, Budget::unlimited().effects(2));
    let out = capped
        .run(
            "billing.settle",
            Tainted::trusted(json!({ "batch": "B-7" })),
        )
        .await?;
    println!("1. two effects of budget, three postings to make");
    println!("   run            → {:?}", out.status);
    if let RunStatus::Exhausted(why) = &out.status {
        println!("   why            → {why}");
    }
    println!(
        "   postings       → {} — the third never started",
        world.load(Ordering::SeqCst)
    );
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert_eq!(world.load(Ordering::SeqCst), 2);

    // ── 2. Resuming under the same ceiling changes nothing ─────────────────
    let again = capped.replay(out.run_id, Mode::Resume).await?;
    println!("\n2. resumed under the same ceiling");
    println!("   run            → {}", again.status.as_str());
    println!(
        "   postings       → {} (unchanged), standing refusals → {}",
        world.load(Ordering::SeqCst),
        count(&store, out.run_id, "BudgetRefused").await
    );
    assert!(matches!(again.status, RunStatus::Exhausted(_)));
    assert_eq!(world.load(Ordering::SeqCst), 2);
    assert_eq!(
        count(&store, out.run_id, "BudgetRefused").await,
        1,
        "re-concluding exhausted must consume the standing refusal, not stack another"
    );

    // ── 3. A raise is a decision, and it is on the record ──────────────────
    // The same store, a plane whose reviewed ceiling is higher. The resume
    // re-asks the ledger now in force; nothing already performed is repeated.
    let raised = plane(&store, &world, Budget::unlimited().effects(5));
    let resumed = raised.replay(out.run_id, Mode::Resume).await?;
    println!("\n3. the ceiling is raised, and the run resumed");
    println!("   run            → {}", resumed.status.as_str());
    println!(
        "   postings       → {} — the first two replayed, the third performed once",
        world.load(Ordering::SeqCst)
    );
    println!(
        "   on the record  → BudgetRefused: {}, BudgetReadmitted: {}",
        count(&store, out.run_id, "BudgetRefused").await,
        count(&store, out.run_id, "BudgetReadmitted").await
    );
    assert_eq!(resumed.status, RunStatus::Succeeded);
    assert_eq!(world.load(Ordering::SeqCst), 3, "each posting exactly once");
    assert_eq!(count(&store, out.run_id, "BudgetReadmitted").await, 1);

    // ── 4. The whole history verifies ──────────────────────────────────────
    let strict = raised.replay(out.run_id, Mode::Strict).await?;
    assert_eq!(strict.status, RunStatus::Succeeded);
    assert_eq!(
        world.load(Ordering::SeqCst),
        3,
        "strict replay must read effects back, never perform them"
    );
    store.verify(out.run_id).await?;
    println!(
        "\n4. strict replay walks refusal, re-admission and completion as one \
         record,\n   and the chain verifies — a pause is history, not damage"
    );

    Ok(())
}
