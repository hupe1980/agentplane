//! One business act, many independent ones: a batch over N items.
//!
//! ```sh
//! cargo run --example batch_run
//! ```
//!
//! A Jahresabrechnung over 10⁵ Marktlokationen is a single thing somebody
//! ordered and a hundred thousand things that each succeed or fail on their
//! own. Both framings are available and both are wrong:
//!
//! * **One run.** Item 60,000 fails, the run fails, and the 59,999 settlements
//!   that worked are sealed inside a failed audit record.
//! * **N unrelated runs.** Nobody can answer *did the Jahresabrechnung finish*
//!   or *what did it cost*, because there is no it.
//!
//! So a batch is its own object: one frozen plan, N runs each with its own
//! journal, budget and outcome, plus a cursor, a census and a terminal state.
//! What this example walks:
//!
//! 1. **A window is a stopping point, not an ending.** The first pass takes two
//!    items and returns `Running` — what a crash at item 3 also leaves.
//! 2. **Resume is item-granular.** The second pass settles items 3 through 6
//!    and re-settles nothing. This is the re-issued invoice the whole design
//!    exists to refuse, and the fresh ledger below is how you can see it.
//! 3. **Partial failure is terminal, and the type says so.** [`BatchStatus`]
//!    has no `Succeeded`: a finished batch is `Completed` carrying counts, so
//!    `if ok()` cannot skip the items that did not settle.
//! 4. **A count is not a finding.** *One failed* is not something anybody can
//!    act on; `items_needing_attention` names the key, and the listing empties
//!    as items are resolved.
//! 5. **Cost is a sum.** Each item's spend is attributed to its own run, so
//!    "what did the settlement run cost" is addition rather than an estimate.
//! 6. **The cursor is an optimisation, not the correctness mechanism.** Losing
//!    it entirely is slow, never wrong: re-running the whole batch performs
//!    nothing, because each item's reservation binds it to a run id and
//!    re-processing replays that run.

use std::sync::{Arc, Mutex};

use agentplane::batch::{BatchItem, BatchStatus, BatchStore, ItemOutcome, ItemSource, SourceError};
use agentplane::core::{
    ArgSource, BatchId, Effect, EffectDescriptor, EffectError, Outcome, PlanIR, PlanNode, Recovery,
    RetryPolicy, Skill, SkillDescriptor, SkillError, Spend, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{BatchSpec, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Every settlement that actually reached the outside world, in order.
///
/// Each pass below gets a *fresh* one. That is the whole demonstration: an
/// empty ledger after a resume is the proof that nothing was done twice, and a
/// shared counter could only ever show a total.
type Ledger = Arc<Mutex<Vec<String>>>;

/// Posting one meter's settlement — the irreversible half of an item.
#[derive(Debug)]
struct Settle {
    meter: String,
    ledger: Ledger,
}

#[async_trait::async_trait]
impl Effect for Settle {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("meter.settle", json!({ "meter": self.meter }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }

    /// Declared by the effect, so the figure lands in the journal beside the
    /// call it belongs to and a replay bills the same amount without
    /// re-deriving it.
    fn spend(&self, _out: &Value) -> Spend {
        Spend {
            tokens: 0,
            minor_units: 250,
        }
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.ledger.lock().expect("ledger").push(self.meter.clone());
        Ok(json!({ "settled": self.meter }))
    }
}

/// Settles one meter. `M-004` is the one that will not.
#[derive(Debug)]
struct Settler {
    ledger: Ledger,
}

#[async_trait::async_trait]
impl Skill for Settler {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("settle").provides("settle")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let meter = input.peek()["meter"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        // A refusal, not a panic: one item that will not settle is the ordinary
        // case a batch exists to survive.
        if meter == "M-004" {
            return Ok(Outcome::fail(format!("{meter} has no valid tariff")));
        }

        cx.effect(Settle {
            meter: meter.clone(),
            ledger: Arc::clone(&self.ledger),
        })
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "settled": meter }))))
    }
}

/// A page-at-a-time source over six meters.
///
/// A cursor rather than a `Vec`, because a batch over 10⁵ meters must not need
/// 10⁵ items in memory — and, more subtly, must not need the caller to have
/// *produced* them all before the first one runs. Keys are zero-padded: the
/// cursor is a string comparison, so `M-010` has to sort after `M-009`.
#[derive(Debug)]
struct Meters(Vec<String>);

impl Meters {
    fn upto(n: usize) -> Self {
        Self((1..=n).map(|i| format!("M-{i:03}")).collect())
    }
}

#[async_trait::async_trait]
impl ItemSource for Meters {
    async fn next(&self, after: Option<&str>, limit: usize) -> Result<Vec<BatchItem>, SourceError> {
        Ok(self
            .0
            .iter()
            .filter(|k| after.is_none_or(|a| k.as_str() > a))
            .take(limit)
            .map(|k| BatchItem::new(k, json!({ "meter": k })))
            .collect())
    }
}

/// One node: settle the item this run was admitted with.
fn plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "settle")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ])
}

/// A plane with a batch store, writing to `ledger`.
fn plane(store: &Arc<RedbStore>, ledger: &Ledger) -> Arc<Runtime> {
    Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
        .owner("settlement")
        .batches(Arc::clone(store) as Arc<dyn BatchStore>)
        .skill(Settler {
            ledger: Arc::clone(ledger),
        })
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let batches = Arc::clone(&store) as Arc<dyn BatchStore>;
    let id = BatchId::generate();

    // ── 1. A window is a stopping point, not an ending ─────────────────────
    // `max_items(2)` is how a very large batch is operated in windows —
    // "settle ten thousand and let me look" — and it leaves exactly the state a
    // crash at item 3 leaves, which is why the resume below is the real thing
    // rather than a simulation of it.
    let first: Ledger = Arc::default();
    let windowed = BatchSpec::new(plan(), Arc::new(Meters::upto(6)))
        .page(1)
        .max_items(2);
    let report = plane(&store, &first).run_batch(id, &windowed).await?;

    println!("1. first pass, a window of two");
    println!("   status         → {:?}", report.status);
    println!("   settled        → {:?}", first.lock().expect("ledger"));
    println!("   cursor         → {:?}", report.cursor.as_deref());
    assert_eq!(report.status, BatchStatus::Running);
    assert_eq!(report.cursor.as_deref(), Some("M-002"));

    // ── 2. Resume is item-granular ─────────────────────────────────────────
    // A fresh ledger, so what this pass settles is all this pass settled.
    let second: Ledger = Arc::default();
    let whole = BatchSpec::new(plan(), Arc::new(Meters::upto(6)));
    let report = plane(&store, &second).run_batch(id, &whole).await?;

    println!("\n2. resumed");
    println!("   settled now    → {:?}", second.lock().expect("ledger"));
    println!("   — M-001 and M-002 are absent: they were not settled again");
    assert_eq!(
        *second.lock().expect("ledger"),
        vec!["M-003", "M-005", "M-006"],
        "a resume that re-settles is the re-issued invoice this design refuses"
    );

    // ── 3. Partial failure is terminal, and the type says so ───────────────
    // No `Succeeded` variant exists. The counts are in the value a caller has
    // to destructure, so "mostly worked" cannot be reported as worked.
    println!("\n3. the batch is finished");
    println!("   status         → {:?}", report.status);
    assert_eq!(
        report.status,
        BatchStatus::Completed {
            succeeded: 5,
            failed: 1,
            quarantined: 0,
        }
    );
    assert!(
        report.needs_attention(),
        "a batch with a failed item needs somebody"
    );

    // ── 4. A count is not a finding ────────────────────────────────────────
    // `failed: 1` is not something anybody can act on. Over 10⁵ items the only
    // other route to the key is paging every row, almost all of them
    // successes — detection without delivery.
    let backlog = batches.items_needing_attention(id, 100).await?;
    println!("\n4. and this is which one");
    for item in &backlog {
        println!(
            "   {} → {:?}   (run {})",
            item.key,
            item.outcome
                .as_ref()
                .map_or("in flight", ItemOutcome::as_str),
            item.run
        );
    }
    assert_eq!(backlog.len(), 1);
    assert_eq!(backlog[0].key, "M-004");

    // ── 5. Cost is a sum ───────────────────────────────────────────────────
    // Five settlements at 250 minor units, attributed per item and added up.
    // The item that failed posted nothing and is billed for nothing.
    println!("\n5. cost");
    println!(
        "   batch          → {} minor units, summed from the five items that \
         settled",
        report.spend.minor_units
    );
    println!("   M-004          → billed for nothing: it posted nothing");
    assert_eq!(report.spend.minor_units, 5 * 250);

    // ── 6. The cursor is an optimisation, not the correctness mechanism ─────
    // Same batch id, same source, from the very beginning. Each item's
    // reservation binds it to a run id, so re-processing replays that run and
    // reads its effects back instead of performing them.
    let third: Ledger = Arc::default();
    let again = plane(&store, &third).run_batch(id, &whole).await?;

    println!("\n6. the whole batch re-run from item one");
    println!(
        "   settled        → {:?} — nothing",
        third.lock().expect("ledger")
    );
    println!(
        "   status         → {:?} — and it still says what happened",
        again.status
    );
    assert!(
        third.lock().expect("ledger").is_empty(),
        "losing the cursor must be slow, never wrong"
    );
    assert_eq!(again.status, report.status);

    println!(
        "\nOne act, six items, five settlements — each performed exactly once,\n\
         and the one that did not is named rather than counted."
    );
    Ok(())
}
