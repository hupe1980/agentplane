//! Batch runs: one act, many items, and what happens when it dies at item 3.
//!
//! The claims under test are the ones §8.4 exists for, and each has a failure
//! mode that looks like success:
//!
//! * **Failure isolation** — one bad item must not stop 99,999 good ones. The
//!   failure mode is a settlement run that aborts at the first exception and
//!   reports an error, leaving nobody sure what did settle.
//! * **Partial failure is terminal** — the report cannot be read as "worked"
//!   without reading the counts.
//! * **Item-granular resume** — dies at item 3, resumes at item 3. The failure
//!   mode is re-issuing every invoice up to 3.
//! * **Per-item cost** — "what did this run cost" is a sum, not an estimate.

#![cfg(feature = "sqlite")]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::batch::{BatchItem, BatchStatus, BatchStore, ItemOutcome, ItemSource, SourceError};
use agentplane::core::{
    ArgSource, BatchId, Effect, EffectDescriptor, EffectError, Outcome, PlanIR, PlanNode, Recovery,
    RetryPolicy, Skill, SkillDescriptor, SkillError, Spend, StoreError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{BatchSpec, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

/// Every settlement that actually reached the world, in order.
type World = Arc<Mutex<Vec<String>>>;

/// A page-at-a-time source over a fixed key list.
#[derive(Debug)]
struct Keys(Vec<String>);

impl Keys {
    fn upto(n: usize) -> Self {
        // Zero-padded: the cursor is a string comparison, so "10" must sort
        // after "9". A source whose keys sort differently than its items are
        // processed would skip work on resume.
        Self((1..=n).map(|i| format!("item-{i:03}")).collect())
    }
}

#[async_trait::async_trait]
impl ItemSource for Keys {
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

#[derive(Debug, Clone)]
struct Settle {
    meter: String,
    world: World,
}

#[async_trait::async_trait]
impl Effect for Settle {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("batch.settle", json!({ "meter": self.meter }))
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
    /// What settling one meter costs. Declared by the effect, so the figure
    /// lands in the journal beside the call it belongs to and a replay bills
    /// the same amount without re-deriving it.
    fn spend(&self, _out: &Value) -> Spend {
        Spend {
            tokens: 10,
            minor_units: 100,
        }
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.lock().unwrap().push(self.meter.clone());
        Ok(json!({ "settled": self.meter }))
    }
}

/// Settles a meter, failing on the ones it was told to.
#[derive(Debug)]
struct Settler {
    world: World,
    fails: Vec<&'static str>,
}

#[async_trait::async_trait]
impl Skill for Settler {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("settle").provides("settle")
    }
    async fn invoke(&self, cx: &mut StepCtx<'_>, i: Tainted<Value>) -> Result<Outcome, SkillError> {
        let meter = i.peek()["meter"].as_str().unwrap_or_default().to_owned();

        if self.fails.iter().any(|f| meter.contains(f)) {
            return Ok(Outcome::fail(format!("{meter} will not settle")));
        }

        cx.effect(Settle {
            meter: meter.clone(),
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "settled": meter }))))
    }
}

fn plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "settle")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ])
}

fn runtime(db: &Arc<SqliteStore>, world: &World, fails: Vec<&'static str>) -> Runtime {
    Runtime::builder(Arc::clone(db) as Arc<dyn JournalStore>)
        .owner("batch")
        .batches(Arc::clone(db) as Arc<dyn BatchStore>)
        .skill(Settler {
            world: Arc::clone(world),
            fails,
        })
        .build()
}

fn db() -> Arc<SqliteStore> {
    Arc::new(SqliteStore::open_in_memory().unwrap())
}

// ── The claims ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn every_item_gets_its_own_run_and_its_own_journal() {
    let store = db();
    let world: World = Arc::default();
    let id = BatchId::generate();

    let spec = BatchSpec::new(plan(), Arc::new(Keys::upto(5)));
    let report = runtime(&store, &world, vec![])
        .run_batch(id, &spec)
        .await
        .unwrap();

    assert_eq!(
        report.status,
        BatchStatus::Completed {
            succeeded: 5,
            failed: 0,
            quarantined: 0
        }
    );
    assert_eq!(world.lock().unwrap().len(), 5);

    let items = store.items(id, 100).await.unwrap();
    assert_eq!(items.len(), 5);
    let runs: std::collections::BTreeSet<_> = items.iter().map(|i| i.run).collect();
    assert_eq!(
        runs.len(),
        5,
        "each item must own a run — sharing one would put five settlements in \
         one journal and one budget, which is the modelling this exists to avoid"
    );
    for item in &items {
        store
            .verify(item.run)
            .await
            .unwrap_or_else(|e| panic!("item {} has a broken chain: {e}", item.key));
    }
}

/// One bad item must not take down the batch.
#[tokio::test]
async fn a_failing_item_does_not_stop_the_ones_after_it() {
    let store = db();
    let world: World = Arc::default();
    let id = BatchId::generate();

    let spec = BatchSpec::new(plan(), Arc::new(Keys::upto(5)));
    let report = runtime(&store, &world, vec!["item-002"])
        .run_batch(id, &spec)
        .await
        .unwrap();

    assert_eq!(
        report.status,
        BatchStatus::Completed {
            succeeded: 4,
            failed: 1,
            quarantined: 0
        },
        "the batch must finish and report the failure, not abort at item 2"
    );
    assert_eq!(
        world.lock().unwrap().len(),
        4,
        "the four settleable meters settled: {:?}",
        world.lock().unwrap()
    );
}

/// The report cannot be read as success without reading the counts.
#[tokio::test]
async fn partial_failure_is_terminal_and_says_so() {
    let store = db();
    let world: World = Arc::default();
    let id = BatchId::generate();

    let report = runtime(&store, &world, vec!["item-003"])
        .run_batch(id, &BatchSpec::new(plan(), Arc::new(Keys::upto(4))))
        .await
        .unwrap();

    assert!(
        !report.status.everything_settled(),
        "a batch with a failed item has not settled everything"
    );
    // There is deliberately no `BatchStatus::Succeeded` to match on. The counts
    // are the only way to read the outcome, which is the whole point: "mostly
    // worked" cannot be mistaken for "worked".
    match report.status {
        BatchStatus::Completed {
            succeeded,
            failed,
            quarantined,
        } => {
            assert_eq!((succeeded, failed, quarantined), (3, 1, 0));
        }
        BatchStatus::Running => panic!("the source was exhausted; this is terminal"),
    }
}

/// Dies at item 3, resumes at item 3 — and does not re-settle 1 and 2.
#[tokio::test]
async fn a_batch_resumes_at_item_granularity() {
    let store = db();
    let id = BatchId::generate();
    let first: World = Arc::default();

    // First pass: stop after two items, as a crash would leave it.
    let partial = runtime(&store, &first, vec![])
        .run_batch(
            id,
            &BatchSpec::new(plan(), Arc::new(Keys::upto(5)))
                .page(1)
                .max_items(2),
        )
        .await
        .unwrap();

    assert_eq!(partial.status, BatchStatus::Running);
    assert_eq!(*first.lock().unwrap(), vec!["item-001", "item-002"]);
    assert_eq!(partial.cursor.as_deref(), Some("item-002"));

    // Second pass, against a fresh world: the first two must not be touched.
    let second: World = Arc::default();
    let done = runtime(&store, &second, vec![])
        .run_batch(id, &BatchSpec::new(plan(), Arc::new(Keys::upto(5))))
        .await
        .unwrap();

    assert_eq!(
        done.status,
        BatchStatus::Completed {
            succeeded: 5,
            failed: 0,
            quarantined: 0
        }
    );
    assert_eq!(
        *second.lock().unwrap(),
        vec!["item-003", "item-004", "item-005"],
        "resuming must not re-settle items 1 and 2 — that is the re-issued \
         invoice this design exists to prevent"
    );
}

/// Losing the cursor must be slow, not wrong.
///
/// The cursor is an optimisation: an item's reservation binds it to a run id, so
/// re-processing an item replays that run and reads its effects back. This test
/// forces the slow path by running the batch again from the beginning.
#[tokio::test]
async fn reprocessing_a_finished_item_performs_nothing() {
    let store = db();
    let id = BatchId::generate();
    let world: World = Arc::default();

    let spec = BatchSpec::new(plan(), Arc::new(Keys::upto(3)));
    runtime(&store, &world, vec![])
        .run_batch(id, &spec)
        .await
        .unwrap();
    assert_eq!(world.lock().unwrap().len(), 3);

    // Same batch id, same source, from scratch.
    let again: World = Arc::default();
    let report = runtime(&store, &again, vec![])
        .run_batch(id, &spec)
        .await
        .unwrap();

    assert!(
        again.lock().unwrap().is_empty(),
        "re-running a completed batch must perform nothing: {:?}",
        again.lock().unwrap()
    );
    assert_eq!(
        report.status,
        BatchStatus::Completed {
            succeeded: 3,
            failed: 0,
            quarantined: 0
        },
        "and it must still report what happened the first time"
    );
}

/// "This settlement run cost €340" has to be a sum, not an estimate.
#[tokio::test]
async fn cost_is_attributed_per_item_and_summed_for_the_batch() {
    let store = db();
    let world: World = Arc::default();
    let id = BatchId::generate();

    let report = runtime(&store, &world, vec![])
        .run_batch(id, &BatchSpec::new(plan(), Arc::new(Keys::upto(4))))
        .await
        .unwrap();

    assert_eq!(
        report.spend,
        Spend {
            tokens: 40,
            minor_units: 400
        },
        "four items at 10 tokens and 100 minor units each"
    );

    let items = store.items(id, 100).await.unwrap();
    for item in items {
        assert_eq!(
            item.spend,
            Spend {
                tokens: 10,
                minor_units: 100
            },
            "item {} must carry its own cost, or the batch total is the only \
             number anyone has and nobody can find the expensive item",
            item.key
        );
    }
}

/// A failing source is the batch's problem, not a silent short read.
#[tokio::test]
async fn a_source_that_errors_stops_the_batch_loudly() {
    #[derive(Debug)]
    struct Broken;

    #[async_trait::async_trait]
    impl ItemSource for Broken {
        async fn next(&self, _: Option<&str>, _: usize) -> Result<Vec<BatchItem>, SourceError> {
            Err(SourceError::new("the meter register is unavailable"))
        }
    }

    let store = db();
    let world: World = Arc::default();
    let err = runtime(&store, &world, vec![])
        .run_batch(
            BatchId::generate(),
            &BatchSpec::new(plan(), Arc::new(Broken)),
        )
        .await
        .expect_err("a source failure must surface, not read as an empty batch");

    assert!(
        err.to_string().contains("meter register"),
        "the reason must survive: {err}"
    );
}

/// An empty source is a completed batch with nothing in it, not an error.
#[tokio::test]
async fn an_empty_source_completes_with_zero_items() {
    let store = db();
    let world: World = Arc::default();
    let report = runtime(&store, &world, vec![])
        .run_batch(
            BatchId::generate(),
            &BatchSpec::new(plan(), Arc::new(Keys::upto(0))),
        )
        .await
        .unwrap();

    assert_eq!(
        report.status,
        BatchStatus::Completed {
            succeeded: 0,
            failed: 0,
            quarantined: 0
        }
    );
    assert!(report.status.everything_settled());
}

/// The cursor is the contiguous terminal prefix, not the highest finished key.
///
/// An item left unfinished behind finished ones must hold the cursor back, or a
/// resume steps over it and the batch reports complete while that item never ran.
#[tokio::test]
async fn an_unfinished_item_holds_the_cursor_behind_it() {
    let store = db();
    let id = BatchId::generate();
    store.open(id, "digest").await.unwrap();

    let r1 = agentplane::core::RunId::generate();
    let r2 = agentplane::core::RunId::generate();
    let r3 = agentplane::core::RunId::generate();
    store.reserve(id, "item-001", r1).await.unwrap();
    store.reserve(id, "item-002", r2).await.unwrap();
    store.reserve(id, "item-003", r3).await.unwrap();

    store
        .record(id, "item-001", &ItemOutcome::Succeeded, Spend::default())
        .await
        .unwrap();
    // item-002 stays reserved — interrupted.
    store
        .record(id, "item-003", &ItemOutcome::Succeeded, Spend::default())
        .await
        .unwrap();

    assert_eq!(
        store.cursor(id).await.unwrap().as_deref(),
        Some("item-001"),
        "the cursor must stop before the unfinished item, not jump to the \
         highest finished one"
    );
}

/// A suspended item keeps the batch `Running`.
///
/// Counting a suspension as a failure would send someone to investigate a run
/// that is waiting exactly as designed; counting it as success would close a
/// batch with work outstanding.
#[tokio::test]
async fn a_suspended_item_keeps_the_batch_running() {
    let store = db();
    let id = BatchId::generate();
    store.open(id, "digest").await.unwrap();

    let run = agentplane::core::RunId::generate();
    store.reserve(id, "item-001", run).await.unwrap();
    store
        .record(
            id,
            "item-001",
            &ItemOutcome::Suspended("waiting for a person".into()),
            Spend::default(),
        )
        .await
        .unwrap();

    let census = store.census(id).await.unwrap();
    assert_eq!(census.suspended, 1);
    assert_eq!(census.terminal(), 0, "a suspension is not terminal");

    // And the report a caller actually reads must say so too: outstanding work
    // is the number an operator acts on, and a batch that reported zero here
    // while holding a waiting item would look finished.
    let world: World = Arc::default();
    let report = runtime(&store, &world, vec![])
        .batch_report(id)
        .await
        .unwrap();
    assert_eq!(report.status, BatchStatus::Running);
    assert_eq!(
        report.in_flight, 1,
        "the suspended item is still outstanding"
    );
}

/// A second reservation must return the first run id, never mint a new one.
///
/// This is the property that makes an interrupted item replayable instead of
/// re-performed. If `reserve` overwrote the row, the first run's journal would
/// be orphaned and its effects would happen twice.
#[tokio::test]
async fn reserving_twice_returns_the_original_run() {
    let store = db();
    let id = BatchId::generate();
    store.open(id, "digest").await.unwrap();

    let first = agentplane::core::RunId::generate();
    let second = agentplane::core::RunId::generate();
    assert_ne!(first, second);

    let a = store.reserve(id, "item-001", first).await.unwrap();
    let b = store.reserve(id, "item-001", second).await.unwrap();

    assert_eq!(a.run, first);
    assert_eq!(
        b.run, first,
        "the second reservation must hand back the first run id — a new one \
         would orphan the journal that already holds this item's effects"
    );
}

/// Unused import guard: `StoreError` is part of the store contract surface.
#[allow(dead_code)]
fn _store_error_is_in_scope(_: StoreError) {}
