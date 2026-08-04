//! Budgets: bounded cost, enforced deterministically.
//!
//! The property that makes this more than a counter: **a replayed run reaches
//! the same budget verdict at the same point as the original.** Spend is
//! journaled rather than recomputed, so an exhausted budget is part of history
//! rather than an artefact of when you looked at it.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{
    ArgSource, Budget, Effect, EffectDescriptor, EffectError, Outcome, PlanIR, PlanNode, Recovery,
    Skill, SkillDescriptor, SkillError, Spend, StepId, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// An effect that reports what it consumed.
#[derive(Debug, Clone)]
struct Metered {
    name: String,
    tokens: u64,
    minor_units: i64,
    calls: Arc<AtomicUsize>,
}

impl Metered {
    fn new(name: &str, tokens: u64, calls: &Arc<AtomicUsize>) -> Self {
        Self {
            name: name.to_owned(),
            tokens,
            minor_units: 0,
            calls: Arc::clone(calls),
        }
    }

    fn money(mut self, minor_units: i64) -> Self {
        self.minor_units = minor_units;
        self
    }
}

#[async_trait::async_trait]
impl Effect for Metered {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(format!("test.{}", self.name), json!(null))
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn spend(&self, _out: &Value) -> Spend {
        Spend {
            tokens: self.tokens,
            minor_units: self.minor_units,
        }
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({ "ok": self.name }))
    }
}

/// A step that does nothing but count that it ran.
#[derive(Debug)]
struct Noop(&'static str, Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Skill for Noop {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.0).provides(self.0)
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(input))
    }
}

/// Performs `n` metered effects, each costing `tokens`.
#[derive(Debug)]
struct Spends {
    n: usize,
    tokens: u64,
    minor_units: i64,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Spends {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("spends").provides("demo.spend")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        for i in 0..self.n {
            cx.effect(
                Metered::new(&format!("op-{i}"), self.tokens, &self.calls).money(self.minor_units),
            )
            .await?;
        }
        Ok(Outcome::done(input))
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    calls: Arc<AtomicUsize>,
}

fn fixture(n: usize, tokens: u64, budget: Budget) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(budget)
        .skill(Spends {
            n,
            tokens,
            minor_units: 0,
            calls: Arc::clone(&calls),
        })
        .build();
    Fixture { store, rt, calls }
}

// ── Enforcement ─────────────────────────────────────────────────────────────

/// An unlimited budget is the explicit default and does not interfere.
#[tokio::test]
async fn an_unlimited_budget_does_not_interfere() {
    let f = fixture(20, 1_000_000, Budget::unlimited());
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 20);
}

/// **The count limit is exact**, because counts are known in advance.
#[tokio::test]
async fn an_effect_count_limit_stops_a_runaway_loop_exactly() {
    let f = fixture(100, 0, Budget::default().effects(5));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();

    match &out.status {
        RunStatus::Exhausted(e) => {
            assert!(e.to_string().contains("effect budget"), "got: {e}");
        }
        other => panic!("the loop must be stopped, got {other:?}"),
    }
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        5,
        "never more operations than permitted"
    );
}

/// A metered limit stops the run, and the error carries the numbers an operator
/// needs to resize it.
#[tokio::test]
async fn a_token_limit_reports_where_it_stood() {
    let f = fixture(100, 40, Budget::default().tokens(100));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();

    match &out.status {
        RunStatus::Exhausted(e) => {
            let msg = e.to_string();
            assert!(msg.contains("100"), "the limit: {msg}");
            assert!(msg.contains("120"), "where it actually got to: {msg}");
        }
        other => panic!("got {other:?}"),
    }
}

/// A cost limit works the same way, in integer minor units.
#[tokio::test]
async fn a_cost_limit_is_enforced_in_minor_units() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().minor_units(250))
        .skill(Spends {
            n: 10,
            tokens: 0,
            minor_units: 100,
            calls: Arc::clone(&calls),
        })
        .build();

    let out = rt.run("demo.spend", json!({})).await.unwrap();
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 3, "stops once 250 is reached");
}

/// A step limit stops the plan between steps, before the next one half-runs.
#[tokio::test]
async fn a_step_limit_stops_the_plan_between_steps() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));

    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().steps(2))
        .skill(Noop("a", Arc::clone(&calls)))
        .skill(Noop("b", Arc::clone(&calls)))
        .skill(Noop("c", Arc::clone(&calls)))
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "a").arg("i", ArgSource::run_input()),
        PlanNode::new(1, "b").arg("i", ArgSource::node(StepId(0))),
        PlanNode::new(2, "c")
            .arg("i", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = rt.run_plan(plan, json!({})).await.unwrap();
    match &out.status {
        RunStatus::Exhausted(e) => assert!(e.to_string().contains("step budget"), "got: {e}"),
        other => panic!("got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the third step never starts"
    );
}

/// **A metered budget overshoots by at most one operation**, because an
/// operation's cost is not known until it has run.
///
/// Stated as a test so nobody discovers it by sizing a limit at their ceiling.
#[tokio::test]
async fn a_metered_budget_overshoots_by_at_most_one_operation() {
    let f = fixture(10, 60, Budget::default().tokens(100));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();

    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        2,
        "0 and 60 both admit; at 120 consumption has reached the limit"
    );
}

// ── Determinism ─────────────────────────────────────────────────────────────

/// **The property that makes this more than a counter.**
///
/// Spend is journaled, so a replayed run bills the same figures and reaches the
/// same verdict at the same point. Recomputing cost at replay time would give a
/// moving answer, and the budget verdict would move with it.
#[tokio::test]
async fn spend_is_journaled_so_replay_bills_identically() {
    let f = fixture(3, 25, Budget::default().tokens(1000));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);

    let records = f.store.read(out.run_id, 1).await.unwrap();
    let billed: u64 = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectDone { spend, .. } => Some(spend.tokens),
            _ => None,
        })
        .sum();
    assert_eq!(billed, 75, "every effect's cost is in the record");

    // Replay performs nothing, and still arrives at the same total.
    let before = f.calls.load(Ordering::SeqCst);
    let again = f.rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        before,
        "replay bills from the journal without performing anything"
    );
}

/// A run that exhausted its budget replays as exhausted — the verdict is part
/// of history, not a function of the limit in force when you replayed it.
#[tokio::test]
async fn an_exhausted_run_replays_as_exhausted() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let skill = || Spends {
        n: 100,
        tokens: 40,
        minor_units: 0,
        calls: Arc::clone(&calls),
    };

    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().tokens(100))
        .skill(skill())
        .build();

    let out = rt.run("demo.spend", json!({})).await.unwrap();
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    let performed = calls.load(Ordering::SeqCst);

    // Replayed under a *far larger* budget. The recorded run still stops where
    // it stopped: history does not change shape because the limit did.
    let generous = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().tokens(1_000_000))
        .skill(skill())
        .build();

    // Asserted exactly, with no `||`. An earlier version accepted *either*
    // `Exhausted` or quarantined, which is how it kept passing while strict
    // replay was actually reporting "this build performs more effects than the
    // recorded one" — a message that sends an operator hunting for a code
    // change that does not exist. An assertion that accepts two outcomes tells
    // you nothing about which one you have.
    let replayed = generous.replay(out.run_id, Mode::Strict).await.unwrap();
    assert!(
        matches!(replayed.status, RunStatus::Exhausted(_)),
        "the recorded stopping point is preserved, got {:?}",
        replayed.status
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        performed,
        "replay performs nothing regardless of the budget in force"
    );
}

/// A free effect still counts against the operation limit — the blunt
/// instrument works even when every operation is free.
#[tokio::test]
async fn free_operations_still_count() {
    let f = fixture(50, 0, Budget::default().effects(4));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert_eq!(f.calls.load(Ordering::SeqCst), 4);
}

/// Exhaustion is not a failure: the run did what it was told, and what it was
/// told included a ceiling. Conflating the two has operators debugging a system
/// that behaved exactly as instructed.
#[tokio::test]
async fn exhaustion_is_distinguishable_from_failure() {
    let f = fixture(100, 0, Budget::default().effects(1));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();

    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert!(
        !matches!(out.status, RunStatus::Failed(_)),
        "a ceiling doing its job is not a fault"
    );
    assert_eq!(out.status.as_str(), "exhausted");
}

/// The journal records the run's terminal state, so the stopping point is
/// auditable rather than inferred.
#[tokio::test]
async fn exhaustion_is_journaled() {
    let f = fixture(100, 0, Budget::default().effects(2));
    let out = f.rt.run("demo.spend", json!({})).await.unwrap();

    let records = f.store.read(out.run_id, 1).await.unwrap();
    let finished = records.iter().any(
        |r| matches!(r.kind(), RecordKind::StepFinished { outcome } if outcome == "exhausted"),
    );
    assert!(finished, "the stopping point must be in the record");
    f.store.verify(out.run_id).await.unwrap();
}

/// A run stopped by the **step** limit also replays as exhausted.
///
/// The step-level refusal happens before the step starts, so it leaves no
/// `StepStarted` either — the same hole as the effect-level one, one level up.
#[tokio::test]
async fn a_step_limited_run_replays_as_exhausted() {
    use agentplane::core::{ArgSource, PlanIR, PlanNode};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().steps(2))
        .skill(Noop("a", Arc::clone(&calls)))
        .skill(Noop("b", Arc::clone(&calls)))
        .skill(Noop("c", Arc::clone(&calls)))
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "a").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "b").arg("x", ArgSource::node(StepId(0))),
        PlanNode::new(2, "c")
            .arg("x", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = rt.run_plan(plan, json!({})).await.unwrap();
    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "got {:?}",
        out.status
    );

    // Replayed under a far larger budget, exactly as the effect-level test
    // does: the recorded run still stops where it stopped.
    let generous = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().steps(100))
        .skill(Noop("a", Arc::clone(&calls)))
        .skill(Noop("b", Arc::clone(&calls)))
        .skill(Noop("c", Arc::clone(&calls)))
        .build();

    let replayed = generous.replay(out.run_id, Mode::Strict).await.unwrap();
    assert!(
        matches!(replayed.status, RunStatus::Exhausted(_)),
        "the recorded stopping point is preserved, got {:?}",
        replayed.status
    );
}
