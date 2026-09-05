//! Budgets: bounded cost, enforced deterministically.
//!
//! The property that makes this more than a counter: **a replayed run reaches
//! the same budget verdict at the same point as the original.** Spend is
//! journaled rather than recomputed, so an exhausted budget is part of history
//! rather than an artefact of when you looked at it.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
    minor_units: u64,
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

    fn money(mut self, minor_units: u64) -> Self {
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
    minor_units: u64,
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
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 20);
}

/// **The count limit is exact**, because counts are known in advance.
#[tokio::test]
async fn an_effect_count_limit_stops_a_runaway_loop_exactly() {
    let f = fixture(100, 0, Budget::default().effects(5));
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();

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
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();

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

    let out = rt
        .run("demo.spend", Tainted::trusted(json!({})))
        .await
        .unwrap();
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

    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .unwrap();
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
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();

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
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();
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

    let out = rt
        .run("demo.spend", Tainted::trusted(json!({})))
        .await
        .unwrap();
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
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert_eq!(f.calls.load(Ordering::SeqCst), 4);
}

/// Exhaustion is not a failure: the run did what it was told, and what it was
/// told included a ceiling. Conflating the two has operators debugging a system
/// that behaved exactly as instructed.
#[tokio::test]
async fn exhaustion_is_distinguishable_from_failure() {
    let f = fixture(100, 0, Budget::default().effects(1));
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();

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
    let out =
        f.rt.run("demo.spend", Tainted::trusted(json!({})))
            .await
            .unwrap();

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

    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .unwrap();
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

// ── Parallelism ─────────────────────────────────────────────────────────────

/// **A ready wave cannot outrun the step ceiling.**
///
/// A step is counted when it finishes, and a plan's ready set is admitted
/// before any of it runs — so three branches asked "is there room for one
/// more?" against a figure none of them had moved yet, and all three were told
/// yes under a ceiling of two. The ceiling has to bound the plan, not the
/// sequential prefix of it, which means admission counts what it has already
/// handed out in this wave.
#[tokio::test]
async fn a_ready_wave_cannot_outrun_the_step_ceiling() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().steps(2))
        .skill(Noop("a", Arc::clone(&calls)))
        .skill(Noop("b", Arc::clone(&calls)))
        .skill(Noop("c", Arc::clone(&calls)))
        .skill(Noop("join", Arc::clone(&calls)))
        .build();

    let out = rt
        .run_plan(
            PlanIR::fan_out(["a", "b", "c"], "join"),
            Tainted::trusted(json!({})),
        )
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a three-wide ready set ran under a ceiling of two"
    );
    assert_eq!(out.consumed.steps, 2);
}

/// **`max_parallel_steps` bounds the width of a ready set.**
///
/// Asserted by watching the peak, because a bound that is merely *usually*
/// respected reads identically to one that is enforced: the branches here all
/// yield, so an unbounded dispatch has every one of them in flight at once.
#[tokio::test]
async fn the_ready_set_is_dispatched_no_wider_than_declared() {
    #[derive(Debug)]
    struct Peaked {
        name: &'static str,
        live: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Skill for Peaked {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.name).provides(self.name)
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.live.fetch_sub(1, Ordering::SeqCst);
            Ok(Outcome::done(input))
        }
    }

    let peak_under = |limit: Option<usize>| async move {
        let store = Arc::new(RedbStore::open_in_memory().unwrap());
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let budget = match limit {
            Some(n) => Budget::unlimited().parallel_steps(n),
            None => Budget::unlimited(),
        };
        let mut b = Runtime::builder(store as Arc<dyn JournalStore>).budget(budget);
        for name in ["a", "b", "c", "d", "join"] {
            b = b.skill(Peaked {
                name,
                live: Arc::clone(&live),
                peak: Arc::clone(&peak),
            });
        }
        let rt = b.build();
        let out = rt
            .run_plan(
                PlanIR::fan_out(["a", "b", "c", "d"], "join"),
                Tainted::trusted(json!({})),
            )
            .await
            .unwrap();
        assert_eq!(out.status, RunStatus::Succeeded);
        peak.load(Ordering::SeqCst)
    };

    assert_eq!(
        peak_under(None).await,
        4,
        "an undeclared width is the plan's own width — the default this bounds"
    );
    assert_eq!(
        peak_under(Some(2)).await,
        2,
        "a declared width of two dispatched more than two at once"
    );
}

// ── One announcement, one slot, on every pass ───────────────────────────────

/// Fails its first attempt, succeeds afterwards.
#[derive(Debug, Clone)]
struct FlakyOnce {
    tries: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Effect for FlakyOnce {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.flaky", json!(null))
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn spend(&self, _out: &Value) -> Spend {
        Spend::default()
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        if self.tries.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(EffectError::Unavailable {
                driver: "test".into(),
                detail: "first try".into(),
            });
        }
        Ok(json!("ok"))
    }
}

/// One flaky effect, a crash point, then one more effect.
#[derive(Debug)]
struct FlakyThenCrash {
    crash: Arc<AtomicBool>,
    tries: Arc<AtomicUsize>,
    after: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for FlakyThenCrash {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("flaky").provides("demo.flaky")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(FlakyOnce {
            tries: Arc::clone(&self.tries),
        })
        .await?;
        if self.crash.load(Ordering::SeqCst) {
            return Err(SkillError::Other("simulated crash".into()));
        }
        cx.effect(Metered::new("after", 0, &self.after)).await?;
        Ok(Outcome::done(input))
    }
}

/// **A recorded failure costs the one slot it cost live.**
///
/// The live pass counted two operations: an attempt that failed and the retry
/// that succeeded. The resume replayed the same two records and counted
/// *three* — the failure was billed once by the arm that read it and again by
/// the code deciding what the run did next — so a run with room to spare
/// concluded `Exhausted` on a ceiling it had never reached, at a point no
/// history contains.
#[tokio::test]
async fn a_recorded_failure_costs_the_one_slot_it_cost_live() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash = Arc::new(AtomicBool::new(true));
    let tries = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().effects(3))
        .skill(FlakyThenCrash {
            crash: Arc::clone(&crash),
            tries: Arc::clone(&tries),
            after: Arc::clone(&after),
        })
        .build();

    let crashed = rt
        .run("demo.flaky", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(crashed.status, RunStatus::Failed(_)));
    assert_eq!(tries.load(Ordering::SeqCst), 2, "one failure, one retry");
    assert_eq!(
        crashed.consumed.effects, 2,
        "the live pass billed the failed attempt and the retry"
    );

    crash.store(false, Ordering::SeqCst);
    let resumed = rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    assert_eq!(
        resumed.status,
        RunStatus::Succeeded,
        "the resume exhausted a ceiling the live pass had room under: {:?}",
        resumed.status
    );
    assert_eq!(after.load(Ordering::SeqCst), 1);
    assert_eq!(
        resumed.consumed.effects, 3,
        "two replayed announcements and one live one"
    );
}

/// **A strict replay reaches the same tally, not merely the same outcome.**
///
/// The umbrella over every arm of the replay loop. Verdict parity is what the
/// journaled-spend design is for, and it is only as good as the arithmetic: an
/// arm that bills twice, or one that drops the figure a superseded record
/// carried, changes where a resumed run stops without changing anything a
/// status assertion can see.
#[tokio::test]
async fn a_strict_replay_reaches_the_same_tally() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let tries = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let skill = || FlakyThenCrash {
        crash: Arc::new(AtomicBool::new(false)),
        tries: Arc::clone(&tries),
        after: Arc::clone(&after),
    };
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::unlimited())
        .skill(skill())
        .build();

    let live = rt
        .run("demo.flaky", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(live.status, RunStatus::Succeeded);

    let replayed = rt.replay(live.run_id, Mode::Strict).await.unwrap();
    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        (replayed.consumed.effects, replayed.consumed.spend),
        (live.consumed.effects, live.consumed.spend),
        "the replay billed a different tally than the run it replays"
    );
}

/// **The last effect slot is taken by one step, not handed to every step that
/// asks for it.**
///
/// A ready set runs concurrently, and a check whose result is acted on later
/// is a check two callers both pass: three branches asked "is there room?" of
/// a ledger nothing had billed yet and all three were told yes under a ceiling
/// of two. The rendezvous is what makes that observable rather than
/// occasional — every branch that reaches the world waits inside the window
/// between the verdict and the billing, so an unreserved slot is handed out
/// three times every run rather than on an unlucky one.
#[tokio::test]
async fn the_last_effect_slot_is_taken_by_one_step_not_by_every_step_that_asks() {
    /// Waits for its siblings inside the call, then returns. The timeout is the
    /// point: a branch the ceiling correctly refused never arrives, and the
    /// test must observe *two* rather than hang waiting for a third.
    #[derive(Debug, Clone)]
    struct Rendezvous {
        name: String,
        gate: Arc<tokio::sync::Barrier>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Effect for Rendezvous {
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
            Spend::default()
        }

        async fn perform(&self) -> Result<Value, EffectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(250), self.gate.wait()).await;
            Ok(json!("ok"))
        }
    }

    #[derive(Debug)]
    struct Branch {
        name: &'static str,
        gate: Arc<tokio::sync::Barrier>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Skill for Branch {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.name).provides(self.name)
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.effect(Rendezvous {
                name: self.name.to_owned(),
                gate: Arc::clone(&self.gate),
                calls: Arc::clone(&self.calls),
            })
            .await?;
            Ok(Outcome::done(input))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Barrier::new(3));
    let mut b =
        Runtime::builder(store as Arc<dyn JournalStore>).budget(Budget::default().effects(2));
    for name in ["a", "b", "c"] {
        b = b.skill(Branch {
            name,
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
        });
    }
    // The join never runs: the ceiling stops the wave before it.
    b = b.skill(Noop("join", Arc::new(AtomicUsize::new(0))));
    let rt = b.build();

    let out = rt
        .run_plan(
            PlanIR::fan_out(["a", "b", "c"], "join"),
            Tainted::trusted(json!({})),
        )
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a ceiling of two admitted a third concurrent effect"
    );
    assert_eq!(out.consumed.effects, 2);
}

// ── Wall clock ──────────────────────────────────────────────────────────────

/// A step that burns real time.
#[derive(Debug)]
struct Slow(&'static str, u64, Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Skill for Slow {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.0).provides(self.0)
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.2.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(self.1)).await;
        Ok(Outcome::done(input))
    }
}

/// **A wall-clock ceiling stops the run.**
///
/// It was a declared ceiling that had never been enforced: the ledger held the
/// comparison and nothing anywhere read a clock into it, so `elapsed_secs`
/// stayed at zero for the life of every run and the limit could not fire. A
/// manifest field naming a control the runtime does not apply is the one
/// release state the invariants refuse — so it is enforced now, from a
/// **journaled** clock read at each step boundary, which is the only kind of
/// reading a replayed run can reach the same verdict from.
#[tokio::test]
async fn a_wall_clock_ceiling_stops_the_run() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().wallclock_secs(1))
        .skill(Slow("a", 1_200, Arc::clone(&calls)))
        .skill(Slow("b", 0, Arc::clone(&calls)))
        .skill(Slow("c", 0, Arc::clone(&calls)))
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "a").arg("i", ArgSource::run_input()),
        PlanNode::new(1, "b").arg("i", ArgSource::node(StepId(0))),
        PlanNode::new(2, "c")
            .arg("i", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .unwrap();

    match &out.status {
        RunStatus::Exhausted(e) => {
            assert!(e.to_string().contains("time budget"), "got: {e}");
        }
        other => panic!("a wall-clock ceiling did not stop the run: {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the first step spends the window; the second observes it and is the \
         last one admitted"
    );
    assert!(out.consumed.elapsed_secs >= 1);

    // The verdict is reproducible, because the instants it compares came out of
    // the journal rather than off the wall.
    let again = rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert!(
        matches!(again.status, RunStatus::Exhausted(_)),
        "got {:?}",
        again.status
    );
    assert_eq!(again.consumed.elapsed_secs, out.consumed.elapsed_secs);
}
