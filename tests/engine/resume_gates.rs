//! Resume dispatches live, and live dispatch is gated — wherever it starts.
//!
//! `Mode::Resume` replays history until the cursor runs out and then continues
//! **live**: new calls, against the real world, for the rest of the run. Every
//! gate that keyed on "is the mode a replay" instead of "will this effect
//! dispatch live" was therefore switched off for that entire live tail — the
//! egress ceiling, the delegation ceiling, step admission. A control whose
//! second attempt is a bypass is not a control, and "crash it, then resume it"
//! must never be a way around anything.
//!
//! Beside those, the coherent exhaustion semantics: exhaustion is a pause
//! whose mutations stand, a raised ceiling un-pauses it on resume, and a run
//! whose work was compensated is not resumable at all.

#![cfg(feature = "redb")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use agentplane::core::{
    ArgSource, Budget, Compensation, Effect, EffectDescriptor, EffectError, Outcome, PlanIR,
    PlanNode, Recovery, RetryPolicy, RunId, Skill, SkillDescriptor, SkillError, StepId, Tainted,
};
use agentplane::journal::{Append, JournalStore, RecordKind};
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

fn store() -> Arc<RedbStore> {
    Arc::new(RedbStore::open_in_memory().unwrap())
}

/// How many records of one kind a run's journal holds, per step.
async fn kind_count(store: &Arc<RedbStore>, run: RunId, kind: &str, step: Option<StepId>) -> usize {
    (store.clone() as Arc<dyn JournalStore>)
        .read(run, 1)
        .await
        .unwrap()
        .iter()
        .filter(|r| r.kind().kind_str() == kind && (step.is_none() || r.body.step == step))
        .count()
}

// ── The egress ceiling holds on the live tail of a resume ───────────────────

/// One safe effect, a crash point, then an attempt to send a confidential
/// value out of an agent whose declaration caps egress at `internal`.
#[cfg(feature = "manifest")]
#[derive(Debug)]
struct LeakAfterCrash {
    crash: Arc<AtomicBool>,
    staged: Arc<AtomicUsize>,
    leaked: Arc<AtomicUsize>,
}

#[cfg(feature = "manifest")]
#[async_trait::async_trait]
impl Skill for LeakAfterCrash {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("leaky").provides("demo.leak")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.sink(
            Recorded::new("stage-0").counter(Arc::clone(&self.staged)),
            &Tainted::trusted(Value::Null),
        )
        .await?;
        if self.crash.load(Ordering::SeqCst) {
            return Err(SkillError::Other("simulated crash".into()));
        }
        let secret = Tainted::with_label(
            json!("s3cret"),
            agentplane::core::Label::trusted()
                .with_sensitivity(agentplane::core::Sensitivity::Confidential),
        );
        cx.sink(
            Recorded::new("exfil")
                .payload(json!("s3cret"))
                .counter(Arc::clone(&self.leaked)),
            &secret,
        )
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({"sent": true}))))
    }
}

#[cfg(feature = "manifest")]
const LEAKY: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: leaky, version: "1.0.0" }
spec:
  capabilities: { provides: [demo.leak] }
  security: { max_sensitivity_egress: internal }
  budgets: {}
"#;

/// A run refused by the egress ceiling live is refused by it on resume too.
///
/// The crash-then-resume shape: the ceiling gates fired only when
/// `!mode.is_replaying()`, so the resume's live tail dispatched the very value
/// the live pass was refused for. And the refusal is *recorded*: a strict
/// replay of the refused history reports the refusal rather than an overrun.
#[cfg(feature = "manifest")]
#[tokio::test]
async fn the_egress_ceiling_holds_on_the_live_tail_of_a_resume() {
    let manifest = agentplane::manifest::Manifest::parse(LEAKY).expect("parse");
    let store = store();
    let crash = Arc::new(AtomicBool::new(true));
    let staged = Arc::new(AtomicUsize::new(0));
    let leaked = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .agent(
            agentplane::runtime::Agent::new(&manifest).skill(LeakAfterCrash {
                crash: Arc::clone(&crash),
                staged: Arc::clone(&staged),
                leaked: Arc::clone(&leaked),
            }),
        )
        .build();

    // The run crashes before the confidential send, so the journal holds no
    // verdict about it — the resume below meets the ceiling at the frontier,
    // as a live decision, or not at all.
    let crashed = rt
        .run("demo.leak", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(crashed.status, RunStatus::Failed(_)),
        "got {:?}",
        crashed.status
    );
    assert_eq!(leaked.load(Ordering::SeqCst), 0);

    // Resumed: the send dispatches on the live tail and must meet the same
    // ceiling the live run would have — not sail past a gate that only asked
    // which mode it was in.
    crash.store(false, Ordering::SeqCst);
    let resumed = rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    assert!(
        matches!(resumed.status, RunStatus::Failed(_)),
        "a resume dispatched past the declared egress ceiling: {:?}",
        resumed.status
    );
    assert_eq!(
        leaked.load(Ordering::SeqCst),
        0,
        "the resume sent the confidential value the ceiling forbids — \
         crash-then-resume must never be a way around a declared ceiling"
    );
    assert_eq!(
        staged.load(Ordering::SeqCst),
        1,
        "stage-0 replayed, not redone"
    );

    // The refusal the resume just made is on the record: strict verification
    // consumes it and reports the refusal, rather than an overrun about a
    // dispatch that never happened — and a further resume re-consumes it
    // rather than re-deciding.
    let strict = rt.replay(crashed.run_id, Mode::Strict).await.unwrap();
    assert!(
        matches!(strict.status, RunStatus::Failed(_)),
        "strict replay of a sink-refused run must report the refusal: {:?}",
        strict.status
    );
    let again = rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    assert!(matches!(again.status, RunStatus::Failed(_)));
    assert_eq!(leaked.load(Ordering::SeqCst), 0);
}

// ── Step admission holds past the frontier ──────────────────────────────────

#[derive(Debug)]
struct Stage {
    name: &'static str,
    provides: &'static str,
    crash: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Stage {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.provides)
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Read-only, so a failing sibling's unwind has nothing to say about
        // these steps — what this module probes is admission and replay, not
        // the saga.
        cx.sink(
            Recorded::new(self.name)
                .read_only()
                .counter(Arc::clone(&self.calls)),
            &Tainted::trusted(Value::Null),
        )
        .await?;
        if self.crash.load(Ordering::SeqCst) {
            return Err(SkillError::Other("simulated crash".into()));
        }
        Ok(Outcome::done(Tainted::trusted(json!({"stage": self.name}))))
    }
}

fn two_step_plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "demo.first").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "demo.second")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ])
}

/// A resumed run past the frontier still meets `max_steps`.
///
/// Step admission answered `Ok` for any replaying mode — but `Resume` runs
/// live past its frontier, so a resumed run could cross the step ceiling
/// unmetered for the rest of its life. The ledger has already been fed the
/// replayed prefix's usage, so the frontier step is admitted against exactly
/// what the run has spent.
#[tokio::test]
async fn a_resumed_run_past_the_frontier_still_meets_max_steps() {
    let store = store();
    let crash = Arc::new(AtomicBool::new(true));
    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(Budget::default().steps(1))
        .skill(Stage {
            name: "first",
            provides: "demo.first",
            crash: Arc::clone(&crash),
            calls: Arc::clone(&first),
        })
        .skill(Stage {
            name: "second",
            provides: "demo.second",
            crash: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&second),
        })
        .build();

    // The run crashes inside step 0, before the ceiling was ever consulted
    // about step 1.
    let crashed = rt
        .run_plan(two_step_plan(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(crashed.status, RunStatus::Failed(_)));

    // The resume completes step 0 from history, then reaches step 1 at the
    // frontier — a live dispatch, which one step of budget does not admit.
    crash.store(false, Ordering::SeqCst);
    let resumed = rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    assert!(
        matches!(resumed.status, RunStatus::Exhausted(_)),
        "a resumed run crossed max_steps unmetered: {:?}",
        resumed.status
    );
    assert_eq!(
        second.load(Ordering::SeqCst),
        0,
        "the refused step performed its effect anyway"
    );
    assert_eq!(
        first.load(Ordering::SeqCst),
        1,
        "step 0 replayed, not redone"
    );
}

// ── The delegation ceiling holds on the live tail of a resume ───────────────

#[cfg(feature = "manifest")]
#[derive(Debug)]
struct ChiefAfterCrash {
    crash: Arc<AtomicBool>,
    staged: Arc<AtomicUsize>,
}

#[cfg(feature = "manifest")]
#[async_trait::async_trait]
impl Skill for ChiefAfterCrash {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("chief").provides("demo.chief")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.sink(
            Recorded::new("stage-0").counter(Arc::clone(&self.staged)),
            &Tainted::trusted(Value::Null),
        )
        .await?;
        if self.crash.load(Ordering::SeqCst) {
            return Err(SkillError::Other("simulated crash".into()));
        }
        let answer = cx
            .commission("demo.helper", Tainted::trusted(json!({})))
            .await?;
        Ok(Outcome::done(answer))
    }
}

#[cfg(feature = "manifest")]
#[derive(Debug)]
struct Helper {
    calls: Arc<AtomicUsize>,
}

#[cfg(feature = "manifest")]
#[async_trait::async_trait]
impl Skill for Helper {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("helper").provides("demo.helper")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(Tainted::trusted(json!({"helped": true}))))
    }
}

#[cfg(feature = "manifest")]
const CHIEF: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: chief, version: "1.0.0" }
spec:
  capabilities: { provides: [demo.chief] }
  security: { max_delegation_depth: 0 }
  budgets: {}
"#;

/// A declaration that forbids delegating forbids it on resume too.
#[cfg(feature = "manifest")]
#[tokio::test]
async fn the_delegation_ceiling_holds_on_the_live_tail_of_a_resume() {
    let manifest = agentplane::manifest::Manifest::parse(CHIEF).expect("parse");
    let store = store();
    let crash = Arc::new(AtomicBool::new(true));
    let staged = Arc::new(AtomicUsize::new(0));
    let helped = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .agent(
            agentplane::runtime::Agent::new(&manifest).skill(ChiefAfterCrash {
                crash: Arc::clone(&crash),
                staged: Arc::clone(&staged),
            }),
        )
        .skill(Helper {
            calls: Arc::clone(&helped),
        })
        .build();

    let crashed = rt
        .run("demo.chief", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(crashed.status, RunStatus::Failed(_)));

    // The commission dispatches on the resume's live tail, and a depth of one
    // exceeds a declared ceiling of zero — the hand-off loop the ceiling
    // exists to prevent does not pause because the run once crashed.
    crash.store(false, Ordering::SeqCst);
    let resumed = rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    assert!(
        matches!(resumed.status, RunStatus::Failed(_)),
        "a resumed run delegated past its declared ceiling: {:?}",
        resumed.status
    );
    assert_eq!(
        helped.load(Ordering::SeqCst),
        0,
        "the specialist handed work off on resume — the ceiling only governed \
         the first attempt"
    );
    assert_eq!(staged.load(Ordering::SeqCst), 1);
}

// ── A final InDoubt on a mutating effect is an operator's question ──────────

#[derive(Debug)]
struct GoesQuiet {
    mutates: bool,
}

#[async_trait::async_trait]
impl Effect for GoesQuiet {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.quiet", json!(null))
    }

    fn mutates(&self) -> bool {
        self.mutates
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        // `Other` deliberately: an error that does not say what it did is
        // in doubt, which is the disposition under test.
        Err(EffectError::Other("the wire went quiet mid-call".into()))
    }
}

#[derive(Debug)]
struct CallsQuiet {
    mutates: bool,
}

#[async_trait::async_trait]
impl Skill for CallsQuiet {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("calls-quiet").provides("demo.quiet")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let v = cx
            .effect(GoesQuiet {
                mutates: self.mutates,
            })
            .await?;
        Ok(Outcome::done(v))
    }
}

/// Attempts exhausted with the outcome unknown: a mutating effect quarantines.
///
/// `Failed` unwinds, and the unwind would compensate every step around a call
/// that may have landed — the refund for money nobody took, issued because a
/// retry policy gave up. I5: a mutating effect's unknown outcome defaults to
/// operator resolution.
#[tokio::test]
async fn a_mutating_effect_that_ends_in_doubt_quarantines() {
    let rt = Runtime::builder(store() as Arc<dyn JournalStore>)
        .skill(CallsQuiet { mutates: true })
        .build();
    let out = rt
        .run("demo.quiet", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "a mutating call whose last attempt is in doubt was classified as an \
         ordinary failure — the unwind would compensate around it: {:?}",
        out.status
    );
}

/// A read that ends in doubt is an ordinary failure: nothing landed that an
/// unwind could betray.
#[tokio::test]
async fn a_non_mutating_effect_that_ends_in_doubt_fails_normally() {
    let rt = Runtime::builder(store() as Arc<dyn JournalStore>)
        .skill(CallsQuiet { mutates: false })
        .build();
    let out = rt
        .run("demo.quiet", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "a doubtful read is a failure, not an incident: {:?}",
        out.status
    );
}

// ── Cancellation refuses to compensate through recorded doubt ───────────────

#[derive(Debug)]
struct Compensable {
    name: &'static str,
    provides: &'static str,
    undone: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Compensable {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.provides)
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(Tainted::trusted(json!({}))))
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn compensate(
        &self,
        _cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        self.undone.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A journal holding a terminal `InDoubt` mutation is not unwound by a stop.
///
/// The orphan case — announced, never concluded — was already refused. This is
/// its concluded twin: the call *ended*, with a record saying nobody knows
/// whether it reached the world, and no reconciliation afterwards. An
/// operator's stop must not compensate every step around it.
// Long because the crash shape is hand-built record by record, which is the
// only way to hold a journal in exactly this state.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn cancellation_refuses_to_unwind_through_a_recorded_in_doubt_mutation() {
    use agentplane::core::{Disposition, EffectKey, Label, Phase, canon};

    let store = store();
    let undone = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Compensable {
            name: "first",
            provides: "demo.first",
            undone: Arc::clone(&undone),
        })
        .skill(Compensable {
            name: "second",
            provides: "demo.second",
            undone: Arc::new(AtomicUsize::new(0)),
        })
        .build();

    // Hand-build the crash shape: step 0 completed a mutation; step 1's
    // mutation concluded in doubt; nothing reconciled it.
    let run = RunId::generate();
    let plan = two_step_plan();
    let journal = store.clone() as Arc<dyn JournalStore>;
    let lease = journal
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    let d0 = EffectDescriptor::new("test.first", json!(null));
    let k0 = EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &d0);
    let d1 = EffectDescriptor::new("test.second", json!(null));
    let k1 = EffectKey::for_effect(StepId(1), Phase::Forward, 0, 1, &d1);
    let _ = canon::VERSION;
    journal
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "demo.first".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: Label::trusted(),
                        policy_bundle: None,
                        canon: canon::VERSION,
                    },
                ),
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        steps: vec!["demo.first".into(), "demo.second".into()],
                        plan: serde_json::to_value(&plan).unwrap(),
                    },
                ),
                Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: "first".into(),
                    },
                )
                .step(StepId(0)),
                Append::new(
                    run,
                    RecordKind::EffectStarted {
                        descriptor: d0,
                        recovery: Recovery::Retry,
                        mutates: true,
                        attempt: 1,
                        backoff_ms: 0,
                        outbound_label: None,
                    },
                )
                .step(StepId(0))
                .effect(k0),
                Append::new(
                    run,
                    RecordKind::EffectDone {
                        output: json!({"did": "first"}),
                        source: None,
                        spend: agentplane::core::Spend::default(),
                    },
                )
                .step(StepId(0))
                .effect(k0),
                Append::new(
                    run,
                    RecordKind::StepFinished {
                        outcome: "succeeded".into(),
                    },
                )
                .step(StepId(0)),
                Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: "second".into(),
                    },
                )
                .step(StepId(1)),
                Append::new(
                    run,
                    RecordKind::EffectStarted {
                        descriptor: d1,
                        recovery: Recovery::Retry,
                        mutates: true,
                        attempt: 1,
                        backoff_ms: 0,
                        outbound_label: None,
                    },
                )
                .step(StepId(1))
                .effect(k1),
                Append::new(
                    run,
                    RecordKind::EffectFailed {
                        error: "connection lost mid-call".into(),
                        disposition: Disposition::InDoubt,
                        spend: agentplane::core::Spend::default(),
                        permanent: false,
                    },
                )
                .step(StepId(1))
                .effect(k1),
            ],
        )
        .await
        .unwrap();
    journal.release_lease(run, lease.epoch).await.unwrap();

    // The operator stops the run. The stop must quarantine rather than unwind:
    // step 1's mutation may or may not stand, and compensating step 0 around
    // it undoes everything except the one thing nobody can account for.
    rt.request_cancel(run, "ops", "stop it").await.unwrap();

    assert_eq!(
        undone.load(Ordering::SeqCst),
        0,
        "the stop compensated around a mutation whose outcome is recorded as \
         unknown — the refund for money nobody took"
    );
    let quarantined = journal.runs_by_outcome("quarantined", 10).await.unwrap();
    assert!(
        quarantined.contains(&run),
        "an unwind blocked by doubt must land in the quarantine backlog"
    );
}

// ── Exhaustion pauses; a raised ceiling resumes ─────────────────────────────

fn three_step_plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "demo.first").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "demo.second").arg("x", ArgSource::node(StepId(0))),
        PlanNode::new(2, "demo.third")
            .arg("x", ArgSource::node(StepId(1)))
            .terminal(),
    ])
}

fn staged_plane(
    store: &Arc<RedbStore>,
    budget: Budget,
    counters: &[Arc<AtomicUsize>; 3],
) -> Arc<Runtime> {
    Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .budget(budget)
        .skill(Stage {
            name: "first",
            provides: "demo.first",
            crash: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&counters[0]),
        })
        .skill(Stage {
            name: "second",
            provides: "demo.second",
            crash: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&counters[1]),
        })
        .skill(Stage {
            name: "third",
            provides: "demo.third",
            crash: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&counters[2]),
        })
        .build()
}

/// The full exhaustion protocol: pause, re-refuse, re-admit, verify.
///
/// A recorded step refusal replayed verbatim forever meant an exhausted run
/// could never continue — the operator's raise changed nothing, because the
/// resume consumed yesterday's verdict instead of asking today's ledger. And
/// once re-admitted, the continuation must verify: the refusal followed by the
/// work is a decision on the record, not divergence.
#[tokio::test]
async fn an_exhausted_run_resumes_under_a_raised_ceiling_and_not_under_the_same_one() {
    let store = store();
    let counters = [
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    ];

    // Two steps of budget for a three-step plan.
    let capped = staged_plane(&store, Budget::default().steps(2), &counters);
    let out = capped
        .run_plan(three_step_plan(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
    assert_eq!(counters[2].load(Ordering::SeqCst), 0);

    // Resumed without a raise: the ledger in force still refuses, so the run
    // concludes exhausted again — and the standing refusal is not duplicated.
    let again = capped.replay(out.run_id, Mode::Resume).await.unwrap();
    assert!(
        matches!(again.status, RunStatus::Exhausted(_)),
        "an unchanged ceiling admitted the step it refused: {:?}",
        again.status
    );
    assert_eq!(counters[2].load(Ordering::SeqCst), 0);
    assert_eq!(
        kind_count(&store, out.run_id, "BudgetRefused", None).await,
        1,
        "re-concluding exhausted must consume the standing refusal, not stack \
         another"
    );

    // Raised and resumed: the refused step is re-admitted against the ledger
    // now in force, the re-admission goes on the record, and the run finishes.
    let raised = staged_plane(&store, Budget::default().steps(5), &counters);
    let resumed = raised.replay(out.run_id, Mode::Resume).await.unwrap();
    assert_eq!(
        resumed.status,
        RunStatus::Succeeded,
        "a raised ceiling must un-pause an exhausted run"
    );
    assert_eq!(counters[0].load(Ordering::SeqCst), 1, "step 0 once, ever");
    assert_eq!(counters[1].load(Ordering::SeqCst), 1, "step 1 once, ever");
    assert_eq!(
        counters[2].load(Ordering::SeqCst),
        1,
        "step 2 ran on resume"
    );
    assert_eq!(
        kind_count(&store, out.run_id, "BudgetReadmitted", None).await,
        1,
        "the re-admission is a decision, and decisions go on the record"
    );

    // The resumed history is coherent under strict verification: the refusal
    // is superseded by the recorded re-admission, so the continuation reads as
    // history rather than as divergence.
    let strict = raised.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(
        strict.status,
        RunStatus::Succeeded,
        "strict replay of a readmitted history stopped at the superseded refusal"
    );
    assert_eq!(
        counters[2].load(Ordering::SeqCst),
        1,
        "verification performs nothing"
    );
}

// ── A compensated run is not resumable ──────────────────────────────────────

#[derive(Debug)]
struct FailsCleanly;

#[async_trait::async_trait]
impl Skill for FailsCleanly {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("refuser").provides("demo.second")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::fail("the counterparty said no"))
    }
}

#[derive(Debug)]
struct MutatesThenCompensates {
    did: Arc<AtomicUsize>,
    undone: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for MutatesThenCompensates {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("mutator").provides("demo.first")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.sink(
            Recorded::new("charge").counter(Arc::clone(&self.did)),
            &Tainted::trusted(Value::Null),
        )
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({"charged": true}))))
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn compensate(
        &self,
        _cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        self.undone.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A failed run whose completed work was compensated may not be resumed.
///
/// The unwind *reversed* the work — the journal's own compensation records say
/// so — and a resume that replayed the forward history and continued would
/// conclude success over a world where the work no longer stands. The operator
/// starts a fresh run instead.
#[tokio::test]
async fn a_run_that_compensated_is_refused_a_resume() {
    let store = store();
    let did = Arc::new(AtomicUsize::new(0));
    let undone = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(MutatesThenCompensates {
            did: Arc::clone(&did),
            undone: Arc::clone(&undone),
        })
        .skill(FailsCleanly)
        .build();

    let out = rt
        .run_plan(two_step_plan(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Failed(_)));
    assert_eq!(
        undone.load(Ordering::SeqCst),
        1,
        "the failure unwound step 0"
    );

    let refused = rt.replay(out.run_id, Mode::Resume).await;
    match refused {
        Err(e) => assert!(
            e.to_string().contains("fresh run"),
            "the refusal must tell the operator what to do instead: {e}"
        ),
        Ok(resumed) => panic!(
            "a resume replayed forward history whose work the same journal \
             records as reversed: {:?}",
            resumed.status
        ),
    }
}

// ── One ending per step, per piece of work ──────────────────────────────────

/// A step that crashes between two effects, so its resume genuinely works.
#[derive(Debug)]
struct CrashBetweenEffects {
    crash: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for CrashBetweenEffects {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("second").provides("demo.second")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.sink(
            Recorded::new("half")
                .read_only()
                .counter(Arc::clone(&self.calls)),
            &Tainted::trusted(Value::Null),
        )
        .await?;
        if self.crash.load(Ordering::SeqCst) {
            return Err(SkillError::Other("simulated crash".into()));
        }
        cx.sink(
            Recorded::new("rest").read_only(),
            &Tainted::trusted(Value::Null),
        )
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({"stage": "second"}))))
    }
}

/// A resumed run appends a `StepFinished` only for steps that did new work.
#[tokio::test]
async fn a_resume_does_not_duplicate_a_replayed_steps_ending() {
    let store = store();
    let crash = Arc::new(AtomicBool::new(true));
    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Stage {
            name: "first",
            provides: "demo.first",
            crash: Arc::new(AtomicBool::new(false)),
            calls: Arc::clone(&first),
        })
        .skill(CrashBetweenEffects {
            crash: Arc::clone(&crash),
            calls: Arc::clone(&second),
        })
        .build();

    // Step 0 completes; step 1 crashes.
    let crashed = rt
        .run_plan(two_step_plan(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(crashed.status, RunStatus::Failed(_)));

    // Two resumes: the first completes the run, the second is a closed-run
    // no-op. Step 0 is fully replayed both times and must keep its single
    // recorded ending; step 1 was genuinely re-executed live and its second
    // ending is the new fact.
    crash.store(false, Ordering::SeqCst);
    rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    rt.replay(crashed.run_id, Mode::Resume).await.unwrap();

    assert_eq!(
        kind_count(&store, crashed.run_id, "StepFinished", Some(StepId(0))).await,
        1,
        "a fully replayed step's ending was appended again — history growing \
         on a pass that did nothing new"
    );
    assert_eq!(
        kind_count(&store, crashed.run_id, "StepFinished", Some(StepId(1))).await,
        2,
        "a step re-executed live records its new ending beside the old one"
    );
    assert_eq!(first.load(Ordering::SeqCst), 1);
    assert_eq!(
        second.load(Ordering::SeqCst),
        1,
        "the crashed step's first effect replayed rather than re-performed"
    );
}

// ── A failed admission leaves nothing behind ────────────────────────────────

/// An admission that fails past its quota reservation gives the slot back and
/// strands no lease.
///
/// The reservation leaked on every post-reserve error, so a tenant at
/// `max_concurrent_runs: 1` whose admission once failed could never start
/// another run — throttled to zero by its own error handling. And the lease
/// used to outlive the failure, which reads to the recovery sweep as "an
/// instance died holding this run".
#[tokio::test]
async fn a_failed_admission_leaks_no_slot_and_no_abandoned_run() {
    use agentplane::quota::{QuotaStore, TenantQuota};

    let store = store();
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        // Short, so a leaked lease would lapse into the recovery queue within
        // this test's patience rather than after it stopped looking.
        .lease_ttl(std::time::Duration::from_secs(2))
        .quota(
            store.clone() as Arc<dyn QuotaStore>,
            TenantQuota {
                max_concurrent_runs: Some(1),
                ..TenantQuota::default()
            },
        )
        .skill(Stage {
            name: "first",
            provides: "demo.first",
            crash: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .build();

    // Fails after the slot is reserved and the lease taken: the case binding
    // names a case that does not exist.
    let ghost = agentplane::core::CaseId::generate();
    let refused = rt
        .run_in_case("demo.first", Tainted::trusted(json!({})), ghost)
        .await;
    assert!(refused.is_err(), "admission into a missing case must fail");

    // The slot came back: with one concurrent run allowed, the next admission
    // only succeeds if the failed one released its reservation.
    let ok = rt
        .run("demo.first", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(
        ok.status,
        RunStatus::Succeeded,
        "the failed admission kept its concurrency slot, so the tenant is \
         throttled by its own error"
    );

    // And no lease was left to lapse into the recovery queue: past the TTL,
    // a leaked lease would surface here as "an instance died holding this
    // run" — and the sweeper would then execute a run that was never admitted.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        (store as Arc<dyn JournalStore>)
            .abandoned_runs(10)
            .await
            .unwrap()
            .is_empty(),
        "a failed admission left a lease the sweeper will read as a crashed run"
    );
}
