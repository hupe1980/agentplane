//! Sagas: undoing a run forward when a later step fails.
//!
//! A plan that touches real systems cannot be a transaction — there is nothing
//! to roll back across a payment provider and a warehouse. The saga answer is
//! to undo forward: compensate the completed steps in reverse order.
//!
//! Two rules here are not the usual ones, and both come from taking distributed
//! systems seriously rather than tidying up and hoping:
//!
//! * **A quarantined run is never unwound.** It holds an effect whose outcome is
//!   unknown, and compensating a payment that may never have gone out creates a
//!   refund for money nobody took. Everything stays where it is until a human
//!   decides.
//! * **An undeclared step is judged on evidence.** A step that performed no
//!   mutating effect has nothing to undo and the journal proves it. One that did
//!   mutate and declared nothing stops the unwind, because silently leaving a
//!   charge in place while reversing everything around it is exactly the outcome
//!   the mechanism exists to prevent.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::Mutex;

use agentplane::core::{
    ArgSource, Budget, Compensation, Effect, EffectDescriptor, EffectError, Outcome, Phase, PlanIR,
    PlanNode, Recovery, RetryPolicy, Skill, SkillDescriptor, SkillError, StepId, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Everything the run did, in order, so a test can assert on the sequence
/// rather than on counters.
type Log = Arc<Mutex<Vec<String>>>;

fn log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

fn entries(l: &Log) -> Vec<String> {
    l.lock().unwrap().clone()
}

/// A mutating effect that records what it did.
#[derive(Debug, Clone)]
struct Mutation {
    what: String,
    log: Log,
    fails: bool,
}

#[async_trait::async_trait]
impl Effect for Mutation {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.mutate", json!({ "what": self.what }))
    }

    fn mutates(&self) -> bool {
        true
    }

    // Declared safe to repeat so a clean failure retries rather than escalating;
    // the retry path is not what these tests are about.
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.log.lock().unwrap().push(self.what.clone());
        if self.fails {
            return Err(EffectError::Rejected(format!("{} refused", self.what)));
        }
        Ok(json!({ "did": self.what }))
    }
}

/// A step that performs one mutating effect and can be told how to compensate.
#[derive(Debug)]
struct Step {
    name: &'static str,
    log: Log,
    declares: Compensation,
    /// The forward pass fails.
    fails: bool,
    /// The compensation fails.
    compensation_fails: bool,
    /// The forward pass performs no effect at all — a pure read.
    pure: bool,
}

impl Step {
    fn new(name: &'static str, log: &Log) -> Self {
        Self {
            name,
            log: Arc::clone(log),
            declares: Compensation::Compensatable,
            fails: false,
            compensation_fails: false,
            pure: false,
        }
    }

    fn declaring(mut self, c: Compensation) -> Self {
        self.declares = c;
        self
    }

    fn failing(mut self) -> Self {
        self.fails = true;
        self
    }

    fn with_failing_compensation(mut self) -> Self {
        self.compensation_fails = true;
        self
    }

    fn pure(mut self) -> Self {
        self.pure = true;
        self
    }
}

#[async_trait::async_trait]
impl Skill for Step {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.name)
    }

    fn compensation(&self) -> Compensation {
        self.declares
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        if self.pure {
            self.log.lock().unwrap().push(format!("{}:pure", self.name));
            return Ok(Outcome::done(Tainted::trusted(
                json!({ "step": self.name }),
            )));
        }
        let out = cx
            .effect(Mutation {
                what: format!("do:{}", self.name),
                log: Arc::clone(&self.log),
                fails: self.fails,
            })
            .await?;
        Ok(Outcome::done(out))
    }

    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Mutation {
            what: format!("undo:{}", self.name),
            log: Arc::clone(&self.log),
            fails: self.compensation_fails,
        })
        .await?;
        Ok(())
    }
}

/// A three-node chain: a -> b -> c.
fn chain() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "a").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "b").arg("x", ArgSource::node(StepId(0))),
        PlanNode::new(2, "c")
            .arg("x", ArgSource::node(StepId(1)))
            .terminal(),
    ])
}

fn runtime(store: &Arc<RedbStore>, steps: Vec<Step>) -> Arc<Runtime> {
    let mut b = Runtime::builder(store.clone() as Arc<dyn JournalStore>).owner("test");
    for s in steps {
        b = b.skill(s);
    }
    b.build()
}

// ── The basic unwind ────────────────────────────────────────────────────────

/// **The saga.** Steps a and b complete, c fails, and the runtime undoes b then
/// a — in reverse order, which is the only order that is safe when later steps
/// depend on earlier ones.
#[tokio::test]
async fn a_failing_step_unwinds_the_completed_ones_in_reverse() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "do:c", "undo:b", "undo:a"],
        "completed steps are undone in reverse; the failed step is not"
    );
}

/// Compensating effects are journaled in their own phase, so an auditor reading
/// the run can tell doing from undoing without guessing from names.
#[tokio::test]
async fn compensating_effects_are_journaled_in_their_own_phase() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    let records = store.read(out.run_id, 1).await.unwrap();

    let compensating = records
        .iter()
        .filter(|r| r.body.phase == Phase::Compensating)
        .count();
    assert!(compensating > 0, "the unwind must leave a trace");

    let compensated: Vec<StepId> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::StepCompensated { .. } => r.body.step,
            _ => None,
        })
        .collect();
    assert_eq!(
        compensated,
        vec![StepId(1), StepId(0)],
        "and name which steps were undone, in the order it happened"
    );
}

/// A step's compensation must not collide with its own forward pass. Without a
/// phase in the effect key the ordinals restart at zero and the second
/// announcement is rejected by the store's uniqueness constraint.
#[tokio::test]
async fn compensation_effects_do_not_collide_with_forward_ones() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    let records = store.read(out.run_id, 1).await.unwrap();

    let mut keys: Vec<String> = records
        .iter()
        .filter(|r| matches!(r.kind(), RecordKind::EffectStarted { .. }))
        .filter_map(|r| r.effect_key().map(agentplane::core::EffectKey::to_hex))
        .collect();
    let total = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), total, "every announcement has its own identity");
}

// ── Declarations ────────────────────────────────────────────────────────────

/// The pivot is the point of no return: nothing at or before it is undone.
#[tokio::test]
async fn a_pivot_stops_the_unwind() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l).declaring(Compensation::Pivot),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Failed(_)));
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "do:c"],
        "once the business has committed, nothing before the pivot is reversed"
    );
}

/// A step that says there is nothing to undo is skipped, and the run keeps
/// unwinding past it.
#[tokio::test]
async fn an_unnecessary_declaration_is_skipped_without_stopping_the_unwind() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l).declaring(Compensation::Unnecessary),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Failed(_)));
    assert_eq!(entries(&l), vec!["do:a", "do:b", "do:c", "undo:a"]);
}

/// **Undeclared is judged on evidence, not waved through.**
///
/// A step that performed no mutating effect has nothing to undo, and the journal
/// proves it. No declaration is needed and none is demanded.
#[tokio::test]
async fn an_undeclared_step_that_changed_nothing_needs_no_compensation() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l)
                .declaring(Compensation::Undeclared)
                .pure(),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(entries(&l), vec!["do:a", "b:pure", "do:c", "undo:a"]);
}

/// **The one that matters.** A step that *did* change something and declared
/// nothing stops the unwind and escalates. Reversing everything around a charge
/// while silently leaving the charge in place is the outcome this prevents.
#[tokio::test]
async fn an_undeclared_step_that_changed_something_escalates() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l).declaring(Compensation::Undeclared),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    match &out.status {
        RunStatus::Quarantined(m) => assert!(
            m.contains("declares no compensation"),
            "the operator must be told which step and why, got: {m}"
        ),
        other => panic!("expected quarantine, got {other:?}"),
    }
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "do:c"],
        "and nothing is unwound past the step nobody described"
    );
}

// ── Failure during the unwind ───────────────────────────────────────────────

/// A failed compensation is not a problem more compensation solves. The run
/// stops, half-unwound, and says which step could not be undone.
#[tokio::test]
async fn a_failed_compensation_quarantines_and_names_the_step() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l).with_failing_compensation(),
            Step::new("c", &l).failing(),
        ],
    );

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    match &out.status {
        RunStatus::Quarantined(m) => {
            assert!(m.contains("compensation failed for step s1"), "got: {m}");
            assert!(m.contains("partially unwound"), "got: {m}");
        }
        other => panic!("expected quarantine, got {other:?}"),
    }
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "do:c", "undo:b"],
        "unwinding stops at the failure rather than continuing past it"
    );
}

// ── When a run must NOT unwind ──────────────────────────────────────────────

/// **A quarantined run is never unwound.**
///
/// Step c leaves an effect whose outcome is unknown. Compensating b and a around
/// it would be undoing everything except the one thing nobody can account for —
/// and if c's payment did go out, the run has now refunded the wrong things.
#[tokio::test]
async fn a_quarantined_run_is_never_unwound() {
    #[derive(Debug)]
    struct Undecidable(Log);

    #[async_trait::async_trait]
    impl Skill for Undecidable {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("c").provides("c")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            #[derive(Debug)]
            struct TimesOut;
            #[async_trait::async_trait]
            impl Effect for TimesOut {
                type Output = Value;
                fn descriptor(&self) -> EffectDescriptor {
                    EffectDescriptor::nullary("test.timeout")
                }
                fn mutates(&self) -> bool {
                    true
                }
                fn retry(&self) -> RetryPolicy {
                    RetryPolicy::never()
                }
                async fn perform(&self) -> Result<Value, EffectError> {
                    Err(EffectError::Timeout {
                        driver: "x".into(),
                        waited_ms: 1,
                    })
                }
            }
            self.0.lock().unwrap().push("do:c".into());
            let v = cx.effect(TimesOut).await?;
            Ok(Outcome::done(v))
        }
    }

    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Step::new("a", &l))
        .skill(Step::new("b", &l))
        .skill(Undecidable(Arc::clone(&l)))
        .build();

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "do:c"],
        "you cannot safely undo around an effect whose outcome is unknown"
    );
}

// ── Budget ──────────────────────────────────────────────────────────────────

/// **Exhaustion is a pause, and its mutations stand.**
///
/// The run did exactly what it was told, and what it was told included a
/// ceiling. Both of the operator's honest options need the completed work
/// standing: raise the ceiling and resume — which continues *over* that work —
/// or cancel, which unwinds through the ordinary evidence-based protocol.
/// Unwinding on exhaustion made the three ends of an exhausted run contradict
/// each other: the work was reversed, the run stayed resumable, and a resume
/// then reported success over a world where the work no longer stood.
#[tokio::test]
async fn an_exhausted_run_pauses_with_its_work_standing() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("test")
        .budget(Budget::default().effects(2))
        .skill(Step::new("a", &l))
        .skill(Step::new("b", &l))
        .skill(Step::new("c", &l))
        .build();

    let out = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b"],
        "exhaustion pauses the run; nothing is undone behind the operator \
         deciding whether to raise the ceiling"
    );

    // Cancelling is the option that unwinds — the operator deciding the work
    // is not worth finishing, through the same protocol every stop uses.
    let fresh = rt
        .request_cancel(out.run_id, "ops", "not worth finishing")
        .await
        .unwrap();
    assert!(fresh, "the first stop request records");
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "undo:b", "undo:a"],
        "cancel unwinds what exhaustion left standing, in reverse"
    );
}

// ── Replay ──────────────────────────────────────────────────────────────────

/// An unwind is history like any other: replaying it performs nothing.
#[tokio::test]
async fn replay_reproduces_an_unwind_without_repeating_it() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime(
        &store,
        vec![
            Step::new("a", &l),
            Step::new("b", &l),
            Step::new("c", &l).failing(),
        ],
    );

    let first = rt
        .run_plan(chain(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    let during = entries(&l);
    assert_eq!(during, vec!["do:a", "do:b", "do:c", "undo:b", "undo:a"]);

    let again = rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(
        entries(&l),
        during,
        "strict replay of a compensated run must not call anything"
    );
    assert_eq!(again.status, first.status);
}

// ── A compensation that waits for a human ───────────────────────────────────

/// **A refund that needs four eyes is still a refund.**
///
/// A compensation may legitimately suspend — approval, a settlement window, a
/// counterparty confirmation. That is not a failed compensation, and reporting
/// it as one quarantines a run that is doing exactly the right thing.
///
/// This is the whole loop: the unwind suspends, the approval arrives, and the
/// run picks the unwind back up where it stopped — without re-running the
/// compensations it had already finished.
/// Undoing this step needs someone to approve the refund first.
#[derive(Debug)]
struct NeedsApproval {
    log: Log,
}

mod approval {
    use super::*;
    use agentplane::core::{AwaitSpec, CorrelationKey, DeadlineSpec};

    #[async_trait::async_trait]
    impl Skill for NeedsApproval {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("b").provides("b")
        }
        fn compensation(&self) -> Compensation {
            Compensation::Compensatable
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let out = cx
                .effect(Mutation {
                    what: "do:b".into(),
                    log: Arc::clone(&self.log),
                    fails: false,
                })
                .await?;
            Ok(Outcome::done(out))
        }
        async fn compensate(
            &self,
            cx: &mut StepCtx<'_>,
            _o: &Tainted<Value>,
        ) -> Result<(), SkillError> {
            cx.deadline("approval-window", &DeadlineSpec::days(1), None)
                .await?;
            self.log.lock().unwrap().push("undo:b:waiting".into());
            cx.await_event(
                &AwaitSpec::new("refund.approved", "approval-window")
                    .correlate(CorrelationKey::new("matter", "M-1")),
            )
            .await?;
            cx.effect(Mutation {
                what: "undo:b".into(),
                log: Arc::clone(&self.log),
                fails: false,
            })
            .await?;
            Ok(())
        }
    }
}

#[tokio::test]
async fn a_compensation_may_wait_for_a_human_and_the_unwind_resumes() {
    use agentplane::case::{CaseStore, EventStore};
    use agentplane::core::{CorrelationKey, Delivery, InboundEvent};

    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(Step::new("a", &l))
        .skill(NeedsApproval {
            log: Arc::clone(&l),
        })
        .skill(Step::new("c", &l).failing())
        .build();

    let key = CorrelationKey::new("matter", "M-1");
    let out = rt
        .run_plan_correlated(
            chain(),
            Tainted::trusted(json!({})),
            "matter",
            std::slice::from_ref(&key),
        )
        .await
        .unwrap();

    assert!(
        out.status.is_suspended(),
        "a waiting compensation is not a failed one, got {:?}",
        out.status
    );
    assert_eq!(
        entries(&l),
        vec!["do:a", "do:b", "do:c", "undo:b:waiting"],
        "the unwind stops at the wait, having undone nothing yet"
    );

    // The approval arrives.
    let delivery = rt
        .deliver(
            &InboundEvent::new(
                "urn:test:auditor",
                "EV-1",
                "refund.approved",
                json!({ "by": "auditor" }),
            )
            .correlate(key),
        )
        .await
        .unwrap();
    assert_eq!(delivery, Delivery::Resumed { run: out.run_id });

    // `undo:b:waiting` appears twice, and that is correct: it is a plain log
    // line inside the skill, not an effect. Resuming re-executes the skill and
    // serves its *effects* from the journal — so the bookkeeping runs again and
    // nothing external does.
    assert_eq!(
        entries(&l),
        vec![
            "do:a",
            "do:b",
            "do:c",
            "undo:b:waiting",
            "undo:b:waiting",
            "undo:b",
            "undo:a"
        ],
        "the unwind picks up where it stopped and finishes in reverse"
    );

    let records = store.read(out.run_id, 1).await.unwrap();
    let compensated: Vec<StepId> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::StepCompensated { .. } => r.body.step,
            _ => None,
        })
        .collect();
    assert_eq!(
        compensated,
        vec![StepId(1), StepId(0)],
        "each step is recorded compensated exactly once across the suspension"
    );
    store.verify(out.run_id).await.unwrap();
}

// ── Concurrency ─────────────────────────────────────────────────────────────

/// **A sibling that succeeded is still compensated when its neighbour fails.**
///
/// Two steps in one ready set dispatch concurrently. `right` completes and
/// mutates; `left` fails. `right`'s work happened, so the unwind has to undo it.
///
/// The first version of concurrent dispatch returned on the first non-success in
/// ready order, which discarded `right`'s completion entirely — it never entered
/// `completed`, and `completed` is exactly what the unwind reverses. The effect
/// had been performed and would never be undone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_succeeding_sibling_is_compensated_when_its_neighbour_fails() {
    use agentplane::core::PlanIR as Plan;

    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Step::new("left", &l).failing())
        .skill(Step::new("right", &l))
        .skill(Step::new("c", &l))
        .build();

    // A diamond: `left` and `right` are siblings, so they are in the ready set
    // together and dispatch at the same time.
    let plan = Plan::new(vec![
        PlanNode::new(0, "left").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "right").arg("input", ArgSource::run_input()),
        PlanNode::new(2, "c")
            .arg("l", ArgSource::node(StepId(0)))
            .arg("r", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "got {:?}",
        out.status
    );

    let entries = entries(&l);
    assert!(
        entries.contains(&"do:right".to_string()),
        "the sibling ran: {entries:?}"
    );
    assert!(
        entries.contains(&"undo:right".to_string()),
        "and having run, it must be undone: {entries:?}"
    );
    assert!(
        !entries.contains(&"undo:left".to_string()),
        "the step that failed is not compensated: {entries:?}"
    );
}

/// **A sibling's wait must not defer another sibling's unwind.**
///
/// `left` suspends on an approval; `right` fails after mutating. Reporting the
/// suspension — which ready order alone would do, since `left` comes first —
/// leaves `right`'s mutation in place until an event that may never arrive.
///
/// A suspension is the run working. A failure is the run over. Severity wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failure_beats_a_siblings_suspension() {
    use agentplane::case::{CaseStore, EventStore};
    use agentplane::core::{AwaitSpec, CorrelationKey, DeadlineSpec, PlanIR as Plan};

    /// Suspends, forever as far as this test is concerned.
    #[derive(Debug)]
    struct Waits(Log);

    #[async_trait::async_trait]
    impl Skill for Waits {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("left").provides("left")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("w", &DeadlineSpec::days(1), None).await?;
            self.0.lock().unwrap().push("left:waiting".into());
            let v = cx
                .await_event(
                    &AwaitSpec::new("never.arrives", "w")
                        .correlate(CorrelationKey::new("matter", "M-9")),
                )
                .await?;
            Ok(Outcome::done(v))
        }
    }

    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(Waits(Arc::clone(&l)))
        .skill(Step::new("right", &l).failing())
        .skill(Step::new("c", &l))
        .build();

    let plan = Plan::new(vec![
        PlanNode::new(0, "left").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "right").arg("input", ArgSource::run_input()),
        PlanNode::new(2, "c")
            .arg("l", ArgSource::node(StepId(0)))
            .arg("r", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = rt
        .run_plan_correlated(
            plan,
            Tainted::trusted(json!({})),
            "matter",
            &[CorrelationKey::new("matter", "M-9")],
        )
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "the failure decides the run, not the wait — got {:?}",
        out.status
    );
    assert!(
        entries(&l).contains(&"left:waiting".to_string()),
        "the sibling really did suspend: {:?}",
        entries(&l)
    );
}
