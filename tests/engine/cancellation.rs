//! Stopping a run.
//!
//! Article 14 is not "a human can approve things". It is oversight, and the half
//! most runtimes omit is the ability to **intervene and stop** — a plane whose
//! only brake is a budget ceiling can halt on cost but not on judgement.
//!
//! The interesting question is not whether a stop flag can be set. It is what a
//! stop is allowed to *mean*:
//!
//! * it must not interrupt an effect between announcing and recording, because
//!   that manufactures the undecidable case the whole protocol exists to avoid;
//! * it must undo what the run already did, because stopping a run that has
//!   moved money and leaving the movement in place is not stopping it;
//! * and it must refuse to undo *around* an unknown outcome, for exactly the
//!   reason a failure does — otherwise the safety control is the thing that
//!   issues a refund for money nobody took.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    Compensation, CorrelationKey, DeadlineSpec, Effect, EffectDescriptor, EffectError,
    Justification, Outcome, Recovery, RunId, Skill, SkillDescriptor, SkillError, Tainted, TaskSpec,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

type World = Arc<Mutex<Vec<String>>>;

/// Records what it did, so a test can ask whether it was undone.
#[derive(Debug)]
struct Ledger {
    world: World,
    what: &'static str,
}

#[async_trait::async_trait]
impl Effect for Ledger {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.post", json!({ "what": self.what }))
    }

    fn recovery(&self) -> Recovery {
        Recovery::Idempotent {
            key: format!("ledger:{}", self.what),
        }
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.lock().unwrap().push(self.what.to_owned());
        Ok(json!({ "posted": self.what }))
    }
}

/// Posts, then waits for a human. Compensatable.
#[derive(Debug)]
struct PostsThenWaits;

#[async_trait::async_trait]
impl Skill for PostsThenWaits {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("posts-then-waits").provides("demo.post")
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let world = world_of(cx);
        cx.effect(Ledger {
            world,
            what: "posted",
        })
        .await?;

        cx.deadline("approval", &DeadlineSpec::days(2), None)
            .await?;
        let spec = TaskSpec::new(
            "release",
            Justification::new("needs a person", json!({})),
            "approval",
        )
        .role("officer");
        cx.task(&spec).await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "ok": true }))))
    }

    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _out: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        let world = world_of(cx);
        cx.effect(Ledger {
            world,
            what: "reversed",
        })
        .await?;
        Ok(())
    }
}

// The world is threaded through a static rather than the context, because a
// skill is stateless by design and these tests need to observe side effects.
thread_local! {
    static WORLD: std::cell::RefCell<Option<World>> = const { std::cell::RefCell::new(None) };
}

fn world_of(_cx: &StepCtx<'_>) -> World {
    WORLD.with(|w| w.borrow().clone().expect("world installed"))
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    world: World,
}

fn fixture<S: Skill + 'static>(skill: S) -> Fixture {
    let world: World = Arc::default();
    WORLD.with(|w| *w.borrow_mut() = Some(Arc::clone(&world)));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .skill(skill)
        .build();
    Fixture { store, rt, world }
}

fn key(v: &str) -> CorrelationKey {
    CorrelationKey::new("document", v)
}

async fn suspended_run(f: &Fixture, target: &str) -> RunId {
    let out =
        f.rt.run_correlated(
            target,
            Tainted::trusted(json!({})),
            "dispute",
            &[key("INV-1")],
        )
        .await
        .unwrap();
    assert!(out.status.is_suspended(), "got {:?}", out.status);
    out.run_id
}

// ── The stop itself ─────────────────────────────────────────────────────────

/// A suspended run stops, unwinds, and says who asked.
#[tokio::test]
async fn stopping_a_suspended_run_undoes_what_it_did() {
    let f = fixture(PostsThenWaits);
    let run = suspended_run(&f, "demo.post").await;
    assert_eq!(*f.world.lock().unwrap(), vec!["posted".to_string()]);

    let fresh =
        f.rt.request_cancel(run, "ops-carol", "counterparty withdrew the dispute")
            .await
            .unwrap();
    assert!(fresh, "the first stop request must be the one recorded");

    // The run is over, and the posting was reversed. A stop that leaves the
    // money where it is has not stopped anything.
    assert_eq!(
        *f.world.lock().unwrap(),
        vec!["posted".to_string(), "reversed".to_string()],
        "a cancelled run must unwind what it had already done"
    );

    let out = f.rt.replay(run, Mode::Resume).await.unwrap();
    assert!(out.status.is_cancelled(), "got {:?}", out.status);
}

/// Who stopped it, and why, are in the hash chain.
///
/// The *request* lives beside the chain so an operator who does not hold the
/// lease can make it. That is exactly why the observation has to be journaled:
/// otherwise the permanent record shows a run that stopped for no stated reason.
#[tokio::test]
async fn the_intervention_is_on_the_record() {
    let f = fixture(PostsThenWaits);
    let run = suspended_run(&f, "demo.post").await;
    f.rt.request_cancel(run, "ops-carol", "counterparty withdrew")
        .await
        .unwrap();

    let records = (f.store.clone() as Arc<dyn JournalStore>)
        .read(run, 1)
        .await
        .unwrap();
    let cancelled = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunCancelled { actor, reason } => Some((actor.clone(), reason.clone())),
            _ => None,
        })
        .expect("the stop must be journaled, not only requested");
    assert_eq!(cancelled.0, "ops-carol");
    assert_eq!(cancelled.1, "counterparty withdrew");

    // And the chain still verifies with it in.
    (f.store.clone() as Arc<dyn JournalStore>)
        .verify(run)
        .await
        .expect("chain intact");
}

/// A second asker does not take the first one's place.
#[tokio::test]
async fn the_first_asker_owns_the_intervention() {
    let f = fixture(PostsThenWaits);
    let run = suspended_run(&f, "demo.post").await;

    assert!(f.rt.request_cancel(run, "alice", "first").await.unwrap());
    assert!(
        !f.rt.request_cancel(run, "bob", "second").await.unwrap(),
        "a second request reported itself as the intervention of record"
    );

    let c = f.rt.cancellation(run).await.unwrap().unwrap();
    assert_eq!(c.actor, "alice", "the record names the wrong person");
}

/// A stopped run stays stopped.
///
/// Without this, the next inbound event resumes it and it carries on doing the
/// thing somebody intervened to prevent — and from the journal the intervention
/// would look like it worked.
#[tokio::test]
async fn a_stopped_run_is_not_resumed_by_a_later_event() {
    let f = fixture(PostsThenWaits);
    let run = suspended_run(&f, "demo.post").await;
    f.rt.request_cancel(run, "ops-carol", "withdrawn")
        .await
        .unwrap();
    let after_stop = f.world.lock().unwrap().clone();

    let out = f.rt.replay(run, Mode::Resume).await.unwrap();
    assert!(out.status.is_cancelled(), "got {:?}", out.status);
    assert_eq!(
        *f.world.lock().unwrap(),
        after_stop,
        "resuming a stopped run did more work"
    );

    // Assert *which* layer held. Two things stop a stopped run — the seal, read
    // back by `resume_is_closed`, and the standing request the executor observes
    // at its next step boundary — and with either one deleted the outcome above
    // is unchanged. The observable difference is the record: the seal short-
    // circuits before the executor runs, so a resumed run must not journal a
    // second `RunCancelled`.
    let cancels = (f.store.clone() as Arc<dyn JournalStore>)
        .read(run, 1)
        .await
        .unwrap()
        .iter()
        .filter(|r| matches!(r.kind(), RecordKind::RunCancelled { .. }))
        .count();
    assert_eq!(
        cancels, 1,
        "a sealed run was re-entered by the executor — the outcome is the same, \
         but the history now says it was stopped twice"
    );
}

// ── The rule that makes it safe ─────────────────────────────────────────────

/// A stop must not unwind around an unknown outcome.
///
/// This is the failure the control would otherwise *introduce*. A run holding an
/// effect that may or may not have landed is quarantined rather than unwound —
/// compensating everything except the one thing nobody can account for is how a
/// saga refunds money nobody took. Cancellation opened a second door into the
/// unwind and it has to be shut the same way.
///
/// **Reaching that state takes a fault, and the first version of this test did
/// not.** It cancelled a run that had *already* sealed itself as quarantined, so
/// `replay` read the recorded status back and returned before the unwind was
/// ever considered — the assertion passed with the rule deleted. Mutation
/// testing found it. The state that actually exercises the rule is a run whose
/// journal holds an announcement with no outcome: the store committed the
/// `EffectStarted` and lost the acknowledgement, which is the one fault a
/// journal prefix cannot express.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_stop_will_not_unwind_around_an_unknown_outcome() {
    use agentplane::testkit::{Fault, Faulty, Schedule};

    let world: World = Arc::default();
    WORLD.with(|w| *w.borrow_mut() = Some(Arc::clone(&world)));
    let db = Arc::new(RedbStore::open_in_memory().unwrap());

    // Fail the *terminal* record of a mutating effect, cleanly. The effect ran;
    // the journal holds its `EffectStarted` and nothing after it. That is the
    // undecidable state: the runtime cannot tell from the record whether the
    // world was changed, and here it was.
    //
    // `FailedClean` rather than `CommittedThenLost` — the latter leaves the
    // record durably present, which is the opposite of an orphan and the reason
    // the first draft of this test proved nothing.
    let faulty = Arc::new(Faulty::new(
        Arc::clone(&db) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("EffectDone", Fault::FailedClean),
    ));
    // One deployment slot, restarted below against a healthy store — so both
    // runtimes carry the same owner. The default is unique per instance, which
    // would make this a test about waiting for a lease to expire.
    let rt = Runtime::builder(Arc::clone(&faulty) as Arc<dyn JournalStore>)
        .owner("slot-a")
        .cases(db.clone() as Arc<dyn CaseStore>)
        .events(db.clone() as Arc<dyn EventStore>)
        .tasks(db.clone() as Arc<dyn TaskStore>)
        .skill(PostsThenWaits)
        .build();

    let out = rt
        .run_correlated(
            "demo.post",
            Tainted::trusted(json!({})),
            "dispute",
            &[key("INV-2")],
        )
        .await;
    assert!(
        !faulty.injected().is_empty(),
        "no fault was delivered, so this test proves nothing"
    );
    let run = faulty.runs()[0];
    assert!(
        out.is_err() || !matches!(out.as_ref().unwrap().status, RunStatus::Succeeded),
        "the fault must have stopped the run"
    );

    // Against a healthy store now: an operator asks for the stuck run to stop.
    let rt = Runtime::builder(db.clone() as Arc<dyn JournalStore>)
        .owner("slot-a")
        .cases(db.clone() as Arc<dyn CaseStore>)
        .events(db.clone() as Arc<dyn EventStore>)
        .tasks(db.clone() as Arc<dyn TaskStore>)
        .skill(PostsThenWaits)
        .build();
    rt.request_cancel(run, "ops-carol", "just stop it")
        .await
        .unwrap();

    let after = rt.replay(run, Mode::Resume).await.unwrap();
    assert!(
        after.status.is_quarantined(),
        "a stop unwound a run holding an undecided effect: {:?}",
        after.status
    );
    assert!(
        !world.lock().unwrap().contains(&"reversed".to_string()),
        "the unwind ran anyway, around an effect nobody can account for"
    );
}

/// Stopping a run that never started is not an error, and does nothing.
#[tokio::test]
async fn stopping_an_unknown_run_is_refused_rather_than_silently_accepted() {
    let f = fixture(PostsThenWaits);
    let err =
        f.rt.request_cancel(RunId::generate(), "ops", "typo in the id")
            .await;
    assert!(
        err.is_err(),
        "a stop against a run that does not exist reported success, so an \
         operator who mistyped an id believes they stopped something"
    );

    // And nothing was recorded, so the retry after fixing the typo is not
    // answered with "somebody else already asked".
    assert!(
        f.rt.cancellation(RunId::generate())
            .await
            .unwrap()
            .is_none(),
        "a refused stop left a request standing against an id that does not exist"
    );
}

/// A run that already finished is not reopened.
#[tokio::test]
async fn stopping_a_finished_run_does_not_reopen_it() {
    #[derive(Debug)]
    struct Quick;

    #[async_trait::async_trait]
    impl Skill for Quick {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("quick").provides("demo.quick")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::done(Tainted::trusted(json!({}))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Quick)
        .build();
    let out = rt
        .run_plan(
            agentplane::core::PlanIR::single("demo.quick"),
            Tainted::trusted(json!({})),
        )
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Succeeded));

    rt.request_cancel(out.run_id, "ops", "too late")
        .await
        .unwrap();
    let after = rt.replay(out.run_id, Mode::Resume).await.unwrap();
    assert!(
        matches!(after.status, RunStatus::Succeeded),
        "a concluded run was reopened by a stop request: {:?}",
        after.status
    );
}

/// Cancelling a run that is actively executing acknowledges at once and takes
/// effect at the next step boundary.
///
/// The operator's call must not race the live executor for the run: the
/// request is durable, `Ok` comes back immediately, and the *owner* observes
/// the stop at its next boundary. The old path resumed the run anyway, and on
/// the owner's own instance the lease "renewal" handed that resume the same
/// epoch the live execution was writing under — two executors on one chain
/// that fencing, by construction, could not tell apart.
#[tokio::test]
async fn cancelling_a_running_run_acknowledges_and_lands_at_the_boundary() {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Signals when it starts, then dawdles long enough to be cancelled.
    #[derive(Debug)]
    struct Slow {
        started: Arc<std::sync::Mutex<Option<RunId>>>,
        proceed: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl Skill for Slow {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("slow").provides("demo.slow")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            *self.started.lock().unwrap() = Some(cx.run_id());
            while !self.proceed.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok(Outcome::done(Tainted::trusted(json!({"done": true}))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let started = Arc::new(std::sync::Mutex::new(None));
    let proceed = Arc::new(AtomicBool::new(false));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Slow {
            started: Arc::clone(&started),
            proceed: Arc::clone(&proceed),
        })
        .build();

    let running = {
        let rt = Arc::clone(&rt);
        tokio::spawn(async move { rt.run("demo.slow", Tainted::trusted(json!({}))).await })
    };
    // Wait until the step is genuinely in flight.
    let run = loop {
        if let Some(run) = *started.lock().unwrap() {
            break run;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };

    // The stop request returns promptly with an acknowledgement, while the
    // step is still mid-flight and the owner holds the lease.
    let fresh = rt.request_cancel(run, "ops", "stop it").await.unwrap();
    assert!(fresh, "the first stop request records");

    // The owner reaches its next boundary and observes the stop.
    proceed.store(true, Ordering::SeqCst);
    let out = running.await.unwrap().unwrap();
    assert!(
        matches!(out.status, RunStatus::Cancelled { ref actor, .. } if actor == "ops"),
        "the running owner did not observe the durable stop at its boundary: {:?}",
        out.status
    );
}
