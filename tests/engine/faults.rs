//! Store faults that a truncated journal cannot express.
//!
//! `tests/simulation.rs` sweeps crash points by truncating history, which covers
//! every clean cut. This file covers the unclean one: **the write committed and
//! the caller was told it failed.** A connection dropped after `COMMIT`, a
//! process killed between the commit and the syscall returning, a proxy timing
//! out a request the database went on to apply.
//!
//! It is the store-level twin of the in-doubt effect the specs model at the
//! world level, and it is the state a prefix sweep provably cannot reach — a
//! prefix is always a point where everything before it happened and everything
//! after it did not. Here the journal is *ahead* of what the process believes it
//! wrote.
//!
//! Every test asserts the fault was actually delivered before asserting on
//! behaviour, because a fault-injection test that injected nothing passes for
//! the wrong reason and the assertions do not show it.

#![cfg(all(feature = "turso", feature = "testkit"))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    ArgSource, Compensation, Effect, EffectDescriptor, EffectError, Outcome, PlanIR, PlanNode,
    Recovery, RetryPolicy, Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime};
use agentplane::store::TursoStore;
use agentplane::testkit::{Fault, Faulty, Schedule, assert_replay_was_not_backstopped};
use serde_json::{Value, json};

/// Every performance of an externally visible effect, in order.
type World = Arc<Mutex<Vec<String>>>;

#[derive(Debug, Clone)]
struct Charge {
    world: World,
}

#[async_trait::async_trait]
impl Effect for Charge {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("fault.charge", json!({}))
    }
    fn mutates(&self) -> bool {
        true
    }
    /// Declared safe to repeat. The harder case on purpose: the runtime must
    /// achieve exactly-once rather than decline to decide.
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.lock().unwrap().push("charged".into());
        Ok(json!({ "ok": true }))
    }
}

#[derive(Debug)]
struct Charger {
    world: World,
}

#[async_trait::async_trait]
impl Skill for Charger {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("charge").provides("charge")
    }
    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }
    async fn invoke(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Charge {
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "charged": true }))))
    }
    async fn compensate(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _o: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Charge {
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(())
    }
}

fn plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "charge")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ])
}

async fn store() -> Arc<TursoStore> {
    Arc::new(TursoStore::open_in_memory().await.unwrap())
}

fn runtime(store: Arc<dyn JournalStore>, world: &World) -> Runtime {
    Runtime::builder(store)
        .owner("faults")
        .skill(Charger {
            world: Arc::clone(world),
        })
        .build()
}

/// The cardinal case: the record of a performed effect is durable, and the
/// process that performed it was told the write failed.
///
/// A resumed run must read that record back and leave the world alone. The
/// failure this rules out is the expensive one — the charge goes out twice
/// because the first one "didn't get recorded".
#[tokio::test]
async fn a_committed_but_lost_effect_record_is_not_performed_again() {
    let db = store().await;
    let world: World = Arc::default();

    // Fail the append that records the effect's completion — after it commits.
    let faulty = Arc::new(Faulty::new(
        Arc::clone(&db) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("EffectDone", Fault::CommittedThenLost),
    ));

    let first = runtime(Arc::clone(&faulty) as Arc<dyn JournalStore>, &world)
        .run_plan(plan(), json!({}))
        .await;

    assert_replay_was_not_backstopped("live run under a lost commit", &first);
    assert_eq!(
        faulty.injected(),
        vec![(faulty.injected()[0].0, Fault::CommittedThenLost)],
        "the fault must actually have been delivered, or this test proves nothing"
    );
    assert!(
        first.is_err() || !matches!(first.as_ref().unwrap().status, RunStatus::Succeeded),
        "a store that reports failure must not yield a successful run"
    );
    assert_eq!(
        world.lock().unwrap().len(),
        1,
        "the effect ran once before the store lost the caller"
    );

    // The record is durably present despite the error the writer saw. That is
    // the whole point of this fault, and the rest of the test is meaningless if
    // it is not true.
    let run = faulty.runs()[0];
    let records = db.read(run, 1).await.unwrap();
    assert!(
        records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::EffectDone { .. })),
        "the write committed, so the journal must hold it even though the \
         caller got an error"
    );

    // Now resume against a healthy store: replay must read the effect back.
    let resumed = runtime(Arc::clone(&db) as Arc<dyn JournalStore>, &world)
        .replay(run, Mode::Resume)
        .await;

    // Checked before the world, because the world is clean either way: if
    // replay stopped reading effects back, the store's unique index blocks the
    // re-announcement and nothing reaches the world. The run then merely
    // "failed", and a world-shaped assertion sees success.
    assert_replay_was_not_backstopped("resume after a lost commit", &resumed);
    assert_eq!(
        *world.lock().unwrap(),
        vec!["charged".to_string()],
        "the effect was journaled, so replay must read it back — performing it \
         again is the duplicate charge this whole design exists to prevent"
    );
    assert!(resumed.is_ok(), "resume failed: {:?}", resumed.err());
    db.verify(run).await.expect("chain intact after the fault");
}

/// The announcement commits and is lost. The world was never touched, but the
/// journal says an effect started — so recovery must treat it as in doubt
/// rather than as done, and rather than as never attempted.
#[tokio::test]
async fn a_committed_but_lost_announcement_leaves_a_resolvable_orphan() {
    let db = store().await;
    let world: World = Arc::default();

    let faulty = Arc::new(Faulty::new(
        Arc::clone(&db) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("EffectStarted", Fault::CommittedThenLost),
    ));

    let first = runtime(Arc::clone(&faulty) as Arc<dyn JournalStore>, &world)
        .run_plan(plan(), json!({}))
        .await;

    assert!(!faulty.injected().is_empty(), "no fault was delivered");
    assert!(
        first.is_err() || !matches!(first.as_ref().unwrap().status, RunStatus::Succeeded),
        "the run must not report success"
    );
    assert!(
        world.lock().unwrap().is_empty(),
        "the announcement failed, so nothing should have been performed"
    );

    let run = faulty.runs()[0];
    let records = db.read(run, 1).await.unwrap();
    assert!(
        records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::EffectStarted { .. })),
        "the announcement committed, so it must be in the journal"
    );

    // An orphan: started, never finished, world state unknown to the runtime.
    // `Recovery::Retry` declares repeating safe, so resume completes it — and
    // exactly once.
    let resumed = runtime(Arc::clone(&db) as Arc<dyn JournalStore>, &world)
        .replay(run, Mode::Resume)
        .await
        .expect("an orphan declared safe to repeat must be resolvable");

    assert!(
        matches!(resumed.status, RunStatus::Succeeded),
        "status: {:?}",
        resumed.status
    );
    assert_eq!(
        *world.lock().unwrap(),
        vec!["charged".to_string()],
        "the orphan is retried once — not skipped as done, not performed twice"
    );
    db.verify(run).await.expect("chain intact after the fault");
}

/// A clean failure is the benign case, and it must stay benign: nothing written,
/// so a resume starts the effect for the first time.
///
/// Present so the suite can tell "survived a fault" from "the fault was a no-op".
#[tokio::test]
async fn a_clean_append_failure_leaves_no_trace() {
    let db = store().await;
    let world: World = Arc::default();

    let faulty = Arc::new(Faulty::new(
        Arc::clone(&db) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("EffectStarted", Fault::FailedClean),
    ));

    let first = runtime(Arc::clone(&faulty) as Arc<dyn JournalStore>, &world)
        .run_plan(plan(), json!({}))
        .await;

    assert!(!faulty.injected().is_empty(), "no fault was delivered");
    assert!(
        first.is_err() || !matches!(first.as_ref().unwrap().status, RunStatus::Succeeded),
        "the run must not report success"
    );

    let run = faulty.runs()[0];
    let records = db.read(run, 1).await.unwrap();
    assert!(
        !records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::EffectStarted { .. })),
        "a clean failure writes nothing — this is what distinguishes it from \
         CommittedThenLost, and if it fails here the two faults are the same \
         fault and one of them is testing nothing"
    );
    assert!(world.lock().unwrap().is_empty());

    let resumed = runtime(Arc::clone(&db) as Arc<dyn JournalStore>, &world)
        .replay(run, Mode::Resume)
        .await
        .expect("nothing was written, so there is nothing to be confused by");

    assert!(matches!(resumed.status, RunStatus::Succeeded));
    assert_eq!(*world.lock().unwrap(), vec!["charged".to_string()]);
    db.verify(run).await.expect("chain intact");
}

/// A fenced writer must not be able to keep appending.
///
/// The fault models the pause fencing exists for: this instance stalled, its
/// lease expired, someone else took the run. Whatever the runtime does next, it
/// must not be "write anyway".
#[tokio::test]
async fn a_fenced_append_stops_the_run_rather_than_forcing_the_write() {
    let db = store().await;
    let world: World = Arc::default();

    let faulty = Arc::new(Faulty::new(
        Arc::clone(&db) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("EffectStarted", Fault::Fenced),
    ));

    let out = runtime(Arc::clone(&faulty) as Arc<dyn JournalStore>, &world)
        .run_plan(plan(), json!({}))
        .await;

    assert!(!faulty.injected().is_empty(), "no fault was delivered");
    assert!(
        out.is_err() || !matches!(out.as_ref().unwrap().status, RunStatus::Succeeded),
        "a fenced writer must never produce a successful run"
    );
    assert!(
        world.lock().unwrap().is_empty(),
        "a fenced writer must not perform effects — it no longer owns the run"
    );
    db.verify(faulty.runs()[0]).await.expect("chain intact");
}

/// The schedule itself is deterministic: the same seed fails in the same place.
///
/// Without this, a failing schedule is not a reproduction artifact and the whole
/// approach reduces to flaky tests with extra machinery.
#[tokio::test]
async fn the_same_seed_injects_the_same_faults() {
    let mut runs = Vec::new();
    for _ in 0..2 {
        let db = store().await;
        let world: World = Arc::default();
        let faulty = Arc::new(Faulty::new(
            db as Arc<dyn JournalStore>,
            Schedule::seeded(0xDEAD_BEEF).every(3, Fault::FailedClean),
        ));
        let _ = runtime(Arc::clone(&faulty) as Arc<dyn JournalStore>, &world)
            .run_plan(plan(), json!({}))
            .await;
        runs.push(faulty.injected());
    }
    assert!(
        !runs[0].is_empty(),
        "the seeded schedule injected nothing, so this proves nothing"
    );
    assert_eq!(
        runs[0], runs[1],
        "the same seed must fail at the same call ordinals, or a failing \
         schedule is not reproducible"
    );
}
