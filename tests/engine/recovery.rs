//! Crash recovery.
//!
//! The scenario the whole design exists for: a long run dies partway through,
//! and resuming it must **not** redo what it already did. A retry loop re-issues
//! the invoice. A durable runtime does not.

// These exercise the runtime end to end, which needs a store. Gated so
// `--no-default-features` still builds and tests cleanly: an embedder who
// brings their own backend must not be forced to compile SQLite.
#![cfg(feature = "redb")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{Outcome, Skill, SkillDescriptor, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// A fixed three-stage pipeline that can be made to die partway through.
///
/// `crash_at` stops the **same program** mid-flight, the way a `kill -9` would,
/// leaving a journal that is a genuine prefix of a complete run. That is what
/// makes resuming meaningful.
///
/// Note what this fixture deliberately does *not* offer: a knob that changes how
/// many stages the program has. Running a shorter program is not a crash
/// simulation — it is a different program, whose history is not a prefix of
/// anything, and resuming it is divergence rather than recovery.
#[derive(Debug)]
struct Pipeline {
    crash_at: Arc<AtomicUsize>,
    calls: Arc<[AtomicUsize; 4]>,
}

/// Sentinel meaning "do not crash".
const NO_CRASH: usize = usize::MAX;

const STAGES: usize = 3;

#[async_trait::async_trait]
impl Skill for Pipeline {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pipeline").provides("demo.pipeline")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let crash_at = self.crash_at.load(Ordering::SeqCst);
        for i in 0..STAGES {
            // Each stage is a distinct effect: distinct kind, distinct ordinal.
            let counter = Arc::new(AtomicUsize::new(0));
            cx.effect(Recorded::new(format!("stage-{i}")).counter(Arc::clone(&counter)))
                .await
                .map_err(agentplane::core::SkillError::Step)?;
            // Count only genuine invocations — a replayed effect never calls
            // `perform`, which is exactly the property under test.
            if counter.load(Ordering::SeqCst) > 0 {
                self.calls[i].fetch_add(1, Ordering::SeqCst);
            }
            if i == crash_at {
                return Err(agentplane::core::SkillError::Other(format!(
                    "simulated crash after stage {i}"
                )));
            }
        }
        Ok(Outcome::done(input))
    }
}

fn pipeline(crash_at: &Arc<AtomicUsize>, calls: &Arc<[AtomicUsize; 4]>) -> Pipeline {
    Pipeline {
        crash_at: Arc::clone(crash_at),
        calls: Arc::clone(calls),
    }
}

fn tally() -> Arc<[AtomicUsize; 4]> {
    Arc::new([
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ])
}

/// **The M1 property.** A run that died after stage 0 resumes at stage 1.
///
/// Stage 0 is performed exactly once *ever*, across the original run and the
/// resume. Stages 1 and 2 are performed exactly once, on the resume.
#[tokio::test]
async fn a_resumed_run_continues_instead_of_restarting() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(0));
    let calls = tally();

    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    // The run gets through stage 0, then the process dies.
    let first = rt.run("pipeline", json!({})).await.unwrap();
    assert!(matches!(first.status, RunStatus::Failed(_)));
    assert_eq!(calls[0].load(Ordering::SeqCst), 1, "stage 0 ran once");

    // The process comes back up. Same code, same program — just alive again.
    crash_at.store(NO_CRASH, Ordering::SeqCst);
    let resumed = rt.replay(first.run_id, Mode::Resume).await.unwrap();
    assert_eq!(resumed.status, RunStatus::Succeeded);

    assert_eq!(
        calls[0].load(Ordering::SeqCst),
        1,
        "stage 0 must NOT be performed again — this is the whole point"
    );
    assert_eq!(
        calls[1].load(Ordering::SeqCst),
        1,
        "stage 1 runs live on resume"
    );
    assert_eq!(
        calls[2].load(Ordering::SeqCst),
        1,
        "stage 2 runs live on resume"
    );
}

/// Resuming extends the same chain rather than starting a new history.
#[tokio::test]
async fn a_resumed_run_extends_the_existing_chain() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &tally()))
        .build();

    let first = rt.run("pipeline", json!({})).await.unwrap();
    let before = store.read(first.run_id, 1).await.unwrap().len();

    crash_at.store(NO_CRASH, Ordering::SeqCst);
    rt.replay(first.run_id, Mode::Resume).await.unwrap();

    let after = store.read(first.run_id, 1).await.unwrap();
    assert!(after.len() > before, "resume must append, not fork");
    store
        .verify(first.run_id)
        .await
        .expect("the extended chain still verifies");
}

/// Resuming repeatedly is safe: each resume replays everything already done and
/// performs only what is genuinely outstanding.
#[tokio::test]
async fn resuming_is_idempotent() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(1));
    let calls = tally();
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    let first = rt.run("pipeline", json!({})).await.unwrap();
    crash_at.store(NO_CRASH, Ordering::SeqCst);
    for _ in 0..4 {
        rt.replay(first.run_id, Mode::Resume).await.unwrap();
    }

    for (i, c) in calls.iter().enumerate().take(STAGES) {
        assert_eq!(c.load(Ordering::SeqCst), 1, "stage {i} ran exactly once");
    }
    store.verify(first.run_id).await.unwrap();
}

/// Resume works when the journal is a genuine *prefix* — including when the
/// interrupted program had more effects queued after the crash point.
///
/// The distinction that matters: a crash truncates history mid-program, so the
/// record is a prefix. A *code change* produces a different program, whose
/// history is not a prefix of anything — and that is divergence, not recovery.
#[tokio::test]
async fn resume_handles_a_crash_before_a_trailing_effect() {
    /// Stages, then a timestamp. The trailing clock read is what makes a naive
    /// "just run fewer stages" simulation wrong: it lands at a different
    /// ordinal, so the journal stops being a prefix.
    #[derive(Debug)]
    struct WithTrailer {
        crash_at: Arc<AtomicUsize>,
        calls: Arc<[AtomicUsize; 4]>,
    }

    #[async_trait::async_trait]
    impl Skill for WithTrailer {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("trailer").provides("demo.trailer")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            let crash_at = self.crash_at.load(Ordering::SeqCst);
            for i in 0..3 {
                let counter = Arc::new(AtomicUsize::new(0));
                cx.effect(Recorded::new(format!("stage-{i}")).counter(Arc::clone(&counter)))
                    .await
                    .map_err(agentplane::core::SkillError::Step)?;
                if counter.load(Ordering::SeqCst) > 0 {
                    self.calls[i].fetch_add(1, Ordering::SeqCst);
                }
                if i == crash_at {
                    return Err(agentplane::core::SkillError::Other("crash".into()));
                }
            }
            let at = cx.now().await.map_err(agentplane::core::SkillError::Step)?;
            Ok(Outcome::done(Tainted::trusted(
                json!({ "at": at.to_string() }),
            )))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(1));
    let calls = tally();
    let rt = Runtime::builder(store.clone())
        .skill(WithTrailer {
            crash_at: Arc::clone(&crash_at),
            calls: Arc::clone(&calls),
        })
        .build();

    let crashed = rt.run("trailer", json!({})).await.unwrap();
    assert!(matches!(crashed.status, RunStatus::Failed(_)));
    assert_eq!(calls[0].load(Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(Ordering::SeqCst), 1);
    assert_eq!(calls[2].load(Ordering::SeqCst), 0, "stage 2 never ran");

    // Process restarts; same code.
    crash_at.store(usize::MAX, Ordering::SeqCst);
    let resumed = rt.replay(crashed.run_id, Mode::Resume).await.unwrap();
    assert_eq!(resumed.status, RunStatus::Succeeded);

    assert_eq!(calls[0].load(Ordering::SeqCst), 1, "stage 0 not repeated");
    assert_eq!(calls[1].load(Ordering::SeqCst), 1, "stage 1 not repeated");
    assert_eq!(calls[2].load(Ordering::SeqCst), 1, "stage 2 ran once, live");
    store.verify(crashed.run_id).await.unwrap();
}

/// A rewritten skill registered under the same name — a code change, not a crash.
#[derive(Debug)]
struct Rewritten;

#[async_trait::async_trait]
impl Skill for Rewritten {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pipeline").provides("demo.pipeline")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        cx.effect(Recorded::new("completely-different"))
            .await
            .map_err(agentplane::core::SkillError::Step)?;
        Ok(Outcome::done(input))
    }
}

/// A journal from a *different program* is divergence, not something to resume.
#[tokio::test]
async fn resume_refuses_a_journal_written_by_different_code() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &tally()))
        .build();

    let recorded = rt.run("pipeline", json!({})).await.unwrap();

    // Not a crash — a rewrite. Stage 0 now does something else entirely.
    let changed = Runtime::builder(store.clone()).skill(Rewritten).build();
    let out = changed.replay(recorded.run_id, Mode::Resume).await.unwrap();

    match out.status {
        RunStatus::Quarantined(msg) => assert!(msg.contains("non-determinism"), "got: {msg}"),
        other => panic!("a rewritten program must not resume someone else's history: {other:?}"),
    }
}

/// A second instance may not seize a run whose owner is still alive.
///
/// Distinguishing this from being fenced matters operationally: a live lease
/// means "wait", a stale epoch means "you are a zombie, drop everything". A
/// single error for both would have operators retrying the one case that must
/// never be retried.
#[tokio::test]
async fn a_live_lease_blocks_takeover_and_says_so_precisely() {
    use agentplane::core::{RunId, StoreError};

    let store = RedbStore::open_in_memory().unwrap();
    let run = RunId::generate();

    store
        .acquire(run, "instance-a", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    let err = store
        .acquire(run, "instance-b", std::time::Duration::from_mins(1))
        .await
        .unwrap_err();

    match err {
        StoreError::LeaseHeld {
            owner,
            remaining_secs,
            ..
        } => {
            assert_eq!(owner, "instance-a");
            assert!(
                remaining_secs > 0,
                "the caller needs to know how long to wait"
            );
        }
        other => panic!("expected a lease conflict, not a fencing error: {other:?}"),
    }

    // The owner can always renew without bumping its own epoch.
    let renewed = store
        .acquire(run, "instance-a", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    assert_eq!(
        renewed.epoch, 1,
        "renewal must not advance the fencing epoch"
    );
}

/// An effect that started but never finished is *not* silently retried when its
/// declared recovery mode forbids guessing.
///
/// A crash between "sent the request" and "recorded the answer" is undecidable
/// from the journal. For a mutating effect the safe answer is a human, and the
/// runtime says so instead of rolling the dice with someone's ledger.
#[tokio::test]
async fn an_orphaned_mutating_effect_is_quarantined_not_retried() {
    use agentplane::core::{EffectDescriptor, EffectKey, Recovery, RunId, StepId};
    use agentplane::journal::{Append, RecordKind};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let run = RunId::generate();
    let plan = agentplane::core::PlanIR::single("demo.pipeline");
    let lease = store
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .unwrap();

    // Hand-build a journal that stops mid-effect, which is exactly the shape a
    // `kill -9` between send and record leaves behind.
    let descriptor = EffectDescriptor::new("test.stage-0", json!(null));
    let key = EffectKey::for_effect(
        StepId(0),
        agentplane::core::Phase::Forward,
        0,
        1,
        &descriptor,
    );

    store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        agent: "demo.pipeline".into(),
                        input: json!({}),
                        policy: None,
                    },
                ),
                // Replay reads the plan back from history rather than
                // recompiling it, so a journal without one cannot be replayed —
                // there would be nothing saying what the run was meant to do.
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        digest: plan.digest(),
                        steps: vec!["demo.pipeline".into()],
                        plan: serde_json::to_value(&plan).unwrap(),
                    },
                ),
                Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: "pipeline".into(),
                    },
                )
                .step(StepId(0)),
                Append::new(
                    run,
                    RecordKind::EffectStarted {
                        descriptor,
                        attempt: 1,
                        backoff_ms: 0,
                        recovery: Recovery::RequiresOperator,
                        mutates: true,
                    },
                )
                .step(StepId(0))
                .effect(key),
            ],
        )
        .await
        .unwrap();

    // Same instance identity as the lease above: this is one process restarting
    // after a crash, which is the realistic recovery path. A *different*
    // instance would have to wait out the lease first.
    let calls = tally();
    let no_crash = Arc::new(AtomicUsize::new(NO_CRASH));
    let rt = Runtime::builder(store.clone())
        .owner("test")
        .skill(pipeline(&no_crash, &calls))
        .build();

    let out = rt.replay(run, Mode::Resume).await.unwrap();

    match out.status {
        RunStatus::Quarantined(msg) => {
            assert!(msg.contains("quarantined"), "got: {msg}");
        }
        other => panic!("an undecidable mutation must not be guessed at, got {other:?}"),
    }
    assert_eq!(
        calls[0].load(Ordering::SeqCst),
        0,
        "the effect must not be re-performed behind the operator's back"
    );
}

/// Resuming a run that already finished is a no-op that returns the recorded
/// outcome.
///
/// Without this, resuming a *completed* run re-executes it — and any work that
/// is not an effect (a case-state write, an outbound notification recorded
/// elsewhere) happens a second time. It is the same class of bug the effect
/// protocol exists to prevent, arriving through a side door: the replay cursor
/// is exhausted from the first instruction, so every step looks live.
#[tokio::test]
async fn resuming_a_finished_run_does_not_re_execute_it() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(NO_CRASH));
    let calls = tally();
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    let done = rt.run("pipeline", json!({})).await.unwrap();
    let records_before = store.read(done.run_id, 1).await.unwrap().len();

    let resumed = rt.replay(done.run_id, Mode::Resume).await.unwrap();
    assert_eq!(
        resumed.status,
        RunStatus::Succeeded,
        "the recorded outcome is returned"
    );

    let records_after = store.read(done.run_id, 1).await.unwrap().len();
    assert_eq!(
        records_before, records_after,
        "resuming a finished run must append nothing"
    );
    for c in calls.iter().take(STAGES) {
        assert_eq!(c.load(Ordering::SeqCst), 1);
    }
}
