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
            let arguments = Tainted::trusted(Value::Null);
            cx.sink(
                Recorded::new(format!("stage-{i}")).counter(Arc::clone(&counter)),
                &arguments,
            )
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
    let first = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
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

/// A failed run is open: findable, resumable, and **not** in the Merkle log.
///
/// Failure is a conclusion, not a closure. It is indexed — whoever clears
/// failures can find it — but no leaf is published for it, because a resume is
/// permitted to grow the history and a checkpoint must never attest a prefix
/// of a run that keeps moving. When the resume succeeds, the run moves out of
/// the failed listing, into the succeeded one, and only then seals. An index
/// that kept the first conclusion would list this run as failed for the rest
/// of its life — a backlog page that never drains.
#[tokio::test]
async fn a_failed_run_is_findable_open_and_moves_on_resume() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(0));
    let calls = tally();
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    let first = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(first.status, RunStatus::Failed(_)));

    let failed = store.runs_by_outcome("failed", 10).await.unwrap();
    assert!(
        failed.contains(&first.run_id),
        "a failed run must be findable by whoever clears failures"
    );
    assert!(
        store.inclusion_proof(first.run_id).await.unwrap().is_none(),
        "a failed run entered the Merkle log — the checkpoint now attests a \
         prefix of a history its own resume is permitted to grow"
    );

    crash_at.store(NO_CRASH, Ordering::SeqCst);
    let resumed = rt.replay(first.run_id, Mode::Resume).await.unwrap();
    assert_eq!(resumed.status, RunStatus::Succeeded);

    assert!(
        !store
            .runs_by_outcome("failed", 10)
            .await
            .unwrap()
            .contains(&first.run_id),
        "a run that later succeeded is still listed as failed — the backlog \
         page never drains, and a wrong answer reads exactly like a right one"
    );
    assert!(
        store
            .runs_by_outcome("succeeded", 10)
            .await
            .unwrap()
            .contains(&first.run_id),
        "the re-conclusion did not move the run into the succeeded listing"
    );
    assert!(
        store.inclusion_proof(first.run_id).await.unwrap().is_some(),
        "the terminal conclusion did not seal — the run never entered the log"
    );
}

/// A recorded ending this build does not recognise refuses to resume.
///
/// Fail closed: `swept`, a future outcome, a corrupted string — an unknown
/// conclusion is not permission to continue. Only `failed` and `exhausted`
/// resume, because those are the two a resume can honestly answer; everything
/// else, known or unknown, stays ended.
#[tokio::test]
async fn an_unrecognised_recorded_outcome_refuses_resume() {
    use agentplane::journal::{Append, RecordKind};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(0));
    let calls = tally();
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    // A real journal whose run is still open (failure does not seal), with an
    // ending appended that this build has no rule for.
    let first = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(first.status, RunStatus::Failed(_)));
    let run = first.run_id;
    let lease = store
        .acquire(run, "test", std::time::Duration::from_secs(30))
        .await
        .unwrap();
    store
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunConcluded {
                    outcome: "swept".to_owned(),
                    chain_head: agentplane::core::Digest::ZERO,
                    reason: None,
                    exhaustion: None,
                    live_spend: agentplane::core::Spend::default(),
                },
            )],
        )
        .await
        .unwrap();
    store.release_lease(run, lease.epoch).await.unwrap();

    crash_at.store(NO_CRASH, Ordering::SeqCst);
    let out = rt.replay(run, Mode::Resume).await.unwrap();
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "an outcome this build does not recognise was treated as resumable — \
         continuing would graft new behaviour onto a history that says it \
         ended: {:?}",
        out.status
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

    let first = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
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

    let first = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
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
                let arguments = Tainted::trusted(Value::Null);
                cx.sink(
                    Recorded::new(format!("stage-{i}")).counter(Arc::clone(&counter)),
                    &arguments,
                )
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

    let crashed = rt
        .run("trailer", Tainted::trusted(json!({})))
        .await
        .unwrap();
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
        let arguments = Tainted::trusted(Value::Null);
        cx.sink(Recorded::new("completely-different"), &arguments)
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
    // Both runtimes share an owner on purpose: this models **one deployment
    // slot** being redeployed, not two live instances racing. The lease owner
    // identifies a process, so leaving it to the default would make this a test
    // about lease expiry instead of about divergence.
    let rt = Runtime::builder(store.clone())
        .owner("slot-a")
        .skill(pipeline(&crash_at, &tally()))
        .build();

    let recorded = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();

    // Not a crash — a rewrite. Stage 0 now does something else entirely.
    let changed = Runtime::builder(store.clone())
        .owner("slot-a")
        .skill(Rewritten)
        .build();
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

    // The owner renews through `renew`, which keeps the epoch — and never
    // through `acquire`, which is a pure claim and refuses even the owner:
    // handing a second entry point on the same instance the live epoch is two
    // executors fencing cannot tell apart.
    let renewed = store
        .renew(run, "instance-a", 1, std::time::Duration::from_mins(1))
        .await
        .unwrap();
    assert_eq!(
        renewed.epoch, 1,
        "renewal must not advance the fencing epoch"
    );
    assert!(
        matches!(
            store
                .acquire(run, "instance-a", std::time::Duration::from_mins(1))
                .await,
            Err(StoreError::LeaseHeld { .. })
        ),
        "acquire renewed the caller's own held lease — a claim and a renewal \
         are different operations, and conflating them is how a heartbeat \
         resurrects a released lease"
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
                        capability: "demo.pipeline".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: agentplane::core::Label::trusted(),
                        policy_bundle: None,
                        canon: agentplane::core::canon::VERSION,
                        idempotency_key: None,
                    },
                ),
                // Replay reads the plan back from history rather than
                // recompiling it, so a journal without one cannot be replayed —
                // there would be nothing saying what the run was meant to do.
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
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
                        outbound_label: None,
                    },
                )
                .step(StepId(0))
                .effect(key),
            ],
        )
        .await
        .unwrap();

    // The crashed process's lease is claimable, not renewable — `acquire` is
    // a pure claim, so even the same instance waits out (or, here, releases)
    // the lease it lost. What matters to this test is what the *resume* does
    // with the orphaned effect, not who performs it.
    store.release_lease(run, lease.epoch).await.unwrap();
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

// ── An orphan whose re-performance fails ────────────────────────────────────
//
// `resolve_orphan` re-performs an interrupted `Recovery::Retry` effect under
// its original key. When that re-performance *fails*, the failure must travel
// through the same disposition machinery a live failure does — an in-doubt
// failure on a mutating effect is an operator's question, not a plain `Failed`
// that unwinds. An earlier version collapsed it to a step failure inside
// `resolve_orphan`, which skipped the classifier entirely.

/// A ledger posting: mutating, declared safe to re-perform, and switchable to
/// time out — so the re-performance of a crash orphan can be made to fail with
/// the outcome unknown.
#[derive(Debug)]
struct FlakyPost {
    attempts: Arc<AtomicUsize>,
    times_out: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl agentplane::core::Effect for FlakyPost {
    type Output = Value;
    fn descriptor(&self) -> agentplane::core::EffectDescriptor {
        agentplane::core::EffectDescriptor::new("ledger.post", json!(null))
    }
    fn mutates(&self) -> bool {
        true
    }
    fn recovery(&self) -> agentplane::core::Recovery {
        agentplane::core::Recovery::Retry
    }
    /// One attempt: the test is about what a *final* in-doubt failure means,
    /// and further attempts would only defer that question.
    fn retry(&self) -> agentplane::core::RetryPolicy {
        agentplane::core::RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, agentplane::core::EffectError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.times_out.load(Ordering::SeqCst) {
            return Err(agentplane::core::EffectError::Timeout {
                driver: "ledger".into(),
                waited_ms: 5,
            });
        }
        Ok(json!({ "posted": true }))
    }
}

/// A step that mutates and knows how to take it back, so the tests below can
/// tell "did not compensate" from "had nothing to compensate".
#[derive(Debug)]
struct Prepares {
    undone: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Prepares {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("prepare").provides("demo.prepare")
    }
    fn compensation(&self) -> agentplane::core::Compensation {
        agentplane::core::Compensation::Compensatable
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let arguments = Tainted::trusted(Value::Null);
        cx.sink(Recorded::new("prepare"), &arguments).await?;
        Ok(Outcome::done(input))
    }
    async fn compensate(
        &self,
        _cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), agentplane::core::SkillError> {
        self.undone.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// The posting step, holding the switchable effect.
#[derive(Debug)]
struct Posts {
    attempts: Arc<AtomicUsize>,
    times_out: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl Skill for Posts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("post").provides("demo.post")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        cx.effect(FlakyPost {
            attempts: Arc::clone(&self.attempts),
            times_out: Arc::clone(&self.times_out),
        })
        .await?;
        Ok(Outcome::done(input))
    }
}

fn prepare_then_post() -> agentplane::core::PlanIR {
    use agentplane::core::{ArgSource, PlanIR, PlanNode, StepId};
    PlanIR::new(vec![
        PlanNode::new(0, "demo.prepare").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "demo.post")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ])
}

/// Run the two-step plan to completion, then rebuild its journal truncated
/// right after the posting effect's announcement — the exact shape a `kill -9`
/// between "sent the request" and "recorded the answer" leaves behind.
///
/// Returns the rebuilt store and the run id. The truncation approach comes
/// from `tests/engine/simulation.rs`: every prefix of an append-only journal
/// is a crash that could have happened.
async fn crashed_mid_post() -> (Arc<RedbStore>, agentplane::core::RunId) {
    use agentplane::journal::{Append, RecordKind};

    let origin = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(origin.clone())
        .owner("origin")
        .skill(Prepares {
            undone: Arc::new(AtomicUsize::new(0)),
        })
        .skill(Posts {
            attempts: Arc::new(AtomicUsize::new(0)),
            times_out: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
        .build();
    let done = rt
        .run_plan(prepare_then_post(), Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(done.status, RunStatus::Succeeded, "the fixture run works");

    let records = origin.read(done.run_id, 1).await.unwrap();
    let cut = records
        .iter()
        .position(|r| {
            matches!(
                r.kind(),
                RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == "ledger.post"
            )
        })
        .expect("the posting effect was announced")
        + 1;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let lease = store
        .acquire(done.run_id, "rebuild", std::time::Duration::from_mins(5))
        .await
        .unwrap();
    for r in &records[..cut] {
        let mut a = Append::new(done.run_id, r.kind().clone()).phase(r.body.phase);
        if let Some(s) = r.body.step {
            a = a.step(s);
        }
        if let Some(c) = r.body.case {
            a = a.case(c);
        }
        if let Some(k) = r.effect_key() {
            a = a.effect(k);
        }
        store.append(lease.epoch, vec![a]).await.unwrap();
    }
    store.release_lease(done.run_id, lease.epoch).await.unwrap();
    (store, done.run_id)
}

/// An orphan whose re-performance fails in doubt is classified, not flattened.
///
/// The resume finds the posting effect announced with no terminal record and —
/// `Recovery::Retry` — re-performs it. The re-performance times out, which is
/// `InDoubt`, and the effect mutates: the disposition classifier's verdict for
/// a final unknown on a mutating call is an operator's question. The run must
/// therefore quarantine *with that diagnosis*. The message assertion is
/// load-bearing: flattening the failure inside `resolve_orphan` would nowadays
/// still quarantine — the failure unwind refuses to compensate around the
/// in-doubt record — but with the unwind's message, after taking the wrong
/// path; and with both regressions in place the run reads `Failed` and the
/// unwind compensates the prepared step around a posting that may have landed.
#[tokio::test]
async fn an_orphan_whose_reperformance_fails_in_doubt_is_classified_not_flattened() {
    let (store, run) = crashed_mid_post().await;

    let undone = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone())
        .owner("resumer")
        .skill(Prepares {
            undone: Arc::clone(&undone),
        })
        .skill(Posts {
            attempts: Arc::clone(&attempts),
            times_out: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        })
        .build();

    let out = rt.replay(run, Mode::Resume).await.unwrap();

    match &out.status {
        RunStatus::Quarantined(msg) => assert!(
            msg.contains("attempts exhausted"),
            "quarantined, but not by the disposition classifier — the failed \
             re-performance took a different path than a live failure: {msg}"
        ),
        other => panic!(
            "a mutating orphan whose re-performance ended in doubt must be an \
             operator's question, got {other:?}"
        ),
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the orphan is re-performed exactly once — a retry after doubt would \
         be a second real performance"
    );
    assert_eq!(
        undone.load(Ordering::SeqCst),
        0,
        "no compensation may run around a call whose outcome is unknown"
    );
    let compensated = store
        .read(run, 1)
        .await
        .unwrap()
        .iter()
        .filter(|r| r.kind().kind_str() == "StepCompensated")
        .count();
    assert_eq!(compensated, 0, "the journal must record no unwind either");
}

/// The positive half: the same crash shape, and the re-performance succeeds.
///
/// The orphan is re-performed under its original announcement — exactly one
/// `EffectStarted` for the posting effect, ever — and the run completes. This
/// is what proves the fixture above models a recoverable crash rather than a
/// broken journal; `resuming_is_idempotent` covers the wider property that
/// repeated resumes stay safe.
#[tokio::test]
async fn an_orphan_whose_reperformance_succeeds_resumes_to_success() {
    let (store, run) = crashed_mid_post().await;

    let undone = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone())
        .owner("resumer")
        .skill(Prepares {
            undone: Arc::clone(&undone),
        })
        .skill(Posts {
            attempts: Arc::clone(&attempts),
            times_out: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
        .build();

    let out = rt.replay(run, Mode::Resume).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the interrupted attempt is resumed as one performance"
    );
    assert_eq!(
        undone.load(Ordering::SeqCst),
        0,
        "nothing unwinds on success"
    );

    let records = store.read(run, 1).await.unwrap();
    let announcements = records
        .iter()
        .filter(|r| {
            matches!(
                r.kind(),
                agentplane::journal::RecordKind::EffectStarted { descriptor, .. }
                    if descriptor.kind == "ledger.post"
            )
        })
        .count();
    assert_eq!(
        announcements, 1,
        "the resumed attempt reuses the announcement already in the journal — \
         a second one would report one interrupted call as two"
    );
    store.verify(run).await.unwrap();
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

    let done = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
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

/// Two runtimes never share a lease owner.
///
/// The owner is a **process-instance** identity, and the store renews a lease
/// *without bumping the epoch* when the holder is the same owner. So two
/// instances sharing an owner string each read the other's lease as their own:
/// no fencing, no epoch bump, two writers on one run — the exact situation the
/// epoch exists to make impossible.
///
/// This was real twice over. The default was the constant `"agentplane"`, which
/// every replica and every restart used; and wiring a manifest set the owner to
/// the *agent's name*, which every replica of that agent would then share.
/// Neither showed up in any test, because nothing had ever asked.
#[tokio::test]
async fn two_runtimes_do_not_share_a_lease_owner() {
    use agentplane::core::{RunId, StoreError};
    use agentplane::journal::JournalStore;
    use agentplane::runtime::Runtime;
    use std::sync::Arc;

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().unwrap());
    let a = Runtime::builder(Arc::clone(&store)).build();
    let b = Runtime::builder(Arc::clone(&store)).build();

    // A run held by one instance must be *refused* to the other while live,
    // rather than silently renewed as if it were the same process.
    let run = RunId::generate();
    store
        .acquire(run, a.owner_id(), std::time::Duration::from_mins(1))
        .await
        .expect("first instance takes the lease");

    match store
        .acquire(run, b.owner_id(), std::time::Duration::from_mins(1))
        .await
    {
        Err(StoreError::LeaseHeld { owner, .. }) => {
            assert_eq!(owner, a.owner_id(), "the wrong instance is named as holder");
        }
        Err(other) => panic!("expected a lease conflict: {other:?}"),
        Ok(_) => panic!(
            "a second runtime renewed the first one's lease without fencing it — \
             both would now write to this run under one epoch"
        ),
    }

    // The refusal above cannot tell two owners apart on its own: `acquire` is
    // a pure claim, so it refuses a live lease *whoever* asks, and it would
    // refuse identically if both instances answered to one name. `renew` is
    // where a shared identity does its damage — it extends a lease for the
    // owner that holds it, so a second instance wearing the same name renews
    // a run it does not own and both write under one epoch, which is the
    // split-brain the fence exists to prevent.
    let held = store
        .acquire(
            RunId::generate(),
            a.owner_id(),
            std::time::Duration::from_mins(1),
        )
        .await
        .expect("a fresh run is free");
    match store
        .renew(
            held.run,
            b.owner_id(),
            held.epoch,
            std::time::Duration::from_mins(1),
        )
        .await
    {
        // `LeaseNotHeld` rather than `LeaseHeld`: the question renewal asks is
        // whether *this* caller holds the lease, and a stranger does not.
        Err(StoreError::LeaseNotHeld { .. }) => {}
        Err(other) => panic!("expected a refusal to renew: {other:?}"),
        Ok(_) => panic!(
            "a second runtime renewed a lease it does not hold — the two \
             instances answer to one owner name, so the fence cannot tell them \
             apart and both write to this run under one epoch"
        ),
    }

    // The positive half: the holder's own renewal still works, so the refusal
    // above is about identity and not about renewal being broken outright.
    store
        .renew(
            held.run,
            a.owner_id(),
            held.epoch,
            std::time::Duration::from_mins(1),
        )
        .await
        .expect("the holder must be able to renew its own lease");
}

/// Wiring a manifest does not make replicas of one agent share an owner.
#[cfg(feature = "manifest")]
#[tokio::test]
async fn a_manifest_does_not_become_the_lease_owner() {
    use agentplane::journal::JournalStore;
    use agentplane::manifest::Manifest;
    use agentplane::runtime::Runtime;
    use std::sync::Arc;

    const AGENT: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: shared-agent, version: "1.0.0" }
spec:
  budgets: {}
"#;
    let m = Manifest::parse(AGENT).expect("parse");
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().unwrap());

    let a = Runtime::builder(Arc::clone(&store))
        .agent(agentplane::runtime::Agent::new(&m))
        .build();
    let b = Runtime::builder(Arc::clone(&store))
        .agent(agentplane::runtime::Agent::new(&m))
        .build();

    assert_ne!(
        a.owner_id(),
        b.owner_id(),
        "two replicas of one agent share a lease owner, so each would renew the \
         other's lease without bumping the epoch"
    );
    assert_ne!(
        a.owner_id(),
        "shared-agent",
        "the agent's name became the instance identity — an agent's name is not \
         a process, and several instances of one agent are normal"
    );
}

/// A run that takes longer than its lease is not taken away from it.
///
/// The lease exists to answer "is this owner dead?", and it answers it by
/// expiry. A live run that never renews therefore looks dead the moment its TTL
/// passes — and agent runs routinely take longer than a lease does, since a
/// single model call can. Another instance then acquires the run, bumps the
/// epoch, and the healthy original is fenced on its next append: killed mid
/// flight, having done real work, for the crime of being slow.
///
/// So the runtime heartbeats while it executes. The TTL then bounds how long a
/// *crashed* owner strands its runs, which is what it is for, rather than how
/// long a run may take, which it should never have bounded.
#[tokio::test]
async fn a_long_run_keeps_its_lease() {
    use std::time::Duration;

    use agentplane::core::StoreError;

    /// Sleeps past the lease, recording its run id so the test can race it.
    #[derive(Debug)]
    struct Slow {
        run: Arc<std::sync::Mutex<Option<agentplane::core::RunId>>>,
        naps: Duration,
    }

    #[async_trait::async_trait]
    impl Skill for Slow {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("slow").provides("slow")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            *self.run.lock().unwrap() = Some(cx.run_id());
            tokio::time::sleep(self.naps).await;
            Ok(Outcome::done(Tainted::trusted(json!({"ok": true}))))
        }
    }

    let ttl = Duration::from_secs(2);
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let seen = Arc::new(std::sync::Mutex::new(None));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("instance-a")
        .lease_ttl(ttl)
        .skill(Slow {
            run: seen.clone(),
            naps: ttl * 3,
        })
        .build();

    let running = tokio::spawn(async move { rt.run("slow", Tainted::trusted(json!({}))).await });

    // Wait until the skill is in flight and its lease has had time to lapse,
    // then do what a recovering instance does: try to take the run over.
    tokio::time::sleep(ttl + ttl / 2).await;
    let run = seen.lock().unwrap().expect("the skill did not start");
    let stolen = (store as Arc<dyn JournalStore>)
        .acquire(run, "instance-b", ttl)
        .await;

    assert!(
        matches!(stolen, Err(StoreError::LeaseHeld { .. })),
        "another instance took over a run that is still executing — the \
         original is now fenced and dies on its next append, having already \
         done the work: {stolen:?}"
    );

    let outcome = running.await.expect("the run task panicked").expect("run");
    assert_eq!(
        outcome.status,
        RunStatus::Succeeded,
        "the run did not survive its own lease"
    );
}

/// A lease too short to be renewed is refused when the plane is built.
///
/// Both stores keep expiry in whole seconds and lapse on `expires_at <= now`, so
/// a one-second lease is expired for part of every second it exists — no
/// renewal frequency saves it. Accepting one would produce a plane whose runs
/// can be taken over while working, and it would only show up under load.
///
/// The refusal is a `BuildError` rather than a setter panic so a plane
/// assembled from runtime input (`try_build`) reports it as a diagnostic
/// instead of aborting the process. The positive half: the same builder with a
/// TTL at the minimum assembles.
#[test]
fn a_lease_too_short_to_renew_is_refused() {
    use std::time::Duration;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let refused = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .lease_ttl(Duration::from_secs(1))
        .try_build();
    let err = refused.expect_err("a one-second lease was accepted");
    assert!(
        matches!(
            err,
            agentplane::runtime::BuildError::LeaseUnrenewable { .. }
        ),
        "refused, but not as the lease refusal: {err}"
    );
    assert!(
        err.to_string().contains("cannot be renewed"),
        "the diagnostic no longer says why the lease is unusable: {err}"
    );

    let accepted = Runtime::builder(store as Arc<dyn JournalStore>)
        .lease_ttl(Duration::from_secs(2))
        .try_build();
    assert!(
        accepted.is_ok(),
        "a lease at the minimum was refused — the check refuses everything, \
         so the negative half above proves nothing"
    );
}

/// The harness establishing "now" for a sweep tick — a test driving the
/// runtime from outside, not a step smuggling non-determinism past the
/// journal, which is what the lint guards against.
#[allow(clippy::disallowed_methods)]
fn sweep_now() -> agentplane::core::Timestamp {
    agentplane::core::Timestamp::now_utc()
}

// ── The recovery sweep ──────────────────────────────────────────────────────
//
// Fencing makes takeover safe and replay makes it correct, but neither makes
// it *happen*. A run whose owner died holding it has no driver: it concluded
// nothing, so no outcome listing carries it; its wake was consumed, so no
// waiting list names it. The sweep's recovery pass is the component that
// notices — an expired lease that still names an owner is exactly "an
// instance died holding this run", because every clean exit releases.

/// The store-level contract: live and released leases are invisible; an
/// expired, unreleased one is the abandonment signal.
#[tokio::test]
async fn an_expired_unreleased_lease_marks_a_run_abandoned() {
    use std::time::Duration;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let journal: Arc<dyn JournalStore> = store;
    let run = agentplane::core::RunId::generate();

    // Held and live: not abandoned, whoever holds it is presumed working.
    let lease = journal
        .acquire(run, "instance-a", Duration::from_secs(2))
        .await
        .unwrap();
    assert!(
        journal.abandoned_runs(10).await.unwrap().is_empty(),
        "a live lease is not abandonment"
    );

    // Released: the owner exited cleanly, whatever the outcome was.
    journal.release_lease(run, lease.epoch).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        journal.abandoned_runs(10).await.unwrap().is_empty(),
        "a released lease is a clean exit, not a death"
    );

    // Held and lapsed: the owner stopped renewing without handing it back.
    journal
        .acquire(run, "instance-b", Duration::from_secs(2))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        journal.abandoned_runs(10).await.unwrap(),
        vec![run],
        "an expired lease that still names an owner is an instance that died \
         holding the run"
    );
}

/// **The liveness property.** A run stranded by a dead instance is found and
/// resumed by the sweep — no event, no timer, no operator.
#[tokio::test]
async fn the_sweep_recovers_a_run_its_owner_died_holding() {
    use std::time::Duration;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let crash_at = Arc::new(AtomicUsize::new(0));
    let calls = tally();
    let rt = Runtime::builder(store.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    // A run dies after stage 0 — and, unlike an orderly failure, its "owner"
    // then vanishes holding the lease, the way a killed process does.
    let first = rt
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(first.status, RunStatus::Failed(_)));
    (store.clone() as Arc<dyn JournalStore>)
        .acquire(first.run_id, "dead-instance", Duration::from_secs(2))
        .await
        .unwrap();

    crash_at.store(NO_CRASH, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let report = rt
        .sweep(sweep_now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(report.runs_recovered, 1, "the sweep took the run over");
    assert_eq!(report.recovery_failures, 0);
    assert!(
        report.record.is_some(),
        "a takeover bumps the epoch and fences the dead owner; who fenced \
         whom must be answerable from the sweep's own sealed run"
    );

    // The resume continued rather than restarted: stage 0 once ever.
    assert_eq!(calls[0].load(Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(Ordering::SeqCst), 1);
    assert_eq!(calls[2].load(Ordering::SeqCst), 1);
    assert!(
        (store.clone() as Arc<dyn JournalStore>)
            .runs_by_outcome("succeeded", 10)
            .await
            .unwrap()
            .contains(&first.run_id)
    );

    // Recovered means recovered: the next tick finds nothing.
    let again = rt
        .sweep(sweep_now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(again.runs_recovered, 0, "recovery is not a loop");
    assert_eq!(again.recovery_failures, 0);
}

/// **A takeover whose note cannot be written is a takeover not taken.**
///
/// The sweeper's rule — the note is durable before the state it describes —
/// bites hardest here, because recovery is the one pass whose act removes the
/// item from the driving query permanently: a resume that concludes releases
/// the lease, so no later tick re-selects the run, and a note written *after*
/// the act would be lost forever by a crash between the two. Who fenced whom
/// must be answerable from the journal, so the order is note, then takeover —
/// and a note that cannot land skips the takeover, which a later tick retries.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_takeover_whose_note_cannot_be_written_is_not_taken() {
    use agentplane::testkit::{Fault, Faulty, Schedule};
    use std::time::Duration;

    let inner = Arc::new(RedbStore::open_in_memory().unwrap());
    let faulty = Arc::new(Faulty::new(
        inner.clone() as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("Swept", Fault::FailedClean),
    ));
    let crash_at = Arc::new(AtomicUsize::new(0));
    let calls = tally();
    // Two instances over one store: one whose evidence writes fail, one
    // healthy — the shape of a store hiccup that clears before the next tick.
    let rt_faulty = Runtime::builder(faulty as Arc<dyn JournalStore>)
        .skill(pipeline(&crash_at, &calls))
        .build();
    let rt_clean = Runtime::builder(inner.clone())
        .skill(pipeline(&crash_at, &calls))
        .build();

    let first = rt_clean
        .run("pipeline", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(first.status, RunStatus::Failed(_)));
    (inner.clone() as Arc<dyn JournalStore>)
        .acquire(first.run_id, "dead-instance", Duration::from_secs(2))
        .await
        .unwrap();
    crash_at.store(NO_CRASH, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = calls[1].load(Ordering::SeqCst);

    // The note fails, so the decision is not taken: no resume, and the run
    // stays selected for the tick that can write its account.
    let swept = rt_faulty
        .sweep(sweep_now(), Duration::from_secs(3600))
        .await;
    assert!(
        swept.is_err(),
        "a sweep whose evidence write failed reported success"
    );
    assert_eq!(
        calls[1].load(Ordering::SeqCst),
        before,
        "the takeover went ahead without its note — a fenced, resumed run \
         whose account no journal carries"
    );
    assert_eq!(
        (inner.clone() as Arc<dyn JournalStore>)
            .abandoned_runs(10)
            .await
            .unwrap(),
        vec![first.run_id],
        "the un-noted run must stay selected for the next tick"
    );

    // The healthy instance's tick writes the note and takes the run over.
    let report = rt_clean
        .sweep(sweep_now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(report.runs_recovered, 1);
    let record = report.record.expect("the takeover is on the record");
    let noted = (inner.clone() as Arc<dyn JournalStore>)
        .read(record, 1)
        .await
        .unwrap()
        .iter()
        .any(|r| {
            matches!(
                r.kind(),
                agentplane::journal::RecordKind::Swept { subject, .. }
                    if *subject == first.run_id.to_string()
            )
        });
    assert!(noted, "the sweep's run does not name the run it took over");
    assert!(
        (inner.clone() as Arc<dyn JournalStore>)
            .runs_by_outcome("succeeded", 10)
            .await
            .unwrap()
            .contains(&first.run_id),
        "the retried takeover resumed the run to its conclusion"
    );
}

/// A lease with nothing under it — admission died between acquiring and its
/// first append — is cleared rather than retried forever.
#[tokio::test]
async fn a_lease_over_an_empty_journal_is_cleared_not_retried() {
    use std::time::Duration;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone()).build();

    let ghost = agentplane::core::RunId::generate();
    (store.clone() as Arc<dyn JournalStore>)
        .acquire(ghost, "dead-instance", Duration::from_secs(2))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

    let report = rt
        .sweep(sweep_now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(
        (report.runs_recovered, report.recovery_failures),
        (1, 0),
        "no run exists, so clearing the lease is the whole recovery — the \
         failure arm would retry a resume that cannot exist, every tick, forever"
    );

    let again = rt
        .sweep(sweep_now(), Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(again.runs_recovered, 0);
    assert_eq!(again.recovery_failures, 0);
}

/// **Every conclusion but success says why, through one accessor.**
///
/// The reason lives inside the variants — a string on `Failed`, a typed
/// `SuspendReason`, a typed `BudgetExceeded`, an operator's words on
/// `Cancelled` — so an embedder mapping outcomes onto its own wire type had to
/// match all of them to find the sentence. The lazy path was to read the status
/// and stop, and a deployment shipped an empty summary on failed runs for a
/// while without noticing. `reason()` makes the lazy path the correct one.
///
/// Exhaustive by construction: the match below has no `_` arm, so a conclusion
/// added later cannot be forgotten here — it will not compile until somebody
/// decides what it says.
#[test]
fn every_conclusion_but_success_carries_a_reason() {
    use agentplane::core::{BudgetExceeded, SuspendReason};
    use agentplane::runtime::RunStatus;

    let statuses = [
        RunStatus::Succeeded,
        RunStatus::Failed("the counterparty refused".into()),
        RunStatus::Quarantined("an effect's outcome is unknown".into()),
        RunStatus::Replanning("the plan no longer fits".into()),
        RunStatus::Cancelled {
            actor: "ops:hupe".into(),
            reason: "stopped for the maintenance window".into(),
        },
        RunStatus::Suspended(SuspendReason::AwaitingTime {
            until: agentplane::core::Timestamp::from_unix_timestamp(1_800_000_000).unwrap(),
        }),
        RunStatus::Exhausted(BudgetExceeded::Steps { allowed: 3 }),
        RunStatus::Abandoned {
            actor: "ops".into(),
            reason: "the provider has no record either way".into(),
        },
    ];

    for status in statuses {
        let reason = status.reason();
        match &status {
            RunStatus::Succeeded => assert!(
                reason.is_none(),
                "a success has no reason to give, and inventing one would put a \
                 sentence in a field an embedder renders as a failure note"
            ),
            RunStatus::Failed(_)
            | RunStatus::Quarantined(_)
            | RunStatus::Replanning(_)
            | RunStatus::Cancelled { .. }
            | RunStatus::Abandoned { .. }
            | RunStatus::Suspended(_)
            | RunStatus::Exhausted(_) => {
                let text = reason.unwrap_or_else(|| {
                    panic!("{} ended without saying why", status.as_str());
                });
                assert!(
                    !text.trim().is_empty(),
                    "{} gave an empty reason, which is the empty summary this \
                     accessor exists to stop",
                    status.as_str()
                );
            }
        }
    }

    // The typed variants are formatted rather than dropped: "suspended" alone
    // does not tell an operator what the run is waiting for, and the ceiling a
    // run hit is the whole content of an exhaustion.
    assert!(
        RunStatus::Exhausted(BudgetExceeded::Steps { allowed: 3 })
            .reason()
            .expect("exhaustion has a reason")
            .contains('3'),
        "the exhaustion's reason must name the ceiling it hit"
    );
}
