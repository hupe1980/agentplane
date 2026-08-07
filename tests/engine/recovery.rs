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

    let recorded = rt.run("pipeline", json!({})).await.unwrap();

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
                        capability: "demo.pipeline".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: agentplane::core::Label::trusted(),
                        policy_bundle: None,
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

    let running = tokio::spawn(async move { rt.run("slow", json!({})).await });

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
#[test]
#[should_panic(expected = "cannot be renewed")]
fn a_lease_too_short_to_renew_is_refused() {
    use std::time::Duration;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let _ = Runtime::builder(store as Arc<dyn JournalStore>)
        .lease_ttl(Duration::from_secs(1))
        .build();
}
