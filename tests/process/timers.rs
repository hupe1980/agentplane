//! Durable timers: a wait whose event is the clock.
//!
//! An in-process sleep holds a worker for its duration and forgets everything if
//! the process dies. A business process that waits five Werktage cannot be a
//! held task. A durable timer is a row: the run suspends, the frame is
//! persisted, and a sweep wakes it when the instant arrives.
//!
//! The property that makes this more than `sleep`: **the wake instant is
//! journaled**. A run that slept until Tuesday still says Tuesday when it is
//! replayed next year, because the instant is a recorded fact rather than a
//! formula re-evaluated on every replay.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::case::TimerStore;
use agentplane::core::{
    Outcome, Skill, SkillDescriptor, SkillError, SuspendReason, Tainted, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Sleeps, then records that it woke. The counter is how many times the *work
/// after the sleep* ran — it must be exactly one across the suspension.
#[derive(Debug)]
struct Sleeps {
    how_long: Duration,
    woke: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Sleeps {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("sleeps").provides("demo.sleep")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Propagated with `?`. Catching the suspension here would turn a durable
        // sleep into a silent hang.
        cx.sleep(self.how_long).await?;
        self.woke.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(Tainted::trusted(json!({ "awake": true }))))
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    woke: Arc<AtomicUsize>,
}

fn fixture(how_long: Duration) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let woke = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .timers(store.clone() as Arc<dyn TimerStore>)
        .skill(Sleeps {
            how_long,
            woke: Arc::clone(&woke),
        })
        .build();
    Fixture { store, rt, woke }
}

fn later(secs: i64) -> Timestamp {
    Timestamp::now_utc()
        .checked_add(time::Duration::seconds(secs))
        .unwrap()
}

// ── Suspending ──────────────────────────────────────────────────────────────

/// A sleeping run is a row, not a thread.
#[tokio::test]
async fn a_sleeping_run_suspends_and_holds_nothing() {
    let f = fixture(Duration::from_secs(3600));

    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();

    match &out.status {
        RunStatus::Suspended(SuspendReason::AwaitingTime { until }) => {
            assert!(
                *until > Timestamp::now_utc(),
                "the instant is in the future"
            );
        }
        other => panic!("expected a time suspension, got {other:?}"),
    }
    assert_eq!(f.woke.load(Ordering::SeqCst), 0, "it has not woken yet");
    assert_eq!(
        f.store.armed_timers(out.run_id).await.unwrap(),
        1,
        "exactly one wake-up is armed"
    );
}

/// A sleep with no timer store is refused, not silently downgraded to an
/// in-process wait that a restart would forget.
#[tokio::test]
async fn sleeping_without_a_timer_store_is_refused() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Sleeps {
            how_long: Duration::from_mins(1),
            woke: Arc::new(AtomicUsize::new(0)),
        })
        .build();

    let out = rt
        .run("demo.sleep", Tainted::trusted(json!({})))
        .await
        .unwrap();
    match &out.status {
        RunStatus::Failed(m) => assert!(m.contains("timer store"), "got: {m}"),
        other => panic!("expected a loud refusal, got {other:?}"),
    }
}

// ── Waking ──────────────────────────────────────────────────────────────────

/// **The loop.** The instant arrives, the sweep wakes the run, and it finishes.
#[tokio::test]
async fn a_sweep_wakes_a_run_whose_instant_arrived() {
    let f = fixture(Duration::from_mins(1));

    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert!(out.status.is_suspended());

    // Nothing is due yet.
    let quiet = f.rt.fire_timers(Timestamp::now_utc()).await.unwrap();
    assert_eq!(quiet.fired, 0, "a timer that is not due must not fire");
    assert_eq!(f.woke.load(Ordering::SeqCst), 0);

    // Time passes.
    let fired = f.rt.fire_timers(later(120)).await.unwrap();
    assert_eq!(fired.fired, 1);
    assert_eq!(
        f.woke.load(Ordering::SeqCst),
        1,
        "the run finished its work"
    );
    assert_eq!(
        f.store.armed_timers(out.run_id).await.unwrap(),
        0,
        "a fired timer is retired"
    );

    let records = f.store.read(out.run_id, 1).await.unwrap();
    assert!(
        records.iter().any(
            |r| matches!(r.kind(), RecordKind::RunConcluded { outcome, .. } if outcome == "succeeded")
        ),
        "the woken run reaches a conclusion"
    );
    f.store.verify(out.run_id).await.unwrap();
}

/// A wake recorded before a crash is not recorded again when the claim
/// re-fires.
///
/// The crash window: last tick appended the wake's `EffectDone` and died
/// before disarming the timer, so the claim lapses and this tick fires the
/// same timer again. The retry must be a second *resume*, never a second
/// record — the journal is the one place a retry may not show up twice.
#[tokio::test]
async fn a_refired_timer_does_not_duplicate_the_recorded_wake() {
    let f = fixture(Duration::from_mins(1));
    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();
    let fired = f.rt.fire_timers(later(120)).await.unwrap();
    assert_eq!(fired.fired, 1);

    // Reconstruct the crash's leftover state: the wake is in the journal, and
    // the timer row is still armed because the disarm never ran.
    let records = f.store.read(out.run_id, 1).await.unwrap();
    let wake = records
        .iter()
        .find(|r| {
            matches!(r.kind(), RecordKind::EffectDone { output, .. }
                if output.get("fired_at").is_some())
        })
        .expect("the wake is on the record");
    let timer = agentplane::core::Timer {
        run: out.run_id,
        case: None,
        effect: wake.effect_key().unwrap(),
        step: wake.body.step.unwrap(),
        phase: wake.body.phase,
        fire_at: later(60),
    };
    (f.store.clone() as Arc<dyn TimerStore>)
        .arm(&timer)
        .await
        .unwrap();

    let refired = f.rt.fire_timers(later(120)).await.unwrap();
    assert_eq!((refired.fired, refired.failed), (1, 0));

    let after = f.store.read(out.run_id, 1).await.unwrap();
    let wakes = after
        .iter()
        .filter(|r| {
            matches!(r.kind(), RecordKind::EffectDone { output, .. }
                if output.get("fired_at").is_some())
        })
        .count();
    assert_eq!(wakes, 1, "the retried wake was appended a second time");
    assert_eq!(
        f.store.armed_timers(out.run_id).await.unwrap(),
        0,
        "the re-fired timer is retired"
    );
    assert_eq!(
        f.woke.load(Ordering::SeqCst),
        1,
        "the work ran exactly once"
    );
}

/// **A wake-up is single-delivery.** Two sweeps racing over one store must not
/// both resume the same run — the same requirement event delivery has, for the
/// same reason.
#[tokio::test]
async fn a_timer_fires_exactly_once_across_two_sweeps() {
    let f = fixture(Duration::from_mins(1));
    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert!(out.status.is_suspended());

    let first = f.rt.fire_timers(later(120)).await.unwrap();
    let second = f.rt.fire_timers(later(120)).await.unwrap();

    assert_eq!(
        (first.fired, second.fired),
        (1, 0),
        "the second sweep finds nothing"
    );
    assert_eq!(
        f.woke.load(Ordering::SeqCst),
        1,
        "the work after the sleep ran exactly once"
    );
}

/// The sweep reports a fired timer without treating it as an incident. A quiet
/// plane and a stalled one must be distinguishable, but nobody is paged for a
/// clock working.
#[tokio::test]
async fn a_fired_timer_is_reported_but_is_not_an_incident() {
    let f = fixture(Duration::from_mins(1));
    f.rt.run("demo.sleep", Tainted::trusted(json!({})))
        .await
        .unwrap();

    let report =
        f.rt.sweep(later(120), std::time::Duration::from_secs(86_400))
            .await
            .unwrap();
    assert_eq!(report.timers_fired, 1);
    assert!(
        !report.needs_attention(),
        "a fired timer is the system working, not something to alert on"
    );
}

// ── The instant is a fact, not a formula ────────────────────────────────────

/// **The property that makes this more than `sleep`.**
///
/// The wake instant is journaled. Replaying the run reads it back rather than
/// recomputing `now + duration`, which would move the instant every time.
#[tokio::test]
async fn the_wake_instant_is_journaled_not_recomputed() {
    let f = fixture(Duration::from_mins(1));
    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();

    let armed = f.rt.timers().unwrap().pending(10).await.unwrap();
    assert_eq!(armed.len(), 1);
    let fire_at = armed[0].fire_at;

    f.rt.fire_timers(later(120)).await.unwrap();

    // The journaled instant is the one that was declared, and the effect args
    // that produced the key carry it too — so a replay recomputing the key gets
    // the same answer.
    let records = f.store.read(out.run_id, 1).await.unwrap();
    let declared = records.iter().find_map(|r| match r.kind() {
        RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == "timer.sleep" => {
            descriptor
                .args
                .get("until")
                .and_then(serde_json::Value::as_i64)
        }
        _ => None,
    });
    assert_eq!(
        declared,
        Some(fire_at.unix_timestamp()),
        "the instant in the journal is the instant the timer was armed for"
    );
}

/// A sweep that runs late must not make the run believe it slept longer than it
/// was told to. The recorded wake is the instant it was *due*, not the instant
/// the sweep noticed.
#[tokio::test]
async fn a_late_sweep_records_the_due_instant_not_its_own() {
    let f = fixture(Duration::from_mins(1));
    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();
    let due = f.rt.timers().unwrap().pending(10).await.unwrap()[0].fire_at;

    // The sweep runs an hour late.
    f.rt.fire_timers(later(3600)).await.unwrap();

    let records = f.store.read(out.run_id, 1).await.unwrap();
    let fired_at = records.iter().find_map(|r| match r.kind() {
        RecordKind::EffectDone { output, .. } => {
            output.get("fired_at").and_then(serde_json::Value::as_i64)
        }
        _ => None,
    });
    assert_eq!(fired_at, Some(due.unix_timestamp()));
}

// ── Replay ──────────────────────────────────────────────────────────────────

/// A completed sleep replays without sleeping again.
#[tokio::test]
async fn replay_reads_the_sleep_back_instead_of_sleeping_again() {
    let f = fixture(Duration::from_mins(1));
    let first =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();
    f.rt.fire_timers(later(120)).await.unwrap();
    assert_eq!(f.woke.load(Ordering::SeqCst), 1);

    let again = f.rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(
        f.store.armed_timers(first.run_id).await.unwrap(),
        0,
        "strict replay must not arm a second timer"
    );
}

/// Replaying a run that is *still* sleeping suspends again rather than re-arming
/// — which would reset the clock on every replay and the run would never wake.
#[tokio::test]
async fn replaying_a_sleeping_run_does_not_reset_its_clock() {
    let f = fixture(Duration::from_mins(1));
    let out =
        f.rt.run("demo.sleep", Tainted::trusted(json!({})))
            .await
            .unwrap();
    let armed = f.rt.timers().unwrap().pending(10).await.unwrap();
    let original = armed[0].fire_at;

    let again = f.rt.replay(out.run_id, Mode::Resume).await.unwrap();
    assert!(again.status.is_suspended(), "still asleep");

    let still = f.rt.timers().unwrap().pending(10).await.unwrap();
    assert_eq!(still.len(), 1, "no second timer was armed");
    assert_eq!(still[0].fire_at, original, "and the instant did not move");
}

// ── The claim, tested where it lives ────────────────────────────────────────

/// **Claiming is what makes a wake-up single-delivery.**
///
/// Tested against the store directly, and deliberately so. Going through two
/// sequential sweeps proves nothing: the first sweep *disarms* the timer, so the
/// second finds an empty table whether or not claiming works. That test passed
/// with the claim deleted — it was measuring cleanup, not exclusion.
///
/// Two sweepers racing over one store see the window this closes: both select
/// before either disarms. So the exclusion is checked at the only level where it
/// is real — claim twice, with no disarm in between.
#[tokio::test]
async fn claiming_a_due_timer_excludes_a_second_claimant() {
    use agentplane::core::{EffectKey, Phase, RunId, StepId, Timer};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let run = RunId::generate();
    let descriptor =
        agentplane::core::EffectDescriptor::new("timer.sleep", json!({ "until": 1_000 }));
    let effect = EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &descriptor);

    store
        .arm(&Timer {
            run,
            case: None,
            effect,
            step: StepId(0),
            phase: Phase::Forward,
            fire_at: Timestamp::from_unix_timestamp(1_000).unwrap(),
        })
        .await
        .unwrap();

    let now = Timestamp::from_unix_timestamp(2_000).unwrap();
    let first = store.claim_due(now, 10).await.unwrap();
    let second = store.claim_due(now, 10).await.unwrap();

    assert_eq!(first.len(), 1, "the first claimant takes it");
    assert!(
        second.is_empty(),
        "a second claimant finds nothing — without this, two sweepers both \
         resume the same run"
    );
}

/// Arming is idempotent on `(run, effect)`. A resumed run that re-registers the
/// same wake-up must not create a second one, or it would be woken twice.
#[tokio::test]
async fn arming_the_same_timer_twice_leaves_one() {
    use agentplane::core::{EffectKey, Phase, RunId, StepId, Timer};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let run = RunId::generate();
    let descriptor =
        agentplane::core::EffectDescriptor::new("timer.sleep", json!({ "until": 1_000 }));
    let timer = Timer {
        run,
        case: None,
        effect: EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &descriptor),
        step: StepId(0),
        phase: Phase::Forward,
        fire_at: Timestamp::from_unix_timestamp(1_000).unwrap(),
    };

    store.arm(&timer).await.unwrap();
    store.arm(&timer).await.unwrap();

    assert_eq!(store.armed_timers(run).await.unwrap(), 1);
}

/// **A claim is a lease, not a permanent mark.**
///
/// A sweeper that dies between claiming a timer and journaling its wake-up would
/// otherwise strand the sleeping run forever: the row stays claimed, no later
/// sweep looks at it again, and the run waits for an instant that has passed.
/// Re-firing is safe — the wake-up is recorded under a fixed effect key, so a
/// second write is the same write.
#[tokio::test]
async fn an_abandoned_claim_is_reclaimed_rather_than_stranding_the_run() {
    use agentplane::core::{EffectKey, Phase, RunId, StepId, Timer};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let run = RunId::generate();
    let descriptor =
        agentplane::core::EffectDescriptor::new("timer.sleep", json!({ "until": 1_000 }));
    store
        .arm(&Timer {
            run,
            case: None,
            effect: EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &descriptor),
            step: StepId(0),
            phase: Phase::Forward,
            fire_at: Timestamp::from_unix_timestamp(1_000).unwrap(),
        })
        .await
        .unwrap();

    // A sweeper claims it, then dies without firing.
    let at = Timestamp::from_unix_timestamp(2_000).unwrap();
    assert_eq!(store.claim_due(at, 10).await.unwrap().len(), 1);

    // Immediately after, the claim still holds — no double-fire.
    assert!(store.claim_due(at, 10).await.unwrap().is_empty());

    // Once the lease lapses, another sweep picks it up.
    let later = Timestamp::from_unix_timestamp(2_000 + 120).unwrap();
    assert_eq!(
        store.claim_due(later, 10).await.unwrap().len(),
        1,
        "an abandoned claim must not strand the sleeping run"
    );
}

// ── Concurrency ─────────────────────────────────────────────────────────────

/// Two concurrent siblings can both sleep, and the run finishes once both wake.
///
/// Note what is *not* asserted: how many times the skill bodies ran. Each wake
/// replays the run, so a plain counter inside a skill climbs past the number of
/// wake-ups — correctly, because a skill body re-executes and only its *effects*
/// are served from the journal. Counting body executions would be measuring
/// replay, not wake-ups. The real properties are the timers, the seal, and the
/// chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_siblings_can_both_sleep() {
    use agentplane::core::{ArgSource, PlanIR, PlanNode, StepId};

    #[derive(Debug)]
    struct Naps(&'static str);

    #[async_trait::async_trait]
    impl Skill for Naps {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.0).provides(self.0)
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.sleep(Duration::from_mins(1)).await?;
            Ok(Outcome::done(Tainted::trusted(json!({ "woke": self.0 }))))
        }
    }

    #[derive(Debug)]
    struct Join;
    #[async_trait::async_trait]
    impl Skill for Join {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("join").provides("join")
        }
        async fn invoke(
            &self,
            _c: &mut StepCtx<'_>,
            i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::done(i))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .timers(store.clone() as Arc<dyn TimerStore>)
        .skill(Naps("left"))
        .skill(Naps("right"))
        .skill(Join)
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "left").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "right").arg("input", ArgSource::run_input()),
        PlanNode::new(2, "join")
            .arg("l", ArgSource::node(StepId(0)))
            .arg("r", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(out.status.is_suspended(), "got {:?}", out.status);
    assert_eq!(
        store.armed_timers(out.run_id).await.unwrap(),
        2,
        "both siblings armed their own wake-up"
    );

    let fired = rt.fire_timers(later(120)).await.unwrap();
    assert_eq!(fired.fired, 2);
    assert_eq!(store.armed_timers(out.run_id).await.unwrap(), 0);

    let seals: Vec<String> = store
        .read(out.run_id, 1)
        .await
        .unwrap()
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::RunConcluded { outcome, .. } => Some(outcome.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(seals, vec!["succeeded".to_string()], "sealed exactly once");
    store.verify(out.run_id).await.unwrap();
}
