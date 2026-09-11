//! Stopping an instance on purpose, rather than being stopped.
//!
//! A process killed mid-step leaves an announced effect with no outcome, and
//! nothing in the journal can say whether that call reached the world. That is
//! the right answer to a crash and the wrong price for a deploy, so a drain
//! exists to turn the second back into an ordinary conclusion. What these pin is
//! the part that is easy to get wrong in the other direction: a drain that
//! hurried the handover along by handing back leases would license a second
//! instance to re-perform a call this one is still inside.

#![cfg(feature = "redb")]

use std::sync::Arc;
use std::time::Duration;

use agentplane::core::{Outcome, RuntimeError, Skill, SkillDescriptor, StoreError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// A skill that reports when it has started and then waits to be let go.
///
/// Two signals rather than one: without `started` a drain could be measured
/// against a run whose task has not been polled yet, and the test would pass
/// for the wrong reason.
#[derive(Debug)]
struct Held {
    started: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl Skill for Held {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("held").provides("demo.held")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        self.started.add_permits(1);
        let permit = self.release.acquire().await.expect("the release gate");
        permit.forget();
        Ok(Outcome::done(Tainted::trusted(json!({ "held": true }))))
    }
}

/// A skill that returns at once.
///
/// The gate test needs this rather than [`Held`]: a mutation that deletes the
/// gate makes the refused run *run*, and a run that blocks turns a failing
/// assertion into a hung sweep — which proves nothing and takes a CI job's whole
/// timeout to say so.
#[derive(Debug)]
struct Instant;

#[async_trait::async_trait]
impl Skill for Instant {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("instant").provides("demo.instant")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        Ok(Outcome::done(Tainted::trusted(json!({ "done": true }))))
    }
}

struct Fixture {
    runtime: Arc<Runtime>,
    store: Arc<RedbStore>,
    started: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

fn fixture() -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Held {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        })
        .skill(Instant)
        .build();
    Fixture {
        runtime,
        store,
        started,
        release,
    }
}

/// A chief that commissions a helper *after* the drain has begun.
///
/// The sequencing is the test: it signals that it has started, waits to be let
/// go, and only then commissions. So by the time the commission is admitted the
/// gate is closed and the drain is already waiting for this very run.
#[derive(Debug)]
struct Chief {
    started: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl Skill for Chief {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("chief").provides("demo.chief")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        self.started.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("the release gate")
            .forget();
        let answer = cx
            .commission("demo.held", Tainted::trusted(json!({})))
            .await?;
        Ok(Outcome::done(answer))
    }
}

/// A drain must not refuse the runs it is waiting for.
///
/// A commission is a **step** of a run this process is already executing, and
/// its failure is `Interrupted` — the in-doubt classification, because a
/// commissioning caller cannot know what the agent it ordered from managed to
/// do. A drain gate that saw commissions would therefore manufacture exactly
/// the undecided state a drain exists to prevent, on every rolling deploy, for
/// every plane whose agents delegate.
#[tokio::test]
async fn a_drain_does_not_refuse_the_commission_of_a_run_it_is_waiting_for() {
    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    // The helper is let go immediately; only the chief is held.
    let helper_release = Arc::new(tokio::sync::Semaphore::new(1));
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Chief {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        })
        .skill(Held {
            started: Arc::new(tokio::sync::Semaphore::new(0)),
            release: helper_release,
        })
        .build();

    let run = runtime
        .spawn("demo.chief", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    let _ = started.acquire().await.expect("the run to start");

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        release.add_permits(1);
    });
    let report = runtime.drain(Duration::from_secs(30)).await;
    assert!(report.is_complete(), "{report:?}");

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");
    assert!(
        matches!(outcome.status, RunStatus::Succeeded),
        "the drain refused a commission of a run it was waiting for: {:?} {:?}",
        outcome.status,
        outcome.reason()
    );
}

/// Every door, because one gate is only worth having if it is the only door.
#[tokio::test]
async fn a_draining_instance_admits_nothing_and_writes_nothing() {
    let f = fixture();
    let report = f.runtime.drain(Duration::ZERO).await;
    assert!(report.is_complete());
    assert!(f.runtime.is_draining());

    let blocking = f
        .runtime
        .run("demo.instant", Tainted::trusted(json!({})))
        .await;
    assert!(
        matches!(blocking, Err(RuntimeError::Draining)),
        "an awaited run: {blocking:?}"
    );
    let background = f
        .runtime
        .spawn("demo.instant", Tainted::trusted(json!({})))
        .await;
    assert!(
        matches!(background, Err(RuntimeError::Draining)),
        "a background run: {background:?}"
    );

    // Refused before the lease, the quota slot and the first append — so a
    // caller that retries elsewhere is not racing a half-admitted run here.
    let recent = f
        .store
        .recent_runs(None, 10)
        .await
        .expect("the activity index");
    assert!(
        recent.is_empty(),
        "a refused admission left a run behind: {recent:?}"
    );
}

#[tokio::test]
async fn a_drain_waits_for_a_background_run_to_reach_its_conclusion() {
    let f = fixture();
    let run = f
        .runtime
        .spawn("demo.held", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    let _ = f.started.acquire().await.expect("the run to start");

    let release = Arc::clone(&f.release);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        release.add_permits(1);
    });

    let report = f.runtime.drain(Duration::from_secs(30)).await;
    assert_eq!(report.at_start, vec![run]);
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.settled(), 1);

    let outcome = f
        .runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");
    assert!(
        matches!(outcome.status, RunStatus::Succeeded),
        "the drain returned before the run concluded: {:?}",
        outcome.status
    );
}

/// The property that decides whether a drain is safe to have at all.
///
/// Handing a lease back says *takeover is safe now*. For a run this process is
/// still inside, it is not: the next owner replays, finds the announced effect
/// with no outcome, and re-performs the call beside the one still in flight. The
/// fence stops the second append and nothing stops the second send. So a
/// drained-out run keeps its lease and expires like a crash, which is the one
/// signal the recovery sweep reads as *an instance died holding this run*.
#[tokio::test]
async fn a_run_the_grace_period_did_not_cover_is_named_and_keeps_its_lease() {
    let f = fixture();
    let run = f
        .runtime
        .spawn("demo.held", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    let _ = f.started.acquire().await.expect("the run to start");

    let report = f.runtime.drain(Duration::from_millis(50)).await;
    assert_eq!(report.unfinished, vec![run], "{report:?}");
    assert_eq!(report.settled(), 0);
    assert!(!report.is_complete());

    let stolen = f
        .store
        .acquire(run, "the-next-instance", Duration::from_secs(30))
        .await;
    assert!(
        matches!(stolen, Err(StoreError::LeaseHeld { .. })),
        "the drain handed back a lease over a run it did not finish: {stolen:?}"
    );

    f.release.add_permits(1);
}

/// A second drain is not a second answer.
#[tokio::test]
async fn draining_an_instance_that_is_already_draining_answers_again() {
    let f = fixture();
    let first = f.runtime.drain(Duration::ZERO).await;
    let second = f.runtime.drain(Duration::ZERO).await;
    assert_eq!(first, second);
    assert!(f.runtime.is_draining());
}
