//! Durable waits that survive losing their registration, and the wake path's
//! lease handover.
//!
//! A durable wait is two writes: the journal announces it (`EffectStarted`),
//! and a store registers it — a timer armed, a subscription filed. A crash, or
//! a transient store error, can land between the two. The journal then reads
//! "waiting" while nothing in the system will ever name the run again: no
//! timer fires, no event matches, the lease is released. That run looks
//! exactly like work in progress and sleeps forever.
//!
//! The repair is on resume: an announced wait whose registration cannot be
//! confirmed is re-registered — idempotently, under the same key, without a
//! second announcement. The tests here manufacture the lost registration
//! directly (disarm the timer, retire the subscription), which is the honest
//! simulation: it is indistinguishable from the crash landing in the window.
//!
//! Beside them, the wake path's lease: firing a timer records the wake under a
//! lease and then resumes the run **holding it**. The old choreography —
//! release, then let the resume re-acquire — left an instant in which the run
//! had a *released* lease, a disarmed timer, and no driver; a crash there was
//! invisible to the abandonment sweep, which lists only leases that expired
//! while still naming an owner.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::case::{CaseStore, EventStore, TimerStore};
use agentplane::core::{
    AwaitSpec, CorrelationKey, DeadlineSpec, Delivery, Digest, Epoch, InboundEvent, Outcome, RunId,
    Seq, Skill, SkillDescriptor, SkillError, StoreError, Tainted, Timestamp,
};
use agentplane::journal::{Append, Head, JournalStore, Lease, Record, RecordKind};
use agentplane::runtime::{Mode, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

fn later(secs: i64) -> Timestamp {
    Timestamp::now_utc()
        .checked_add(time::Duration::seconds(secs))
        .unwrap()
}

/// The key of the one recorded wait of `kind` in a run's journal.
async fn wait_key(store: &Arc<RedbStore>, run: RunId, kind: &str) -> agentplane::core::EffectKey {
    (store.clone() as Arc<dyn JournalStore>)
        .read(run, 1)
        .await
        .unwrap()
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == kind => {
                r.effect_key()
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {kind} announcement in the journal"))
}

/// How many announcements a run's journal holds for one wait kind.
async fn announcements(store: &Arc<RedbStore>, run: RunId, kind: &str) -> usize {
    (store.clone() as Arc<dyn JournalStore>)
        .read(run, 1)
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            matches!(
                r.kind(),
                RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == kind
            )
        })
        .count()
}

// ── Timers ──────────────────────────────────────────────────────────────────

/// Sleeps, then counts that the work after the sleep ran.
#[derive(Debug)]
struct Naps {
    woke: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Naps {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("naps").provides("demo.nap")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.sleep(Duration::from_secs(2)).await?;
        self.woke.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(Tainted::trusted(json!({ "awake": true }))))
    }
}

/// An orphaned durable sleep is re-armed by the resume.
///
/// The journal announces `timer.sleep`; the timer store holds nothing — the
/// crash landed between announce and arm. Without repair the run is stranded:
/// the sweep's own tick proves it, firing nothing. A resume must re-arm the
/// recorded instant under the same key, after which the ordinary wake path
/// completes the run — and the journal must hold exactly one announcement for
/// the sleep, because the repair is a re-registration, not a second wait.
#[tokio::test]
async fn an_orphaned_sleep_is_rearmed_on_resume_and_then_fires() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let woke = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .timers(store.clone() as Arc<dyn TimerStore>)
        .skill(Naps {
            woke: Arc::clone(&woke),
        })
        .build();

    let out = rt
        .run("demo.nap", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(out.status.is_suspended(), "got {:?}", out.status);
    assert_eq!(store.armed_timers(out.run_id).await.unwrap(), 1);

    // The crash between announce and arm, manufactured: the announcement
    // stands, the registration is gone.
    let key = wait_key(&store, out.run_id, "timer.sleep").await;
    (store.clone() as Arc<dyn TimerStore>)
        .disarm(out.run_id, key)
        .await
        .unwrap();

    // Stranded for real: nothing fires, however late the sweep runs. This is
    // the state the repair exists for, and it is also the fixture's proof —
    // the positive half below only means something because this tick found
    // nothing.
    let quiet = rt.fire_timers(later(3600)).await.unwrap();
    assert_eq!(quiet.fired, 0, "no timer exists to fire");
    assert_eq!(woke.load(Ordering::SeqCst), 0);

    // The resume finds the announced wait with no confirmable registration
    // and re-arms it, suspending as before.
    let resumed = rt.replay(out.run_id, Mode::Resume).await.unwrap();
    assert!(
        resumed.status.is_suspended(),
        "the run is healthy and waiting again: {:?}",
        resumed.status
    );
    assert_eq!(
        store.armed_timers(out.run_id).await.unwrap(),
        1,
        "the resume must re-arm the orphaned sleep — without this the run \
         sleeps forever and looks exactly like work in progress"
    );

    // The ordinary wake path finishes the run.
    let fired = rt.fire_timers(later(3600)).await.unwrap();
    assert_eq!(fired.fired, 1);
    assert_eq!(woke.load(Ordering::SeqCst), 1, "the run completed");
    assert!(
        (store.clone() as Arc<dyn JournalStore>)
            .runs_by_outcome("succeeded", 10)
            .await
            .unwrap()
            .contains(&out.run_id)
    );
    assert_eq!(
        announcements(&store, out.run_id, "timer.sleep").await,
        1,
        "the repair re-registers; it must not announce the wait a second time"
    );
    store.verify(out.run_id).await.unwrap();
}

// ── Event waits ─────────────────────────────────────────────────────────────

/// Waits for an approval, then finishes.
#[derive(Debug)]
struct AwaitsApproval {
    done: Arc<AtomicUsize>,
    matter: &'static str,
}

#[async_trait::async_trait]
impl Skill for AwaitsApproval {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("awaits").provides("demo.await")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("window", &DeadlineSpec::days(1), None).await?;
        let v = cx
            .await_event(
                &AwaitSpec::new("go.ahead", "window")
                    .correlate(CorrelationKey::new("matter", self.matter)),
            )
            .await?;
        self.done.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(v))
    }
}

fn await_plan() -> agentplane::core::PlanIR {
    use agentplane::core::{ArgSource, PlanIR, PlanNode};
    PlanIR::new(vec![
        PlanNode::new(0, "demo.await")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ])
}

/// An orphaned event wait is re-subscribed by the resume.
///
/// Same window, other store: the wait is announced and the subscription is
/// gone. Later events for the correlation would buffer until they dead-letter
/// while the run sleeps unfindable. The resume re-walks the registration —
/// subscription back under the same key, no second announcement — and a
/// delivery afterwards resumes the run to completion, which is only possible
/// through a live subscription. The healthy neighbour run is the fixture's
/// positive half: the same delivery shape resumes it with no repair involved.
#[tokio::test]
async fn an_orphaned_event_wait_is_resubscribed_on_resume() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let done = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(AwaitsApproval {
            done: Arc::clone(&done),
            matter: "M-1",
        })
        .build();

    let out = rt
        .run_plan_correlated(
            await_plan(),
            Tainted::trusted(json!({})),
            "matter",
            &[CorrelationKey::new("matter", "M-1")],
        )
        .await
        .unwrap();
    assert!(out.status.is_suspended(), "got {:?}", out.status);

    // The crash window, manufactured: announced, not subscribed.
    let key = wait_key(&store, out.run_id, "event.await").await;
    (store.clone() as Arc<dyn EventStore>)
        .unsubscribe(out.run_id, key)
        .await
        .unwrap();

    // The resume re-registers and suspends again.
    let resumed = rt.replay(out.run_id, Mode::Resume).await.unwrap();
    assert!(
        resumed.status.is_suspended(),
        "the run is waiting again: {:?}",
        resumed.status
    );

    // A delivery completes the run — possible only through a subscription, so
    // this is the assertion that the resume re-registered it.
    let delivery = rt
        .deliver(
            &InboundEvent::new(
                "urn:test:approver",
                "EV-1",
                "go.ahead",
                json!({ "ok": true }),
            )
            .correlate(CorrelationKey::new("matter", "M-1")),
        )
        .await
        .unwrap();
    assert_eq!(
        delivery,
        Delivery::Resumed { run: out.run_id },
        "the delivery found no waiter — the resume did not re-register the \
         orphaned subscription, and the event will sit buffered until it \
         dead-letters"
    );
    assert_eq!(done.load(Ordering::SeqCst), 1, "the run finished");
    assert_eq!(
        announcements(&store, out.run_id, "event.await").await,
        1,
        "re-registration must not announce the wait a second time"
    );
    store.verify(out.run_id).await.unwrap();
}

// ── The wake path's lease handover ──────────────────────────────────────────

/// A journal store that counts lease acquisitions, so a test can see the
/// choreography rather than infer it. Everything else passes through.
#[derive(Debug)]
struct CountsAcquires {
    inner: Arc<dyn JournalStore>,
    acquires: AtomicUsize,
}

#[async_trait::async_trait]
impl JournalStore for CountsAcquires {
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }
    fn atomic(&self) -> Option<&dyn agentplane::journal::AtomicJournal> {
        self.inner.atomic()
    }
    fn tenant(&self) -> &str {
        self.inner.tenant()
    }
    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        self.inner.append(epoch, batch).await
    }
    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        self.inner.read(run, from).await
    }
    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }
    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
    }
    async fn case_history(
        &self,
        case: agentplane::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        self.inner.case_history(case, limit).await
    }
    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        self.inner.head(run).await
    }
    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        self.acquires.fetch_add(1, Ordering::SeqCst);
        self.inner.acquire(run, owner, ttl).await
    }
    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: Duration,
    ) -> Result<Lease, StoreError> {
        self.inner.renew(run, owner, epoch, ttl).await
    }
    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
        self.inner.release_lease(run, epoch).await
    }
    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.abandoned_runs(limit).await
    }
    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        self.inner.seal(run, epoch, outcome).await
    }
    async fn checkpoint(&self) -> Result<agentplane::journal::Checkpoint, StoreError> {
        self.inner.checkpoint().await
    }
    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError> {
        self.inner.consistency_proof(old_size).await
    }
    async fn inclusion_proof(
        &self,
        run: RunId,
    ) -> Result<Option<agentplane::journal::Inclusion>, StoreError> {
        self.inner.inclusion_proof(run).await
    }
    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }
    async fn cancellation(
        &self,
        run: RunId,
    ) -> Result<Option<agentplane::journal::Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}

/// Firing a due timer hands its lease to the resume instead of releasing and
/// re-acquiring — and releases it once the run concludes.
///
/// One acquisition for the whole wake: the count is the choreography made
/// visible. The old release-then-re-acquire spelling showed up here as a
/// second acquisition, and between its two halves lay the window this test
/// exists to keep closed — a *released* lease over a run whose timer was
/// already disarmed, which a crash turns into a run no queue in the system
/// names: the abandonment sweep lists only leases that expired while still
/// held. The positive half: the wake completes the run, and afterwards the
/// lease is genuinely free — another owner's claim succeeds, so the handover
/// did not trade the window for a stuck lease.
#[tokio::test]
async fn a_timer_wake_resumes_under_its_own_lease_and_releases_it_after() {
    let redb = Arc::new(RedbStore::open_in_memory().unwrap());
    let counted = Arc::new(CountsAcquires {
        inner: redb.clone() as Arc<dyn JournalStore>,
        acquires: AtomicUsize::new(0),
    });
    let woke = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(counted.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .timers(redb.clone() as Arc<dyn TimerStore>)
        .skill(Naps {
            woke: Arc::clone(&woke),
        })
        .build();

    let out = rt
        .run("demo.nap", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(out.status.is_suspended());

    // Count only the wake's choreography, not the admission's.
    counted.acquires.store(0, Ordering::SeqCst);

    let fired = rt.fire_timers(later(3600)).await.unwrap();
    assert_eq!((fired.fired, fired.failed), (1, 0));
    assert_eq!(woke.load(Ordering::SeqCst), 1, "the wake completed the run");
    assert_eq!(
        counted.acquires.load(Ordering::SeqCst),
        1,
        "the wake acquired more than once — the lease was released and \
         re-acquired around the resume, reopening the window in which a crash \
         leaves a released lease over an undriven run that the abandonment \
         sweep can never find"
    );

    // Concluded means released: a different owner can claim the run.
    let claim = (counted.clone() as Arc<dyn JournalStore>)
        .acquire(out.run_id, "someone-else", Duration::from_secs(30))
        .await;
    assert!(
        claim.is_ok(),
        "the handover must still hand the lease back at conclusion: {claim:?}"
    );
    assert!(
        (redb.clone() as Arc<dyn JournalStore>)
            .runs_by_outcome("succeeded", 10)
            .await
            .unwrap()
            .contains(&out.run_id)
    );
}
