//! Durable waits: suspension, delivery, and the race between them.
//!
//! A run sends a request and waits for a reply that may take days. The hard part
//! is not the waiting — it is that the reply can arrive at *any* moment,
//! including before the run reaches the wait at all.

#![cfg(feature = "redb")]
// Tests drive the runtime rather than run inside it, so establishing "now" here
// is the harness doing its job, not a step smuggling non-determinism past the
// journal.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::case::{CaseStore, EventStore};
use agentplane::core::{
    AwaitSpec, CorrelationKey, DeadlineSpec, Delivery, InboundEvent, Outcome, Skill,
    SkillDescriptor, SkillError, Tainted, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

// ── Fixtures ────────────────────────────────────────────────────────────────

fn key(v: &str) -> CorrelationKey {
    CorrelationKey::new("document", v)
}

/// Sends a request, registers an obligation, then waits for the reply.
///
/// The counter records how many times the *request* was actually sent, which
/// must stay at one across the suspension and every resume.
#[derive(Debug)]
struct RequestAndWait {
    sends: Arc<AtomicUsize>,
    doc: &'static str,
}

#[async_trait::async_trait]
impl Skill for RequestAndWait {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("request-and-wait").provides("demo.request")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let arguments = Tainted::trusted(Value::Null);
        cx.sink(
            agentplane::runtime::effects::Recorded::new("send-request")
                .counter(Arc::clone(&self.sends)),
            &arguments,
        )
        .await?;

        cx.deadline("reply", &DeadlineSpec::days(5), None).await?;

        // Propagated with `?`. Catching the suspension here would turn a
        // durable wait into a silent hang.
        let reply = cx
            .await_event(&AwaitSpec::new("reply.received", "reply").correlate(key(self.doc)))
            .await?;

        cx.meet_deadline("reply").await?;
        Ok(Outcome::done(reply))
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    sends: Arc<AtomicUsize>,
}

fn fixture(doc: &'static str) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let sends = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(RequestAndWait {
            sends: Arc::clone(&sends),
            doc,
        })
        .build();
    Fixture { store, rt, sends }
}

fn reply(id: &str, doc: &str, body: Value) -> InboundEvent {
    InboundEvent::new("urn:test:counterparty", id, "reply.received", body).correlate(key(doc))
}

// ── The happy path ──────────────────────────────────────────────────────────

/// A run that reaches a wait suspends, and delivery resumes it.
#[tokio::test]
async fn a_run_suspends_on_a_wait_and_resumes_on_delivery() {
    let f = fixture("D-1");

    let out =
        f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-1")])
            .await
            .unwrap();

    assert!(out.status.is_suspended(), "got {:?}", out.status);
    assert_eq!(
        f.sends.load(Ordering::SeqCst),
        1,
        "the request went out once"
    );

    // A suspended run holds no task and no connection — it is a row.
    let waiting = f.store.waiting(10).await.unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].run, out.run_id);

    let delivery =
        f.rt.deliver(&reply("EV-1", "D-1", json!({ "status": "accepted" })))
            .await
            .unwrap();

    assert_eq!(delivery, Delivery::Resumed { run: out.run_id });
    assert_eq!(
        f.sends.load(Ordering::SeqCst),
        1,
        "resuming must not re-send the request"
    );

    // The subscription is consumed.
    assert!(f.store.waiting(10).await.unwrap().is_empty());

    // The run reached its conclusion, and the obligation is satisfied.
    let records = f.store.read(out.run_id, 1).await.unwrap();
    let finished = records.iter().any(
        |r| matches!(r.kind(), RecordKind::StepFinished { outcome } if outcome == "succeeded"),
    );
    assert!(finished, "the resumed run must complete");
    f.store.verify(out.run_id).await.unwrap();
}

/// **The race this design exists for.**
///
/// The reply arrives *before* the run reaches its wait. A system that matches
/// subscriptions on arrival and discards on a miss would drop it, and the run
/// would then wait forever for something that already happened.
#[tokio::test]
async fn an_event_arriving_before_the_wait_is_not_lost() {
    let f = fixture("D-2");

    // Nothing is running yet.
    let delivery =
        f.rt.deliver(&reply("EV-2", "D-2", json!({ "status": "early" })))
            .await
            .unwrap();
    assert_eq!(
        delivery,
        Delivery::Buffered,
        "an event with no waiter is held, not dropped"
    );

    // Now the run starts and reaches the wait. It should find the reply already
    // waiting for it and never suspend at all.
    let out =
        f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-2")])
            .await
            .unwrap();

    assert_eq!(
        out.status,
        RunStatus::Succeeded,
        "the buffered event must satisfy the wait immediately"
    );
    assert_eq!(
        out.output,
        Some(json!({ "status": "early" })),
        "the run must receive the event that arrived early"
    );
    assert!(f.store.waiting(10).await.unwrap().is_empty());
}

/// Retries are harmless: the same event id is delivered once.
#[tokio::test]
async fn duplicate_delivery_is_a_no_op() {
    let f = fixture("D-3");
    f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-3")])
        .await
        .unwrap();

    let first = f.rt.deliver(&reply("EV-3", "D-3", json!(1))).await.unwrap();
    assert!(matches!(first, Delivery::Resumed { .. }));

    // The counterparty retries, as counterparties do.
    let second = f.rt.deliver(&reply("EV-3", "D-3", json!(1))).await.unwrap();
    assert_eq!(second, Delivery::Duplicate);
}

/// An event for a different key does not satisfy someone else's wait.
#[tokio::test]
async fn events_are_matched_by_correlation_not_by_kind_alone() {
    let f = fixture("D-4");
    let out =
        f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-4")])
            .await
            .unwrap();
    assert!(out.status.is_suspended());

    // Right kind, wrong document.
    let delivery =
        f.rt.deliver(&reply("EV-4", "SOMEONE-ELSE", json!(1)))
            .await
            .unwrap();
    assert_eq!(delivery, Delivery::Buffered);
    assert_eq!(
        f.store.waiting(10).await.unwrap().len(),
        1,
        "the run is still waiting for its own reply"
    );
}

/// One event resumes one run. Two runs waiting on the same key do not both
/// consume a single message.
#[tokio::test]
async fn an_event_is_delivered_to_exactly_one_waiter() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let sends = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(RequestAndWait {
            sends: Arc::clone(&sends),
            doc: "D-5",
        })
        .build();

    // Two runs, same correlation key, both waiting.
    let a = rt
        .run_in_case("demo.request", json!({}), "matter", &[key("D-5")])
        .await
        .unwrap();
    let b = rt
        .run_in_case("demo.request", json!({}), "matter", &[key("D-5")])
        .await
        .unwrap();
    assert!(a.status.is_suspended() && b.status.is_suspended());
    assert_eq!(store.waiting(10).await.unwrap().len(), 2);

    rt.deliver(&reply("EV-5", "D-5", json!(1))).await.unwrap();

    assert_eq!(
        store.waiting(10).await.unwrap().len(),
        1,
        "exactly one waiter consumed the event"
    );
}

// ── Dead letters ────────────────────────────────────────────────────────────

/// An event nobody claims within the window is dead-lettered — by the *sweep*,
/// not on arrival.
///
/// The distinction matters: "nobody is waiting yet" and "nobody will ever want
/// this" are different claims, and only the second is safe to act on.
#[tokio::test]
async fn unclaimed_events_are_dead_lettered_by_the_sweep_not_on_arrival() {
    let f = fixture("D-6");

    let orphan = reply("EV-6", "NOBODY-WAITS-FOR-THIS", json!({}));
    assert_eq!(f.rt.deliver(&orphan).await.unwrap(), Delivery::Buffered);
    assert!(
        f.store.dead_letters(10).await.unwrap().is_empty(),
        "arrival must not dead-letter: the waiter may not have started yet"
    );

    // With no grace period, everything already buffered ages out.
    let retired = f.rt.sweep_events(time::Duration::ZERO).await.unwrap();
    assert_eq!(retired, 1);

    let dead = f.store.dead_letters(10).await.unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].event.id, "EV-6");
    assert!(
        dead[0].reason.contains("grace"),
        "the reason must be diagnosable"
    );
}

/// The sweep does not retire an event a run is actively waiting for.
#[tokio::test]
async fn the_sweep_leaves_claimed_events_alone() {
    let f = fixture("D-7");
    f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-7")])
        .await
        .unwrap();
    f.rt.deliver(&reply("EV-7", "D-7", json!(1))).await.unwrap();

    let retired = f.rt.sweep_events(time::Duration::ZERO).await.unwrap();
    assert_eq!(retired, 0, "a consumed event is not garbage");
    assert!(f.store.dead_letters(10).await.unwrap().is_empty());
}

// ── Journal integrity across suspension ─────────────────────────────────────

/// A suspended run is not sealed: its chain is going to be extended.
#[tokio::test]
async fn a_suspended_run_is_not_sealed_and_records_why() {
    let f = fixture("D-8");
    let out =
        f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-8")])
            .await
            .unwrap();

    let records = f.store.read(out.run_id, 1).await.unwrap();
    let suspended = records
        .iter()
        .any(|r| matches!(r.kind(), RecordKind::RunSuspended { .. }));
    assert!(suspended, "the reason for stopping must be in the history");
    assert!(
        !records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::StepFinished { .. })),
        "a suspended step has not finished"
    );
    f.store.verify(out.run_id).await.unwrap();
}

/// After delivery, the whole run replays deterministically — the awaited event
/// is read back from the journal like any other recorded effect.
#[tokio::test]
async fn a_resumed_run_replays_strictly() {
    let f = fixture("D-9");
    let out =
        f.rt.run_in_case("demo.request", json!({}), "matter", &[key("D-9")])
            .await
            .unwrap();
    f.rt.deliver(&reply("EV-9", "D-9", json!({ "ok": true })))
        .await
        .unwrap();

    let before = f.sends.load(Ordering::SeqCst);
    let replayed = f.rt.replay(out.run_id, Mode::Strict).await.unwrap();

    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        f.sends.load(Ordering::SeqCst),
        before,
        "strict replay performs nothing, including the wait"
    );
    f.store.verify(out.run_id).await.unwrap();
}

/// An inbound event is external data and is labeled as such.
#[tokio::test]
async fn a_delivered_event_is_untrusted() {
    #[derive(Debug)]
    struct Inspects;

    #[async_trait::async_trait]
    impl Skill for Inspects {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("inspects").provides("demo.inspect")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("reply", &DeadlineSpec::days(1), None).await?;
            let ev = cx
                .await_event(&AwaitSpec::new("reply.received", "reply").correlate(key("D-10")))
                .await?;
            assert!(
                ev.label().is_untrusted(),
                "an inbound message is external data, whoever sent it"
            );
            Ok(Outcome::done(Tainted::trusted(json!("checked"))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(Inspects)
        .build();

    rt.run_in_case("demo.inspect", json!({}), "matter", &[key("D-10")])
        .await
        .unwrap();
    let out = rt
        .deliver(&reply("EV-10", "D-10", json!("payload")))
        .await
        .unwrap();
    assert!(matches!(out, Delivery::Resumed { .. }));
}

/// A wait must name a registered obligation. An unbounded wait is a run that can
/// hang forever with nothing to notice it.
#[tokio::test]
async fn a_wait_without_a_registered_deadline_is_refused() {
    #[derive(Debug)]
    struct Unbounded;

    #[async_trait::async_trait]
    impl Skill for Unbounded {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("unbounded").provides("demo.unbounded")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            // No `cx.deadline(...)` first.
            let ev = cx
                .await_event(&AwaitSpec::new("reply.received", "never-registered"))
                .await?;
            Ok(Outcome::done(ev))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(Unbounded)
        .build();

    let out = rt
        .run_in_case("demo.unbounded", json!({}), "matter", &[key("D-11")])
        .await
        .unwrap();

    match out.status {
        RunStatus::Failed(msg) => assert!(msg.contains("horizon"), "got: {msg}"),
        other => panic!("an unbounded wait must be refused, got {other:?}"),
    }
}

/// Delivery against a runtime with no event store is refused, not ignored.
#[tokio::test]
async fn delivery_without_an_event_store_is_refused() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>).build();
    let err = rt
        .deliver(&reply("EV-X", "D-X", json!({})))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("event store"), "got: {err}");
}

/// The buffer survives a wait that never comes, and the sweep reports what it
/// retired so the count can be alerted on.
#[tokio::test]
async fn the_sweep_reports_what_it_retired() {
    let f = fixture("D-12");
    for i in 0..3 {
        f.rt.deliver(&reply(&format!("EV-{i}"), "ORPHAN", json!(i)))
            .await
            .unwrap();
    }
    assert_eq!(f.rt.sweep_events(time::Duration::ZERO).await.unwrap(), 3);
    assert_eq!(f.store.dead_letters(10).await.unwrap().len(), 3);

    // Sweeping again finds nothing new.
    assert_eq!(f.rt.sweep_events(time::Duration::ZERO).await.unwrap(), 0);
}

/// A far-future grace window protects everything recently received.
#[tokio::test]
async fn the_grace_window_is_respected() {
    let f = fixture("D-13");
    f.rt.deliver(&reply("EV-13", "ORPHAN", json!({})))
        .await
        .unwrap();

    let retired = f.rt.sweep_events(time::Duration::days(30)).await.unwrap();
    assert_eq!(retired, 0, "recent events are still claimable");

    let _ = Timestamp::now_utc();
}

/// Waiting without an event store is refused with an actionable message, rather
/// than silently never resuming.
#[tokio::test]
async fn waiting_without_an_event_store_is_refused() {
    #[derive(Debug)]
    struct Waits;

    #[async_trait::async_trait]
    impl Skill for Waits {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("waits").provides("demo.waits")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("reply", &DeadlineSpec::days(1), None).await?;
            let ev = cx
                .await_event(&AwaitSpec::new("reply.received", "reply").correlate(key("D-14")))
                .await?;
            Ok(Outcome::done(ev))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    // Cases but no events: correlation and obligations work, waits do not.
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(Waits)
        .build();

    let out = rt
        .run_in_case("demo.waits", json!({}), "matter", &[key("D-14")])
        .await
        .unwrap();

    match out.status {
        RunStatus::Failed(msg) => assert!(msg.contains("event store"), "got: {msg}"),
        other => panic!("expected an actionable refusal, got {other:?}"),
    }
}

/// Cases work fully without an event store — only waits need one.
#[tokio::test]
async fn cases_do_not_require_an_event_store() {
    #[derive(Debug)]
    struct NoWait;

    #[async_trait::async_trait]
    impl Skill for NoWait {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("no-wait").provides("demo.nowait")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("obligation", &DeadlineSpec::days(1), None)
                .await?;
            cx.meet_deadline("obligation").await?;
            Ok(Outcome::done(input))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(NoWait)
        .build();

    let out = rt
        .run_in_case("demo.nowait", json!({}), "matter", &[key("D-15")])
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
}

/// **A wait in a later step resumes.**
///
/// Two bugs made this impossible, and both hid behind the same thing: every
/// other wait test uses a one-step plan, where a step's identity and the run's
/// coincide.
///
/// * Delivery journaled the awaited result under a hardcoded step zero, so a
///   wait anywhere else was recorded against the wrong step. Replay verifies
///   effects per step, so the resumed run never found it and suspended again.
/// * `resume_is_closed` scanned backwards for a `StepFinished` it recognised and
///   *skipped* ones it did not. A run whose later step was still outstanding
///   matched an earlier `succeeded` and was reported closed — so the resume
///   returned success without executing anything.
#[tokio::test]
async fn a_wait_in_a_later_step_resumes_and_completes() {
    use agentplane::core::{ArgSource, PlanIR, PlanNode, StepId};

    /// Step 0: does nothing but produce a value.
    #[derive(Debug)]
    struct First;

    #[async_trait::async_trait]
    impl Skill for First {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("first").provides("demo.first")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::done(Tainted::trusted(json!({ "step": 0 }))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let sends = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(First)
        .skill(RequestAndWait {
            doc: "D-LATE",
            sends: Arc::clone(&sends),
        })
        .build();

    // The wait lives in step 1, not step 0.
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "demo.first").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "demo.request")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ]);

    let out = rt
        .run_plan_in_case(plan, json!({}), "matter", &[key("D-LATE")])
        .await
        .unwrap();
    assert!(out.status.is_suspended(), "got {:?}", out.status);

    let delivery = rt
        .deliver(&reply("EV-LATE", "D-LATE", json!({ "status": "accepted" })))
        .await
        .unwrap();
    assert_eq!(delivery, Delivery::Resumed { run: out.run_id });
    assert_eq!(sends.load(Ordering::SeqCst), 1, "resuming must not re-send");

    let records = store.read(out.run_id, 1).await.unwrap();
    let sealed = records.iter().any(
        |r| matches!(r.kind(), RecordKind::RunSealed { outcome, .. } if outcome == "succeeded"),
    );
    assert!(
        sealed,
        "the resumed run must reach a conclusion, not suspend again"
    );
    store.verify(out.run_id).await.unwrap();
}

/// The sender is in the awaited value's provenance, live and on replay alike.
///
/// A sink may allow an authority-bearing field from `event:reply.received` in
/// general, or from one counterparty in particular — `sender:` is what makes the
/// second expressible. It is journaled rather than recomputed for the usual
/// reason: a replayed run that labelled the same value differently would reach a
/// different verdict at every taint gate downstream, which is divergence.
#[tokio::test]
async fn an_awaited_events_sender_is_in_its_provenance_and_survives_replay() {
    use agentplane::core::{Label, SourceId};
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Seen(Mutex<Vec<Label>>);

    #[derive(Debug)]
    struct Waits(Arc<Seen>);

    #[async_trait::async_trait]
    impl Skill for Waits {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("waits").provides("demo.request")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let reply = cx
                .await_event(&AwaitSpec::new("reply.received", "reply").correlate(key("DOC-77")))
                .await?;
            self.0.0.lock().expect("seen").push(reply.label().clone());
            Ok(Outcome::done(reply))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let seen = Arc::new(Seen::default());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(Waits(Arc::clone(&seen)))
        .build();

    let out = rt
        .run_in_case("demo.request", json!({}), "clearing", &[key("DOC-77")])
        .await
        .expect("run");
    rt.deliver(&reply("EV-77", "DOC-77", json!({ "status": "ok" })))
        .await
        .expect("deliver");

    let live = seen
        .0
        .lock()
        .expect("seen")
        .last()
        .cloned()
        .expect("a label");
    assert!(
        live.provenance
            .contains(&SourceId::new("event:reply.received")),
        "the event kind must be in provenance: {live:?}"
    );
    assert!(
        live.provenance
            .contains(&SourceId::new("sender:urn:test:counterparty")),
        "the sender must be in provenance, or a sink cannot say which \
         counterparty an authority-bearing field may come from: {live:?}"
    );

    // The whole point of journaling it: replay must label it identically.
    rt.replay(out.run_id, agentplane::runtime::Mode::Strict)
        .await
        .expect("replay");
    let replayed = seen
        .0
        .lock()
        .expect("seen")
        .last()
        .cloned()
        .expect("a label");
    assert_eq!(
        replayed, live,
        "a replayed run labelled the same value differently from the live one, \
         so every taint gate downstream may reach a different verdict"
    );
}
