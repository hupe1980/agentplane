//! Observability: proving the runtime says what it does.
//!
//! Principle P7 is *no silent anything*, and until something is emitted that is
//! an aspiration rather than a property. These tests assert on what a subscriber
//! actually **received** — not on what the source contains — because an
//! instrumentation test that greps is checking the author's intent rather than
//! the runtime's behaviour.

#![cfg(feature = "turso")]
#![allow(clippy::disallowed_methods)]
// Holding a `std::sync::Mutex` across an `.await` is normally a deadlock risk,
// and here it is the point: the lock must span the whole run, because what it
// serialises is an ambient `tracing` subscriber that the run's events dispatch
// to. Each `#[tokio::test]` builds its own current-thread runtime, so there is
// no second task on this runtime to contend for it.
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Effect, EffectDescriptor, EffectError, Outcome, Recovery, RetryPolicy, Skill, SkillDescriptor,
    SkillError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx, telemetry};
use agentplane::store::TursoStore;
use serde_json::{Value, json};
use tracing::{Event, Metadata, Subscriber, span};

/// A span and the span it was created inside.
type Parented = (String, Option<String>);

/// Records the spans and events a run produced, and how they nested.
///
/// Parentage is tracked by maintaining the enter/exit stack the way a real
/// subscriber does, because "is the trace tree correct" cannot be answered from
/// a flat list of names.
#[derive(Debug, Default, Clone)]
struct Recorder {
    spans: Arc<Mutex<Vec<String>>>,
    events: Arc<Mutex<Vec<String>>>,
    /// `(span, its parent at creation)`.
    tree: Arc<Mutex<Vec<Parented>>>,
    /// Currently entered, innermost last.
    stack: Arc<Mutex<Vec<(u64, String)>>>,
    next: Arc<Mutex<u64>>,
}

impl Recorder {
    fn spans(&self) -> Vec<String> {
        self.spans.lock().unwrap().clone()
    }
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
    fn tree(&self) -> Vec<Parented> {
        self.tree.lock().unwrap().clone()
    }
    /// Spans still entered once the run is over. A non-empty stack means a
    /// guard outlived the work it was describing.
    fn still_entered(&self) -> Vec<String> {
        self.stack
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| n.clone())
            .collect()
    }
}

impl Subscriber for Recorder {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
        let name = attrs.metadata().name().to_owned();
        self.spans.lock().unwrap().push(name.clone());
        let parent = self.stack.lock().unwrap().last().map(|(_, n)| n.clone());
        self.tree.lock().unwrap().push((name.clone(), parent));

        let mut next = self.next.lock().unwrap();
        *next += 1;
        let id = *next;
        span::Id::from_u64(id)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        self.events
            .lock()
            .unwrap()
            .push(event.metadata().target().to_owned());
    }
    fn enter(&self, id: &span::Id) {
        let name = self
            .tree
            .lock()
            .unwrap()
            .get(usize::try_from(id.into_u64() - 1).unwrap_or(usize::MAX))
            .map_or_else(|| "?".to_owned(), |(n, _)| n.clone());
        self.stack.lock().unwrap().push((id.into_u64(), name));
    }
    fn exit(&self, id: &span::Id) {
        let mut stack = self.stack.lock().unwrap();
        if let Some(pos) = stack.iter().rposition(|(i, _)| *i == id.into_u64()) {
            stack.remove(pos);
        }
    }
}

/// An effect that can be told to fail in a specific way.
#[derive(Debug, Clone)]
struct Scripted {
    mutates: bool,
    recovery: Recovery,
    fails: Option<&'static str>,
}

#[async_trait::async_trait]
impl Effect for Scripted {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.op", json!(null))
    }
    fn mutates(&self) -> bool {
        self.mutates
    }
    fn recovery(&self) -> Recovery {
        self.recovery.clone()
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        match self.fails {
            None => Ok(json!({ "ok": true })),
            Some("timeout") => Err(EffectError::Timeout {
                driver: "t".into(),
                waited_ms: 1,
            }),
            Some(_) => Err(EffectError::Rejected("no".into())),
        }
    }
}

#[derive(Debug)]
struct One(Scripted);

#[async_trait::async_trait]
impl Skill for One {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("one").provides("demo.one")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let v = cx.effect(self.0.clone()).await?;
        Ok(Outcome::done(v))
    }
}

async fn runtime(effect: Scripted) -> (Arc<TursoStore>, Runtime) {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .skill(One(effect))
        .build();
    (store, rt)
}

fn healthy() -> Scripted {
    Scripted {
        mutates: false,
        recovery: Recovery::Retry,
        fails: None,
    }
}

// ── Spans ───────────────────────────────────────────────────────────────────

/// A run produces the three-level trace §16.6 promises: one span per run, one
/// per step, one per effect attempt.
#[tokio::test]
async fn a_run_produces_run_step_and_effect_spans() {
    let rec = Recorder::default();
    let (_s, rt) = runtime(healthy()).await;

    let _ambient = crate::ambient_subscriber();

    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt.run("demo.one", json!({})).await.unwrap();
    drop(guard);
    assert_eq!(out.status, RunStatus::Succeeded);

    let spans = rec.spans();
    for expected in [
        telemetry::RUN_SPAN,
        telemetry::STEP_SPAN,
        telemetry::EFFECT_SPAN,
    ] {
        assert!(
            spans.iter().any(|s| s == expected),
            "no `{expected}` span was emitted; got {spans:?}"
        );
    }
}

// ── The loud events ─────────────────────────────────────────────────────────

/// **An undecidable outcome is announced, not just returned.**
///
/// A mutating call that timed out is the case the whole recovery design exists
/// for. An operator has to learn about it from the telemetry, not by noticing a
/// run stopped.
#[tokio::test]
async fn an_undecidable_outcome_emits_its_event() {
    let rec = Recorder::default();
    let (_s, rt) = runtime(Scripted {
        mutates: true,
        recovery: Recovery::RequiresOperator,
        fails: Some("timeout"),
    })
    .await;

    let _ambient = crate::ambient_subscriber();

    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt.run("demo.one", json!({})).await.unwrap();
    drop(guard);
    assert!(matches!(out.status, RunStatus::Quarantined(_)));

    let events = rec.events();
    assert!(
        events.iter().any(|e| e == telemetry::UNDECIDABLE),
        "expected `{}`, got {events:?}",
        telemetry::UNDECIDABLE
    );
    assert!(
        events.iter().any(|e| e == telemetry::QUARANTINED),
        "a quarantined run must announce itself; got {events:?}"
    );
}

/// A budget refusal is announced.
#[tokio::test]
async fn a_budget_refusal_emits_its_event() {
    use agentplane::core::Budget;

    let rec = Recorder::default();
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().effects(0))
        .skill(One(healthy()))
        .build();

    let _ambient = crate::ambient_subscriber();

    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt.run("demo.one", json!({})).await.unwrap();
    drop(guard);
    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "got {:?}",
        out.status
    );

    let events = rec.events();
    assert!(
        events.iter().any(|e| e == telemetry::BUDGET_REFUSED),
        "expected `{}`, got {events:?}",
        telemetry::BUDGET_REFUSED
    );
}

// ── Replay must be distinguishable ──────────────────────────────────────────

/// **A replayed effect is marked as replayed.**
///
/// A replayed run re-executes its skills, so it emits spans again. Without the
/// distinction an operator sees each run twice, and a metric like "effect
/// latency by driver" silently averages real calls with journal reads.
#[tokio::test]
async fn a_replayed_effect_is_not_reported_as_a_real_call() {
    let (_s, rt) = runtime(healthy()).await;
    let first = rt.run("demo.one", json!({})).await.unwrap();

    let rec = Recorder::default();
    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(rec.clone());
    rt.replay(first.run_id, Mode::Strict).await.unwrap();
    drop(guard);

    // The effect span belongs to the live path only. On replay the effect is
    // read back and reported as an event carrying `replayed = true`, so the two
    // can never be summed together by accident.
    let spans = rec.spans();
    assert!(
        !spans.iter().any(|s| s == telemetry::EFFECT_SPAN),
        "a journal read must not look like a performed effect; got {spans:?}"
    );
    assert!(
        spans.iter().any(|s| s == telemetry::RUN_SPAN),
        "the replay itself is still traced; got {spans:?}"
    );
}

// ── The trace tree must survive concurrency ─────────────────────────────────

/// **Each effect belongs to the step that performed it.**
///
/// This is the test that catches a span guard held across an `.await`. Holding
/// `Entered` across a suspension point leaves the span entered on that *thread*,
/// so when the future yields, whatever runs next is attributed to it. With
/// sequential dispatch that is invisible — there is only ever one step in
/// flight. With two siblings running at once it silently reparents their
/// effects, and every latency attribution downstream is wrong.
///
/// The fix is `Instrument`, which attaches the span to the *future* rather than
/// to the thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_steps_do_not_capture_each_others_spans() {
    use agentplane::core::{ArgSource, PlanIR, PlanNode, StepId};

    #[derive(Debug)]
    struct Chatty(&'static str);

    #[async_trait::async_trait]
    impl Skill for Chatty {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.0).provides(self.0)
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            for _ in 0..3 {
                cx.effect(healthy()).await?;
                tokio::task::yield_now().await;
            }
            Ok(Outcome::done(Tainted::trusted(json!({ "s": self.0 }))))
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

    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Chatty("left"))
        .skill(Chatty("right"))
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

    let rec = Recorder::default();
    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt.run_plan(plan, json!({})).await.unwrap();
    drop(guard);
    assert_eq!(out.status, RunStatus::Succeeded);

    // Every effect span's parent is a step span — never another effect, and
    // never the run directly.
    for (name, parent) in rec.tree() {
        if name == telemetry::EFFECT_SPAN {
            assert_eq!(
                parent.as_deref(),
                Some(telemetry::STEP_SPAN),
                "an effect span was parented to {parent:?} instead of its step \
                 — a span guard is leaking across an await"
            );
        }
        if name == telemetry::STEP_SPAN {
            assert_eq!(
                parent.as_deref(),
                Some(telemetry::RUN_SPAN),
                "a step span was parented to {parent:?} instead of the run"
            );
        }
    }

    assert!(
        rec.still_entered().is_empty(),
        "spans were left entered after the run finished: {:?}",
        rec.still_entered()
    );
}
