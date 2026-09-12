//! Observability: proving the runtime says what it does.
//!
//! Principle P7 is *no silent anything*, and until something is emitted that is
//! an aspiration rather than a property. These tests assert on what a subscriber
//! actually **received** — not on what the source contains — because an
//! instrumentation test that greps is checking the author's intent rather than
//! the runtime's behaviour.

#![cfg(feature = "redb")]
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
use agentplane::store::RedbStore;
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
    /// Values written *after* a span opened, as `field=value`.
    ///
    /// Needed because an attribute the runtime only knows once it has the
    /// effect in hand — `gen_ai.operation.name` — is `record`ed rather than
    /// declared, and a recorder that drops `record` cannot see it at all.
    recorded: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    fn recorded(&self) -> Vec<String> {
        self.recorded.lock().unwrap().clone()
    }
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
        self.tree.lock().unwrap().push((name, parent));

        let mut next = self.next.lock().unwrap();
        *next += 1;
        let id = *next;
        span::Id::from_u64(id)
    }
    fn record(&self, _: &span::Id, values: &span::Record<'_>) {
        struct Capture<'a>(&'a Recorder);
        impl tracing::field::Visit for Capture<'_> {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0
                    .recorded
                    .lock()
                    .unwrap()
                    .push(format!("{}={v:?}", f.name()));
            }
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                self.0
                    .recorded
                    .lock()
                    .unwrap()
                    .push(format!("{}={v}", f.name()));
            }
        }
        values.record(&mut Capture(self));
    }
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

/// Two effects, distinct keys, so the second is the one a ceiling of one
/// refuses.
#[derive(Debug)]
struct Two(Scripted);

#[async_trait::async_trait]
impl Skill for Two {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("two").provides("demo.two")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let v = cx.effect(Numbered(self.0.clone(), 1)).await?;
        let _ = cx.effect(Numbered(self.0.clone(), 2)).await?;
        Ok(Outcome::done(v))
    }
}

/// `Scripted` under a distinct key, since exactly-once is keyed on the
/// descriptor and two identical ones are one effect.
#[derive(Debug, Clone)]
struct Numbered(Scripted, u8);

#[async_trait::async_trait]
impl Effect for Numbered {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(format!("test.op{}", self.1), json!(null))
    }
    fn mutates(&self) -> bool {
        self.0.mutates()
    }
    fn recovery(&self) -> Recovery {
        self.0.recovery()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        self.0.perform().await
    }
}

fn runtime(effect: Scripted) -> (Arc<RedbStore>, Arc<Runtime>) {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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

/// A run produces the three-level trace the design promises: one span per run, one
/// per step, one per effect attempt.
#[tokio::test]
async fn a_run_produces_run_step_and_effect_spans() {
    let rec = Recorder::default();
    let (_s, rt) = runtime(healthy());

    let _ambient = crate::ambient_subscriber();

    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt
        .run("demo.one", Tainted::trusted(json!({})))
        .await
        .unwrap();
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
    });

    let _ambient = crate::ambient_subscriber();

    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt
        .run("demo.one", Tainted::trusted(json!({})))
        .await
        .unwrap();
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

/// **Writing off an unexplained mutation is announced too.**
///
/// A person decided it, so an alert cannot tell them anything they do not know
/// — and they are not the audience. Whoever answers for what the run left
/// standing is somewhere else, and an intervention visible only to the person
/// who made it is not oversight. The lasting record is the `agentplane audit`
/// finding; this is the notification that one now exists.
#[tokio::test]
async fn abandoning_a_quarantined_run_emits_its_event() {
    let rec = Recorder::default();
    let (_s, rt) = runtime(Scripted {
        mutates: true,
        recovery: Recovery::RequiresOperator,
        fails: Some("timeout"),
    });

    let _ambient = crate::ambient_subscriber();
    let out = rt
        .run("demo.one", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Quarantined(_)));

    let guard = tracing::subscriber::set_default(rec.clone());
    let closed = rt
        .decide_quarantine(
            out.run_id,
            "ada",
            "two weeks of provider tickets; nobody can say",
            agentplane::core::QuarantineDecision::Abandon,
        )
        .await
        .unwrap();
    drop(guard);
    assert!(matches!(
        closed.status,
        agentplane::runtime::RunStatus::Abandoned { .. }
    ));

    let events = rec.events();
    assert!(
        events.iter().any(|e| e == telemetry::ABANDONED),
        "expected `{}`, got {events:?}",
        telemetry::ABANDONED
    );
}

/// A budget refusal is announced.
#[tokio::test]
async fn a_budget_refusal_emits_its_event() {
    use agentplane::core::Budget;

    let rec = Recorder::default();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    // A ceiling of one, reached by the *second* effect. A ceiling of zero would
    // be refused at build — it permits nothing at all, so the plane could never
    // run — and a run that never starts emits no budget event to observe.
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().effects(1))
        .skill(Two(healthy()))
        .build();

    let _ambient = crate::ambient_subscriber();

    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt
        .run("demo.two", Tainted::trusted(json!({})))
        .await
        .unwrap();
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
    let (_s, rt) = runtime(healthy());
    let first = rt
        .run("demo.one", Tainted::trusted(json!({})))
        .await
        .unwrap();

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

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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
    let out = rt
        .run_plan(plan, Tainted::trusted(json!({})))
        .await
        .unwrap();
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

// ── GenAI semantic conventions ──────────────────────────────────────────────

/// A skill whose one effect is a model completion.
///
/// Gated with its test: the fake provider lives in `testkit`, so the type
/// itself does not exist in a build without that feature.
#[cfg(feature = "testkit")]
#[derive(Debug)]
struct Asks(Arc<agentplane::testkit::FakeProvider>);

#[cfg(feature = "testkit")]
#[async_trait::async_trait]
impl Skill for Asks {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("asks").provides("demo.asks")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let prompt = Tainted::trusted(json!("hello"));
        let call = agentplane::model::ModelCall::new(
            Arc::clone(&self.0) as Arc<dyn agentplane::model::ModelProvider>,
            agentplane::model::ModelId::new("fake", "m"),
            prompt.peek().clone(),
        );
        cx.sink(call, &prompt).await?;
        Ok(Outcome::done(input))
    }
}

/// **A completion is reported as a `GenAI` operation, not just as an effect.**
///
/// `gen_ai.operation.name` is the attribute observability tooling keys on. A
/// span without it is emitted and still invisible *as an agent operation*, so a
/// trace would show the agent invocation and nothing about the model call
/// inside it — which is precisely the view an operator needs when a run gets
/// expensive or slow.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_model_call_is_reported_as_a_gen_ai_chat() {
    let rec = Recorder::default();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let provider = Arc::new(agentplane::testkit::FakeProvider::new());
    provider.will_say("ok");
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Asks(Arc::clone(&provider)))
        .build();

    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt
        .run("demo.asks", Tainted::trusted(json!({})))
        .await
        .unwrap();
    drop(guard);
    assert_eq!(out.status, RunStatus::Succeeded);

    let recorded = rec.recorded();
    let want = format!("{}={}", telemetry::GEN_AI_OPERATION, telemetry::GEN_AI_CHAT);
    assert!(
        recorded.contains(&want),
        "the model call's span carries no `{want}`; recorded: {recorded:?}"
    );

    // The operation name alone is not a `GenAI` span. Which model, of which
    // provider, at what cost is the whole reason the convention exists, and a
    // panel keyed on those reads blank as *no model* rather than *nothing
    // reports it*.
    for want in [
        format!("{}=fake", telemetry::GEN_AI_PROVIDER),
        format!("{}=m", telemetry::GEN_AI_REQUEST_MODEL),
    ] {
        assert!(
            recorded.contains(&want),
            "the model call's span carries no `{want}`; recorded: {recorded:?}"
        );
    }
    for key in [
        telemetry::GEN_AI_INPUT_TOKENS,
        telemetry::GEN_AI_OUTPUT_TOKENS,
    ] {
        assert!(
            recorded.iter().any(|r| r.starts_with(&format!("{key}="))),
            "the model call's span carries no `{key}`, so its cost is invisible \
             to the convention's own attribute; recorded: {recorded:?}"
        );
    }

    // And the tool key stays off a completion: `gen_ai.tool.name` on a chat
    // span would make every model call look like a tool invocation.
    assert!(
        !recorded
            .iter()
            .any(|r| r.starts_with(&format!("{}=", telemetry::GEN_AI_TOOL_NAME))),
        "a completion claimed a tool name: {recorded:?}"
    );

    // What the provider said about its own answer. The response model is the
    // one attribute the request half cannot stand in for: an alias that
    // resolves, or a deployment moved under a pinned name, is visible here and
    // nowhere else in a trace.
    for want in [
        format!("{}=m", telemetry::GEN_AI_RESPONSE_MODEL),
        format!("{}=end_turn", telemetry::GEN_AI_FINISH_REASON),
    ] {
        assert!(
            recorded.contains(&want),
            "the model call's span carries no `{want}`; recorded: {recorded:?}"
        );
    }
    for key in [
        telemetry::GEN_AI_CACHE_READ_TOKENS,
        telemetry::GEN_AI_CACHE_WRITE_TOKENS,
    ] {
        assert!(
            recorded.iter().any(|r| r.starts_with(&format!("{key}="))),
            "the model call's span carries no `{key}`, so a deployment cannot \
             tell cached input from fresh — and the two are billed about an \
             order of magnitude apart; recorded: {recorded:?}"
        );
    }
}

/// **A failed attempt says what class of thing went wrong.**
///
/// `agentplane.outcome` says *whether* the attempt succeeded, which makes a
/// failure countable and nothing more. The convention asks for `error.type` on
/// any operation that ends in error, and without it every `GenAI` panel reports
/// a plane with no failures at all — the one claim this runtime exists not to
/// make. The value is the fault class, so "which driver fails how" is a
/// group-by rather than a search through rendered prose.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_failed_attempt_names_the_class_of_fault() {
    let rec = Recorder::default();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let provider = Arc::new(agentplane::testkit::FakeProvider::new());
    provider.will_fail(agentplane::model::ModelError::Refused {
        model: agentplane::model::ModelId::new("fake", "m"),
        detail: "no".to_owned(),
    });
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Asks(Arc::clone(&provider)))
        .build();

    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(rec.clone());
    let _ = rt.run("demo.asks", Tainted::trusted(json!({}))).await;
    drop(guard);

    let recorded = rec.recorded();
    let want = format!("{}=refused", telemetry::ERROR_TYPE);
    assert!(
        recorded.contains(&want),
        "a failed attempt carries no `{want}`, so its span says only that \
         something went wrong; recorded: {recorded:?}"
    );
}

/// **An erased effect reports what a typed one does.**
///
/// `Box<dyn AnyEffect>` implements `Effect` so an undo and a group member travel
/// the same dispatch path as anything else — the module doc says so in those
/// words. Every `Effect` method has a default, so a seam the erasure does not
/// forward silently answers that default, and the same call opens a span naming
/// a model when it is typed and naming nothing when it is boxed.
///
/// Asserted through a subscriber rather than by reading the source, because the
/// sibling guard in `tests/guards/layering.rs` already reads the source and the
/// question here is whether the value arrives.
#[tokio::test]
async fn an_erased_effect_reports_what_a_typed_one_does() {
    struct Erasable;
    #[async_trait::async_trait]
    impl Effect for Erasable {
        type Output = Value;
        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::nullary("test.erased")
        }
        fn mutates(&self) -> bool {
            false
        }
        fn gen_ai_operation(&self) -> Option<&'static str> {
            Some(telemetry::GEN_AI_CHAT)
        }
        fn gen_ai_request(&self) -> Option<agentplane::core::GenAiRequest> {
            Some(agentplane::core::GenAiRequest {
                provider: Some("erased".to_owned()),
                name: "boxed-1".to_owned(),
            })
        }
        fn gen_ai_response(&self, _: &Value) -> Option<agentplane::core::GenAiResponse> {
            Some(agentplane::core::GenAiResponse {
                model: Some("boxed-1-served".to_owned()),
                finish_reason: Some("end_turn".to_owned()),
                input_tokens: 7,
                output_tokens: 3,
                ..agentplane::core::GenAiResponse::default()
            })
        }
        async fn perform(&self) -> Result<Value, EffectError> {
            Ok(json!("ok"))
        }
    }

    #[derive(Debug)]
    struct Boxes;
    #[async_trait::async_trait]
    impl Skill for Boxes {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("boxes").provides("demo.boxes")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let erased: Box<dyn agentplane::core::AnyEffect> = Box::new(Erasable);
            cx.effect(erased).await?;
            Ok(Outcome::done(input))
        }
    }

    let rec = Recorder::default();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Boxes)
        .build();

    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt
        .run("demo.boxes", Tainted::trusted(json!({})))
        .await
        .unwrap();
    drop(guard);
    assert_eq!(out.status, RunStatus::Succeeded);

    let recorded = rec.recorded();
    for want in [
        format!("{}=erased", telemetry::GEN_AI_PROVIDER),
        format!("{}=boxed-1", telemetry::GEN_AI_REQUEST_MODEL),
        format!("{}=boxed-1-served", telemetry::GEN_AI_RESPONSE_MODEL),
        format!("{}=7", telemetry::GEN_AI_INPUT_TOKENS),
    ] {
        assert!(
            recorded.contains(&want),
            "an erased effect's span carries no `{want}`, so the erasure answers \
             the trait's default where a typed effect answers its own; \
             recorded: {recorded:?}"
        );
    }
}

/// **An effect that is not a `GenAI` operation does not claim to be one.**
///
/// Stated separately because the opposite defect is just as bad and would pass
/// the test above: labelling a clock read or a case-state write as `chat` makes
/// the attribute meaningless, and every dashboard built on it wrong.
#[tokio::test]
async fn an_ordinary_effect_carries_no_gen_ai_operation() {
    let rec = Recorder::default();
    let (_s, rt) = runtime(healthy());

    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(rec.clone());
    let out = rt
        .run("demo.one", Tainted::trusted(json!({})))
        .await
        .unwrap();
    drop(guard);
    assert_eq!(out.status, RunStatus::Succeeded);

    let recorded = rec.recorded();
    assert!(
        !recorded
            .iter()
            .any(|r| r.starts_with(telemetry::GEN_AI_OPERATION)),
        "a non-GenAI effect was labelled as one: {recorded:?}"
    );
}
