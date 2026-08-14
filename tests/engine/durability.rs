//! The properties the runtime exists to provide.
//!
//! Each test here corresponds to a claim that would otherwise be marketing.
//! If one of these regresses, the value proposition is gone regardless of what
//! else still works.

// These exercise the runtime end to end, which needs a store. Gated so
// `--no-default-features` still builds and tests cleanly: an embedder who
// brings their own backend must not be forced to compile SQLite.
#![cfg(feature = "redb")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{
    Digest, Outcome, Release, ReleaseScope, Sensitivity, Skill, SkillDescriptor, SourceId,
    StepError, Tainted,
};
use agentplane::journal::{JournalStore, Record, RecordKind};
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

// ── Test skills ─────────────────────────────────────────────────────────────

/// Performs one externally visible effect and counts real invocations.
#[derive(Debug)]
struct CallsTool {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for CallsTool {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("calls-tool").provides("demo.call")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let arguments = Tainted::trusted(Value::Null);
        let out = cx
            .sink(
                Recorded::new("post").counter(Arc::clone(&self.calls)),
                &arguments,
            )
            .await
            .map_err(agentplane::core::SkillError::Step)?;
        // The label joins: this step's output derives from its input *and*
        // from what the effect returned, so it carries whichever is less trusted.
        Ok(Outcome::done(input.zip(out).map(|(_, o)| o)))
    }
}

/// Performs a number of effects that depends on a runtime-settable knob — used
/// to simulate a code change between the recorded run and the replay.
#[derive(Debug)]
struct VariableEffects {
    count: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for VariableEffects {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("variable").provides("demo.variable")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let n = self.count.load(Ordering::SeqCst);
        for i in 0..n {
            let arguments = Tainted::trusted(Value::Null);
            cx.sink(
                Recorded::new(format!("step-{i}")).counter(Arc::clone(&self.calls)),
                &arguments,
            )
            .await
            .map_err(agentplane::core::SkillError::Step)?;
        }
        Ok(Outcome::done(input))
    }
}

/// Reads the journaled clock twice and returns both instants.
#[derive(Debug)]
struct ReadsClock;

#[async_trait::async_trait]
impl Skill for ReadsClock {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("reads-clock").provides("demo.clock")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let a = cx.now().await.map_err(agentplane::core::SkillError::Step)?;
        let b = cx.now().await.map_err(agentplane::core::SkillError::Step)?;
        Ok(Outcome::done(Tainted::trusted(
            json!({ "first": a.to_string(), "second": b.to_string() }),
        )))
    }
}

/// Tries to push a labeled value into a sink.
#[derive(Debug)]
struct SinksLabeled {
    label_sensitivity: Sensitivity,
    ceiling: Sensitivity,
    untrusted: bool,
    mutating: bool,
}

#[async_trait::async_trait]
impl Skill for SinksLabeled {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("sinks").provides("demo.sink")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let value = if self.untrusted {
            Tainted::from_source(json!("payload"), SourceId::new("tool://external"))
        } else {
            Tainted::trusted(json!("payload"))
        };
        let label = value
            .label()
            .clone()
            .with_sensitivity(self.label_sensitivity);
        let value = Tainted::with_label(value.peek().clone(), label);

        let mut sink = Recorded::new("sink")
            .payload(value.peek().clone())
            .ceiling(self.ceiling);
        if !self.mutating {
            sink = sink.read_only();
        }

        let out = cx
            .sink(sink, &value)
            .await
            .map_err(agentplane::core::SkillError::Step)?;
        Ok(Outcome::done(out))
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn store() -> Arc<dyn JournalStore> {
    Arc::new(RedbStore::open_in_memory().expect("open in-memory store"))
}

fn count_kind(records: &[Record], want: &str) -> usize {
    records
        .iter()
        .filter(|r| r.kind().kind_str() == want)
        .count()
}

// ── The claims ──────────────────────────────────────────────────────────────

/// **The headline property.** A replayed run does not re-perform its effects.
///
/// This is what separates a durable runtime from a retry loop: resuming a
/// 40-minute run that died at minute 38 must not re-issue the invoice it
/// already issued.
#[tokio::test]
async fn replay_does_not_re_perform_effects() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store())
        .skill(CallsTool {
            calls: Arc::clone(&calls),
        })
        .build();

    let first = rt
        .run("calls-tool", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the live run performs the effect once"
    );

    for _ in 0..5 {
        let replayed = rt.replay(first.run_id, Mode::Strict).await.unwrap();
        assert_eq!(replayed.status, RunStatus::Succeeded);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "five replays must not touch the outside world even once"
    );
}

/// Replay reproduces outputs exactly, including values that came from outside.
#[tokio::test]
async fn replay_reproduces_the_recorded_output() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store())
        .skill(CallsTool {
            calls: Arc::clone(&calls),
        })
        .build();

    let first = rt
        .run("calls-tool", Tainted::trusted(json!({"x": 1})))
        .await
        .unwrap();
    let again = rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(first.output, again.output);
    assert_eq!(
        first.chain_head, again.chain_head,
        "verification must not extend the chain"
    );
}

/// A replayed clock returns the instant the *original* run saw.
///
/// Without this, a replayed run makes different time-dependent decisions than
/// the run it claims to reproduce — and the audit trail becomes fiction.
#[tokio::test]
async fn the_clock_is_journaled_not_re_read() {
    let rt = Runtime::builder(store()).skill(ReadsClock).build();

    let first = rt
        .run("reads-clock", Tainted::trusted(json!({})))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let again = rt.replay(first.run_id, Mode::Strict).await.unwrap();

    assert_eq!(
        first.output, again.output,
        "replay must see the original instants, not the current ones"
    );
}

/// Two clock reads at different ordinals are distinct effects, not one memoized
/// value — otherwise a skill could not measure elapsed time.
#[tokio::test]
async fn effects_at_different_ordinals_are_distinct() {
    let rt = Runtime::builder(store()).skill(ReadsClock).build();
    let out = rt
        .run("reads-clock", Tainted::trusted(json!({})))
        .await
        .unwrap();
    let records = rt.store().read(out.run_id, 1).await.unwrap();
    assert_eq!(count_kind(&records, "EffectStarted"), 2);
    assert_eq!(count_kind(&records, "EffectDone"), 2);
}

/// **Divergence is loud.** A build that performs *more* effects than the record
/// is quarantined, not quietly accepted.
///
/// Ordered key comparison cannot catch this on its own: there is nothing left in
/// history to disagree with. Strict mode treats running past the end as the
/// divergence it is.
#[tokio::test]
async fn strict_replay_rejects_a_build_that_does_more_than_the_record() {
    let count = Arc::new(AtomicUsize::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store())
        .skill(VariableEffects {
            count: Arc::clone(&count),
            calls: Arc::clone(&calls),
        })
        .build();

    let first = rt
        .run("variable", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);

    // Simulate shipping a change that adds a step.
    count.store(2, Ordering::SeqCst);

    let replayed = rt.replay(first.run_id, Mode::Strict).await.unwrap();
    match replayed.status {
        RunStatus::Quarantined(msg) => assert!(
            msg.contains("replay overrun"),
            "expected an overrun diagnosis, got: {msg}"
        ),
        other => panic!("divergence must quarantine, got {other:?}"),
    }
}

/// A build that performs *different* effects is caught by key comparison.
#[tokio::test]
async fn strict_replay_rejects_a_build_that_does_something_different() {
    let count = Arc::new(AtomicUsize::new(2));
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store())
        .skill(VariableEffects {
            count: Arc::clone(&count),
            calls: Arc::clone(&calls),
        })
        .build();

    let first = rt
        .run("variable", Tainted::trusted(json!({})))
        .await
        .unwrap();

    // Fewer effects: the second recorded key is never requested. That is
    // divergence just as surely as a mismatched key — this build is a
    // different program from the one that wrote the record — and it is the
    // direction ordered comparison alone cannot see, because there is nothing
    // left to compare against. Strict verification must therefore check
    // consumption: a pass that reported `Succeeded` here was confirming a
    // history it had only read half of.
    count.store(1, Ordering::SeqCst);
    let replayed = rt.replay(first.run_id, Mode::Strict).await.unwrap();
    match replayed.status {
        RunStatus::Quarantined(msg) => assert!(
            msg.contains("never requested"),
            "the finding must name the first unconsumed effect: {msg}"
        ),
        other => panic!(
            "a build performing fewer effects than the record passed strict \
             verification: {other:?}"
        ),
    }

    // Whereas performing a *differently named* effect at the same position is
    // caught immediately by the key.
    let other = Runtime::builder(rt.store().clone())
        .skill(CallsTool {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .build();
    let err = other.replay(first.run_id, Mode::Strict).await;
    assert!(
        err.is_err(),
        "a journal written by a different skill must not resolve"
    );
}

/// **Exactly-once is a database invariant.**
///
/// Not a code path someone might forget to call: the unique index rejects a
/// second start for one effect key, so the guarantee survives a caller that
/// bypasses the runtime entirely.
#[tokio::test]
async fn the_store_refuses_a_duplicate_effect_start() {
    use agentplane::core::{EffectDescriptor, EffectKey, Recovery, RunId};
    use agentplane::journal::Append;

    let s = RedbStore::open_in_memory().unwrap();
    let run = RunId::generate();
    let lease = s
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    let key = EffectKey::from_hex(&Digest::of(b"same").to_hex()).unwrap();

    let started = || RecordKind::EffectStarted {
        descriptor: EffectDescriptor::nullary("tool.call"),
        recovery: Recovery::RequiresOperator,
        mutates: true,
        attempt: 1,
        backoff_ms: 0,
        outbound_label: None,
    };

    s.append(lease.epoch, vec![Append::new(run, started()).effect(key)])
        .await
        .unwrap();
    let err = s
        .append(lease.epoch, vec![Append::new(run, started()).effect(key)])
        .await
        .unwrap_err();

    assert!(
        matches!(err, agentplane::core::StoreError::DuplicateEffect(_)),
        "the engine itself must refuse a second start, got {err:?}"
    );
}

/// **Fencing.** A stale writer cannot append after losing its lease.
///
/// The check happens inside the append transaction, so there is no window
/// between "am I still the owner?" and the write for a paused instance to
/// squeeze through.
#[tokio::test]
async fn a_fenced_writer_cannot_append() {
    use agentplane::core::RunId;
    use agentplane::journal::Append;

    let s = RedbStore::open_in_memory().unwrap();
    let run = RunId::generate();

    // Instance A takes a lease that expires immediately.
    let a = s
        .acquire(run, "instance-a", std::time::Duration::from_secs(0))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Instance B takes over; the epoch advances.
    let b = s
        .acquire(run, "instance-b", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    assert!(b.epoch > a.epoch, "takeover must advance the fencing epoch");

    // A wakes up and tries to keep working.
    let err = s
        .append(
            a.epoch,
            vec![Append::new(
                run,
                RecordKind::StepStarted {
                    skill: "zombie".into(),
                },
            )],
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, agentplane::core::StoreError::Fenced { .. }),
        "the store must fence the stale writer, got {err:?}"
    );

    // B is unaffected.
    s.append(
        b.epoch,
        vec![Append::new(
            run,
            RecordKind::StepStarted {
                skill: "live".into(),
            },
        )],
    )
    .await
    .unwrap();
}

/// The chain verifies end to end, and every run seals to its terminal hash.
#[tokio::test]
async fn the_journal_chain_verifies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store()).skill(CallsTool { calls }).build();
    let out = rt
        .run("calls-tool", Tainted::trusted(json!({})))
        .await
        .unwrap();

    let head = rt.store().verify(out.run_id).await.unwrap();
    assert_eq!(
        head, out.chain_head,
        "the sealed head must be the verified head"
    );
}

/// Replay refuses to run against a journal that does not verify.
///
/// A tampered history could otherwise be used to "confirm" something that never
/// happened, which is worse than having no journal at all.
#[tokio::test]
async fn replay_refuses_a_tampered_journal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let s = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(s.clone())
        .skill(CallsTool { calls })
        .build();
    let out = rt
        .run("calls-tool", Tainted::trusted(json!({"v": 1})))
        .await
        .unwrap();

    // Edit a record's bytes behind the runtime's back.
    s.tamper_for_test(out.run_id, 1, br#"{"seq":1,"tampered":true}"#.to_vec())
        .await
        .unwrap();

    let err = rt.replay(out.run_id, Mode::Strict).await.unwrap_err();
    assert!(
        matches!(err, agentplane::core::RuntimeError::ChainBroken { .. }),
        "tampering must be refused, got {err:?}"
    );
}

/// **Egress ceiling.** A value may not enter a sink that is not cleared for it.
#[tokio::test]
async fn a_sink_refuses_data_above_its_ceiling() {
    let rt = Runtime::builder(store())
        .skill(SinksLabeled {
            label_sensitivity: Sensitivity::Secret,
            ceiling: Sensitivity::Internal,
            untrusted: false,
            mutating: false,
        })
        .build();

    let out = rt.run("sinks", Tainted::trusted(json!({}))).await.unwrap();
    match out.status {
        RunStatus::Failed(msg) => assert!(msg.contains("exceeds"), "got: {msg}"),
        other => panic!("expected the ceiling to reject, got {other:?}"),
    }
}

/// **Taint gate.** Untrusted data may not reach a mutating sink without release.
#[tokio::test]
async fn untrusted_data_cannot_reach_a_mutating_sink() {
    let rt = Runtime::builder(store())
        .skill(SinksLabeled {
            label_sensitivity: Sensitivity::Internal,
            ceiling: Sensitivity::Secret,
            untrusted: true,
            mutating: true,
        })
        .build();

    let out = rt.run("sinks", Tainted::trusted(json!({}))).await.unwrap();
    match out.status {
        RunStatus::Failed(msg) => {
            assert!(msg.contains("untrusted"), "got: {msg}");
        }
        other => panic!("the taint gate must reject, got {other:?}"),
    }
}

/// The same value is fine at a read-only sink: the gate is about *acting* on
/// untrusted data, not about reading it.
#[tokio::test]
async fn untrusted_data_may_reach_a_read_only_sink() {
    let rt = Runtime::builder(store())
        .skill(SinksLabeled {
            label_sensitivity: Sensitivity::Internal,
            ceiling: Sensitivity::Secret,
            untrusted: true,
            mutating: false,
        })
        .build();

    let out = rt.run("sinks", Tainted::trusted(json!({}))).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
}

/// Release is never silent: it lands in the journal with typed evidence.
#[tokio::test]
async fn release_is_journaled_with_its_evidence() {
    #[derive(Debug)]
    struct Releases;

    #[async_trait::async_trait]
    impl Skill for Releases {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("releases").provides("demo.release")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            let secret = Tainted::from_source(json!("s"), SourceId::new("vault"));
            let plain = cx
                .release(
                    secret,
                    Release::whole(
                        ReleaseScope::trust(),
                        "operator approved for settlement export",
                        "run.output",
                        ["approval:SET-42".to_owned()],
                    ),
                )
                .await
                .map_err(agentplane::core::SkillError::Step)?;
            Ok(Outcome::done(plain))
        }
    }

    let rt = Runtime::builder(store()).skill(Releases).build();
    let out = rt
        .run("demo.release", Tainted::trusted(json!({})))
        .await
        .unwrap();
    let records = rt.store().read(out.run_id, 1).await.unwrap();

    let found = records.iter().any(|r| match r.kind() {
        RecordKind::Released {
            release,
            label,
            result_label,
            value,
            ..
        } => {
            release.basis().contains("operator approved")
                && label.is_untrusted()
                && !result_label.is_untrusted()
                && *value
                    == agentplane::core::Digest::of(
                        &serde_json::to_vec(&json!("s")).expect("serialize fixture"),
                    )
        }
        _ => false,
    });
    assert!(found, "release must leave a permanent, evidenced record");
}

/// Completion is decided by the runtime, not claimed by the workload.
#[tokio::test]
async fn a_failing_skill_does_not_succeed() {
    #[derive(Debug)]
    struct Claims;

    #[async_trait::async_trait]
    impl Skill for Claims {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("claims").provides("demo.claims")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            Ok(Outcome::fail("objective not met"))
        }
    }

    let rt = Runtime::builder(store()).skill(Claims).build();
    let out = rt.run("claims", Tainted::trusted(json!({}))).await.unwrap();
    assert!(matches!(out.status, RunStatus::Failed(_)));
}

/// An unknown target is refused at admission rather than half-executed.
#[tokio::test]
async fn an_unknown_target_is_refused_before_anything_happens() {
    let rt = Runtime::builder(store()).build();
    let err = rt
        .run("nonexistent", Tainted::trusted(json!({})))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        agentplane::core::RuntimeError::NoProvider { .. }
    ));
}

/// A skill is reachable by the capability it provides, not only by its name —
/// capabilities are how a domain adapter binds its own vocabulary.
#[tokio::test]
async fn skills_resolve_by_capability() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store())
        .skill(CallsTool {
            calls: Arc::clone(&calls),
        })
        .build();
    let out = rt
        .run("demo.call", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// The `StepError` for a divergence names both keys, so an operator can see
/// which effect moved without reading the journal by hand.
#[test]
fn divergence_errors_are_diagnosable() {
    let e = StepError::NonDeterminism {
        seq: 7,
        expected: agentplane::core::EffectKey::from_hex(&Digest::of(b"a").to_hex()).unwrap(),
        actual: agentplane::core::EffectKey::from_hex(&Digest::of(b"b").to_hex()).unwrap(),
    };
    let msg = e.to_string();
    assert!(msg.contains("seq 7") && msg.contains("ek:"));
}

/// Strict replay must be a pure read. It verifies; it does not write.
///
/// A verification pass that appends to the journal would corrupt the very
/// history it is checking — and would make the chain head move every time
/// someone ran a regression test.
#[tokio::test]
async fn strict_replay_writes_nothing() {
    #[derive(Debug)]
    struct Releases;

    #[async_trait::async_trait]
    impl Skill for Releases {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("releases").provides("demo.release")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            cx.note("about to release").await?;
            let secret = Tainted::from_source(json!("s"), SourceId::new("vault"));
            let plain = cx
                .release(
                    secret,
                    Release::whole(
                        ReleaseScope::trust(),
                        "approved",
                        "run.output",
                        ["approval:test".to_owned()],
                    ),
                )
                .await?;
            Ok(Outcome::done(plain))
        }
    }

    let s = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(s.clone()).skill(Releases).build();
    let out = rt
        .run("demo.release", Tainted::trusted(json!({})))
        .await
        .unwrap();

    let before = s.read(out.run_id, 1).await.unwrap();
    for _ in 0..3 {
        rt.replay(out.run_id, Mode::Strict).await.unwrap();
    }
    let after = s.read(out.run_id, 1).await.unwrap();

    assert_eq!(
        before.len(),
        after.len(),
        "strict replay appended {} record(s) — verification must not mutate history",
        after.len() - before.len()
    );
    assert_eq!(before.last().unwrap().hash, after.last().unwrap().hash);
}

/// Reasoning notes reach the journal, adjacent to the effects they explain.
///
/// Adjacency is the whole value: a note next to the action it claims to justify
/// makes reasoning-versus-action mismatch detectable after the fact.
#[tokio::test]
async fn notes_are_journaled_next_to_their_effects() {
    #[derive(Debug)]
    struct Explains;

    #[async_trait::async_trait]
    impl Skill for Explains {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("explains").provides("demo.explains")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            cx.note("deviation exceeds threshold; escalating").await?;
            let arguments = Tainted::trusted(Value::Null);
            cx.sink(Recorded::new("escalate"), &arguments).await?;
            Ok(Outcome::done(input))
        }
    }

    let rt = Runtime::builder(store()).skill(Explains).build();
    let out = rt
        .run("explains", Tainted::trusted(json!({})))
        .await
        .unwrap();
    let records = rt.store().read(out.run_id, 1).await.unwrap();

    let note_at = records
        .iter()
        .position(|r| matches!(r.kind(), RecordKind::Note { text } if text.contains("deviation")));
    let effect_at = records
        .iter()
        .position(|r| r.kind().kind_str() == "EffectStarted");

    let note_at = note_at.expect("the note must be in the journal, not only in memory");
    let effect_at = effect_at.expect("the effect must be journaled");
    assert!(
        note_at < effect_at,
        "the note must precede the action it explains"
    );
}

/// A run written under another canonicalization rule is *unverifiable*, not
/// *divergent*.
///
/// Every effect key comes out of the canonicalizer, so a rule change moves all
/// of them at once. Without the recorded version, a replay of healthy history
/// recomputes different keys and reports **non-determinism** — the most serious
/// conclusion this runtime reaches, for a run that did nothing wrong, with
/// nothing on the record to say the rule moved underneath it. The rule has
/// already changed once, from UTF-8 byte ordering to RFC 8785's UTF-16 code
/// units, so this is a thing that happened rather than a thing that might.
///
/// The chain is deliberately *not* implicated: it hashes the bytes it stored
/// rather than re-canonicalizing them, so the history is intact and readable —
/// it simply cannot be re-derived here. The test asserts that too, because a
/// refusal that also claimed corruption would be the wrong answer twice.
#[tokio::test]
async fn history_under_an_older_canonicalization_rule_is_unverifiable_not_divergent() {
    use agentplane::journal::{Append, Record, RecordKind};

    let store = store();
    let rt = Runtime::builder(Arc::clone(&store))
        .skill(CallsTool {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .build();
    let run = agentplane::core::RunId::generate();

    // History whose admission names a canonicalization rule this build does
    // not implement.
    let lease = store
        .acquire(run, "canon", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    store
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "pay".into(),
                    governed_by: None,
                    input: json!({}),
                    input_label: agentplane::core::Label::trusted(),
                    policy_bundle: None,
                    canon: 999,
                },
            )],
        )
        .await
        .unwrap();

    let err = rt
        .replay(run, Mode::Strict)
        .await
        .expect_err("history under another canonicalization rule was replayed");
    assert!(
        matches!(
            err,
            agentplane::core::RuntimeError::CanonicalizationChanged { recorded: 999, .. }
        ),
        "a rule change was reported as something else: {err}"
    );

    // The history is intact. A refusal that also implied corruption would send
    // an operator hunting for tampering that did not happen.
    let records = store.read(run, 1).await.unwrap();
    Record::verify_chain(&records, agentplane::core::Digest::ZERO)
        .expect("the chain hashes stored bytes, so a rule change cannot break it");

    // And the positive half: a run this build wrote replays normally, or the
    // check above would be satisfied by refusing everything.
    let fresh = rt
        .run("calls-tool", Tainted::trusted(json!({})))
        .await
        .unwrap();
    rt.replay(fresh.run_id, Mode::Strict)
        .await
        .expect("a run written by this build replays");
}
