//! Retries: repeating a failed effect, and refusing to.
//!
//! The property that makes this more than a loop: **whether a call is repeated
//! depends on whether it reached the outside world, not on whether the error
//! looked transient.** A refused connection and a timed-out request are both
//! transient; only one of them is safe to send at a ledger again.
//!
//! Three gates decide, in order — the failure's `Disposition`, the effect's
//! `Recovery`, and only then the `RetryPolicy`. A policy can narrow what the
//! first two allow and can never widen it, which is what the tests below pin
//! down: raising `max_attempts` must not make a mutating in-doubt call
//! retryable.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::core::{
    Disposition, Effect, EffectDescriptor, EffectError, Outcome, Phase, Recovery, RetryPolicy,
    Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// How an attempt should end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    Succeed,
    /// The peer refused it; nothing was applied.
    RefusedCleanly,
    /// The peer understood the request and said no — an answer, not a fault.
    AnsweredNo,
    /// It timed out. Whether it was applied is unknowable.
    TimedOut,
    /// It landed and the answer would not decode.
    LandedUndecodable,
}

/// An effect that fails according to a script, one entry per attempt.
///
/// Scripted rather than random so a test pins an exact sequence: "fail twice,
/// then succeed" is a claim about the runtime, and a flaky effect could only
/// support a claim about averages.
#[derive(Debug, Clone)]
struct Scripted {
    script: Vec<Attempt>,
    calls: Arc<AtomicUsize>,
    mutates: bool,
    recovery: Recovery,
    policy: RetryPolicy,
}

impl Scripted {
    fn new(script: &[Attempt], calls: &Arc<AtomicUsize>) -> Self {
        Self {
            script: script.to_vec(),
            calls: Arc::clone(calls),
            mutates: false,
            recovery: Recovery::Retry,
            policy: fast_policy(RetryPolicy::default()),
        }
    }

    /// A mutating effect, which defaults to refusing to guess.
    fn mutating(mut self) -> Self {
        self.mutates = true;
        self.recovery = Recovery::RequiresOperator;
        self
    }

    fn recovery(mut self, r: Recovery) -> Self {
        self.recovery = r;
        self
    }

    fn policy(mut self, p: RetryPolicy) -> Self {
        self.policy = fast_policy(p);
        self
    }
}

/// Keep the suite fast without disabling the schedule: the ordering and the
/// attempt count are what is under test, not the wall-clock duration.
fn fast_policy(p: RetryPolicy) -> RetryPolicy {
    p.with_backoff(Duration::from_millis(1), Duration::from_millis(4))
}

#[async_trait::async_trait]
impl Effect for Scripted {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.scripted", json!(null))
    }

    fn mutates(&self) -> bool {
        self.mutates
    }

    fn recovery(&self) -> Recovery {
        self.recovery.clone()
    }

    fn retry(&self) -> RetryPolicy {
        self.policy
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.script.get(n).copied().unwrap_or(Attempt::Succeed) {
            Attempt::Succeed => Ok(json!({ "attempt": n + 1 })),
            Attempt::RefusedCleanly => Err(EffectError::Rejected("peer said no".into())),
            Attempt::AnsweredNo => Err(EffectError::Refused(
                "the model does not exist and never will".into(),
            )),
            Attempt::TimedOut => Err(EffectError::Timeout {
                driver: "test".into(),
                waited_ms: 30_000,
            }),
            Attempt::LandedUndecodable => Err(EffectError::OutputShape(
                serde_json::from_str::<Value>("{{{").unwrap_err(),
            )),
        }
    }
}

/// A step that performs one scripted effect.
#[derive(Debug)]
struct Once(Scripted);

#[async_trait::async_trait]
impl Skill for Once {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("once").provides("demo.once")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let out = cx.effect(self.0.clone()).await?;
        Ok(Outcome::done(out))
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    calls: Arc<AtomicUsize>,
}

fn fixture(effect: Scripted, calls: Arc<AtomicUsize>) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Once(effect))
        .build();
    Fixture { store, rt, calls }
}

fn scripted(script: &[Attempt]) -> (Scripted, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (Scripted::new(script, &calls), calls)
}

// ── The disposition gate ────────────────────────────────────────────────────

/// A clean refusal never reached the peer, so repeating it is safe.
#[tokio::test]
async fn a_clean_refusal_is_retried_and_can_succeed() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::Succeed]);
    let f = fixture(e, calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 2, "one retry, then success");
}

/// **The gate is the disposition, not `mutates`.**
///
/// A mutating effect whose call provably never landed is as safe to repeat as a
/// read. Gating on `mutates` instead would refuse to retry a payment whose
/// connection was refused — correct-looking, and needlessly useless.
#[tokio::test]
async fn a_mutating_effect_is_retried_when_the_call_provably_did_not_land() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::Succeed]);
    let f = fixture(e.mutating(), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

/// **The claim this whole design exists for.**
///
/// A timeout on something that mutates is in-doubt: the payment may well have
/// been taken. The runtime does not repeat it and does not report success — it
/// quarantines the run for a human, exactly as it does for a crash-orphan.
#[tokio::test]
async fn a_timeout_on_a_mutating_effect_is_never_retried() {
    let (e, calls) = scripted(&[Attempt::TimedOut, Attempt::Succeed]);
    let f = fixture(e.mutating(), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "an in-doubt mutating call must never be sent twice"
    );
    match &out.status {
        RunStatus::Quarantined(m) => assert!(
            m.contains("undecidable"),
            "the operator must be told why, got: {m}"
        ),
        other => panic!("expected quarantine, got {other:?}"),
    }
}

/// **A refusal that is an answer is not retried — the first no is the last.**
///
/// `Rejected` covers transient refusals (an overloaded gateway, a 5xx) and is
/// retried under policy; `Refused` is the peer *understanding* the request and
/// saying no — an unknown model, a malformed schema — where every further
/// attempt asks the same rule the same question. The distinction existed in
/// the model driver's error taxonomy and governed nothing: both collapsed to
/// the same variant, and a permanently-wrong request burned every permitted
/// attempt with backoff. Its sibling test above is the positive half — the
/// same script with `Rejected` retries and succeeds.
#[tokio::test]
async fn a_refusal_that_is_an_answer_is_not_retried() {
    let (e, calls) = scripted(&[Attempt::AnsweredNo, Attempt::Succeed]);
    let f = fixture(e, calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "an answer was retried as though it were a fault — the success scripted \
         for attempt two proves the loop went back"
    );
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "a refused run concludes failed (and open for resume), got {:?}",
        out.status
    );

    // The bit survives replay: the recorded run stopped after one attempt, and
    // a strict pass must stop at the same place rather than expecting the
    // retry the live run never made.
    let replayed = f.rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert!(
        matches!(replayed.status, RunStatus::Failed(_)),
        "strict replay reached a different conclusion over the same history: {:?}",
        replayed.status
    );
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "strict replay performed an effect"
    );
}

/// The same timeout against something declared safe to repeat *is* retried.
/// The difference is the declaration, and nothing else.
#[tokio::test]
async fn a_timeout_is_retried_when_recovery_declares_it_safe() {
    let (e, calls) = scripted(&[Attempt::TimedOut, Attempt::Succeed]);
    let f = fixture(e.recovery(Recovery::Retry), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

/// An idempotency key is the other way to declare a repeat safe, and it works
/// on a mutating effect — that is the entire point of holding one.
#[tokio::test]
async fn an_idempotency_key_makes_a_mutating_timeout_retryable() {
    let (e, calls) = scripted(&[Attempt::TimedOut, Attempt::Succeed]);
    let f = fixture(
        e.mutating().recovery(Recovery::Idempotent {
            key: "order-4711".into(),
        }),
        calls,
    );

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

/// A call that landed is never repeated, however many attempts remain. Its
/// response was unusable; sending it again would perform it a second time and
/// produce a second unusable response.
#[tokio::test]
async fn an_effect_that_landed_is_never_repeated() {
    let (e, calls) = scripted(&[Attempt::LandedUndecodable, Attempt::Succeed]);
    let f = fixture(e.policy(RetryPolicy::attempts(5)), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(out.status, RunStatus::Failed(_)));
}

// ── The policy gate ─────────────────────────────────────────────────────────

/// Attempts are bounded, and the operator is told what the bound was.
#[tokio::test]
async fn attempts_are_exhausted_and_the_error_says_so() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly; 10]);
    let f = fixture(e.policy(RetryPolicy::attempts(3)), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 3, "exactly the limit");
    match &out.status {
        RunStatus::Failed(m) => assert!(
            m.contains("attempt 3 of 3"),
            "the message must name the bound, got: {m}"
        ),
        other => panic!("expected failure, got {other:?}"),
    }
}

/// `never()` means one attempt, not zero.
#[tokio::test]
async fn a_never_policy_performs_exactly_one_attempt() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::Succeed]);
    let f = fixture(e.policy(RetryPolicy::never()), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(out.status, RunStatus::Failed(_)));
}

/// **A policy cannot widen what the safety gates allow.**
///
/// Ten attempts against a mutating in-doubt failure is still one attempt. If
/// this ever regresses, `max_attempts` has quietly become an override for the
/// exactly-once guarantee.
#[tokio::test]
async fn raising_max_attempts_does_not_make_an_in_doubt_call_retryable() {
    let (e, calls) = scripted(&[Attempt::TimedOut; 10]);
    let f = fixture(e.mutating().policy(RetryPolicy::attempts(10)), calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(out.status, RunStatus::Quarantined(_)));
}

// ── What the journal records ────────────────────────────────────────────────

/// Every attempt is on the record, numbered, with what its failure meant.
///
/// An operator asking "why did this call the endpoint three times" gets the
/// answer from the journal rather than from correlating logs.
#[tokio::test]
async fn every_attempt_is_journaled_with_its_number_and_disposition() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::RefusedCleanly]);
    let f = fixture(e, calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);

    let records = f.store.read(out.run_id, 1).await.unwrap();

    let attempts: Vec<u32> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectStarted { attempt, .. } => Some(*attempt),
            _ => None,
        })
        .collect();
    assert_eq!(attempts, vec![1, 2, 3], "attempts are numbered from one");

    let dispositions: Vec<Disposition> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectFailed { disposition, .. } => Some(*disposition),
            _ => None,
        })
        .collect();
    assert_eq!(
        dispositions,
        vec![Disposition::DidNotHappen, Disposition::DidNotHappen],
        "each failure records what it meant, not just what it said"
    );

    // Attempts 2 and 3 waited; attempt 1 did not.
    let backoffs: Vec<u64> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectStarted { backoff_ms, .. } => Some(*backoff_ms),
            _ => None,
        })
        .collect();
    assert_eq!(backoffs[0], 0, "the first attempt never waits");
}

/// Each attempt is a distinct effect key, or the second would collide with the
/// first's recorded failure and be read back as history.
#[tokio::test]
async fn attempts_do_not_share_an_effect_key() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::RefusedCleanly]);
    let f = fixture(e, calls);

    let out =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    let records = f.store.read(out.run_id, 1).await.unwrap();

    let mut keys: Vec<_> = records
        .iter()
        .filter(|r| matches!(r.kind(), RecordKind::EffectStarted { .. }))
        .filter_map(agentplane::journal::Record::effect_key)
        .collect();
    let total = keys.len();
    keys.sort_unstable_by_key(|k| k.to_hex());
    keys.dedup();
    assert_eq!(keys.len(), total, "every attempt has its own identity");
}

// ── Replay ──────────────────────────────────────────────────────────────────

/// A retry sequence replays without performing anything.
#[tokio::test]
async fn replay_reproduces_a_retry_sequence_without_repeating_it() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::RefusedCleanly]);
    let f = fixture(e, calls);

    let first =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);
    let performed = f.calls.load(Ordering::SeqCst);
    assert_eq!(performed, 3);

    let again = f.rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        performed,
        "strict replay of a retry sequence must not call anything"
    );
    assert_eq!(again.output, first.output, "and reaches the same answer");
}

/// **History outranks the policy.**
///
/// A run that made three attempts made three attempts. Replaying it under a
/// policy that now permits only one must reproduce the run, not truncate it —
/// otherwise editing a config file silently rewrites what happened.
#[tokio::test]
async fn replay_follows_history_even_when_the_policy_has_since_shrunk() {
    let (e, calls) = scripted(&[Attempt::RefusedCleanly, Attempt::RefusedCleanly]);
    let f = fixture(e, Arc::clone(&calls));

    let first =
        f.rt.run("demo.once", Tainted::trusted(json!({})))
            .await
            .unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 3);

    // Same journal, same store — but a runtime whose policy now forbids retrying
    // at all.
    let (tightened, _) = scripted(&[Attempt::RefusedCleanly, Attempt::RefusedCleanly]);
    let rt = Runtime::builder(f.store.clone() as Arc<dyn JournalStore>)
        .skill(Once(
            tightened.policy(RetryPolicy::never()).clone_calls(&calls),
        ))
        .build();

    let again = rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(
        again.status,
        RunStatus::Succeeded,
        "the recorded run is authoritative; a shrunken policy must not truncate it"
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 3, "and nothing re-runs");
}

impl Scripted {
    /// Point a rebuilt effect at an existing call counter, so a second runtime
    /// over the same journal keeps counting into the same total.
    fn clone_calls(mut self, calls: &Arc<AtomicUsize>) -> Self {
        self.calls = Arc::clone(calls);
        self
    }
}

// ── Interaction with the budget ─────────────────────────────────────────────

/// **A retry is a real call and costs real money.**
///
/// Admission is checked per attempt, not once per effect. A ceiling that only
/// counted first attempts is a ceiling a retry storm walks straight through,
/// which is the failure mode a budget exists to prevent.
#[tokio::test]
async fn every_attempt_is_admitted_against_the_budget() {
    use agentplane::core::Budget;

    let (e, calls) = scripted(&[Attempt::RefusedCleanly; 10]);
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().effects(2))
        .skill(Once(e.policy(RetryPolicy::attempts(10))))
        .build();

    let out = rt
        .run("demo.once", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the budget must bound the retries, not just the first call"
    );
    assert!(matches!(out.status, RunStatus::Exhausted(_)));
}

// ── Crash between a failure and the retry that follows ──────────────────────

/// A crash after recording a failure, before starting the next attempt.
///
/// History ends on an `EffectFailed` whose disposition permitted another go, so
/// the recorded run died in the gap. Resume recomputes that decision — a pure
/// function of the disposition, the recovery mode, and the policy — and carries
/// on with the attempt the crashed run never started.
#[tokio::test]
async fn resume_continues_a_retry_the_crashed_run_never_started() {
    use agentplane::core::{EffectKey, PlanIR, StepId};
    use agentplane::journal::Append;

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let (e, calls) = scripted(&[Attempt::Succeed]);
    // Same owner identity as the lease taken below: this is one process
    // restarting after a crash, which is the realistic recovery path.
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Once(e))
        .build();

    let run = agentplane::core::RunId::generate();
    let plan = PlanIR::single("demo.once");
    let lease = store
        .acquire(run, "test", Duration::from_mins(1))
        .await
        .unwrap();

    let descriptor = EffectDescriptor::new("test.scripted", json!(null));
    let attempt1 = EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &descriptor);

    store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "demo.once".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: agentplane::core::Label::trusted(),
                        policy_bundle: None,
                        canon: agentplane::core::canon::VERSION,
                    },
                ),
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        steps: vec!["demo.once".into()],
                        plan: serde_json::to_value(&plan).unwrap(),
                    },
                ),
                Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: "once".into(),
                    },
                )
                .step(StepId(0)),
                Append::new(
                    run,
                    RecordKind::EffectStarted {
                        descriptor,
                        recovery: Recovery::Retry,
                        mutates: false,
                        attempt: 1,
                        backoff_ms: 0,
                        outbound_label: None,
                    },
                )
                .step(StepId(0))
                .effect(attempt1),
                // The failure is durable. The retry it authorised is not — that
                // is the gap the process died in.
                Append::new(
                    run,
                    RecordKind::EffectFailed {
                        error: "peer said no".into(),
                        disposition: Disposition::DidNotHappen,
                        spend: agentplane::core::Spend::default(),
                        permanent: false,
                    },
                )
                .step(StepId(0))
                .effect(attempt1),
            ],
        )
        .await
        .unwrap();
    // The process died: its lease is claimable, not renewable.
    store.release_lease(run, lease.epoch).await.unwrap();

    let out = rt.replay(run, Mode::Resume).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "attempt 1 is read from history; only the attempt it never started runs"
    );

    let records = store.read(run, 1).await.unwrap();
    let numbered: Vec<u32> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectStarted { attempt, .. } => Some(*attempt),
            _ => None,
        })
        .collect();
    assert_eq!(numbered, vec![1, 2], "history is extended, not rewritten");
}

// ── The rest of the disposition taxonomy ────────────────────────────────────

/// A connection that died mid-flight is in doubt, exactly like a timeout.
///
/// `Interrupted` is the other way a request reaches the peer and leaves no
/// answer. It had a `Disposition` and no test, which meant the taxonomy was one
/// third assertion: the variant existed and nothing proved the runtime treated
/// it as dangerous.
#[tokio::test]
async fn an_interrupted_connection_is_in_doubt_not_retried() {
    #[derive(Debug, Clone)]
    struct Cut(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl Effect for Cut {
        type Output = Value;
        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::nullary("test.cut")
        }
        fn mutates(&self) -> bool {
            true
        }
        fn retry(&self) -> RetryPolicy {
            fast_policy(RetryPolicy::attempts(5))
        }
        async fn perform(&self) -> Result<Value, EffectError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(EffectError::Interrupted {
                driver: "net".into(),
                detail: "connection reset after the request went out".into(),
            })
        }
    }

    #[derive(Debug)]
    struct Once(Cut);

    #[async_trait::async_trait]
    impl Skill for Once {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("cut").provides("demo.cut")
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

    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Once(Cut(Arc::clone(&calls))))
        .build();

    let out = rt
        .run("demo.cut", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a mutating call cut mid-flight must never be sent twice, whatever the \
         policy permits"
    );
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "got {:?}",
        out.status
    );
}

/// A skill that rejects its input says so with the variant meant for it, and the
/// run fails rather than being quarantined — bad input is not undecidable.
#[tokio::test]
async fn a_skill_can_reject_its_input() {
    #[derive(Debug)]
    struct Picky;

    #[async_trait::async_trait]
    impl Skill for Picky {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("picky").provides("demo.picky")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Err(SkillError::Input("expected an object with `amount`".into()))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Picky)
        .build();

    let out = rt
        .run("demo.picky", Tainted::trusted(json!(42)))
        .await
        .unwrap();
    match &out.status {
        RunStatus::Failed(m) => assert!(m.contains("amount"), "got: {m}"),
        other => panic!("bad input is a failure, not a quarantine: {other:?}"),
    }
}

/// Exhausting the attempts must not turn "it was refused" into "we cannot tell".
///
/// A driver reports [`Disposition::DidNotHappen`] to say the call was declined
/// *before* it reached anything. The runtime used to flatten that into an
/// untyped error on the way out, and an untyped error reads as `InDoubt` — the
/// most dangerous verdict available. Everything that acts on doubt was then
/// acting on a fabrication: a saga would refuse to unwind around a call that
/// provably did nothing, and an escalation would be raised for a failure that
/// needed nobody.
///
/// Invisible until something read the disposition back off the error rather
/// than off the record, which is exactly what an effect group does.
#[tokio::test]
async fn exhausting_the_attempts_keeps_the_driver_s_verdict() {
    use agentplane::core::{Disposition, EffectDescriptor, EffectError, RetryPolicy};

    #[derive(Debug)]
    struct AlwaysRefused;

    #[async_trait::async_trait]
    impl agentplane::core::Effect for AlwaysRefused {
        type Output = Value;
        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::nullary("test.refused")
        }
        fn retry(&self) -> RetryPolicy {
            RetryPolicy::attempts(2)
                .with_backoff(Duration::from_millis(1), Duration::from_millis(1))
        }
        async fn perform(&self) -> Result<Value, EffectError> {
            Err(EffectError::Rejected("declined outright".into()))
        }
    }

    #[derive(Debug)]
    struct Reports;

    #[async_trait::async_trait]
    impl Skill for Reports {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("reports").provides("demo.reports")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let err = cx
                .effect(AlwaysRefused)
                .await
                .expect_err("a refused effect succeeded");
            let agentplane::core::StepError::Effect(inner) = &err else {
                panic!("expected an effect failure, got {err:?}");
            };
            Ok(Outcome::done(Tainted::trusted(json!({
                "disposition": format!("{:?}", inner.disposition()),
            }))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Reports)
        .build();

    let out = rt
        .run("demo.reports", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(
        out.output.expect("output").peek()["disposition"],
        format!("{:?}", Disposition::DidNotHappen),
        "the retry wrapper laundered a refusal into doubt — everything that \
         decides whether it is safe to unwind now has the wrong answer"
    );
}
