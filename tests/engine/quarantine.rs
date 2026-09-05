//! Answering a quarantine: the verb that closes the runtime's own loop.
//!
//! A quarantine is this runtime's most serious conclusion and its most honest
//! one. An effect was announced, the process died or the provider went quiet,
//! and the journal cannot say whether the call reached the world — so nothing
//! unwinds, because compensating around an unknown outcome is a refund for
//! money nobody took.
//!
//! The rule has a cost, and this file is where the cost is paid. What it pins
//! is the shape of the answer, which is deliberately not "an operator declares
//! the run finished":
//!
//! * A person supplies **facts** about individual effects. The runtime still
//!   supplies the **verdict** about the run, and reaches the same quarantine
//!   again when the facts do not settle it.
//! * Giving up is a recorded ending — `abandoned` — and it unwinds nothing,
//!   because impatience is not evidence.
//! * The doubt outlives the run. A status is something a later action
//!   overwrites; the `agentplane audit` finding is derived from the journal and
//!   nothing can take it off.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::core::{
    ArgSource, Assertion, Compensation, Disposition, Doubt, Effect, EffectDescriptor, EffectError,
    Outcome, PlanIR, PlanNode, QuarantineDecision, Reconciliation, Recovery, RetryPolicy, RunId,
    RuntimeError, Skill, SkillDescriptor, SkillError, StepId, Tainted,
};
use agentplane::journal::{Append, JournalStore, Record, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// A mutating call that times out and whose provider cannot say what happened.
///
/// The canonical in-doubt effect: `Recovery::Reconcile` means the runtime asks
/// rather than guessing, and a probe that answers `Inconclusive` leaves the
/// doubt exactly where it was — which is the only state this whole file is
/// about.
#[derive(Debug, Clone)]
struct Charge {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Effect for Charge {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.charge", json!({ "ref": "order-4711" }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Reconcile
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::attempts(1)
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(EffectError::Timeout {
            driver: "payments".into(),
            waited_ms: 30_000,
        })
    }

    async fn reconcile(&self) -> Result<Reconciliation<Value>, EffectError> {
        Ok(Reconciliation::Inconclusive)
    }
}

/// A mutating call that always works, so the step before the doubt has
/// something standing in the world for an unwind to reach for.
#[derive(Debug, Clone)]
struct Book {
    log: Arc<std::sync::Mutex<Vec<String>>>,
    what: String,
}

#[async_trait::async_trait]
impl Effect for Book {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.book", json!({ "what": self.what }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.log.lock().unwrap().push(self.what.clone());
        Ok(json!({ "did": self.what }))
    }
}

#[derive(Debug)]
struct Booking(Arc<std::sync::Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl Skill for Booking {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("book").provides("demo.book")
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let out = cx
            .effect(Book {
                log: Arc::clone(&self.0),
                what: "do:book".into(),
            })
            .await?;
        Ok(Outcome::done(out))
    }

    async fn compensate(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Book {
            log: Arc::clone(&self.0),
            what: "undo:book".into(),
        })
        .await?;
        Ok(())
    }
}

#[derive(Debug)]
struct Paying(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Skill for Paying {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pay").provides("demo.pay")
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let out = cx
            .effect(Charge {
                calls: Arc::clone(&self.0),
            })
            .await?;
        Ok(Outcome::done(out))
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    calls: Arc<AtomicUsize>,
    log: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Fixture {
    async fn records(&self, run: RunId) -> Vec<Record> {
        (self.store.clone() as Arc<dyn JournalStore>)
            .read(run, 1)
            .await
            .expect("read")
    }
}

fn fixture() -> Fixture {
    let calls = Arc::new(AtomicUsize::new(0));
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Booking(Arc::clone(&log)))
        .skill(Paying(Arc::clone(&calls)))
        .build();
    Fixture {
        store,
        rt,
        calls,
        log,
    }
}

/// book -> pay. The first step leaves something standing; the second cannot say
/// whether it did.
fn plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "demo.book").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "demo.pay")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ])
}

/// A run stopped on an unanswerable payment, with the booking standing.
async fn quarantined(f: &Fixture) -> RunId {
    let out =
        f.rt.run_plan(plan(), Tainted::trusted(json!({})))
            .await
            .expect("run");
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "expected a quarantine, got {:?}",
        out.status
    );
    assert_eq!(
        f.log.lock().unwrap().as_slice(),
        ["do:book"],
        "the booking stands and nothing was undone — unwinding around doubt is \
         the one thing quarantine forbids"
    );
    out.run_id
}

// ── The quarantine is a pause, not an ending ────────────────────────────────

/// **The premise everything else rests on.** A quarantine does not seal.
///
/// A Merkle leaf is a claim that a history is complete, and a quarantine is the
/// runtime saying it does not know — so sealing one published a proof of
/// completeness over an admittedly incomplete record. The practical half is
/// sharper: a sealed chain refuses further appends, so the code's own promise
/// that "a human must resolve it before it can run again" named a resolution
/// the durable format made impossible.
#[tokio::test]
async fn a_quarantined_run_is_open_and_seals_only_when_it_truly_ends() {
    let f = fixture();
    let run = quarantined(&f).await;
    let store = f.store.clone() as Arc<dyn JournalStore>;

    assert!(
        store.inclusion_proof(run).await.unwrap().is_none(),
        "a run whose outcome is undecided is not in the log of finished runs"
    );

    f.rt.decide_quarantine(
        run,
        "ada",
        "the provider has no record either way",
        QuarantineDecision::Abandon,
    )
    .await
    .expect("abandon");

    assert!(
        store.inclusion_proof(run).await.unwrap().is_some(),
        "abandoning it is an ending, and endings enter the log"
    );
}

/// The backlog gauge drains, because a person can now act on it.
#[tokio::test]
async fn answering_a_quarantine_takes_it_off_the_quarantine_backlog() {
    let f = fixture();
    let run = quarantined(&f).await;
    let store = f.store.clone() as Arc<dyn JournalStore>;

    assert_eq!(store.count_by_outcome("quarantined").await.unwrap(), 1);

    f.rt.decide_quarantine(
        run,
        "ada",
        "written off after two weeks",
        QuarantineDecision::Abandon,
    )
    .await
    .expect("abandon");

    assert_eq!(
        store.count_by_outcome("quarantined").await.unwrap(),
        0,
        "the gauge behind the alert has to fall when somebody acts, or it is a \
         counter wearing a gauge's description"
    );
    assert_eq!(store.count_by_outcome("abandoned").await.unwrap(), 1);
    assert_eq!(
        store.runs_by_outcome("abandoned", 10).await.unwrap(),
        vec![run]
    );
}

// ── What an operator is told to look up ─────────────────────────────────────

/// A quarantine names the call, not just the situation.
///
/// "An effect was announced and never terminated" is a description; an operator
/// needs the key, the step and what the call was, or the next move is to read
/// the journal by hand.
#[tokio::test]
async fn the_run_says_which_effect_is_in_doubt() {
    let f = fixture();
    let run = quarantined(&f).await;

    let undecided = f.rt.undecided(run).await.expect("undecided");
    assert_eq!(undecided.len(), 1, "got {undecided:?}");
    assert_eq!(undecided[0].kind, "test.charge");
    assert_eq!(undecided[0].step, StepId(1));
    assert_eq!(
        undecided[0].doubt,
        Doubt::Inconclusive,
        "the provider was asked and could not tell — a different starting point \
         for an investigator than never having heard back"
    );
}

/// The booking is not in the list. It landed, and a landed effect is not a
/// question anybody has to answer.
#[tokio::test]
async fn an_effect_that_completed_is_not_in_doubt() {
    let f = fixture();
    let run = quarantined(&f).await;

    let undecided = f.rt.undecided(run).await.expect("undecided");
    assert!(
        undecided.iter().all(|u| u.kind != "test.book"),
        "got {undecided:?}"
    );
}

// ── Facts from a person, verdicts from the runtime ──────────────────────────

/// **The case this verb exists for.** An operator looks the charge up, finds
/// it, says so, and the run finishes reading their answer back — without the
/// call being made a second time.
#[tokio::test]
async fn an_operators_landed_verdict_finishes_the_run_without_repeating_the_call() {
    let f = fixture();
    let run = quarantined(&f).await;
    let key = f.rt.undecided(run).await.unwrap()[0].effect;

    f.rt.reconcile_effect(
        run,
        key,
        Assertion::Landed(json!({ "captured": true, "via": "operator" })),
        "ada",
        "charge ch_9RtQ exists in the provider console, created 12:41Z",
    )
    .await
    .expect("assert");

    let out =
        f.rt.decide_quarantine(
            run,
            "ada",
            "the charge is in the provider's ledger",
            QuarantineDecision::Reopen,
        )
        .await
        .expect("reopen");

    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        out.output.as_ref().and_then(|v| v.peek().get("via")),
        Some(&json!("operator")),
        "the run reads back what the person established"
    );
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "the whole point: the charge was never sent twice"
    );
    assert_eq!(
        f.log.lock().unwrap().as_slice(),
        ["do:book"],
        "and the booking was neither repeated nor undone"
    );
}

/// A person's assertion is attributed, and its value takes the conservative
/// label.
///
/// Every other output in this runtime is labelled by the effect that produced
/// it. There is no effect here — an offline verb holds no instance, and the
/// person typing the value is not the provider that returned it — so it takes
/// the lattice point an inbound event's payload gets. Letting the resolution
/// declare its own trust would make this the one place in the design where a
/// person declassifies by typing.
#[tokio::test]
async fn an_asserted_result_names_its_author_and_is_not_trusted() {
    let f = fixture();
    let run = quarantined(&f).await;
    let key = f.rt.undecided(run).await.unwrap()[0].effect;

    f.rt.reconcile_effect(
        run,
        key,
        Assertion::Landed(json!({ "captured": true })),
        "ada",
        "checked the console",
    )
    .await
    .expect("assert");

    let recs = f.records(run).await;
    let asserted = recs
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::EffectReconciled {
                asserted_by: Some(who),
                declared,
                disposition,
                ..
            } => Some((who.clone(), *declared, *disposition)),
            _ => None,
        })
        .expect("an operator's reconciliation is on the record");

    assert_eq!(asserted.0, "ada");
    assert_eq!(asserted.2, Disposition::Landed);
    assert_eq!(
        asserted.1,
        Some(agentplane::core::DeclaredOutput::untrusted()),
        "stated on the record rather than left to a reader's default — a durable \
         format that does not say what it means is one a later build guesses about"
    );
}

/// Evidence is not a decision.
///
/// Answering one doubt does not hand the run back — several can be answered
/// before it is judged again, and answering one of three is not a judgement.
/// Collapsing the two would mean the first person to look at an effect decides
/// the run, which is not how any of the escalations this runtime raises are
/// meant to be closed.
#[tokio::test]
async fn an_assertion_alone_does_not_reopen_the_run() {
    let f = fixture();
    let run = quarantined(&f).await;
    let key = f.rt.undecided(run).await.unwrap()[0].effect;

    f.rt.reconcile_effect(
        run,
        key,
        Assertion::Landed(json!({ "captured": true })),
        "ada",
        "charge ch_9RtQ exists",
    )
    .await
    .expect("assert");

    let out = f.rt.replay(run, Mode::Resume).await.expect("resume");
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "the doubt is answered, but nobody has said the run may carry on: {:?}",
        out.status
    );
}

/// **A person supplies facts; the runtime still decides.**
///
/// Reopening a run whose doubt nobody answered reaches the same quarantine, on
/// the record, and needs a fresh decision before it can be tried again. The
/// alternative — treating one judgement as a standing licence to retry — is how
/// an undecidable situation becomes an unnoticed retry loop.
#[tokio::test]
async fn reopening_without_answering_the_doubt_quarantines_again() {
    let f = fixture();
    let run = quarantined(&f).await;

    let out =
        f.rt.decide_quarantine(run, "ada", "looks fine to me", QuarantineDecision::Reopen)
            .await
            .expect("reopen");
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "got {:?}",
        out.status
    );
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "and it did not send the charge again on the way to finding that out"
    );

    // The earlier decision was made about a history that has since moved, so it
    // is spent: an ordinary resume is closed again.
    //
    // Asserted on the *sentence*, because both a closed resume and a resume
    // that ran and re-quarantined answer `Quarantined` — and only one of them
    // executed. The closed answer is the one that names what has to happen
    // next; the executor's own reason describes the doubt.
    let again = f.rt.replay(run, Mode::Resume).await.expect("resume");
    match &again.status {
        RunStatus::Quarantined(why) => assert!(
            why.contains("a named person has to answer it"),
            "the resume ran again on a spent decision — one judgement became a \
             standing licence to retry, which is a feedback path with no bound: {why}"
        ),
        other => panic!("expected the run to stay closed, got {other:?}"),
    }
}

/// An assertion may supply a missing fact and never replace a recorded one.
///
/// Without this an operator could talk a run out of compensating work that is
/// standing in the world, and the journal would show an orderly reconciliation
/// while it happened.
#[tokio::test]
async fn an_assertion_cannot_overwrite_an_outcome_the_journal_holds() {
    let f = fixture();
    let run = quarantined(&f).await;

    // The booking's key, read off its announcement. It completed, so it is not
    // a question anybody may answer.
    let booked = f
        .records(run)
        .await
        .iter()
        .find(|r| {
            matches!(r.kind(), RecordKind::EffectStarted { descriptor, .. }
                if descriptor.kind == "test.book")
        })
        .and_then(agentplane::journal::Record::effect_key)
        .expect("the booking was announced");

    let refused =
        f.rt.reconcile_effect(
            run,
            booked,
            Assertion::DidNotHappen,
            "mallory",
            "i would rather this had not happened",
        )
        .await;
    assert!(
        matches!(refused, Err(RuntimeError::NotUndecided { .. })),
        "got {refused:?}"
    );
}

/// Only a run the runtime could not decide is asking a question.
#[tokio::test]
async fn a_run_that_is_not_quarantined_refuses_both_decisions() {
    let f = fixture();
    // A booking on its own succeeds.
    let out =
        f.rt.run("demo.book", Tainted::trusted(json!({})))
            .await
            .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);

    let refused =
        f.rt.decide_quarantine(out.run_id, "ada", "tidying up", QuarantineDecision::Abandon)
            .await;
    match refused {
        Err(RuntimeError::NotQuarantined { status, .. }) => assert_eq!(status, "succeeded"),
        other => panic!("expected a refusal naming the state, got {other:?}"),
    }
}

/// A decision with no name or no stated finding is not a decision.
///
/// The whole weight of the record is that a named person took responsibility
/// for a fact the runtime could not establish, and "unknown decided this for no
/// stated reason" documents nothing while looking like process.
#[tokio::test]
async fn a_decision_needs_a_decider_and_a_reason() {
    let f = fixture();
    let run = quarantined(&f).await;

    for (decider, reason) in [("", "checked"), ("ada", "   ")] {
        let refused =
            f.rt.decide_quarantine(run, decider, reason, QuarantineDecision::Reopen)
                .await;
        assert!(
            refused.is_err(),
            "accepted decider={decider:?} reason={reason:?}"
        );
    }
}

// ── Giving up ───────────────────────────────────────────────────────────────

/// **Abandoning unwinds nothing**, and that is the content of the decision.
///
/// The booking is compensatable and standing. A cancellation would reverse it;
/// this must not, because reversing the steps *around* a call that may have
/// landed is the refund for money nobody took — and an operator's patience
/// running out is not new evidence.
#[tokio::test]
async fn abandoning_leaves_the_world_exactly_as_the_run_left_it() {
    let f = fixture();
    let run = quarantined(&f).await;

    let out =
        f.rt.decide_quarantine(
            run,
            "ada",
            "two weeks of provider tickets; nobody can say",
            QuarantineDecision::Abandon,
        )
        .await
        .expect("abandon");

    match &out.status {
        RunStatus::Abandoned { actor, reason } => {
            assert_eq!(actor, "ada");
            assert!(reason.contains("nobody can say"), "{reason}");
        }
        other => panic!("expected abandoned, got {other:?}"),
    }
    assert_eq!(
        f.log.lock().unwrap().as_slice(),
        ["do:book"],
        "the booking still stands: abandoning is not cancelling"
    );
    assert!(
        !f.records(run)
            .await
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::StepCompensated { .. })),
        "nothing was compensated"
    );
}

/// The decision is journaled **before** it is acted on, so a crash in between
/// leaves the instruction standing rather than lost — and the next resume
/// finishes the job rather than finding a run stuck between two states.
#[tokio::test]
async fn an_abandonment_recorded_before_a_crash_is_finished_by_the_next_resume() {
    let f = fixture();
    let run = quarantined(&f).await;
    let store = f.store.clone() as Arc<dyn JournalStore>;

    // The instruction, written by a pass that then died.
    let lease = store
        .acquire(run, "a-process-that-died", Duration::from_secs(30))
        .await
        .expect("lease");
    store
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::QuarantineDecided {
                    decider: "ada".into(),
                    reason: "written off".into(),
                    decision: QuarantineDecision::Abandon,
                },
            )],
        )
        .await
        .expect("append");
    store
        .release_lease(run, lease.epoch)
        .await
        .expect("release");

    let out = f.rt.replay(run, Mode::Resume).await.expect("resume");
    assert!(
        matches!(out.status, RunStatus::Abandoned { .. }),
        "got {:?}",
        out.status
    );
    assert_eq!(
        f.log.lock().unwrap().as_slice(),
        ["do:book"],
        "and it finished the ending rather than re-running the run"
    );
}

/// The order on the chain, asserted directly: an instruction that landed after
/// its own conclusion could not be read by a recovery.
#[tokio::test]
async fn the_decision_is_on_the_chain_before_the_ending_it_asks_for() {
    let f = fixture();
    let run = quarantined(&f).await;
    f.rt.decide_quarantine(run, "ada", "written off", QuarantineDecision::Abandon)
        .await
        .expect("abandon");

    let recs = f.records(run).await;
    let decided = recs
        .iter()
        .position(|r| matches!(r.kind(), RecordKind::QuarantineDecided { .. }))
        .expect("the decision is on the chain");
    let ended = recs
        .iter()
        .rposition(|r| {
            matches!(r.kind(), RecordKind::RunConcluded { outcome, .. }
            if outcome == "abandoned")
        })
        .expect("the ending is on the chain");
    assert!(decided < ended, "the instruction must precede the ending");
}

// ── Cancelling is not abandoning ────────────────────────────────────────────

/// A stop request against a quarantined run is refused rather than recorded and
/// ignored.
///
/// Cancelling promises to unwind and put the world back, which is the one thing
/// a run holding an unknown outcome may not do. The shape this replaces landed
/// the request durably, answered `recorded: true`, and then walked straight
/// past it — an operator who believes they stopped a run holding an unresolved
/// payment is worse off than one who was told no.
#[tokio::test]
async fn cancelling_a_quarantined_run_is_refused_and_names_the_two_verbs() {
    let f = fixture();
    let run = quarantined(&f).await;

    let refused = f.rt.request_cancel(run, "ada", "stop it").await;
    let message = match refused {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a cancellation that unwinds must not be accepted here"),
    };
    assert!(message.contains("reopen"), "{message}");
    assert!(message.contains("abandon"), "{message}");
    assert!(
        f.rt.cancellation(run).await.unwrap().is_none(),
        "and nothing was recorded, so no later path can act on it"
    );
}

// ── The doubt outlives the run ──────────────────────────────────────────────

/// **The finding that no status can clear.**
///
/// Abandoning takes the run off the quarantine backlog, which was the only
/// listing that carried it. What the run left in the world does not go away
/// with the listing — so the record of it is derived from the journal, where
/// nothing an operator does can take it off.
#[tokio::test]
async fn an_abandoned_doubt_is_reportable_from_the_journal_forever() {
    let f = fixture();
    let run = quarantined(&f).await;
    let key = f.rt.undecided(run).await.unwrap()[0].effect;

    // While it is open the doubt is the ordinary crash shape a person may still
    // answer, and flagging it would teach the reader this finding is weather.
    let store = f.store.clone() as Arc<dyn JournalStore>;
    let before = agentplane::audit::audit(&store, &[run], &agentplane::audit::Evidence::default())
        .await
        .expect("audit");
    assert!(before.is_sound(), "{:?}", before.findings);

    f.rt.decide_quarantine(run, "ada", "written off", QuarantineDecision::Abandon)
        .await
        .expect("abandon");

    let after = agentplane::audit::audit(&store, &[run], &agentplane::audit::Evidence::default())
        .await
        .expect("audit");
    assert!(
        after.findings.iter().any(|finding| matches!(
            finding,
            agentplane::audit::Finding::EffectUndecided { effect, .. } if *effect == key
        )),
        "the effect nobody could account for has to survive the run's closure, \
         got {:?}",
        after.findings
    );
}

/// A run that was *answered* and finished leaves no finding: the doubt is gone,
/// not merely closed over.
#[tokio::test]
async fn an_answered_doubt_leaves_no_finding() {
    let f = fixture();
    let run = quarantined(&f).await;
    let key = f.rt.undecided(run).await.unwrap()[0].effect;

    f.rt.reconcile_effect(
        run,
        key,
        Assertion::Landed(json!({ "captured": true })),
        "ada",
        "charge ch_9RtQ exists",
    )
    .await
    .expect("assert");
    f.rt.decide_quarantine(run, "ada", "confirmed", QuarantineDecision::Reopen)
        .await
        .expect("reopen");

    let store = f.store.clone() as Arc<dyn JournalStore>;
    let report = agentplane::audit::audit(&store, &[run], &agentplane::audit::Evidence::default())
        .await
        .expect("audit");
    assert!(report.is_sound(), "{:?}", report.findings);
}

/// The whole history still verifies, and a strict pass over it re-reaches the
/// same ending without performing anything.
#[tokio::test]
async fn an_answered_run_replays_strictly() {
    let f = fixture();
    let run = quarantined(&f).await;
    let key = f.rt.undecided(run).await.unwrap()[0].effect;

    f.rt.reconcile_effect(
        run,
        key,
        Assertion::Landed(json!({ "captured": true })),
        "ada",
        "charge ch_9RtQ exists",
    )
    .await
    .expect("assert");
    f.rt.decide_quarantine(run, "ada", "confirmed", QuarantineDecision::Reopen)
        .await
        .expect("reopen");

    let before = f.calls.load(Ordering::SeqCst);
    let strict = f.rt.replay(run, Mode::Strict).await.expect("strict replay");
    assert_eq!(strict.status, RunStatus::Succeeded);
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        before,
        "a strict pass performs nothing, including the call a person answered for"
    );
}
