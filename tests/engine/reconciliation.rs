//! Reconciliation: resolving an unknown outcome by asking instead of guessing.
//!
//! Every durable runtime hits the same wall — a call timed out, or a crash
//! landed between "sent" and "recorded", and nothing observable says whether it
//! was applied. The usual answers are to retry and demand idempotency, or to
//! stop and page someone.
//!
//! There is a third answer, and every serious provider supports it: **ask**.
//! Retrieve the payment intent by id. Query the transfer by reference. A probe
//! turns an undecidable outcome into a decided one, and it is the only route to
//! that outcome that is not a bet.
//!
//! What the tests below pin down is that the probe is treated as *evidence*, not
//! as permission: a probe that says "it landed" completes the effect without
//! re-performing it, one that says "it never landed" permits an ordinary retry,
//! and one that cannot tell leaves the run exactly where it was — escalated.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::core::{
    Disposition, Effect, EffectDescriptor, EffectError, EffectKey, Outcome, Phase, PlanIR,
    Reconciliation, Recovery, RetryPolicy, RunId, Skill, SkillDescriptor, SkillError, StepId,
    Tainted,
};
use agentplane::journal::{Append, JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// What the provider will say when asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    SaysItLanded,
    SaysItDidNot,
    CannotTell,
    /// The probe call itself fails.
    Unreachable,
}

/// A mutating effect that always times out, and answers probes as configured.
///
/// Timing out is the point: it is the canonical in-doubt failure, and without
/// reconciliation a mutating effect in that state can only be escalated.
#[derive(Debug, Clone)]
struct Payment {
    probe: Probe,
    calls: Arc<AtomicUsize>,
    probes: Arc<AtomicUsize>,
    /// When set, the effect succeeds instead of timing out.
    succeeds: bool,
}

impl Payment {
    fn new(probe: Probe, calls: &Arc<AtomicUsize>, probes: &Arc<AtomicUsize>) -> Self {
        Self {
            probe,
            calls: Arc::clone(calls),
            probes: Arc::clone(probes),
            succeeds: false,
        }
    }
}

#[async_trait::async_trait]
impl Effect for Payment {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("test.payment", json!({ "ref": "order-4711" }))
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Reconcile
    }

    fn retry(&self) -> RetryPolicy {
        RetryPolicy::attempts(2).with_backoff(Duration::from_millis(1), Duration::from_millis(2))
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.succeeds {
            return Ok(json!({ "captured": true, "via": "perform" }));
        }
        Err(EffectError::Timeout {
            driver: "payments".into(),
            waited_ms: 30_000,
        })
    }

    async fn reconcile(&self) -> Result<Reconciliation<Value>, EffectError> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        match self.probe {
            Probe::SaysItLanded => Ok(Reconciliation::Landed(
                json!({ "captured": true, "via": "probe" }),
            )),
            Probe::SaysItDidNot => Ok(Reconciliation::DidNotHappen),
            Probe::CannotTell => Ok(Reconciliation::Inconclusive),
            Probe::Unreachable => Err(EffectError::Unavailable {
                driver: "payments".into(),
                detail: "probe endpoint down".into(),
            }),
        }
    }
}

#[derive(Debug)]
struct Pay(Payment);

#[async_trait::async_trait]
impl Skill for Pay {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pay").provides("demo.pay")
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
    probes: Arc<AtomicUsize>,
}

fn fixture(probe: Probe) -> Fixture {
    let (calls, probes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .skill(Pay(Payment::new(probe, &calls, &probes)))
        .build();
    Fixture {
        store,
        rt,
        calls,
        probes,
    }
}

fn reconciliations(records: &[agentplane::journal::Record]) -> Vec<Disposition> {
    records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectReconciled { disposition, .. } => Some(*disposition),
            _ => None,
        })
        .collect()
}

// ── Probing after an in-doubt failure ───────────────────────────────────────

/// **The case reconciliation exists for.**
///
/// A payment times out. Without a probe this is a quarantine — correct, and
/// expensive, because someone has to go and look. With one, the runtime looks:
/// the provider says the capture landed, so the effect completes with the
/// recovered result and nothing is sent twice.
#[tokio::test]
async fn a_probe_that_finds_it_landed_completes_the_effect_without_repeating_it() {
    let f = fixture(Probe::SaysItLanded);

    let out = f.rt.run("demo.pay", json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(f.calls.load(Ordering::SeqCst), 1, "sent exactly once");
    assert_eq!(f.probes.load(Ordering::SeqCst), 1, "and asked once");
    assert_eq!(
        out.output.as_ref().and_then(|v| v.peek().get("via")),
        Some(&json!("probe")),
        "the result is the one recovered from the provider"
    );
}

/// A probe that finds it never landed turns an escalation into an ordinary
/// retry. The mutation is then safe to send *because it was established that it
/// had not been sent*, not because anyone assumed so.
#[tokio::test]
async fn a_probe_that_finds_it_never_landed_permits_a_retry() {
    let (calls, probes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    // Attempt 1 times out; the probe says nothing landed; attempt 2 succeeds.
    let mut effect = Payment::new(Probe::SaysItDidNot, &calls, &probes);
    effect.succeeds = false;
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Pay(effect))
        .build();

    let out = rt.run("demo.pay", json!({})).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the retry is permitted once the probe establishes nothing was applied"
    );
    assert_eq!(
        probes.load(Ordering::SeqCst),
        2,
        "each doubt is asked about"
    );
    // Both attempts time out, so the run still fails — but it fails as an
    // ordinary exhausted retry, not as an undecidable escalation.
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "got {:?}",
        out.status
    );
}

/// A probe that cannot tell changes nothing. The run is escalated exactly as it
/// would have been without one — the doubt survived being asked about.
#[tokio::test]
async fn a_probe_that_cannot_tell_still_escalates() {
    let f = fixture(Probe::CannotTell);

    let out = f.rt.run("demo.pay", json!({})).await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1, "never sent twice");
    assert_eq!(f.probes.load(Ordering::SeqCst), 1);
    match &out.status {
        RunStatus::Quarantined(m) => assert!(
            m.contains("could not establish"),
            "the operator must be told the probe ran and failed to decide, got: {m}"
        ),
        other => panic!("expected quarantine, got {other:?}"),
    }
}

/// A probe that is itself unreachable is not an excuse to guess.
#[tokio::test]
async fn an_unreachable_probe_escalates_rather_than_assuming() {
    let f = fixture(Probe::Unreachable);

    let out = f.rt.run("demo.pay", json!({})).await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(out.status, RunStatus::Quarantined(_)));
}

// ── What the journal records ────────────────────────────────────────────────

/// **"We did not know, we asked, and here is what we learned."**
///
/// The verdict is journaled even when inconclusive. Leaving that out would make
/// an escalation look like nobody tried, and the operator would repeat the probe
/// by hand.
#[tokio::test]
async fn the_verdict_is_journaled_even_when_it_resolves_nothing() {
    for (probe, expected) in [
        (Probe::SaysItLanded, Disposition::Landed),
        (Probe::SaysItDidNot, Disposition::DidNotHappen),
        (Probe::CannotTell, Disposition::InDoubt),
        (Probe::Unreachable, Disposition::InDoubt),
    ] {
        let f = fixture(probe);
        let out = f.rt.run("demo.pay", json!({})).await.unwrap();
        let records = f.store.read(out.run_id, 1).await.unwrap();
        assert_eq!(
            reconciliations(&records).first(),
            Some(&expected),
            "probe {probe:?} must record its verdict"
        );
    }
}

/// A probe that failed says so on the record, so the operator does not have to
/// go and discover the endpoint was down.
#[tokio::test]
async fn a_failed_probe_records_why() {
    let f = fixture(Probe::Unreachable);
    let out = f.rt.run("demo.pay", json!({})).await.unwrap();
    let records = f.store.read(out.run_id, 1).await.unwrap();

    let detail = records.iter().find_map(|r| match r.kind() {
        RecordKind::EffectReconciled { detail, .. } => detail.clone(),
        _ => None,
    });
    assert!(
        detail.is_some_and(|d| d.contains("probe endpoint down")),
        "the probe's own failure belongs on the record"
    );
}

// ── Replay ──────────────────────────────────────────────────────────────────

/// The probe is a network call like any other: replay reads its verdict back
/// rather than asking again.
#[tokio::test]
async fn replay_reads_the_verdict_back_instead_of_probing_again() {
    let f = fixture(Probe::SaysItLanded);

    let first = f.rt.run("demo.pay", json!({})).await.unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);
    assert_eq!(f.probes.load(Ordering::SeqCst), 1);

    let again = f.rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(again.output, first.output);
    assert_eq!(
        f.probes.load(Ordering::SeqCst),
        1,
        "strict replay must not re-probe the provider"
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

// ── Probing after a crash ───────────────────────────────────────────────────

/// A crash between "sent" and "recorded" leaves the same doubt a timeout does,
/// and resolves the same way.
#[tokio::test]
async fn a_crash_orphan_is_resolved_by_the_probe_rather_than_escalated() {
    let f = fixture(Probe::SaysItLanded);

    let run = RunId::generate();
    let plan = PlanIR::single("demo.pay");
    let lease = f
        .store
        .acquire(run, "test", Duration::from_mins(1))
        .await
        .unwrap();

    let descriptor = EffectDescriptor::new("test.payment", json!({ "ref": "order-4711" }));
    let key = EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &descriptor);

    f.store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "demo.pay".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: agentplane::core::Label::trusted(),
                        policy_bundle: None,
                    },
                ),
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        digest: plan.digest(),
                        steps: vec!["demo.pay".into()],
                        plan: serde_json::to_value(&plan).unwrap(),
                    },
                ),
                Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: "pay".into(),
                    },
                )
                .step(StepId(0)),
                // Announced, then the process died. Did the payment go out?
                Append::new(
                    run,
                    RecordKind::EffectStarted {
                        descriptor,
                        recovery: Recovery::Reconcile,
                        mutates: true,
                        attempt: 1,
                        backoff_ms: 0,
                        outbound_label: None,
                    },
                )
                .step(StepId(0))
                .effect(key),
            ],
        )
        .await
        .unwrap();

    let out = f.rt.replay(run, Mode::Resume).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        0,
        "the interrupted payment must not be sent again — the probe found it landed"
    );
    assert_eq!(f.probes.load(Ordering::SeqCst), 1);
}

/// **Strict replay is a pure read, orphan or not.**
///
/// An earlier version fell through to the re-perform path here, so verifying a
/// crashed run performed its interrupted effect for real and appended to the
/// history it was meant to be checking. A regression check that mutates the
/// thing it checks is worse than no check.
#[tokio::test]
async fn strict_replay_of_an_orphan_neither_performs_nor_probes_nor_writes() {
    let f = fixture(Probe::SaysItLanded);

    let run = RunId::generate();
    let plan = PlanIR::single("demo.pay");
    let lease = f
        .store
        .acquire(run, "test", Duration::from_mins(1))
        .await
        .unwrap();

    let descriptor = EffectDescriptor::new("test.payment", json!({ "ref": "order-4711" }));
    let key = EffectKey::for_effect(StepId(0), Phase::Forward, 0, 1, &descriptor);

    f.store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "demo.pay".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: agentplane::core::Label::trusted(),
                        policy_bundle: None,
                    },
                ),
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        digest: plan.digest(),
                        steps: vec!["demo.pay".into()],
                        plan: serde_json::to_value(&plan).unwrap(),
                    },
                ),
                Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: "pay".into(),
                    },
                )
                .step(StepId(0)),
                Append::new(
                    run,
                    RecordKind::EffectStarted {
                        descriptor,
                        recovery: Recovery::Reconcile,
                        mutates: true,
                        attempt: 1,
                        backoff_ms: 0,
                        outbound_label: None,
                    },
                )
                .step(StepId(0))
                .effect(key),
            ],
        )
        .await
        .unwrap();

    let before = f.store.read(run, 1).await.unwrap();
    let out = f.rt.replay(run, Mode::Strict).await.unwrap();
    let after = f.store.read(run, 1).await.unwrap();

    assert_eq!(f.calls.load(Ordering::SeqCst), 0, "performed nothing");
    assert_eq!(f.probes.load(Ordering::SeqCst), 0, "probed nothing");
    assert_eq!(
        before.len(),
        after.len(),
        "strict replay appended {} record(s) — verification must not mutate history",
        after.len() - before.len()
    );
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "an incomplete journal cannot be verified, got {:?}",
        out.status
    );
}
