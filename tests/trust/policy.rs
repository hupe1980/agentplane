//! Authorization: the gate, and the guarantee that replay never re-opens it.
//!
//! The claims, each with a failure mode that reads as success:
//!
//! * **A denial stops the effect before it reaches the world.** The failure mode
//!   is a gate that runs after dispatch and reports a denial for something that
//!   already happened.
//! * **A denial is journaled.** Without a record, strict replay reaches that
//!   point, finds no history, and reports "this build performs more effects than
//!   the recorded one" — sending an operator to look for a code change that does
//!   not exist. This is exactly why `BudgetRefused` exists.
//! * **Replay never consults the engine.** The load-bearing one. If policy were
//!   re-evaluated during replay, editing a rule would silently re-judge last
//!   year's run under this year's rules, and the audit trail would quietly
//!   become a lie. Every test here that replays uses an engine that *panics* if
//!   asked, so the guarantee is enforced rather than described.
//! * **A permit costs no journal.** The effect's own record is the evidence.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use agentplane::core::{
    ACTION_ADMIT, ACTION_PERFORM, Digest, Effect, EffectDescriptor, EffectError, Outcome, PlanIR,
    PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Recovery, Release,
    ReleaseScope, RetryPolicy, RunId, RuntimeError, Skill, SkillDescriptor, SkillError, SourceId,
    Tainted,
};
use agentplane::journal::{Append, JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Effects that actually reached the world.
type World = Arc<Mutex<Vec<String>>>;

fn test_bundle(rules: &'static [u8]) -> PolicyBundleIdentity {
    PolicyBundleIdentity::new(Digest::of(rules), "agentplane-test/policy-v1")
}

// ── Engines ─────────────────────────────────────────────────────────────────

/// Permits everything, and counts how often it was asked.
#[derive(Debug, Default)]
struct Counting {
    asked: AtomicUsize,
}

impl PolicyEngine for Counting {
    fn authorize(&self, _r: &PolicyRequest<'_>) -> PolicyDecision {
        self.asked.fetch_add(1, Ordering::SeqCst);
        PolicyDecision::Permit
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        test_bundle(b"counting")
    }
}

/// Refuses one resource by name, permits the rest.
#[derive(Debug)]
struct Refuses(&'static str);

impl PolicyEngine for Refuses {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        if r.resource == self.0 {
            PolicyDecision::deny(format!("'{}' is not permitted for this agent", r.resource))
        } else {
            PolicyDecision::Permit
        }
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        test_bundle(b"refuses")
    }
}

/// Refuses only attempts to release data from the information-flow lattice.
#[derive(Debug)]
struct RefusesRelease;

impl PolicyEngine for RefusesRelease {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        if r.action == "data:release" {
            PolicyDecision::deny("this agent may not release externally sourced data")
        } else {
            PolicyDecision::Permit
        }
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        test_bundle(b"refuses-release")
    }
}

/// Fails the test if it is ever consulted.
///
/// This is how "replay does not re-evaluate policy" is *enforced* rather than
/// asserted after the fact — a re-evaluation cannot slip through as a decision
/// that happened to match.
#[derive(Debug)]
struct MustNotBeAsked;

impl PolicyEngine for MustNotBeAsked {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        panic!(
            "replay consulted the policy engine ('{}' on '{}'). A replayed effect \
             never reaches the world, so it must never reach the gate — otherwise \
             editing a rule silently re-judges a run that already happened.",
            r.action, r.resource
        );
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        test_bundle(b"must-not-be-asked")
    }
}

/// Panics if consulted while presenting the same identity as `Refuses`.
#[derive(Debug)]
struct RefusesIdentityButMustNotBeAsked;

impl PolicyEngine for RefusesIdentityButMustNotBeAsked {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        panic!(
            "resume re-evaluated a recorded refusal ('{}' on '{}')",
            r.action, r.resource
        );
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        test_bundle(b"refuses")
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Touch {
    kind: &'static str,
    world: World,
}

#[async_trait::async_trait]
impl Effect for Touch {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(self.kind, json!({}))
    }
    fn mutates(&self) -> bool {
        true
    }
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.lock().unwrap().push(self.kind.to_string());
        Ok(json!({ "did": self.kind }))
    }
}

/// Performs two effects: one benign, one the policy may refuse.
#[derive(Debug)]
struct Pays {
    world: World,
}

#[async_trait::async_trait]
impl Skill for Pays {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pay").provides("pay")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Touch {
            kind: "ledger.read",
            world: Arc::clone(&self.world),
        })
        .await?;
        cx.effect(Touch {
            kind: "ledger.transfer",
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "paid": true }))))
    }
}

fn db() -> Arc<RedbStore> {
    Arc::new(RedbStore::open_in_memory().unwrap())
}

fn runtime(
    db: &Arc<RedbStore>,
    world: &World,
    engine: Option<Arc<dyn PolicyEngine>>,
) -> Arc<Runtime> {
    let mut b = Runtime::builder(Arc::clone(db) as Arc<dyn JournalStore>)
        .owner("policy")
        .skill(Pays {
            world: Arc::clone(world),
        });
    if let Some(e) = engine {
        b = b.policy(e);
    }
    b.build()
}

#[derive(Debug)]
struct Releases;

#[async_trait::async_trait]
impl Skill for Releases {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("release").provides("release")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let external = Tainted::from_source(json!({ "account": "customer" }), SourceId::new("crm"));
        let released = cx
            .release(
                external,
                Release::whole(
                    ReleaseScope::trust(),
                    "reviewed against the settlement record",
                    "run.output",
                    ["review:SET-42".to_owned()],
                ),
            )
            .await?;
        Ok(Outcome::done(released))
    }
}

// ── The gate ────────────────────────────────────────────────────────────────

/// A release is an authority-bearing operation, not a logging helper.
#[tokio::test]
async fn policy_can_refuse_a_release_before_the_label_is_improved() {
    let store = db();
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("policy")
        .policy(Arc::new(RefusesRelease))
        .skill(Releases)
        .build();

    let out = runtime.run("release", json!({})).await.unwrap();
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "{:?}",
        out.status
    );

    let records = store.read(out.run_id, 1).await.unwrap();
    assert!(
        !records
            .iter()
            .any(|record| matches!(record.kind(), RecordKind::Released { .. })),
        "a denied release removed the label and recorded it as approved"
    );
    assert!(records.iter().any(|record| matches!(
        record.kind(),
        RecordKind::PolicyDenied { action, .. } if action == "data:release"
    )));

    let replay = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("policy")
        .policy(Arc::new(MustNotBeAsked))
        .skill(Releases)
        .build()
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("recorded release denial replays");
    assert_eq!(replay.status, out.status);
}

#[derive(Debug)]
struct ReleasesWithBasis(&'static str);

#[async_trait::async_trait]
impl Skill for ReleasesWithBasis {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("release-with-basis").provides("release-with-basis")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let external = Tainted::from_source(json!({ "account": "customer" }), SourceId::new("crm"));
        Ok(Outcome::done(
            cx.release(
                external,
                Release::whole(
                    ReleaseScope::trust(),
                    self.0,
                    "run.output",
                    ["review:SET-42".to_owned()],
                ),
            )
            .await?,
        ))
    }
}

#[tokio::test]
async fn changing_release_evidence_is_replay_divergence() {
    let store = db();
    let first = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(ReleasesWithBasis("matched settlement revision 1"))
        .build()
        .run("release-with-basis", json!({}))
        .await
        .unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);

    let replay = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(ReleasesWithBasis("matched settlement revision 2"))
        .build()
        .replay(first.run_id, Mode::Strict)
        .await
        .unwrap();
    assert!(
        matches!(replay.status, RunStatus::Quarantined(_)),
        "changed release evidence rewrote history: {:?}",
        replay.status
    );
}

/// A denied effect never reaches the world, and the one before it still did.
#[tokio::test]
async fn a_denied_effect_is_refused_before_it_is_performed() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Refuses("ledger.transfer"))))
        .run("pay", json!({}))
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "status: {:?}",
        out.status
    );
    assert_eq!(
        *world.lock().unwrap(),
        vec!["ledger.read".to_string()],
        "the permitted effect ran; the denied one must not have reached the world"
    );
}

/// The reason survives to the caller. "Denied by policy" is not actionable.
#[tokio::test]
async fn a_denial_carries_a_reason_someone_can_act_on() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Refuses("ledger.transfer"))))
        .run("pay", json!({}))
        .await
        .unwrap();

    let RunStatus::Failed(why) = &out.status else {
        panic!("expected a failure: {:?}", out.status)
    };
    assert!(
        why.contains("not permitted"),
        "the engine's reason must reach the operator: {why}"
    );
    assert!(
        why.contains("ledger.transfer"),
        "and it must say what was refused: {why}"
    );
}

/// Admission is gated too — and a refused run leaves no journal at all.
#[tokio::test]
async fn a_run_the_policy_refuses_to_admit_never_starts() {
    let store = db();
    let world: World = Arc::default();

    let err = runtime(&store, &world, Some(Arc::new(Refuses("pay"))))
        .run("pay", json!({}))
        .await
        .expect_err("admission must be refused");

    assert!(err.to_string().contains(ACTION_ADMIT), "error: {err}");
    assert!(world.lock().unwrap().is_empty());
}

// ── The journal ─────────────────────────────────────────────────────────────

/// A denial is recorded, because it is a place the run stopped.
#[tokio::test]
async fn a_denial_is_journaled_like_a_budget_refusal() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Refuses("ledger.transfer"))))
        .run("pay", json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let denial = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::PolicyDenied {
                reason,
                action,
                resource,
            } => Some((reason.clone(), action.clone(), resource.clone())),
            _ => None,
        })
        .expect("the denial must be on the record, or replay cannot reproduce it");

    assert_eq!(denial.1, ACTION_PERFORM);
    assert_eq!(denial.2, "ledger.transfer");
    assert!(denial.0.contains("not permitted"));
    store.verify(out.run_id).await.expect("chain intact");
}

/// A permit costs nothing. The effect's own record is the evidence it was allowed.
#[tokio::test]
async fn a_permit_writes_no_record_of_its_own() {
    let store = db();
    let world: World = Arc::default();
    let engine = Arc::new(Counting::default());

    let out = runtime(&store, &world, Some(engine.clone()))
        .run("pay", json!({}))
        .await
        .unwrap();

    assert!(matches!(out.status, RunStatus::Succeeded));
    let records = store.read(out.run_id, 1).await.unwrap();
    assert!(
        !records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::PolicyDenied { .. })),
        "nothing was denied, so nothing should be recorded as denied"
    );
    assert!(
        engine.asked.load(Ordering::SeqCst) >= 3,
        "admission plus two effects should have been authorized, not {}",
        engine.asked.load(Ordering::SeqCst)
    );
}

/// Which complete policy bundle governed a run is answerable years later.
#[tokio::test]
async fn the_admission_record_names_the_policy_set() {
    let store = db();
    let world: World = Arc::default();
    let engine = Arc::new(Counting::default());
    let expected = engine.bundle();

    let out = runtime(&store, &world, Some(engine))
        .run("pay", json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let admitted = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted { policy_bundle, .. } => Some(policy_bundle.clone()),
            _ => None,
        })
        .expect("RunAdmitted");
    assert_eq!(
        admitted,
        Some(expected),
        "the complete policy bundle must be on the admission record"
    );
}

/// No engine is recorded as no engine — not as a permissive one.
///
/// "Was policy switched on for this run" must be answerable from the journal
/// rather than from someone's memory of how the deployment was wired.
#[tokio::test]
async fn a_run_with_no_policy_layer_says_so_on_the_record() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, None)
        .run("pay", json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let policy_bundle = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted { policy_bundle, .. } => Some(policy_bundle.clone()),
            _ => None,
        })
        .expect("RunAdmitted");
    assert_eq!(policy_bundle, None);
    assert!(matches!(out.status, RunStatus::Succeeded));
}

// ── The guarantee ───────────────────────────────────────────────────────────

/// Replay must not consult the engine — enforced by an engine that panics.
///
/// A replayed effect never reaches the world, so it must never reach the gate.
/// Re-evaluating would mean a rule edited today silently re-judges a run from
/// last year, and the audit trail becomes a lie that still verifies.
#[tokio::test]
async fn strict_replay_never_asks_the_policy_engine() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Counting::default())))
        .run("pay", json!({}))
        .await
        .unwrap();
    assert_eq!(world.lock().unwrap().len(), 2);

    let replayed: World = Arc::default();
    let verified = runtime(&store, &replayed, Some(Arc::new(MustNotBeAsked)))
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("a strict replay of a permitted run must verify");

    assert!(matches!(verified.status, RunStatus::Succeeded));
    assert!(
        replayed.lock().unwrap().is_empty(),
        "a strict replay performs nothing"
    );
}

/// Resume may dispatch work after the recorded prefix, so it cannot silently
/// switch to a different policy bundle midway through one run.
#[tokio::test]
async fn an_open_run_refuses_to_resume_under_a_different_policy_bundle() {
    let store = db();
    let run = RunId::generate();
    let plan = PlanIR::single("pay");
    let admitted = Counting::default().bundle();
    let lease = store
        .acquire(run, "policy", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "pay".into(),
                        governed_by: None,
                        input: json!({}),
                        input_label: agentplane::core::Label::trusted(),
                        policy_bundle: Some(admitted),
                    },
                ),
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        steps: vec!["pay".into()],
                        plan: serde_json::to_value(plan).unwrap(),
                    },
                ),
            ],
        )
        .await
        .unwrap();

    let world: World = Arc::default();
    let err = runtime(&store, &world, Some(Arc::new(Refuses("nothing"))))
        .replay(run, Mode::Resume)
        .await
        .expect_err("bundle drift must stop resume before dispatch");
    assert!(matches!(err, RuntimeError::PolicyBundleChanged { .. }));
    assert!(world.lock().unwrap().is_empty());

    // Offline verification does not compare or consult policy. This prefix may
    // still be reported as incomplete, which is a separate replay result.
    let strict = runtime(&store, &world, Some(Arc::new(MustNotBeAsked)))
        .replay(run, Mode::Strict)
        .await;
    assert!(!matches!(
        strict,
        Err(RuntimeError::PolicyBundleChanged { .. })
    ));
    assert!(world.lock().unwrap().is_empty());
}

/// A recorded denial replays as that denial, under any policy set.
///
/// The run stopped there, and it must keep stopping there — even if the rule
/// that stopped it has since been relaxed. Otherwise replaying an old run under
/// today's rules produces a history that never happened.
#[tokio::test]
async fn a_recorded_denial_replays_even_if_the_policy_would_now_permit() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Refuses("ledger.transfer"))))
        .run("pay", json!({}))
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Failed(_)));

    // Replay under an engine that would now permit everything — and that panics
    // if consulted, because it must not be.
    let replayed: World = Arc::default();
    let again = runtime(&store, &replayed, Some(Arc::new(MustNotBeAsked)))
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("replay of a denied run is a pure read");

    let RunStatus::Failed(why) = &again.status else {
        panic!("the denial must survive replay: {:?}", again.status)
    };
    assert!(
        why.contains("not permitted"),
        "and it must keep its original reason: {why}"
    );
    assert!(
        replayed.lock().unwrap().is_empty(),
        "nothing may be performed on a replay of a denied run"
    );
}

/// Resuming a denied run does not silently retry the denied effect.
#[tokio::test]
async fn resuming_a_denied_run_does_not_perform_the_denied_effect() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Refuses("ledger.transfer"))))
        .run("pay", json!({}))
        .await
        .unwrap();

    let resumed: World = Arc::default();
    let again = runtime(
        &store,
        &resumed,
        Some(Arc::new(RefusesIdentityButMustNotBeAsked)),
    )
    .replay(out.run_id, Mode::Resume)
    .await
    .expect("resume reads the denial back");

    assert!(matches!(again.status, RunStatus::Failed(_)));
    assert!(
        resumed.lock().unwrap().is_empty(),
        "the denied effect must not be performed on resume: {:?}",
        resumed.lock().unwrap()
    );
}

/// Authorization runs before the budget is spent.
///
/// An agent that is not allowed to act must not be able to exhaust a run's
/// allowance by asking — otherwise a denied principal still costs money.
#[tokio::test]
async fn authorization_is_checked_before_the_budget_is_charged() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, Some(Arc::new(Refuses("ledger.transfer"))))
        .run("pay", json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let denied_at = records
        .iter()
        .position(|r| matches!(r.kind(), RecordKind::PolicyDenied { .. }));
    let started = records
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.kind(), RecordKind::EffectStarted { .. }))
        .count();

    assert!(denied_at.is_some(), "the denial is on the record");
    assert_eq!(
        started, 1,
        "only the permitted effect announced itself — a denied effect must not \
         reach the announce step at all"
    );
}

/// The default engine refuses, and says why.
///
/// There is deliberately no `AllowAll`: a permissive engine and no engine are
/// the same behaviour, and two ways to spell it is how a plane ends up with a
/// policy layer everyone believes is switched on.
#[tokio::test]
async fn the_default_engine_denies_and_explains_itself() {
    let store = db();
    let world: World = Arc::default();

    let err = runtime(
        &store,
        &world,
        Some(Arc::new(agentplane::core::DenyAll) as Arc<dyn PolicyEngine>),
    )
    .run("pay", json!({}))
    .await
    .expect_err("DenyAll must refuse admission");

    assert!(err.to_string().contains("pay"), "error: {err}");
    assert!(world.lock().unwrap().is_empty());
}

/// The engine sees a principal, an action, and a resource it can key on.
#[tokio::test]
async fn the_request_carries_what_a_rule_needs() {
    #[derive(Debug, Default)]
    struct Capturing(Mutex<Vec<(String, String, String)>>);

    impl PolicyEngine for Capturing {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0.lock().unwrap().push((
                r.principal.to_string(),
                r.action.to_string(),
                r.resource.to_string(),
            ));
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            test_bundle(b"capturing")
        }
    }

    let store = db();
    let world: World = Arc::default();
    let engine = Arc::new(Capturing::default());
    runtime(&store, &world, Some(engine.clone()))
        .run("pay", json!({}))
        .await
        .unwrap();

    let seen = engine.0.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(p, a, r)| p == "pay" && a == ACTION_ADMIT && r == "pay"),
        "admission must be authorized: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|(p, a, r)| p == "pay" && a == ACTION_PERFORM && r == "ledger.transfer"),
        "each effect must be authorized by its kind: {seen:?}"
    );
}

/// A run id is never leaked into the principal by accident.
///
/// The principal is the agent, and a rule written against it must not have to
/// match a ULID that changes every run.
#[tokio::test]
async fn the_principal_is_stable_across_runs() {
    #[derive(Debug, Default)]
    struct Principals(Mutex<Vec<String>>);

    impl PolicyEngine for Principals {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0.lock().unwrap().push(r.principal.to_string());
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            test_bundle(b"principals")
        }
    }

    let store = db();
    let world: World = Arc::default();
    let engine = Arc::new(Principals::default());
    for _ in 0..2 {
        runtime(&store, &world, Some(engine.clone()))
            .run("pay", json!({}))
            .await
            .unwrap();
    }

    let seen = engine.0.lock().unwrap().clone();
    let distinct: std::collections::BTreeSet<_> = seen.iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "the principal must be stable, not per-run: {distinct:?}"
    );
    let _ = RunId::generate();
}

// ── Denial feedback as a side channel ───────────────────────────────────────
//
// A refusal message written for an operator is precise on purpose: which
// principal, which sink, what sensitivity, which ceiling. Fed back into a
// prompt, that precision turns the policy into a queryable service — vary the
// request, watch which variants are refused, read the boundary off the answers.
// `EgressCeiling` is the sharpest: it reports the sensitivity of data the run
// was never allowed to reveal.

/// Every refusal reads the same to a model, whatever was actually wrong.
#[test]
fn a_model_is_told_the_same_thing_whatever_the_reason() {
    use agentplane::core::{PolicyError, REFUSED, Sensitivity};

    let denials = [
        PolicyError::Denied {
            principal: "agent:switch-bot".into(),
            action: "perform".into(),
            resource: "tool.transfer".into(),
        },
        PolicyError::TaintGate {
            sink: "tool.transfer".into(),
        },
        PolicyError::EgressCeiling {
            sink: "tool.email".into(),
            actual: Sensitivity::Secret,
            ceiling: Sensitivity::Public,
        },
    ];

    for d in &denials {
        assert_eq!(
            d.for_model(),
            REFUSED,
            "a model-facing refusal must not differentiate: {d}"
        );
    }

    // And the operator-facing form must still say everything.
    let detailed = denials[2].to_string();
    assert!(
        detailed.contains("Secret") && detailed.contains("email"),
        "the journal keeps the detail an auditor needs: {detailed}"
    );
    assert!(
        !REFUSED.contains("Secret"),
        "the uniform text must not carry the very thing it hides"
    );
}

/// A run that keeps hitting the policy is probing it, and the probing stops.
///
/// The uniform message removes *which* boundary was hit; it cannot remove the
/// refused/allowed bit itself. Nothing can, short of fabricating success. What
/// bounds that channel is bounding the attempts.
///
/// Note what is asserted and what is not. A probing loop swallows the error it
/// gets back — that is what makes it a probing loop — so the guarantee is not
/// "the skill gives up". It is that **no further attempt is admitted**: past the
/// ceiling every effect is refused before it is performed, so the number of
/// distinct refusals an attacker can observe is bounded no matter how many times
/// the loop asks.
#[tokio::test]
async fn a_run_that_keeps_being_refused_stops_learning() {
    use agentplane::core::Budget;

    const CEILING: u32 = 3;
    const ATTEMPTS: usize = 40;

    #[derive(Debug)]
    struct Probes;

    #[async_trait::async_trait]
    impl Skill for Probes {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("probes").provides("demo.probe")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            // Each refusal is swallowed and the loop asks again, which is
            // exactly the behaviour the ceiling exists to bound.
            for i in 0..ATTEMPTS {
                let arguments = Tainted::trusted(Value::Null);
                let _ = cx
                    .sink(
                        agentplane::runtime::effects::Recorded::new(format!("probe-{i}")),
                        &arguments,
                    )
                    .await;
            }
            Ok(Outcome::done(Tainted::trusted(json!("done probing"))))
        }
    }

    /// Admits the run, then refuses every effect it tries.
    #[derive(Debug)]
    struct RefusesEveryEffect;

    impl PolicyEngine for RefusesEveryEffect {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            if r.action == ACTION_PERFORM {
                PolicyDecision::deny("no")
            } else {
                PolicyDecision::Permit
            }
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            test_bundle(b"refuses-every-effect")
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::new(RefusesEveryEffect))
        .budget(Budget::unlimited().denials(CEILING))
        .skill(Probes)
        .build()
        .run("demo.probe", json!({}))
        .await
        .unwrap();

    let denials = store
        .read(out.run_id, 1)
        .await
        .unwrap()
        .iter()
        .filter(|r| matches!(r.kind(), RecordKind::PolicyDenied { .. }))
        .count();

    assert!(
        denials <= CEILING as usize + 1,
        "{denials} refusals were recorded against a ceiling of {CEILING}, from \
         {ATTEMPTS} attempts. Each one an attacker can observe is a bit about \
         where the boundary lies, so the count has to be bounded by the ceiling \
         rather than by how many times the loop felt like asking"
    );
    assert!(
        denials > 0,
        "the fixture must actually be refused, or this asserts nothing"
    );
}

// ── Provenance is visible to authorization, not only to the hardcoded gates ──

/// Denies a mutating sink whenever the value it will send is untrusted.
///
/// A rule an operator would plausibly write, and one that cannot be written at
/// all unless the label reaches the request.
#[derive(Debug)]
struct RefusesUntrustedArguments;

impl PolicyEngine for RefusesUntrustedArguments {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        if r.action != ACTION_PERFORM {
            return PolicyDecision::Permit;
        }
        match r.context["label"]["trust"].as_str() {
            Some("untrusted") => PolicyDecision::deny(format!(
                "'{}' may not be called with untrusted arguments",
                r.resource
            )),
            // Absent means the gate cannot see provenance at all, which is the
            // defect this test exists to catch — permit, so the assertion below
            // reports the missing field rather than an unrelated denial.
            _ => PolicyDecision::Permit,
        }
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        test_bundle(b"refuses-untrusted-arguments")
    }
}

/// Sends a labelled value through `sink`.
#[derive(Debug)]
struct Posts {
    trusted: bool,
}

#[async_trait::async_trait]
impl Skill for Posts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("posts").provides("demo.post")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let args = if self.trusted {
            Tainted::trusted(json!({ "memo": "quarterly close" }))
        } else {
            Tainted::from_source(
                json!({ "memo": "quarterly close" }),
                SourceId::new("peer:broker-x"),
            )
        };
        let call = Bound {
            args: args.peek().clone(),
        };
        let out = cx.sink(call, &args).await?;
        Ok(Outcome::done(out.map(|v| v)))
    }
}

/// A mutating sink that binds its outbound arguments and declares no protected
/// fields, so only the whole-value gate and policy stand in front of it.
#[derive(Debug)]
struct Bound {
    args: Value,
}

#[async_trait::async_trait]
impl Effect for Bound {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.post_entry", self.args.clone())
    }
    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.args)
    }
    /// Raised so this test isolates *provenance*: the crate's own ceiling would
    /// otherwise refuse the untrusted value first, for a different reason.
    fn max_sensitivity(&self) -> agentplane::core::Sensitivity {
        agentplane::core::Sensitivity::Internal
    }
    /// Declared non-mutating for the same reason: the unconditional taint gate
    /// would refuse before policy is consulted, and what is under test is
    /// whether a *rule* can see where the value came from.
    fn mutates(&self) -> bool {
        false
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "posted": true }))
    }
}

/// A rule may key on **where the value came from**, not only on what it is.
///
/// Provenance and authorization are two graphs, and an attack lives in the gap
/// between them: an agent is permitted to call a tool in general, and that
/// permission never accounts for the provenance of the particular value it is
/// called with. This crate closes the gap with hardcoded checks — the taint gate
/// and per-field source rules — but if the label never reaches the policy
/// request, a *deployment* cannot express the alignment at all. It can say
/// "amounts over 5000 need approval"; it cannot say "not with data that passed
/// through that peer", which is the rule the attack calls for.
#[tokio::test]
async fn a_rule_can_refuse_an_effect_for_where_its_arguments_came_from() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(Arc::new(RefusesUntrustedArguments))
        .skill(Posts { trusted: false })
        .build();

    let out = rt.run("demo.post", json!({})).await.unwrap();
    let RunStatus::Failed(why) = &out.status else {
        panic!(
            "a rule keyed on provenance did not fire — the policy request \
             carries no label, so authorization cannot see where the value came \
             from: {:?}",
            out.status
        );
    };
    assert!(
        why.contains("untrusted arguments"),
        "denied for an unrelated reason: {why}"
    );
}

/// And the same rule permits the same call when the value is trusted, so the
/// test above refuses the *provenance* rather than refusing everything.
#[tokio::test]
async fn the_same_rule_permits_the_same_effect_when_the_value_is_trusted() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(Arc::new(RefusesUntrustedArguments))
        .skill(Posts { trusted: true })
        .build();

    let out = rt.run("demo.post", json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded, "got {:?}", out.status);
}

/// The label the gate consulted is on the record.
///
/// Authorization reads the outbound label, so a record without it describes a
/// decision whose inputs cannot be recovered. Policy here is total and
/// side-effect free, which means an auditor holding the bundle identity, the
/// effect descriptor and this label can reach the same verdict offline — and
/// without it they must take the runtime's word that the right label was
/// presented.
///
/// Named by the property-level evidence literature as *policy basis*: the
/// question is not only *was this permitted* but *under what, and can someone
/// else check it*.
#[tokio::test]
async fn the_label_authorization_consulted_is_journaled() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        // Permissive on purpose: what is under test is whether the label the
        // gate *consulted* is recorded, and a denial stops before the effect is
        // ever announced.
        .policy(Arc::new(Counting::default()))
        .skill(Posts { trusted: false })
        .build();

    let out = rt.run("demo.post", json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded, "got {:?}", out.status);

    let labels: Vec<_> = store
        .read(out.run_id, 1)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectStarted { outbound_label, .. } => outbound_label.clone(),
            _ => None,
        })
        .collect();

    let sink = labels
        .iter()
        .find(|l| {
            l.provenance
                .iter()
                .any(|s| s.to_string().contains("broker-x"))
        })
        .expect(
            "the label the gate consulted is absent from the record, so the \
             authorization decision cannot be re-derived by anyone who was not \
             there",
        );
    assert_eq!(sink.trust, agentplane::core::Trust::Untrusted);

    // And an effect that binds no value records none, so the field means
    // *what was presented* rather than defaulting to something plausible.
    assert!(
        labels.len() < 4,
        "every effect recorded a label, including those that present none: {labels:?}"
    );
}

/// **A case read is not a mutation; a case write is** — as policy sees it.
///
/// `context.mutates` is what a deployment writes its taint gate against — the
/// worked rule on the security page is literally
/// `forbid ... when { context.mutates && context.label.trust == "untrusted" }`.
/// So the flag has to be right on the effects that carry it, and nothing pinned
/// it: a mutation sweep flipped `WriteCaseState::mutates` to `false` and the
/// whole suite stayed green. Under that mutation a case-state write of untrusted
/// data reaches policy as a *read*, and every rule keyed on `context.mutates`
/// silently stops applying to it.
///
/// Both directions are asserted, because only one of them is dangerous and the
/// other is what makes the assertion mean anything: a test that merely required
/// `mutates == true` somewhere would pass with it hard-coded true everywhere.
#[tokio::test]
async fn policy_sees_a_case_read_as_a_read_and_a_case_write_as_a_mutation() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, PolicyEngine};

    /// Records `(resource, mutates)` for every authorization request.
    #[derive(Debug, Default)]
    struct Watching(Mutex<Vec<(String, bool)>>);

    impl PolicyEngine for Watching {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            let mutates = r
                .context
                .get("mutates")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            self.0
                .lock()
                .unwrap()
                .push((r.resource.to_owned(), mutates));
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            test_bundle(b"watching")
        }
    }

    #[derive(Debug)]
    struct TouchesCase;

    #[async_trait::async_trait]
    impl Skill for TouchesCase {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("touches").provides("demo.touch")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let (_state, at) = cx.case_state().await?;
            cx.put_case_state(at, json!({ "seen": true })).await?;
            // The other two case mutations, so the same assertion covers every
            // effect that changes state other runs observe.
            cx.deadline("window", &agentplane::core::DeadlineSpec::days(1), None)
                .await?;
            cx.meet_deadline("window").await?;
            cx.set_case_status(agentplane::core::CaseStatus::Closed)
                .await?;
            Ok(Outcome::done(Tainted::trusted(json!({}))))
        }
    }

    let watching = Arc::new(Watching::default());
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .policy(Arc::clone(&watching) as Arc<dyn PolicyEngine>)
        .skill(TouchesCase)
        .build()
        .run_in_case(
            "demo.touch",
            json!({}),
            "demo",
            &[CorrelationKey::new("doc", "C-1")],
        )
        .await
        .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);

    let seen = watching.0.lock().unwrap().clone();
    let read = seen
        .iter()
        .find(|(r, _)| r == "case.read_state")
        .unwrap_or_else(|| panic!("no case read reached policy: {seen:?}"));
    let write = seen
        .iter()
        .find(|(r, _)| r == "case.write_state")
        .unwrap_or_else(|| panic!("no case write reached policy: {seen:?}"));

    assert!(
        !read.1,
        "a case-state read reached policy as a mutation, so a rule that gates \
         mutations would fire on every read"
    );
    assert!(
        write.1,
        "a case-state write reached policy as a read, so every rule keyed on \
         `context.mutates` silently stops applying to it — including the taint \
         gate published on the security page"
    );

    // The other two mutations of shared state, for the same reason.
    for resource in ["case.set_status", "case.transition_deadline"] {
        let (_, mutates) = seen
            .iter()
            .find(|(r, _)| r == resource)
            .unwrap_or_else(|| panic!("no {resource} reached policy: {seen:?}"));
        assert!(
            *mutates,
            "{resource} reached policy as a read; it changes state other runs \
             observe, so a rule gating mutations must see it as one"
        );
    }

    // And a deadline *resolution* is not itself a mutation — it computes an
    // instant. Without this the assertions above would pass with `mutates`
    // hard-coded true for everything.
    let (_, resolve) = seen
        .iter()
        .find(|(r, _)| r == "deadline.resolve")
        .unwrap_or_else(|| panic!("no deadline resolution reached policy: {seen:?}"));
    assert!(
        !resolve,
        "resolving a deadline reached policy as a mutation, so a rule gating \
         mutations would fire on a calculation"
    );
}

// ── What the runtime puts in a context ──────────────────────────────────────

/// An engine that refuses to see a JSON `null` in any request it is handed.
///
/// The `PolicyEngine` seam is public, and what an engine can accept is its own
/// business — Cedar, notably, has no `null` at all and rejects a whole context
/// containing one. So *the runtime* must not send a value it means as absent
/// spelled as a null, whatever engine is wired in.
///
/// The Cedar adapter also strips nulls, which is the right belt for data the
/// runtime does not author (an effect's own arguments are arbitrary caller
/// JSON). This is the braces: it holds the runtime's *own* contexts to the same
/// rule, so a fix that lives only in one adapter is not mistaken for a fix in
/// the runtime — an embedder's engine gets a clean context too.
#[derive(Debug, Default)]
struct RefusesNulls {
    seen: AtomicUsize,
    offending: Mutex<Vec<String>>,
}

impl RefusesNulls {
    fn walk(path: &str, value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Null => out.push(path.to_owned()),
            Value::Object(map) => {
                for (k, v) in map {
                    Self::walk(&format!("{path}/{k}"), v, out);
                }
            }
            Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    Self::walk(&format!("{path}/{i}"), v, out);
                }
            }
            _ => {}
        }
    }
}

impl PolicyEngine for RefusesNulls {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        self.seen.fetch_add(1, Ordering::SeqCst);
        let mut found = Vec::new();
        // `args` is deliberately exempt, and the exemption is the finding rather
        // than a hole in it. Those are the **effect's own arguments** — caller
        // data, and part of the effect key, so the runtime must pass them
        // through byte for byte rather than tidying them. A model call alone
        // carries four legitimate nulls there (`schema`, `reasoning_effort`,
        // `continuation`, `provider_profile`: every optional knob nobody set),
        // and a tool's arguments may contain any JSON at all.
        //
        // That is precisely why the Cedar adapter strips nulls instead of the
        // producers doing it: no amount of care upstream lets the runtime
        // promise that data it did not author contains none. What the runtime
        // *can* promise, and what this checks, is that the metadata it writes
        // itself — the agent, the label, the tenant, the delegation chain —
        // spells absent as absent.
        for (key, value) in request.context.as_object().into_iter().flatten() {
            if key == "args" {
                continue;
            }
            Self::walk(&format!("{}:/{key}", request.action), value, &mut found);
        }
        self.offending.lock().unwrap().extend(found);
        PolicyDecision::Permit
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"test.refuses-nulls"), "test/refuses-nulls-v1")
    }
}

/// **The runtime sends no JSON `null` to a policy engine.**
///
/// A value the runtime means as *absent* must be spelled absent. It was not:
/// `context.agent.publisher` is an `Option`, `None` serialized to `null`, and
/// most manifests are unpublished — so on a Cedar plane every admission came
/// back malformed and the whole plane denied everything, while the caller was
/// told only that it was declined.
///
/// Asserted against an engine that inspects rather than one that parses, so the
/// guarantee is about *what the runtime sends* and does not quietly become a
/// test of one adapter's tolerance. The count assertion is there because an
/// engine that was never called sees no nulls and would pass perfectly.
#[tokio::test]
async fn the_runtime_never_sends_a_null_to_policy() {
    let engine = Arc::new(RefusesNulls::default());
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::clone(&engine) as Arc<dyn PolicyEngine>)
        .skill(Pays {
            world: Arc::new(Mutex::new(Vec::new())),
        })
        .build();
    // A run with a real effect in it, so the perform context is exercised and
    // not only admission — the two are built in different places and only one
    // of them had the defect.
    let outcome = rt.run("pay", json!({})).await.unwrap();
    assert!(
        matches!(outcome.status, RunStatus::Succeeded),
        "{outcome:?}"
    );

    assert!(
        engine.seen.load(Ordering::SeqCst) >= 2,
        "the engine was barely consulted, so seeing no nulls proves nothing"
    );
    let offending = engine.offending.lock().unwrap().clone();
    assert!(
        offending.is_empty(),
        "the runtime sent JSON nulls to policy at {offending:?} — a value the \
         runtime means as absent must be spelled absent, since an engine may \
         have no null at all"
    );
}

/// The same rule, for the context only a **declared** agent produces.
///
/// The test above runs a coded skill, so `governed_by` is `None` and the `agent`
/// block — the one that carried the null — is never built at all. A guarantee
/// checked only on the path that cannot reach the defect is the fixture-shaped
/// failure this repository keeps a catalogue of, so the declarative path gets
/// its own case.
#[cfg(all(feature = "manifest", feature = "testkit"))]
#[tokio::test]
async fn a_declared_agent_sends_no_null_either() {
    use agentplane::manifest::Manifest;
    use agentplane::runtime::Agent;

    let manifest = Manifest::parse(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: summariser, version: "1.0.0" }
spec:
  execution: { kind: completion }
  identity: { role: "Summarise", constraints: "One sentence." }
  capabilities: { provides: [support.summarise] }
  models: { privileged: { provider: fake, model: sum-1 } }
  budgets: { max_tokens: 1000 }
"#,
    )
    .expect("manifest");
    // Never published, so `AgentIdentity::publisher` is `None` — the exact
    // condition that produced `"publisher": null`.
    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_say("a summary");
    let engine = Arc::new(RefusesNulls::default());
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::clone(&engine) as Arc<dyn PolicyEngine>)
        .provider(
            "fake",
            provider as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest))
        .build();
    let outcome = rt
        .run("support.summarise", json!({"ticket": "printer on fire"}))
        .await
        .unwrap();
    assert!(
        matches!(outcome.status, RunStatus::Succeeded),
        "{outcome:?}"
    );

    assert!(
        engine.seen.load(Ordering::SeqCst) >= 2,
        "the engine was barely consulted, so seeing no nulls proves nothing"
    );
    let offending = engine.offending.lock().unwrap().clone();
    assert!(
        offending.is_empty(),
        "a declared agent sent JSON nulls to policy at {offending:?}"
    );
}
