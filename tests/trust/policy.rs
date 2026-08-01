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

#![cfg(feature = "sqlite")]
#![allow(clippy::disallowed_methods)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use agentplane::core::{
    ACTION_ADMIT, ACTION_PERFORM, Digest, Effect, EffectDescriptor, EffectError, Outcome,
    PolicyDecision, PolicyEngine, PolicyRequest, Recovery, RetryPolicy, RunId, Skill,
    SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

/// Effects that actually reached the world.
type World = Arc<Mutex<Vec<String>>>;

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
    fn digest(&self) -> Digest {
        Digest::of(b"counting")
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
    fn digest(&self) -> Digest {
        Digest::of(b"refuses")
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
    fn digest(&self) -> Digest {
        Digest::of(b"must-not-be-asked")
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

fn db() -> Arc<SqliteStore> {
    Arc::new(SqliteStore::open_in_memory().unwrap())
}

fn runtime(db: &Arc<SqliteStore>, world: &World, engine: Option<Arc<dyn PolicyEngine>>) -> Runtime {
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

// ── The gate ────────────────────────────────────────────────────────────────

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

/// Which rules governed a run is answerable from the journal, years later.
#[tokio::test]
async fn the_admission_record_names_the_policy_set() {
    let store = db();
    let world: World = Arc::default();
    let engine = Arc::new(Counting::default());
    let expected = engine.digest();

    let out = runtime(&store, &world, Some(engine))
        .run("pay", json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let admitted = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted { policy, .. } => Some(*policy),
            _ => None,
        })
        .expect("RunAdmitted");
    assert_eq!(
        admitted,
        Some(expected),
        "the policy digest must be on the admission record"
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
    let policy = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted { policy, .. } => Some(*policy),
            _ => None,
        })
        .expect("RunAdmitted");
    assert_eq!(policy, None);
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
    let again = runtime(&store, &resumed, Some(Arc::new(MustNotBeAsked)))
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
        fn digest(&self) -> Digest {
            Digest::of(b"capturing")
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
        fn digest(&self) -> Digest {
            Digest::of(b"principals")
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
                let _ = cx
                    .effect(agentplane::runtime::effects::Recorded::new(format!(
                        "probe-{i}"
                    )))
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
        fn digest(&self) -> Digest {
            Digest::of(b"refuses-every-effect")
        }
    }

    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
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
