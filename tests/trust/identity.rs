//! Delegation: on whose behalf, and the guarantee that authority only narrows.
//!
//! The claims:
//!
//! * **Scope containment is segment-aware.** `admin.*` must not cover
//!   `administrator-override`. A prefix match without a segment boundary is the
//!   classic authorization bug, and it grants exactly the thing whose name is
//!   longest and most alarming.
//! * **Delegation only narrows.** A widened scope is refused at construction, so
//!   an escalating chain is not representable — there is no code path that has
//!   to remember to check.
//! * **Depth is bounded.** A request that has travelled too far from the human
//!   who authorized it is refused.
//! * **The chain is journaled and read back.** Credentials expire; re-verifying
//!   them on replay would fail an audit of a decision that was sound when it was
//!   made. The chain that governed the run is what the journal holds.
//! * **An out-of-scope plan never starts.** The plan is the authorization graph,
//!   so authority is checked against it before anything runs.

#![cfg(feature = "sqlite")]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Capability, Delegation, DelegationError, Effect, EffectDescriptor, EffectError,
    MAX_DELEGATION_DEPTH, Outcome, PlanIR, PlanNode, Principal, Recovery, RetryPolicy, Scope,
    Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

// ── Scope containment ───────────────────────────────────────────────────────

fn cap(s: &str) -> Capability {
    Capability::new(s)
}

#[test]
fn a_wildcard_covers_its_own_prefix_and_everything_under_it() {
    let s = Scope::of(["billing.*"]);
    assert!(s.permits(&cap("billing")), "the prefix itself is included");
    assert!(s.permits(&cap("billing.reconcile")));
    assert!(s.permits(&cap("billing.eu.settle")), "and deeper segments");
}

/// The bug this check exists for.
///
/// A plain `starts_with` would have `admin.*` grant `administrator-override` —
/// the longest, most alarming capability in the system, quietly included by a
/// pattern that reads as if it only covers a family.
#[test]
fn a_wildcard_does_not_leak_across_a_segment_boundary() {
    let s = Scope::of(["admin.*"]);
    assert!(s.permits(&cap("admin.read")));
    assert!(
        !s.permits(&cap("administrator-override")),
        "the boundary is a segment, not a character"
    );
    assert!(!s.permits(&cap("adminx")));
    assert!(!s.permits(&cap("administration.read")));
}

#[test]
fn an_exact_pattern_permits_only_itself() {
    let s = Scope::of(["billing.reconcile"]);
    assert!(s.permits(&cap("billing.reconcile")));
    assert!(!s.permits(&cap("billing")));
    assert!(!s.permits(&cap("billing.reconcile.force")));
}

#[test]
fn the_root_scope_permits_everything_and_the_empty_scope_nothing() {
    assert!(Scope::root().permits(&cap("anything.at.all")));
    assert!(!Scope::empty().permits(&cap("anything.at.all")));
    assert!(Scope::empty().is_empty());
}

/// Containment between patterns, which is what attenuation is tested with.
#[test]
fn containment_is_directional() {
    let wide = Scope::of(["billing.*"]);
    let narrow = Scope::of(["billing.reconcile"]);

    assert!(
        wide.contains(&narrow),
        "a family contains one of its members"
    );
    assert!(
        !narrow.contains(&wide),
        "a member must never be found to contain its family — that is the \
         escalation this whole mechanism exists to prevent"
    );
    assert!(wide.contains(&wide));
}

/// Wildcard-versus-wildcard is where containment is easiest to get wrong.
#[test]
fn a_wildcard_contains_a_narrower_wildcard_but_not_the_reverse() {
    let wide = Scope::of(["billing.*"]);
    let narrower = Scope::of(["billing.eu.*"]);

    assert!(wide.contains(&narrower));
    assert!(!narrower.contains(&wide));
    assert!(
        !narrower.contains(&Scope::of(["billing.fr"])),
        "a sibling branch is not covered"
    );
    assert!(
        !Scope::of(["bill.*"]).contains(&Scope::of(["billing.*"])),
        "and neither is a lexical near-miss"
    );
}

#[test]
fn only_the_root_scope_contains_the_root_scope() {
    assert!(Scope::root().contains(&Scope::root()));
    assert!(Scope::root().contains(&Scope::of(["a.*"])));
    assert!(!Scope::of(["a.*"]).contains(&Scope::root()));
}

// ── Delegation ──────────────────────────────────────────────────────────────

fn owner() -> Delegation {
    Delegation::root(Principal::new("user:hupe", Scope::root()))
}

#[test]
fn a_chain_narrows_at_every_hop() {
    let chain = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap()
        .delegate(Principal::new("agent:checker", Scope::of(["audit.check"])))
        .unwrap();

    assert_eq!(chain.owner().id, "user:hupe");
    assert_eq!(chain.subject().id, "agent:checker");
    assert_eq!(chain.depth(), 2);
    assert!(chain.effective_scope().permits(&cap("audit.check")));
    assert!(
        !chain.effective_scope().permits(&cap("audit.write")),
        "the last link's authority is what applies, not the owner's"
    );
}

/// The escalation is refused at construction, so it is not representable.
#[test]
fn a_delegate_cannot_widen_its_delegator_s_authority() {
    let auditor = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap();

    let err = auditor
        .delegate(Principal::new(
            "agent:sneaky",
            Scope::of(["audit.check", "billing.transfer"]),
        ))
        .expect_err("widening must be refused");

    assert!(
        matches!(err, DelegationError::ScopeWidened { ref widened, .. } if widened == "billing.transfer"),
        "the refusal must name what was widened: {err}"
    );
}

/// Widening to a *family* from a member is the subtle case.
#[test]
fn a_delegate_cannot_promote_an_exact_grant_into_a_wildcard() {
    let checker = owner()
        .delegate(Principal::new("agent:checker", Scope::of(["audit.check"])))
        .unwrap();

    let err = checker
        .delegate(Principal::new("agent:more", Scope::of(["audit.check.*"])))
        .expect_err("a member may not become a family");
    assert!(matches!(err, DelegationError::ScopeWidened { .. }), "{err}");
}

#[test]
fn a_chain_may_not_run_deeper_than_the_cap() {
    let mut chain = owner();
    for i in 0..MAX_DELEGATION_DEPTH {
        chain = chain
            .delegate(Principal::new(format!("agent:{i}"), Scope::of(["audit.*"])))
            .unwrap();
    }
    assert_eq!(chain.depth(), MAX_DELEGATION_DEPTH);

    let err = chain
        .delegate(Principal::new("agent:toofar", Scope::of(["audit.*"])))
        .expect_err("past the cap");
    assert!(
        matches!(err, DelegationError::TooDeep { max, .. } if max == MAX_DELEGATION_DEPTH),
        "{err}"
    );
}

/// A chain read back from the journal is re-checked structurally.
///
/// Not the credentials — those expire — but the property that costs nothing to
/// confirm and everything to assume.
#[test]
fn a_rehydrated_chain_is_rechecked_for_widening() {
    let good = vec![
        Principal::new("user:hupe", Scope::root()),
        Principal::new("agent:auditor", Scope::of(["audit.*"])),
    ];
    assert!(Delegation::rehydrate(good).is_ok());

    let tampered = vec![
        Principal::new("agent:auditor", Scope::of(["audit.check"])),
        Principal::new("agent:auditor", Scope::of(["audit.*"])),
    ];
    assert!(
        Delegation::rehydrate(tampered).is_err(),
        "a journal tampered into holding a widening chain must be caught, not \
         trusted because it came from storage"
    );

    assert!(matches!(
        Delegation::rehydrate(Vec::new()),
        Err(DelegationError::Empty)
    ));
}

// ── Wired into a run ────────────────────────────────────────────────────────

type World = Arc<Mutex<Vec<String>>>;

#[derive(Debug)]
struct Touch {
    world: World,
}

#[async_trait::async_trait]
impl Effect for Touch {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("audit.touch", json!({}))
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
        self.world.lock().unwrap().push("touched".into());
        Ok(json!({}))
    }
}

#[derive(Debug)]
struct Checker {
    name: &'static str,
    world: World,
}

#[async_trait::async_trait]
impl Skill for Checker {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.name)
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Touch {
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({}))))
    }
}

fn db() -> Arc<SqliteStore> {
    Arc::new(SqliteStore::open_in_memory().unwrap())
}

fn runtime(store: &Arc<SqliteStore>, world: &World, chain: Option<Delegation>) -> Runtime {
    let mut b = Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
        .owner("identity")
        .skill(Checker {
            name: "audit.check",
            world: Arc::clone(world),
        })
        .skill(Checker {
            name: "billing.transfer",
            world: Arc::clone(world),
        });
    if let Some(c) = chain {
        b = b.acting_as(c);
    }
    b.build()
}

fn plan(capability: &str) -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, capability)
            .arg("input", agentplane::core::ArgSource::run_input())
            .terminal(),
    ])
}

/// The plan is the authorization graph, so authority is checked against it
/// before anything runs.
#[tokio::test]
async fn a_plan_outside_the_chain_s_authority_never_starts() {
    let store = db();
    let world: World = Arc::default();
    let chain = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap();

    let err = runtime(&store, &world, Some(chain))
        .run_plan(plan("billing.transfer"), json!({}))
        .await
        .expect_err("out of scope");

    assert!(
        err.to_string().contains("billing.transfer"),
        "the refusal must name the capability: {err}"
    );
    assert!(
        world.lock().unwrap().is_empty(),
        "nothing may run when the plan exceeds the chain's authority"
    );
}

#[tokio::test]
async fn a_plan_within_authority_runs() {
    let store = db();
    let world: World = Arc::default();
    let chain = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap();

    let out = runtime(&store, &world, Some(chain))
        .run_plan(plan("audit.check"), json!({}))
        .await
        .unwrap();

    assert!(matches!(out.status, RunStatus::Succeeded));
    assert_eq!(world.lock().unwrap().len(), 1);
}

/// "On whose behalf" is answerable from the journal, not reconstructed.
#[tokio::test]
async fn the_chain_is_journaled_at_admission() {
    let store = db();
    let world: World = Arc::default();
    let chain = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap()
        .delegate(Principal::new("agent:checker", Scope::of(["audit.check"])))
        .unwrap();

    let out = runtime(&store, &world, Some(chain))
        .run_plan(plan("audit.check"), json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let bound = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::IdentityBound { chain } => Some(chain.clone()),
            _ => None,
        })
        .expect("the chain must be on the record");

    assert_eq!(bound.len(), 3, "owner and two delegates: {bound:?}");
    assert_eq!(bound[0].id, "user:hupe");
    assert_eq!(bound[2].id, "agent:checker");
    store.verify(out.run_id).await.expect("chain intact");
}

/// A run with no delegation says so, rather than looking like an unbounded one.
#[tokio::test]
async fn a_run_with_no_chain_records_none() {
    let store = db();
    let world: World = Arc::default();

    let out = runtime(&store, &world, None)
        .run_plan(plan("audit.check"), json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    assert!(
        !records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::IdentityBound { .. })),
        "no chain, no record — an absent delegation must not be spelled the \
         same way as an unrestricted one"
    );
}

/// Replay reads the recorded chain back rather than re-deriving it.
///
/// A credential expires. Re-verifying during replay would fail an audit of a
/// decision that was sound when it was made — and skipping verification would
/// let a forged chain in through the audit path. Reading back is neither.
#[tokio::test]
async fn replay_uses_the_recorded_chain_not_the_configured_one() {
    let store = db();
    let world: World = Arc::default();
    let chain = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap();

    let out = runtime(&store, &world, Some(chain))
        .run_plan(plan("audit.check"), json!({}))
        .await
        .unwrap();

    // Replay under a *narrower* chain that would have refused this plan. The
    // recorded run must still verify: it is history, not a new request.
    let narrower = owner()
        .delegate(Principal::new(
            "agent:auditor",
            Scope::of(["audit.nothing"]),
        ))
        .unwrap();

    let replayed: World = Arc::default();
    let verified = runtime(&store, &replayed, Some(narrower))
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("a recorded run replays under its own recorded authority");

    assert!(matches!(verified.status, RunStatus::Succeeded));
    assert!(replayed.lock().unwrap().is_empty());
}

/// The policy engine sees the whole chain, not just the acting workload.
#[tokio::test]
async fn the_policy_request_carries_the_owner_and_the_depth() {
    use agentplane::core::{Digest, PolicyDecision, PolicyEngine, PolicyRequest};

    #[derive(Debug, Default)]
    struct Capturing(Mutex<Vec<Value>>);

    impl PolicyEngine for Capturing {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0.lock().unwrap().push(r.context.clone());
            PolicyDecision::Permit
        }
        fn digest(&self) -> Digest {
            Digest::of(b"capturing")
        }
    }

    let store = db();
    let world: World = Arc::default();
    let engine = Arc::new(Capturing::default());
    let chain = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .unwrap();

    Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("identity")
        .acting_as(chain)
        .policy(engine.clone())
        .skill(Checker {
            name: "audit.check",
            world: Arc::clone(&world),
        })
        .build()
        .run_plan(plan("audit.check"), json!({}))
        .await
        .unwrap();

    let seen = engine.0.lock().unwrap().clone();
    assert!(
        seen.iter().any(|c| c["owner"] == "user:hupe"),
        "a rule keyed on the human owner needs the owner: {seen:?}"
    );
    assert!(
        seen.iter().any(|c| c["delegation_depth"] == 1),
        "and §11.1's depth cap is expressible in Cedar only if depth is in the \
         context: {seen:?}"
    );
}
