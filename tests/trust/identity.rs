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
//!   to remember to check. *Construction* includes deserializing: a chain
//!   arrives from a credential, a journal record and a peer far more often than
//!   from a call to `delegate`.
//! * **Depth is bounded.** A request that has travelled too far from the human
//!   who authorized it is refused.
//! * **The chain is journaled and read back.** Credentials expire; re-verifying
//!   them on replay would fail an audit of a decision that was sound when it was
//!   made. The chain that governed the run is what the journal holds.
//! * **An out-of-scope plan never starts.** The plan is the authorization graph,
//!   so authority is checked against it before anything runs.
//! * **Validity and audience attenuate like scope, and bind at admission.** A
//!   delegate may not outlive its delegator or name another plane; an expired
//!   chain, or one issued for another plane, is refused before the run exists
//!   — and never re-judged afterwards.
//! * **The chain is per run, not per plane.** Terms carrying a chain admit the
//!   run under *that* chain: it is what the plan is checked against and what
//!   the journal names, so a served surface's runs act as their callers.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Capability, Delegation, DelegationError, Effect, EffectDescriptor, EffectError,
    MAX_DELEGATION_DEPTH, Outcome, PlanIR, PlanNode, Principal, Recovery, RetryPolicy,
    RuntimeError, Scope, Skill, SkillDescriptor, SkillError, Tainted, TenantId, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, RunTerms, Runtime, StepCtx};
use agentplane::store::RedbStore;
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

/// Deserializing is a constructor, and it takes the same door as the others.
///
/// The claim this file's header makes — an escalating chain "is not
/// representable" — is spent by every caller that gets a `Delegation` from
/// `serde` rather than from `delegate`: a credential an `Authenticator` parsed,
/// a journal record, a chain from a peer. A derived `Deserialize` reaches the
/// fields directly and is exactly the `Delegation::new(links)` this type
/// refuses to offer.
///
/// Each case below is one `rehydrate` refuses, so the assertion is about the
/// door rather than about the rule — and each is written so that *bypassing*
/// the check yields a chain the test can see, not an error it cannot
/// distinguish from a malformed fixture.
#[test]
fn a_deserialized_chain_cannot_widen_skip_the_depth_cap_or_be_empty() {
    let widening = json!({"links": [
        {"id": "user:hupe",      "scope": ["crm.read"]},
        {"id": "agent:exfil",    "scope": ["*"]}
    ]});
    let err = serde_json::from_value::<Delegation>(widening)
        .expect_err("a chain rooted at crm.read must not deserialize into one holding '*'");
    assert!(
        err.to_string().contains("delegation may only narrow"),
        "and it must fail with the attenuation rule's own words, not a shape \
         error that any malformed input would also produce: {err}"
    );

    // The narrowing chain with the same shape deserializes, so the refusal
    // above is the rule and not the fixture being unreachable.
    let narrowing = json!({"links": [
        {"id": "user:hupe",   "scope": ["crm.*"]},
        {"id": "agent:audit", "scope": ["crm.read"]}
    ]});
    let ok: Delegation = serde_json::from_value(narrowing).expect("narrowing still deserializes");
    assert_eq!(ok.subject().id, "agent:audit");
    assert_eq!(ok.depth(), 1);

    let deep = json!({"links": (0..=MAX_DELEGATION_DEPTH + 1)
        .map(|i| json!({"id": format!("agent:{i}"), "scope": ["*"]}))
        .collect::<Vec<_>>()});
    assert!(
        serde_json::from_value::<Delegation>(deep).is_err(),
        "the depth cap binds a deserialized chain too, or a credential is how \
         you buy an extra hop"
    );

    // An empty chain used to deserialize and then panic in `owner()`. It is
    // now unrepresentable: the owner is a field, not the head of a list.
    let err = serde_json::from_value::<Delegation>(json!({"links": []}))
        .expect_err("an empty chain is refused rather than panicking later");
    assert!(err.to_string().contains("no principal to act as"), "{err}");
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

fn db() -> Arc<RedbStore> {
    Arc::new(RedbStore::open_in_memory().unwrap())
}

fn runtime(store: &Arc<RedbStore>, world: &World, chain: Option<Delegation>) -> Arc<Runtime> {
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
        .run_plan(plan("billing.transfer"), Tainted::trusted(json!({})))
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
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
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
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
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
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
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
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
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
    use agentplane::core::{
        Digest, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest,
    };

    #[derive(Debug, Default)]
    struct Capturing(Mutex<Vec<Value>>);

    impl PolicyEngine for Capturing {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0.lock().unwrap().push(r.context.clone());
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            PolicyBundleIdentity::new(
                Digest::of(b"capturing"),
                "agentplane-test/identity-policy-v1",
            )
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
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
        .await
        .unwrap();

    let seen = engine.0.lock().unwrap().clone();
    assert!(
        seen.iter().any(|c| c["owner"] == "user:hupe"),
        "a rule keyed on the human owner needs the owner: {seen:?}"
    );
    assert!(
        seen.iter().any(|c| c["delegation_depth"] == 1),
        "and a depth cap is expressible in Cedar only if depth is in the \
         context: {seen:?}"
    );
}

// ── Validity and audience ───────────────────────────────────────────────────

fn at(unix: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(unix).expect("a representable instant")
}

/// A delegate that expires later than its delegator holds authority the
/// delegator will no longer have — the scope rule on the time axis.
#[test]
fn a_delegate_cannot_outlive_its_delegator() {
    let chain = owner()
        .delegate(Principal::new("agent:a", Scope::of(["audit.*"])).until(at(1_000)))
        .unwrap();
    let err = chain
        .delegate(Principal::new("agent:b", Scope::of(["audit.check"])).until(at(2_000)))
        .expect_err("a later expiry is a widening");
    assert!(
        matches!(err, DelegationError::ValidityWidened { .. }),
        "the refusal must be typed as a validity widening, not a generic one: {err:?}"
    );
    assert!(err.to_string().contains("may only narrow"), "{err}");

    // Earlier, equal and unset all narrow.
    for later in [None, Some(at(500)), Some(at(1_000))] {
        let mut link = Principal::new("agent:b", Scope::of(["audit.check"]));
        if let Some(t) = later {
            link = link.until(t);
        }
        let ok = chain
            .delegate(link)
            .expect("narrowing validity is permitted");
        assert_eq!(ok.not_after(), Some(later.unwrap_or(at(1_000))));
    }
    // A chain in which nobody set a bound has none, and a later link may set
    // one — that is narrowing from unbounded.
    assert_eq!(owner().not_after(), None);
    let bounded = owner()
        .delegate(Principal::new("agent:a", Scope::of(["audit.*"])).until(at(9)))
        .unwrap();
    assert_eq!(bounded.not_after(), Some(at(9)));
}

/// A delegate may not carry the chain to a plane its delegator was not
/// issued for.
#[test]
fn a_delegate_cannot_change_its_delegators_audience() {
    let chain = owner()
        .delegate(Principal::new("agent:a", Scope::of(["audit.*"])).for_audience("acme"))
        .unwrap();
    let err = chain
        .delegate(Principal::new("agent:b", Scope::of(["audit.check"])).for_audience("globex"))
        .expect_err("another audience is a widening");
    assert!(
        matches!(err, DelegationError::AudienceWidened { .. }),
        "{err:?}"
    );
    // The same audience, or none, narrows.
    assert_eq!(
        chain
            .delegate(Principal::new("agent:b", Scope::of(["audit.check"])).for_audience("acme"))
            .unwrap()
            .audience(),
        Some("acme")
    );
    assert_eq!(
        chain
            .delegate(Principal::new("agent:b", Scope::of(["audit.check"])))
            .unwrap()
            .audience(),
        Some("acme"),
        "an unset audience inherits rather than clears"
    );
}

/// Both new bounds are re-checked on the way back from storage, exactly as
/// scope is: a journal record or a credential is a construction path too.
#[test]
fn a_deserialized_chain_cannot_widen_validity_or_audience() {
    let outlives = json!({"links": [
        {"id": "user:hupe", "scope": ["*"], "not_after": "2030-01-01T00:00:00Z"},
        {"id": "agent:x",   "scope": ["*"], "not_after": "2031-01-01T00:00:00Z"}
    ]});
    let err = serde_json::from_value::<Delegation>(outlives).expect_err("outlives its delegator");
    assert!(err.to_string().contains("may only narrow"), "{err}");

    let elsewhere = json!({"links": [
        {"id": "user:hupe", "scope": ["*"], "audience": "acme"},
        {"id": "agent:x",   "scope": ["*"], "audience": "globex"}
    ]});
    let err = serde_json::from_value::<Delegation>(elsewhere).expect_err("names another plane");
    assert!(err.to_string().contains("may only narrow"), "{err}");

    // A chain written before the bounds existed reads back as declaring
    // neither, and one that declares them round-trips without a null.
    let bare: Delegation =
        serde_json::from_value(json!({"links": [{"id": "user:hupe", "scope": ["*"]}]}))
            .expect("absent bounds are absent");
    assert_eq!((bare.not_after(), bare.audience()), (None, None));
    let wire = serde_json::to_value(&bare).unwrap();
    assert_eq!(
        wire["links"][0].as_object().unwrap().len(),
        2,
        "unset bounds must not be written as nulls: {wire}"
    );
}

/// The one clocked check, and it refuses before the run exists.
#[tokio::test]
async fn an_expired_chain_is_refused_at_admission() {
    let store = db();
    let world: World = Arc::default();
    let expired = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])).until(at(1_000_000)))
        .unwrap();

    let err = runtime(&store, &world, Some(expired))
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
        .await
        .expect_err("a chain past its validity admits nothing");
    assert!(
        matches!(
            err,
            RuntimeError::Delegation(DelegationError::Expired { .. })
        ),
        "typed as an expired delegation, so a caller knows to fetch a fresh \
         credential rather than retry: {err:?}"
    );
    assert!(world.lock().unwrap().is_empty(), "nothing ran");
    assert!(
        store.recent_runs(None, 10).await.unwrap().is_empty(),
        "a refused admission leaves no run behind"
    );
}

/// A credential minted for another plane is refused here, however valid.
#[tokio::test]
async fn a_chain_bound_to_another_plane_is_refused_at_admission() {
    let store = db();
    let world: World = Arc::default();
    let elsewhere = owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])).for_audience("globex"))
        .unwrap();

    let err = runtime(&store, &world, Some(elsewhere))
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
        .await
        .expect_err("the plane is not the audience");
    assert!(
        matches!(
            err,
            RuntimeError::Delegation(DelegationError::WrongAudience { .. })
        ),
        "{err:?}"
    );
    assert!(world.lock().unwrap().is_empty());

    // The same chain bound to *this* plane is admitted — the refusal above is
    // the audience rule, not the fixture being unrunnable.
    let here = owner()
        .delegate(
            Principal::new("agent:auditor", Scope::of(["audit.*"])).for_audience(TenantId::DEFAULT),
        )
        .unwrap();
    let out = runtime(&store, &world, Some(here))
        .run_plan(plan("audit.check"), Tainted::trusted(json!({})))
        .await
        .expect("bound to this plane");
    assert!(matches!(out.status, RunStatus::Succeeded));
}

/// Terms carrying a chain admit the run under that chain — gate and record
/// both — and the plane's own chain does not reach the run.
#[tokio::test]
async fn a_run_acts_under_the_terms_chain_not_the_planes() {
    let store = db();
    let world: World = Arc::default();
    // The plane holds everything; only the caller's chain can refuse.
    let rt = runtime(&store, &world, Some(owner()));
    let alice = Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])));

    let err = rt
        .run_plan_under(
            plan("billing.transfer"),
            Tainted::trusted(json!({})),
            RunTerms::default().acting_as(alice.clone()),
        )
        .await
        .expect_err("outside the caller's scope, inside the plane's");
    assert!(err.to_string().contains("billing.transfer"), "{err}");
    assert!(world.lock().unwrap().is_empty());

    let out = rt
        .run_plan_under(
            plan("audit.check"),
            Tainted::trusted(json!({})),
            RunTerms::default().acting_as(alice),
        )
        .await
        .expect("inside the caller's scope");
    let records = store.read(out.run_id, 1).await.unwrap();
    let bound = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::IdentityBound { chain } => Some(chain.clone()),
            _ => None,
        })
        .expect("the chain must be on the record");
    assert_eq!(bound.len(), 1, "{bound:?}");
    assert_eq!(
        bound[0].id, "user:alice",
        "the journal must name the caller, not the plane: {bound:?}"
    );
}

/// Every step of a run acts under the chain the run was admitted with — in
/// the policy context live, and read back from `IdentityBound` on replay —
/// never under whatever chain the plane happens to be configured with now.
#[tokio::test]
async fn a_steps_policy_context_names_the_runs_chain_live_and_on_replay() {
    use agentplane::core::{
        Digest, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest,
    };

    #[derive(Debug, Default)]
    struct Capturing(Mutex<Vec<(String, Value)>>);

    impl PolicyEngine for Capturing {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0
                .lock()
                .unwrap()
                .push((r.action.to_owned(), r.context.clone()));
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            PolicyBundleIdentity::new(
                Digest::of(b"capturing"),
                "agentplane-test/identity-policy-v1",
            )
        }
    }

    fn subjects_of(engine: &Capturing) -> Vec<String> {
        engine
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(action, _)| action == "effect:perform")
            .map(|(_, cx)| cx["subject"].as_str().unwrap_or("<none>").to_owned())
            .collect()
    }

    let store = db();
    let world: World = Arc::default();
    let plane_chain = owner()
        .delegate(Principal::new("agent:plane", Scope::of(["audit.*"])))
        .unwrap();
    let alice = Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])));

    let live = Arc::new(Capturing::default());
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("identity")
        .acting_as(plane_chain.clone())
        .policy(live.clone())
        .skill(Checker {
            name: "audit.check",
            world: Arc::clone(&world),
        })
        .build()
        .run_plan_under(
            plan("audit.check"),
            Tainted::trusted(json!({})),
            RunTerms::default().acting_as(alice),
        )
        .await
        .unwrap();
    assert_eq!(
        subjects_of(&live),
        vec!["user:alice"],
        "the effect gate was asked about the plane's chain, not the run's"
    );

    // Strict replay on a plane configured with a *different* chain: the
    // context still names the recorded one.
    let replayed = Arc::new(Capturing::default());
    Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("identity")
        .acting_as(plane_chain)
        .policy(replayed.clone())
        .skill(Checker {
            name: "audit.check",
            world: Arc::default(),
        })
        .build()
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("a recorded run replays");
    // Replay re-opens no historical gate, so no `effect:perform` request is
    // expected at all — what must not happen is a request naming the plane.
    assert!(
        !subjects_of(&replayed).iter().any(|s| s == "agent:plane"),
        "a replayed step asked the policy about the plane's chain: {:?}",
        subjects_of(&replayed)
    );
}

#[derive(Debug)]
struct Orderer {
    world: World,
}

#[async_trait::async_trait]
impl Skill for Orderer {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("audit.order").provides("audit.order")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.world.lock().unwrap().push("ordered".into());
        let answer = cx.commission("audit.check", input).await?;
        Ok(Outcome::done(answer))
    }
}

/// A commissioned sub-run acts under the orderer's chain plus one link naming
/// the commissioned agent — the in-plane twin of the peer-call rule — so its
/// journal answers "on whose behalf" with the same owner.
#[tokio::test]
async fn a_commissioned_run_acts_under_the_orderers_chain_plus_one_link() {
    let store = db();
    let world: World = Arc::default();
    let alice = Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("identity")
        // The plane's own chain is deliberately different, so a sub-run
        // admitted under it would be visible.
        .acting_as(owner())
        .skill(Orderer {
            world: Arc::clone(&world),
        })
        .skill(Checker {
            name: "audit.check",
            world: Arc::clone(&world),
        })
        .build();

    let out = rt
        .run_plan_under(
            plan("audit.order"),
            Tainted::trusted(json!({})),
            RunTerms::default().acting_as(alice),
        )
        .await
        .unwrap();
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");

    let chains: Vec<Vec<String>> = {
        let mut found = Vec::new();
        for (run, _) in store.recent_runs(None, 10).await.unwrap() {
            let records = store.read(run, 1).await.unwrap();
            if let Some(chain) = records.iter().find_map(|r| match r.kind() {
                RecordKind::IdentityBound { chain } => Some(chain.clone()),
                _ => None,
            }) {
                found.push(chain.into_iter().map(|p| p.id).collect());
            }
        }
        found.sort();
        found
    };
    assert_eq!(
        chains,
        vec![
            vec!["user:alice".to_owned()],
            vec!["user:alice".to_owned(), "agent/audit.check".to_owned()],
        ],
        "the sub-run must act under the orderer's chain extended by the \
         commissioned agent, not under the plane's: {chains:?}"
    );
}

#[derive(Debug)]
struct WhoAmI;

#[async_trait::async_trait]
impl Skill for WhoAmI {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("audit.whoami").provides("audit.whoami")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let subject = cx.acting_as().map(|chain| chain.subject().id.clone());
        Ok(Outcome::done(Tainted::trusted(
            json!({ "subject": subject }),
        )))
    }
}

/// A step reads the chain its run was admitted under — the one to extend
/// toward a peer — and a replay reads the same chain back from the journal,
/// not from the plane it happens to be replayed on.
#[tokio::test]
async fn a_replayed_step_reads_the_recorded_chain_not_the_configured_one() {
    let store = db();
    let alice = Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])));
    let plane = |chain: Delegation| {
        Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .owner("identity")
            .acting_as(chain)
            .skill(WhoAmI)
            .build()
    };

    let out = plane(owner())
        .run_plan_under(
            plan("audit.whoami"),
            Tainted::trusted(json!({})),
            RunTerms::default().acting_as(alice),
        )
        .await
        .unwrap();
    assert_eq!(
        out.output.as_ref().map(|o| o.peek()["subject"].clone()),
        Some(json!("user:alice")),
        "the step saw the plane's chain, not the run's: {out:?}"
    );

    // Replayed on a plane whose configured chain names somebody else.
    let other = owner()
        .delegate(Principal::new("agent:other", Scope::of(["audit.*"])))
        .unwrap();
    let replayed = plane(other)
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("a recorded run replays");
    assert_eq!(
        replayed
            .output
            .as_ref()
            .map(|o| o.peek()["subject"].clone()),
        Some(json!("user:alice")),
        "a replayed step acted under the plane's current chain instead of the \
         recorded one: {replayed:?}"
    );
}
