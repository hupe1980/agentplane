//! Cedar as the authorization engine.
//!
//! The policies here are the ones §11.2 specifies — a read-only tool set, a
//! risk-tier ceiling, a taint gate, an egress gate, a quarantined role with no
//! authority, and a delegation-depth cap. If the adapter cannot express those,
//! the design's authorization story does not hold and the seam was shaped wrong.
//!
//! One test matters more than the rest: **a policy that fails to evaluate must
//! not read as an ordinary refusal.** Cedar is total, so a broken rule simply
//! does not contribute and the decision comes back a clean `Deny`. An operator
//! then sees "denied" and goes looking for the rule that said no, while the real
//! situation is that the policy set is broken and the plane has been enforcing
//! nothing anyone intended.

#![cfg(all(feature = "cedar", feature = "redb"))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    ACTION_ADMIT, ACTION_PERFORM, Delegation, Effect, EffectDescriptor, EffectError, Outcome,
    PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Principal, Recovery,
    RetryPolicy, Scope, Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::policy::{CedarEngine, CedarError};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

fn ask<'a>(
    engine: &CedarEngine,
    principal: &'a str,
    action: &'a str,
    resource: &'a str,
    context: &'a Value,
) -> PolicyDecision {
    engine.authorize(&PolicyRequest {
        principal,
        action,
        resource,
        context,
    })
}

// ── Cedar's default, and ours ───────────────────────────────────────────────

/// An empty policy set permits nothing, and says so in those words.
///
/// Cedar denies by default. "No policy permits this" is a different message from
/// "a forbid rule fired", and conflating them sends someone hunting for a rule
/// that does not exist.
#[test]
fn an_empty_policy_set_denies_and_says_nothing_permits() {
    let engine = CedarEngine::new("").unwrap();
    let ctx = json!({});
    let d = ask(&engine, "agent:a", ACTION_PERFORM, "ledger.transfer", &ctx);

    let PolicyDecision::Deny { reason } = d else {
        panic!("an empty policy set must permit nothing")
    };
    assert!(
        reason.contains("no policy permits"),
        "the reason must distinguish 'nothing allowed it' from 'a rule refused': {reason}"
    );
}

/// A malformed policy set fails at construction, not at the first request.
#[test]
fn a_policy_set_that_does_not_parse_is_refused_at_startup() {
    let err = CedarEngine::new("permit(principal, action")
        .expect_err("a malformed policy set must not compile");
    assert!(err.to_string().contains("does not parse"), "{err}");
}

// ── §11.2's shapes ──────────────────────────────────────────────────────────

const READ_ONLY: &str = r#"
permit(
    principal == Agent::"agent:auditor",
    action == Action::"effect:perform",
    resource == Resource::"ledger.read"
);
"#;

#[test]
fn a_permit_allows_exactly_what_it_names() {
    let engine = CedarEngine::new(READ_ONLY).unwrap();
    let ctx = json!({});

    assert!(
        ask(
            &engine,
            "agent:auditor",
            ACTION_PERFORM,
            "ledger.read",
            &ctx
        )
        .is_permit(),
        "the named tool is allowed"
    );
    assert!(
        !ask(
            &engine,
            "agent:auditor",
            ACTION_PERFORM,
            "ledger.transfer",
            &ctx
        )
        .is_permit(),
        "and nothing else is"
    );
    assert!(
        !ask(&engine, "agent:other", ACTION_PERFORM, "ledger.read", &ctx).is_permit(),
        "nor is another principal"
    );
}

/// The taint gate, expressed as a rule rather than as runtime code.
///
/// The runtime enforces this too — untrusted data cannot reach a mutating sink —
/// and the two are not redundant: the runtime's gate is structural and always
/// on, while a policy can express *conditions* the lattice has no vocabulary
/// for, such as which authorized releases a given agent may rely on.
const TAINT_GATE: &str = r#"
permit(principal, action == Action::"effect:perform", resource);

forbid(principal, action == Action::"effect:perform", resource)
when { context.mutates && context.args_trust == "untrusted" && !context.released };
"#;

#[test]
fn a_forbid_beats_a_permit_and_reads_the_context() {
    let engine = CedarEngine::new(TAINT_GATE).unwrap();

    let clean = json!({ "mutates": true, "args_trust": "trusted", "released": false });
    assert!(
        ask(
            &engine,
            "agent:a",
            ACTION_PERFORM,
            "ledger.transfer",
            &clean
        )
        .is_permit(),
        "trusted arguments reach a mutating tool"
    );

    let tainted = json!({ "mutates": true, "args_trust": "untrusted", "released": false });
    let d = ask(
        &engine,
        "agent:a",
        ACTION_PERFORM,
        "ledger.transfer",
        &tainted,
    );
    assert!(!d.is_permit(), "untrusted arguments do not");

    let PolicyDecision::Deny { reason } = d else {
        unreachable!()
    };
    assert!(
        reason.contains("policy"),
        "the refusal names the rule that fired: {reason}"
    );

    let cleared = json!({ "mutates": true, "args_trust": "untrusted", "released": true });
    assert!(
        ask(
            &engine,
            "agent:a",
            ACTION_PERFORM,
            "ledger.transfer",
            &cleared
        )
        .is_permit(),
        "a journaled release lifts it"
    );
}

/// §11.1's depth cap, which is expressible only because the runtime puts the
/// delegation depth in the context.
const DEPTH_CAP: &str = r"
permit(principal, action, resource);
forbid(principal, action, resource) when { context.delegation_depth >= 3 };
";

#[test]
fn a_rule_can_cap_delegation_depth() {
    let engine = CedarEngine::new(DEPTH_CAP).unwrap();

    for (depth, allowed) in [(0, true), (2, true), (3, false), (4, false)] {
        let ctx = json!({ "delegation_depth": depth });
        assert_eq!(
            ask(&engine, "agent:a", ACTION_PERFORM, "x", &ctx).is_permit(),
            allowed,
            "depth {depth}"
        );
    }
}

/// A role that holds no authority at all — §12's quarantined model.
#[test]
fn a_forbidden_principal_holds_no_authority() {
    let engine = CedarEngine::new(
        r#"
        permit(principal, action, resource);
        forbid(principal == Agent::"agent:quarantined", action, resource);
        "#,
    )
    .unwrap();
    let ctx = json!({});

    assert!(ask(&engine, "agent:normal", ACTION_PERFORM, "anything", &ctx).is_permit());
    for action in [ACTION_PERFORM, ACTION_ADMIT] {
        assert!(
            !ask(&engine, "agent:quarantined", action, "anything", &ctx).is_permit(),
            "the quarantined role's permitted action set must be empty"
        );
    }
}

// ── Entity ids the runtime actually produces ────────────────────────────────

/// Effect kinds are not bare identifiers, and must survive anyway.
///
/// `mcp.tools/call` contains a `.` and a `/`. If the adapter did not quote entity
/// ids, this request would fail to parse and be denied — reported as a policy
/// decision, when in fact no rule was ever consulted.
#[test]
fn an_effect_kind_with_punctuation_is_a_usable_entity_id() {
    let engine =
        CedarEngine::new(r#"permit(principal, action, resource == Resource::"mcp.tools/call");"#)
            .unwrap();
    let ctx = json!({});

    assert!(
        ask(&engine, "agent:a", ACTION_PERFORM, "mcp.tools/call", &ctx).is_permit(),
        "an effect kind with a dot and a slash must reach the rules intact"
    );
}

/// A principal containing a quote cannot break out of the entity literal.
#[test]
fn a_principal_containing_a_quote_cannot_forge_an_entity() {
    let engine =
        CedarEngine::new(r#"permit(principal == Agent::"agent:real", action, resource);"#).unwrap();
    let ctx = json!({});

    let hostile = r#"nobody" || true || Agent::"agent:real"#;
    assert!(
        !ask(&engine, hostile, ACTION_PERFORM, "x", &ctx).is_permit(),
        "a crafted principal must not be able to match a rule it is not"
    );
}

// ── The case this module exists for ─────────────────────────────────────────

/// A policy that cannot evaluate must not read as an ordinary refusal.
///
/// Here `context.risk_tier` is absent, so the `when` clause errors. Cedar is
/// total: the rule simply does not contribute and the answer is `Deny`. Without
/// distinguishing that, an operator reads "denied", looks for the rule, finds
/// one that *should* have permitted, and concludes the runtime is broken — while
/// the truth is the policy set is, and every request is being denied for a
/// reason nothing intended.
#[test]
fn a_policy_that_fails_to_evaluate_is_reported_as_broken_not_as_a_refusal() {
    let engine =
        CedarEngine::new(r"permit(principal, action, resource) when { context.risk_tier < 3 };")
            .unwrap();

    let ctx = json!({});
    let d = ask(&engine, "agent:a", ACTION_PERFORM, "x", &ctx);

    let PolicyDecision::Deny { reason } = d else {
        panic!("a policy that cannot evaluate must still deny")
    };
    assert!(
        reason.contains("policy error"),
        "the reason must say the policy set is broken, not that a rule refused: {reason}"
    );
    assert!(
        !reason.contains("no policy permits"),
        "and it must not be reported as an ordinary default-deny: {reason}"
    );
}

/// The same policy, with the attribute present, permits — proving the test
/// above fails for the reason it claims rather than because the rule is wrong.
#[test]
fn the_same_policy_permits_once_the_attribute_is_present() {
    let engine =
        CedarEngine::new(r"permit(principal, action, resource) when { context.risk_tier < 3 };")
            .unwrap();
    let ctx = json!({ "risk_tier": 1 });
    assert!(ask(&engine, "agent:a", ACTION_PERFORM, "x", &ctx).is_permit());
}

// ── The digest ──────────────────────────────────────────────────────────────

/// The digest identifies the rules, so an audit can ask what governed a run.
#[test]
fn the_digest_follows_the_policy_text() {
    let a = CedarEngine::new(READ_ONLY).unwrap();
    let b = CedarEngine::new(READ_ONLY).unwrap();
    let c = CedarEngine::new(TAINT_GATE).unwrap();

    assert_eq!(
        a.digest(),
        b.digest(),
        "the same rules identify the same way"
    );
    assert_ne!(
        a.digest(),
        c.digest(),
        "different rules must not share a digest, or the journal cannot say \
         which set governed a run"
    );
}

const REQUEST_SCHEMA: &str = r#"
{
    "": {
        "entityTypes": {
            "Agent": {},
            "Resource": {}
        },
        "actions": {
            "effect:perform": {
                "appliesTo": {
                    "principalTypes": ["Agent"],
                    "resourceTypes": ["Resource"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "risk_tier": { "type": "Long", "required": true }
                        },
                        "additionalAttributes": false
                    }
                }
            }
        }
    }
}
"#;

/// Rules are only one input to an authorization decision. The bundle identity
/// must move when schema, static entities, evaluator, or adapter configuration
/// moves even if the Cedar source does not.
#[test]
fn the_bundle_identity_covers_every_static_policy_input() {
    let plain = CedarEngine::new("").unwrap().bundle();
    let with_schema = CedarEngine::from_bundle("", Some(REQUEST_SCHEMA), None)
        .unwrap()
        .bundle();
    let with_entities = CedarEngine::from_bundle(
        "",
        None,
        Some(r#"[{"uid":{"type":"Agent","id":"agent:a"},"attrs":{"risk":"low"},"parents":[]}]"#),
    )
    .unwrap()
    .bundle();

    assert_ne!(plain.digest(), with_schema.digest());
    assert_ne!(plain.digest(), with_entities.digest());
    assert!(with_schema.schema().is_some());
    assert!(with_entities.entities().is_some());
    assert!(plain.configuration().is_some());

    let other_evaluator = PolicyBundleIdentity::new(
        plain.rules(),
        "cedar-policy/next;agentplane-adapter/2;extensions=all-available",
    )
    .with_configuration(plain.configuration().expect("adapter configuration"));
    assert_ne!(
        plain.digest(),
        other_evaluator.digest(),
        "an evaluator semantic change must change the bundle identity"
    );
}

/// Formatting a JSON component is not a policy change. Canonical component
/// digests avoid false bundle drift while preserving every semantic field.
#[test]
fn schema_identity_uses_canonical_json_not_file_formatting() {
    let compact = serde_json::to_string(
        &serde_json::from_str::<Value>(REQUEST_SCHEMA).expect("schema fixture"),
    )
    .unwrap();
    let a = CedarEngine::from_bundle("", Some(REQUEST_SCHEMA), None).unwrap();
    let b = CedarEngine::from_bundle("", Some(&compact), None).unwrap();
    assert_eq!(a.bundle(), b.bundle());
}

/// A declared schema is executable configuration: it validates policies at
/// startup and request context at evaluation, rather than merely entering a
/// digest.
#[test]
fn the_declared_schema_is_enforced() {
    let source = r#"permit(principal, action == Action::"effect:perform", resource);"#;
    let engine = CedarEngine::from_bundle(source, Some(REQUEST_SCHEMA), None).unwrap();

    assert!(
        ask(
            &engine,
            "agent:a",
            ACTION_PERFORM,
            "ledger.read",
            &json!({ "risk_tier": 2 })
        )
        .is_permit()
    );
    let denied = ask(
        &engine,
        "agent:a",
        ACTION_PERFORM,
        "ledger.read",
        &json!({ "risk_tier": "two" }),
    );
    let PolicyDecision::Deny { reason } = denied else {
        panic!("a context violating the declared schema was accepted")
    };
    assert!(reason.contains("defect"), "wrong refusal: {reason}");
}

/// Static entities are part of both evaluation and identity.
#[test]
fn static_entities_are_used_by_authorization() {
    let source = r#"
                permit(principal, action, resource)
                when { principal.risk == "low" };
        "#;
    let entities = r#"
            [{"uid":{"type":"Agent","id":"agent:a"},
                "attrs":{"risk":"low"},"parents":[]}]
        "#;
    let engine = CedarEngine::from_bundle(source, None, Some(entities)).unwrap();
    assert!(ask(&engine, "agent:a", ACTION_PERFORM, "x", &json!({})).is_permit());
    assert!(!ask(&engine, "agent:b", ACTION_PERFORM, "x", &json!({})).is_permit());
}

#[test]
fn malformed_bundle_components_are_refused_at_startup() {
    assert!(CedarEngine::from_bundle("", Some("{"), None).is_err());
    assert!(CedarEngine::from_bundle("", None, Some("{"),).is_err());

    let unknown_action = r#"
        permit(principal, action == Action::"not-declared", resource);
    "#;
    assert!(matches!(
        CedarEngine::from_bundle(unknown_action, Some(REQUEST_SCHEMA), None),
        Err(CedarError::Validation(_))
    ));

    let unknown_entity_type = r#"[{"uid":{"type":"Unknown","id":"a"},"attrs":{},"parents":[]}]"#;
    assert!(matches!(
        CedarEngine::from_bundle("", Some(REQUEST_SCHEMA), Some(unknown_entity_type)),
        Err(CedarError::Entities(_))
    ));
}

/// The evaluator tag is deliberately hard-coded because Cargo exposes this
/// crate's version, not a dependency's. This guard makes a dependency bump that
/// forgot the semantic identity fail in the same change.
#[test]
fn the_evaluator_identity_tracks_the_pinned_cedar_version() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(cargo.contains("cedar-policy = { version = \"4.12.0\""));
    assert!(
        CedarEngine::new("")
            .unwrap()
            .bundle()
            .evaluator()
            .contains("cedar-policy/4.12.0")
    );
}

// ── End to end ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Transfer {
    world: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl Effect for Transfer {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.transfer", json!({}))
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
        self.world.lock().unwrap().push("transferred".into());
        Ok(json!({}))
    }
}

#[derive(Debug)]
struct Pays {
    world: Arc<Mutex<Vec<String>>>,
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
        cx.effect(Transfer {
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(Outcome::done(Tainted::trusted(json!({}))))
    }
}

/// Cedar governs a real run, and the rules it enforced are on the record.
#[tokio::test]
async fn cedar_governs_a_run_and_the_digest_lands_in_the_journal() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let world = Arc::new(Mutex::new(Vec::new()));

    let engine = Arc::new(
        CedarEngine::new(
            r#"
            permit(principal, action == Action::"run:admit", resource);
            forbid(principal, action == Action::"effect:perform",
                   resource == Resource::"ledger.transfer");
            "#,
        )
        .unwrap(),
    );
    let expected = engine.bundle();

    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(engine)
        .skill(Pays {
            world: Arc::clone(&world),
        })
        .build()
        .run("pay", json!({}))
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "the transfer is forbidden: {:?}",
        out.status
    );
    assert!(
        world.lock().unwrap().is_empty(),
        "and must not have happened"
    );

    let records = store.read(out.run_id, 1).await.unwrap();
    let recorded = records
        .iter()
        .find_map(|r| match r.kind() {
            agentplane::journal::RecordKind::RunAdmitted { policy_bundle, .. } => {
                Some(policy_bundle.clone())
            }
            _ => None,
        })
        .expect("RunAdmitted");
    assert_eq!(
        recorded,
        Some(expected),
        "the journal must name the complete policy bundle that governed this run"
    );
}

/// A delegation chain's owner and depth reach the rules.
#[tokio::test]
async fn cedar_can_key_on_the_delegation_chain() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let world = Arc::new(Mutex::new(Vec::new()));

    let chain = Delegation::root(Principal::new("user:hupe", Scope::root()))
        .delegate(Principal::new("pay", Scope::of(["pay"])))
        .unwrap();

    let engine = Arc::new(
        CedarEngine::new(
            r#"
            permit(principal, action, resource);
            forbid(principal, action, resource)
            when { context.owner != "user:hupe" };
            "#,
        )
        .unwrap(),
    );

    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .acting_as(chain)
        .policy(engine)
        .skill(Pays {
            world: Arc::clone(&world),
        })
        .build()
        .run("pay", json!({}))
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the owner matches, so the rule permits: {:?}",
        out.status
    );
    assert_eq!(world.lock().unwrap().len(), 1);
}
