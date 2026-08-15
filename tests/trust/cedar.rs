//! Cedar as the authorization engine.
//!
//! The policies here are the ones the authorization design calls for — a
//! read-only tool set, a risk-tier ceiling, a taint gate, an egress gate, a
//! quarantined role with no authority, and a delegation-depth cap. If the
//! adapter cannot express those, the authorization story does not hold and the
//! seam was shaped wrong.
//!
//! Every context in this file is built by `sink_context`, which mirrors what
//! `StepCtx::authorize` actually sends. That is not tidiness: a policy checked
//! only against a context the test invented is a policy checked against itself,
//! and one in this file was — it read `context.args_trust`, a key the runtime
//! has never sent, so the taint gate it demonstrated failed open.
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

/// The effect kind a tool call authorizes under.
const TOOL_CALL: &str = "tool.call";

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

// ── The shapes the authorization design calls for ─────────────────────────

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
///
/// The **real** context key, not an invented one.
///
/// This policy used to read `context.args_trust` and `context.released`, and
/// the test that exercised it built a context containing them. Neither key is
/// anything the runtime sends: a sink authorization carries `context.label`,
/// whose fields are `provenance`, `trust` and `sensitivity`.
///
/// The consequence is the reason this comment exists. Cedar is *total*, so a
/// `when` clause reading a missing attribute does not raise — the policy is
/// simply not satisfied. The `forbid` therefore never matched, the blanket
/// `permit` stood, and the taint gate an adopter copied out of this file
/// **failed open** against the runtime it was written for, while every
/// assertion below passed. A policy tested only against a hand-built context is
/// a policy tested against itself.
const TAINT_GATE: &str = r#"
permit(principal, action == Action::"effect:perform", resource);

forbid(principal, action == Action::"effect:perform", resource)
when { context.mutates && context.label.trust == "untrusted" };
"#;

/// The context a `sink` authorization actually carries.
///
/// Built here rather than per test so every policy in this file is exercised
/// against one shape, and so that shape has a single place to be corrected when
/// the runtime's changes.
fn sink_context(trust: &str, sensitivity: &str, provenance: &[&str]) -> Value {
    request_context(trust, sensitivity, provenance, "ledger", 0)
}

/// The same shape with every attribute a published policy reads varied.
fn request_context(
    trust: &str,
    sensitivity: &str,
    provenance: &[&str],
    server: &str,
    delegation_depth: u32,
) -> Value {
    request_with(
        trust,
        sensitivity,
        provenance,
        server,
        delegation_depth,
        true,
    )
}

fn request_with(
    trust: &str,
    sensitivity: &str,
    provenance: &[&str],
    server: &str,
    delegation_depth: u32,
    mutates: bool,
) -> Value {
    json!({
        "run": "run_01KZ0000000000000000000000",
        "step": 0,
        "tenant": "default",
        "mutates": mutates,
        "delegation_depth": delegation_depth,
        "args": {
            "server": server,
            "tool": "transfer",
            "arguments": { "recipient": "AC-1", "amount": 2500 }
        },
        "label": {
            "provenance": provenance,
            "trust": trust,
            "sensitivity": sensitivity
        }
    })
}

#[test]
fn a_forbid_beats_a_permit_and_reads_the_context() {
    let engine = CedarEngine::new(TAINT_GATE).unwrap();

    let clean = sink_context("trusted", "internal", &["operator:ops"]);
    assert!(
        ask(&engine, "agent:a", ACTION_PERFORM, TOOL_CALL, &clean).is_permit(),
        "trusted arguments reach a mutating tool"
    );

    let tainted = sink_context("untrusted", "internal", &["tool:ledger"]);
    let d = ask(&engine, "agent:a", ACTION_PERFORM, TOOL_CALL, &tainted);
    assert!(!d.is_permit(), "untrusted arguments do not");

    let PolicyDecision::Deny { reason } = d else {
        unreachable!()
    };
    assert!(
        reason.contains("policy"),
        "the refusal names the rule that fired: {reason}"
    );
}

/// A forbid that cannot evaluate takes its permit down with it.
///
/// Cedar is total: a rule that errors — here a `forbid` reading
/// `context.args_trust`, a key the runtime never sends — contributes nothing,
/// so the `permit` beside it produces a clean-looking `Allow`. That `Allow`
/// may exist only *because* the veto broke, which makes every evaluation
/// error a switch that turns a forbid off — a gate an unusual request shape
/// can disarm. So the adapter refuses it, and the refusal reads as a
/// **defect** rather than a rule firing, because the operator's fix is the
/// policy set and not the request.
#[test]
fn a_forbid_on_an_attribute_the_request_lacks_fails_closed() {
    let engine = CedarEngine::new(
        r#"
        permit(principal, action == Action::"effect:perform", resource);
        forbid(principal, action == Action::"effect:perform", resource)
        when { context.mutates && context.args_trust == "untrusted" };
        "#,
    )
    .unwrap();

    let tainted = sink_context("untrusted", "internal", &["tool:ledger"]);
    let d = ask(&engine, "agent:a", ACTION_PERFORM, TOOL_CALL, &tainted);
    // `Malformed`, not `Deny`: the difference between a rule refusing and the
    // rules being broken is a variant now, so nothing has to read a sentence to
    // tell them apart.
    let PolicyDecision::Malformed { reason } = d else {
        panic!("an Allow reached beside an evaluation error must not stand: {d:?}");
    };
    assert!(
        reason.contains("policy evaluation error"),
        "the reason must say the policy set is broken: {reason}"
    );
    assert!(
        reason.contains("defect in the policy set, not a rule"),
        "the reason must distinguish a defect from a rule firing: {reason}"
    );
    assert!(
        !reason.contains("no policy permits"),
        "and it must not read as an ordinary default-deny: {reason}"
    );
}

/// The same pair, evaluable, decides both ways — proving the refusal above is
/// about the *error*, not the forbid: a clean `Allow` still permits, and the
/// forbid still vetoes when its attribute is present and matches.
#[test]
fn the_same_forbid_decides_once_its_attribute_is_present() {
    let engine = CedarEngine::new(
        r#"
        permit(principal, action == Action::"effect:perform", resource);
        forbid(principal, action == Action::"effect:perform", resource)
        when { context.mutates && context.args_trust == "untrusted" };
        "#,
    )
    .unwrap();

    let mut clean = sink_context("untrusted", "internal", &["tool:ledger"]);
    clean["args_trust"] = json!("trusted");
    assert!(
        ask(&engine, "agent:a", ACTION_PERFORM, TOOL_CALL, &clean).is_permit(),
        "a clean Allow must still permit, or the fail-closed rule above is a \
         deny-everything change passing its own test"
    );

    let mut vetoed = sink_context("untrusted", "internal", &["tool:ledger"]);
    vetoed["args_trust"] = json!("untrusted");
    assert!(
        !ask(&engine, "agent:a", ACTION_PERFORM, TOOL_CALL, &vetoed).is_permit(),
        "the forbid must still fire when it can evaluate"
    );
}

/// A delegation-depth cap, expressible only because the runtime puts the
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

/// A role that holds no authority at all — the quarantined model.
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
/// `tool.call` contains a `.` and a `/`. If the adapter did not quote entity
/// ids, this request would fail to parse and be denied — reported as a policy
/// decision, when in fact no rule was ever consulted.
#[test]
fn an_effect_kind_with_punctuation_is_a_usable_entity_id() {
    let engine =
        CedarEngine::new(r#"permit(principal, action, resource == Resource::"tool.call");"#)
            .unwrap();
    let ctx = json!({});

    assert!(
        ask(&engine, "agent:a", ACTION_PERFORM, "tool.call", &ctx).is_permit(),
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

    let PolicyDecision::Malformed { reason } = d else {
        panic!("a policy that cannot evaluate must still refuse, as a defect: {d:?}")
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
    let PolicyDecision::Malformed { reason } = denied else {
        panic!("a context violating the declared schema was accepted: {denied:?}")
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
        .run("pay", Tainted::trusted(json!({})))
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
        .run("pay", Tainted::trusted(json!({})))
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the owner matches, so the rule permits: {:?}",
        out.status
    );
    assert_eq!(world.lock().unwrap().len(), 1);
}

/// Every Cedar policy published on the documentation site compiles and decides.
///
/// This guard exists because its absence produced a real defect. The only
/// worked taint gate in this repository read `context.args_trust`, an attribute
/// the runtime has never sent. Cedar is total, so the `when` clause did not
/// raise — the `forbid` was simply unsatisfied, the accompanying `permit` stood,
/// and the gate an adopter would have copied **failed open**. Every test around
/// it passed, because every one of them built a context containing the invented
/// key.
///
/// So the site's policies are executed here against contexts the runtime
/// actually produces, and each must produce **more than one decision** across
/// them. Compiling is not enough: a rule keyed on an attribute nobody sends
/// parses perfectly and decides nothing, which is precisely the shape being
/// guarded against.
///
/// The matrix varies every attribute the published policies read — trust,
/// sensitivity, provenance, the tool's server, delegation depth and the
/// principal — because a matrix that varied fewer would report a working policy
/// as inert. That happened while writing this: a two-row matrix held `server`
/// fixed and flagged the one policy that keys on it.
#[test]
fn every_documented_cedar_policy_decides_against_the_real_context() {
    let page = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("site/content/docs/security.md"),
    )
    .expect("the security page is readable");

    let matrix: Vec<(&str, Value)> = vec![
        (
            "trusted, public, own server",
            request_context("trusted", "public", &["operator:ops"], "ledger", 0),
        ),
        (
            "untrusted, internal, own server",
            request_context("untrusted", "internal", &["tool:ledger"], "ledger", 0),
        ),
        (
            "trusted, confidential, via a peer",
            request_context("trusted", "confidential", &["peer:broker"], "ledger", 0),
        ),
        (
            "trusted, public, another server",
            request_context("trusted", "public", &["operator:ops"], "tickets", 0),
        ),
        (
            "trusted, public, deeply delegated",
            request_context("trusted", "public", &["operator:ops"], "ledger", 4),
        ),
        (
            "a read, not a mutation",
            request_with("trusted", "public", &["operator:ops"], "ledger", 0, false),
        ),
    ];

    let mut checked = 0usize;
    for (index, block) in page.split("```").enumerate() {
        if index % 2 == 0 || !block.starts_with("cedar") {
            continue;
        }
        let source = block.split_once('\n').map_or("", |(_, rest)| rest);
        checked += 1;

        let engine = CedarEngine::new(source).unwrap_or_else(|e| {
            panic!("a policy published on the security page does not compile: {e}\n{source}")
        });

        let decisions: Vec<(&str, bool)> = matrix
            .iter()
            .flat_map(|(name, context)| {
                ["agent:auditor", "agent:other"].map(|principal| {
                    (
                        *name,
                        ask(&engine, principal, ACTION_PERFORM, TOOL_CALL, context).is_permit(),
                    )
                })
            })
            .collect();

        assert!(
            decisions.iter().any(|(_, d)| *d) && decisions.iter().any(|(_, d)| !*d),
            "this published policy returns the same decision for every request \
             in the matrix, so it distinguishes nothing a reader could rely on — \
             which is exactly how a rule keyed on an attribute the runtime never \
             sends reads:\n{source}\ndecisions: {decisions:?}"
        );
    }

    assert!(
        checked >= 4,
        "only {checked} cedar blocks were found on the security page — the fence \
         scan stopped matching them and this guard is now inert"
    );
}

// ── The context the runtime actually sends at admission ─────────────────────

/// A JSON `null` reaches policy as an **absent attribute**, not as an outage.
///
/// Cedar has no `null`, and `Context::from_json_value` refuses a document
/// containing one anywhere — not the field, the whole record. The consequence
/// was severe and quiet: the request never reached a rule, so the answer was a
/// clean `Deny`, and an operator reading "denied" hunted for the rule that said
/// no while nothing had been evaluated at all.
///
/// The adapter now strips nulls, mapping them to Cedar's own idiom for optional
/// data. Both halves are asserted: the request is **evaluable**, and a policy
/// asking `has` gets the honest answer rather than a match on something
/// unmatchable.
#[test]
fn a_null_reaches_policy_as_an_absent_attribute() {
    // Permits only when the publisher is present, which is the rule an operator
    // writes when they mean "only agents somebody vouched for".
    let engine = CedarEngine::new(
        "permit(principal, action, resource) when { context.agent has publisher };",
    )
    .expect("policy");

    let unsigned =
        json!({ "tenant": "default", "agent": { "digest": "abc", "publisher": Value::Null } });
    let decision = ask(&engine, "p", ACTION_ADMIT, "r", &unsigned);
    let PolicyDecision::Deny { reason } = decision else {
        panic!("an absent publisher satisfied a rule that requires one: {decision:?}");
    };
    assert!(
        !reason.contains("could not be expressed"),
        "a null still makes the request unevaluable: {reason}"
    );

    // And the same rule permits once a publisher is there, so the test above is
    // a rule answering honestly rather than an adapter refusing everything.
    let signed = json!({ "tenant": "default", "agent": { "digest": "abc", "publisher": "key-1" } });
    assert!(
        matches!(
            ask(&engine, "p", ACTION_ADMIT, "r", &signed),
            PolicyDecision::Permit
        ),
        "a present publisher did not satisfy the rule"
    );
}

/// The same, for a null the runtime cannot fix at the source.
///
/// `context.args` is the effect's own arguments — **arbitrary caller JSON**, and
/// a model call's request profile carries `null` for every optional knob nobody
/// set. This is why the fix lives in the adapter and not only at the producers:
/// no amount of care upstream lets the runtime promise that data it did not
/// author contains no nulls.
#[test]
fn a_null_inside_caller_arguments_does_not_deny_everything() {
    let engine = CedarEngine::new(
        "permit(principal, action, resource) when { context.args.amount <= 100 };",
    )
    .expect("policy");
    let context = json!({
        "tenant": "default",
        "mutates": true,
        "args": { "amount": 50, "memo": Value::Null, "tags": ["a", Value::Null, "b"] },
    });
    assert!(
        matches!(
            ask(&engine, "p", ACTION_PERFORM, "tool.call", &context),
            PolicyDecision::Permit
        ),
        "a null in caller arguments denied a request the rule permits"
    );
}

/// Stripping a null leaves a record an audit can find.
///
/// The stripping above is safe — Cedar has no null literal, so nothing removed
/// was matchable — but it still means the rules evaluated a context that is
/// not byte-for-byte the arguments the effect key canonicalized. Two views of
/// one call, and without this event the only way to learn they differed is to
/// re-derive the stripping by hand. Both halves are asserted: the event fires
/// when something was removed, and stays silent when nothing was — an event on
/// every request would bury the divergence it exists to surface.
#[test]
fn null_stripping_is_visible_to_an_audit() {
    #[derive(Debug, Default, Clone)]
    struct Sink {
        events: Arc<Mutex<Vec<(String, String)>>>,
    }
    impl tracing::Subscriber for Sink {
        fn enabled(&self, _m: &tracing::Metadata<'_>) -> bool {
            true
        }
        /// Without this the test is a coin flip, and it was: `tracing` caches
        /// one process-wide maximum level, a subscriber that offers no hint
        /// leaves it wherever the last install left it, and the stripping
        /// event is `debug`. Run alone the test passed; run beside its
        /// siblings, another thread's dispatcher guard could drop the cached
        /// maximum below `debug` while this closure was still inside its
        /// own — and the event that had already been decided on was never
        /// emitted, so the sink saw nothing and the assertion blamed the
        /// stripping. Saying `TRACE` is what keeps the level a property of
        /// this subscriber rather than of the test schedule.
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }
        fn new_span(&self, _s: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _s: &tracing::span::Id, _v: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _s: &tracing::span::Id, _f: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, "{}={:?} ", field.name(), value);
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.events
                .lock()
                .unwrap()
                .push((event.metadata().target().to_owned(), fields.0));
        }
        fn enter(&self, _s: &tracing::span::Id) {}
        fn exit(&self, _s: &tracing::span::Id) {}
    }

    let engine = CedarEngine::new("permit(principal, action, resource);").unwrap();
    let sink = Sink::default();
    let events = Arc::clone(&sink.events);

    // Two nulls — an unset object member and an array element — so the count
    // proves the pass saw both shapes rather than only the easy one.
    let with_nulls = json!({
        "args": { "amount": 50, "memo": Value::Null, "tags": ["a", Value::Null] },
    });
    let decision = tracing::subscriber::with_default(sink.clone(), || {
        // `tracing` caches, once and process-wide, whether anybody is
        // interested in a callsite. If this `debug!` is first reached on a
        // thread with no subscriber — which any other test building a plane
        // can do — the answer "nobody" is cached, and this closure then emits
        // nothing however correct the stripping is. Rebuilding with the sink
        // installed makes the test a question about stripping rather than
        // about which test ran first.
        tracing::callsite::rebuild_interest_cache();
        ask(&engine, "p", ACTION_PERFORM, TOOL_CALL, &with_nulls)
    });
    assert!(decision.is_permit(), "the stripped request still evaluates");
    let recorded = events.lock().unwrap().clone();
    assert!(
        recorded.iter().any(|(target, fields)| {
            target == agentplane::policy::CONTEXT_NULLS_STRIPPED && fields.contains("removed=2")
        }),
        "stripping left no record an audit could find: {recorded:?}"
    );

    events.lock().unwrap().clear();
    let untouched = json!({ "args": { "amount": 50, "tags": ["a"] } });
    let decision = tracing::subscriber::with_default(sink, || {
        ask(&engine, "p", ACTION_PERFORM, TOOL_CALL, &untouched)
    });
    assert!(decision.is_permit());
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|(target, _)| target != agentplane::policy::CONTEXT_NULLS_STRIPPED),
        "an untouched context must not claim it was stripped"
    );
}

/// **An unsigned manifest must still reach a rule.**
///
/// The runtime describes the declaration to policy so a rule can bind to the
/// **digest** rather than to a reusable name. One field it sends is `publisher`,
/// the key that vouched for the manifest — and most manifests have none, because
/// publisher attestation is opt-in.
///
/// `Option::None` serialized straight into the context put a JSON `null` there,
/// which by the test above makes the entire request unevaluable. So **every run
/// on a Cedar plane with an unsigned manifest was denied**, and the caller was
/// told only that it was declined, since naming the reason to an external caller
/// is precisely what this crate refuses to do. The adapter's own module
/// documentation already said the field is *"or absent"*; only the code
/// disagreed.
///
/// This test drives the runtime's real `authorize_admission` rather than a
/// hand-built copy of its context, because a fixture written from the same
/// misreading as the code passes forever.
///
/// Found by running `agentplane serve` against a permit-everything policy and
/// reading the operator-side log — the only place the reason appears, and a
/// place nothing was listening until the CLI installed a subscriber.
#[tokio::test]
async fn an_unsigned_manifest_still_reaches_a_rule_at_admission() {
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
    // Deliberately never published: the publisher is plane state, set by
    // `publish_signed`, and an agent registered straight from a file has none.
    // That absence is the whole condition under test.

    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_say("a summary");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(
            Arc::new(CedarEngine::new("permit(principal, action, resource);").expect("policy"))
                as Arc<dyn PolicyEngine>,
        )
        .provider(
            "fake",
            provider as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest))
        .build();

    let outcome = rt
        .run(
            "support.summarise",
            Tainted::trusted(json!({"ticket": "printer on fire"})),
        )
        .await;
    assert!(
        matches!(
            outcome.as_ref().map(|o| &o.status),
            Ok(RunStatus::Succeeded)
        ),
        "a permit-everything policy refused an unsigned manifest: {outcome:?}"
    );
}

// ── The shape that denies everything, caught before it can ──────────────────

/// **A rule that reads a conditional attribute unguarded is refused at build.**
///
/// Cedar evaluates every rule against every request, so a `when` clause reading
/// an attribute the request does not carry does not fail to match — it errors,
/// and an unevaluable rule may be the `forbid` that would have stopped the
/// call, so the gate refuses. One such rule therefore denies every effect of
/// every run, from a policy set that parsed cleanly and validated against its
/// schema.
///
/// `delegation_depth` is exactly that attribute: it exists only where a
/// delegation chain does. A deployment wrote this rule against a plane that
/// always had one, ran it on a plane that did not, and found out at the first
/// effect of the first run — as a plane that refused everything, with nothing
/// at boot to say why.
///
/// The positive half is the same rule written correctly: guarded with `has`, it
/// builds, because the guard is what makes it evaluable on both shapes.
#[test]
fn a_rule_reading_a_conditional_attribute_unguarded_is_refused_at_build() {
    let unguarded = r#"
        permit(principal, action, resource);
        forbid(principal, action == Action::"effect:perform", resource)
        when { context.delegation_depth >= 1 };
    "#;
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let err = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::new(CedarEngine::new(unguarded).expect("it compiles")))
        .try_build()
        .expect_err("a policy set that cannot be evaluated must not assemble a plane");
    let text = err.to_string();
    assert!(
        text.contains("delegation_depth"),
        "the refusal must name the attribute that could not be read: {text}"
    );
    assert!(
        text.contains("context has"),
        "the refusal must show the guard that fixes it: {text}"
    );

    // The guarded form of the same rule — the one the docs should teach — is
    // evaluable against both shapes and assembles.
    let guarded = r#"
        permit(principal, action, resource);
        forbid(principal, action == Action::"effect:perform", resource)
        when { context has delegation_depth && context.delegation_depth >= 1 };
    "#;
    Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::new(CedarEngine::new(guarded).expect("it compiles")))
        .try_build()
        .expect("a guarded rule is evaluable on every request shape");

    // And the unguarded rule is *correct* on a plane that always carries a
    // chain, so the check asks the question this plane will actually ask
    // rather than a stricter one. Probing a shape the plane never produces
    // would refuse working deployments, which is how a boot check becomes the
    // thing people disable.
    Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::new(CedarEngine::new(unguarded).expect("it compiles")))
        .acting_as(
            Delegation::root(Principal::new("user:hupe", Scope::root()))
                .delegate(Principal::new("pay", Scope::of(["pay"])))
                .expect("a one-link chain"),
        )
        .try_build()
        .expect("a plane whose requests always carry the attribute may read it");
}

/// A policy set that merely *denies* still builds.
///
/// The preflight asks whether the rules can be evaluated, not whether they are
/// permissive: a default-deny plane is the recommended posture, and refusing to
/// boot over it would make this check the reason nobody writes one.
#[test]
fn a_default_deny_policy_set_still_assembles() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    Runtime::builder(store as Arc<dyn JournalStore>)
        .policy(Arc::new(
            CedarEngine::new("").expect("an empty set compiles"),
        ))
        .try_build()
        .expect("a set that denies everything is a working plane, not a broken one");
}
