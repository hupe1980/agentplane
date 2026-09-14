//! One contract, run against every policy engine.
//!
//! The trait asks for three things no signature can express — **total, pure, no
//! I/O** — and the whole authorization story rests on them. Totality is why
//! there is no error case in [`PolicyDecision`]: a gate that can fail is a gate
//! that fails open on the day it matters. Purity is why an auditor holding the
//! journal can re-derive a verdict offline, which is a claim about the engine
//! and not only about the record. And the bundle identity is journaled at
//! admission, so a run's answer to *what governed this* is only as good as an
//! implementation's promise that the identity covers every static input.
//!
//! None of that is checked by the type system, and the crate ships two
//! implementations that agree — which is the condition under which a third
//! implementation's disagreement goes unnoticed.
//!
//! What this battery cannot tell you: whether the rules are **right**. An
//! engine that permits everything passes every check here, exactly as
//! [`PolicyEngine::preflight`]'s own docs warn about an empty answer.
//!
//! [`PolicyDecision`]: crate::core::PolicyDecision
//! [`PolicyEngine::preflight`]: crate::core::PolicyEngine::preflight

use std::panic::AssertUnwindSafe;

use serde_json::{Value, json};

use crate::core::{PolicyDecision, PolicyEngine, PolicyRequest};

use super::conformance::Report;

/// Request shapes a conforming engine must answer rather than panic on.
///
/// The hostile half is deliberate: an engine reached by an effect gate is
/// reached with whatever context the runtime assembled, and an implementation
/// that indexes into the context or unwraps a field is one bad run away from
/// taking the process down at the moment a decision was required.
fn shapes() -> Vec<(&'static str, String, String, String, Value)> {
    let long = "x".repeat(4096);
    vec![
        (
            "the effect gate",
            "agent:triage".to_owned(),
            "effect:perform".to_owned(),
            "tool.call".to_owned(),
            json!({ "amount_eur": 10, "labels": ["internal"] }),
        ),
        (
            "admission",
            "agent:triage".to_owned(),
            "run:admit".to_owned(),
            "order.settle".to_owned(),
            json!({ "input": { "amount_eur": 5000 } }),
        ),
        (
            "an operator API verb",
            "operator:ana".to_owned(),
            "api:task.decide".to_owned(),
            "task".to_owned(),
            json!({}),
        ),
        (
            "empty strings",
            String::new(),
            String::new(),
            String::new(),
            json!({}),
        ),
        (
            "a context that is not an object",
            "agent:triage".to_owned(),
            "effect:perform".to_owned(),
            "tool.call".to_owned(),
            Value::Null,
        ),
        (
            "a context that is an array",
            "agent:triage".to_owned(),
            "effect:perform".to_owned(),
            "tool.call".to_owned(),
            json!([1, 2, 3]),
        ),
        (
            "an unknown action",
            "agent:triage".to_owned(),
            "something:nobody:wrote:a:rule:for".to_owned(),
            "tool.call".to_owned(),
            json!({}),
        ),
        (
            "very long fields",
            long.clone(),
            long.clone(),
            long,
            json!({ "note": "x".repeat(4096) }),
        ),
        (
            "characters a rule language may treat specially",
            "agent:\"; permit(principal, action, resource);".to_owned(),
            "effect:perform".to_owned(),
            "tool.call\u{0}\u{1f}\u{202e}".to_owned(),
            json!({ "emoji": "🙂", "nested": { "deep": { "deeper": [null] } } }),
        ),
    ]
}

fn ask(engine: &dyn PolicyEngine, request: &PolicyRequest<'_>) -> Option<PolicyDecision> {
    std::panic::catch_unwind(AssertUnwindSafe(|| engine.authorize(request))).ok()
}

/// Run the battery every policy engine answers, whatever it evaluates.
///
/// Hand it the engine a deployment actually wires — a rule set compiled from
/// the operator's own file, not a stand-in — because two of these checks are
/// about *that* set's behaviour and not only the evaluator's.
pub fn check(engine: &dyn PolicyEngine, report: &mut Report) {
    evaluation_is_total(engine, report);
    evaluation_is_pure(engine, report);
    evaluation_carries_no_state_between_requests(engine, report);
    a_refusal_says_which_rule(engine, report);
    the_bundle_identity_is_stable(engine, report);
    the_digest_is_the_bundles(engine, report);
    preflight_is_total(engine, report);
}

/// Every shape gets a decision. There is no error case in the return type, so
/// the only way an engine declines to answer is by unwinding.
fn evaluation_is_total(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "evaluation is total";
    for (what, principal, action, resource, context) in shapes() {
        let request = PolicyRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &context,
        };
        report.checked += 1;
        if ask(engine, &request).is_none() {
            report.record(
                RULE,
                format!(
                    "authorize panicked on {what} — a gate reached by every effect must \
                     answer rather than unwind, which is why the decision type has no \
                     error case"
                ),
            );
        }
    }
}

/// The same request twice is the same answer. A clock read, a counter, a cache
/// keyed on something that moves — all of them show up here, and all of them
/// break a third party's ability to re-derive the verdict from the journal.
fn evaluation_is_pure(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "evaluation is pure";
    for (what, principal, action, resource, context) in shapes() {
        let request = PolicyRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &context,
        };
        let (Some(first), Some(second)) = (ask(engine, &request), ask(engine, &request)) else {
            continue; // Totality already recorded it.
        };
        report.checked += 1;
        if first != second {
            report.record(
                RULE,
                format!(
                    "{what} answered {first:?} then {second:?} — the journal records the \
                     bundle identity and the request so a verdict can be re-derived \
                     offline, and an engine that answers twice cannot be"
                ),
            );
        }
    }
}

/// Evaluating A then B is the same as B then A. A shared mutable cache keyed on
/// the wrong thing is invisible to the repeat check above and visible here.
fn evaluation_carries_no_state_between_requests(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "no state between requests";
    let all = shapes();
    let forwards: Vec<Option<PolicyDecision>> = all
        .iter()
        .map(|(_, p, a, r, c)| {
            ask(
                engine,
                &PolicyRequest {
                    principal: p,
                    action: a,
                    resource: r,
                    context: c,
                },
            )
        })
        .collect();
    let backwards: Vec<Option<PolicyDecision>> = all
        .iter()
        .rev()
        .map(|(_, p, a, r, c)| {
            ask(
                engine,
                &PolicyRequest {
                    principal: p,
                    action: a,
                    resource: r,
                    context: c,
                },
            )
        })
        .collect();
    report.checked += 1;
    for (i, (forward, backward)) in forwards
        .iter()
        .zip(backwards.iter().rev())
        .enumerate()
        .filter(|(_, (f, b))| f != b)
    {
        let _ = (forward, backward);
        report.record(
            RULE,
            format!(
                "{} answered differently depending on what was evaluated before it — \
                 an engine holding state across requests decides one run's effect by \
                 another run's history",
                all[i].0
            ),
        );
    }
}

/// A refusal names the rule, because the caller already holds the action and
/// the resource and puts them in the record it journals.
fn a_refusal_says_which_rule(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "a refusal says which rule";
    for (what, principal, action, resource, context) in shapes() {
        let request = PolicyRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &context,
        };
        let Some(decision) = ask(engine, &request) else {
            continue;
        };
        let reason = match &decision {
            PolicyDecision::Permit => continue,
            PolicyDecision::Deny { reason } | PolicyDecision::Malformed { reason } => reason,
        };
        report.checked += 1;
        if reason.trim().is_empty() {
            report.record(
                RULE,
                format!(
                    "{what} was refused with an empty reason — the wrapper supplies the \
                     action and the resource, so this string's only job is saying which \
                     rule fired, and an empty one sends somebody to read the whole set"
                ),
            );
        }
    }
}

/// The identity journaled at admission does not move while the process runs.
fn the_bundle_identity_is_stable(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "the bundle identity is stable";
    report.checked += 1;
    let first = engine.bundle();
    let second = engine.bundle();
    if first.digest() != second.digest() {
        report.record(
            RULE,
            "two calls to bundle() gave different digests — the identity is journaled \
             once at admission and answers *what governed this run* forever after, so \
             one that moves makes every such answer unfalsifiable",
        );
    }
}

/// `digest` defaults to `bundle().digest()`, and an override that drifts is two
/// spellings of one fact — the shape this design treats most seriously.
fn the_digest_is_the_bundles(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "digest is the bundle's";
    report.checked += 1;
    if engine.digest() != engine.bundle().digest() {
        report.record(
            RULE,
            "digest() and bundle().digest() disagree — one of them is journaled and the \
             other is what an auditor recomputes, and nothing reconciles them",
        );
    }
}

/// Preflight runs during `build`, so it is held to the same contract.
fn preflight_is_total(engine: &dyn PolicyEngine, report: &mut Report) {
    const RULE: &str = "preflight is total";
    let all = shapes();
    let requests: Vec<PolicyRequest<'_>> = all
        .iter()
        .map(|(_, p, a, r, c)| PolicyRequest {
            principal: p,
            action: a,
            resource: r,
            context: c,
        })
        .collect();
    report.checked += 1;
    if std::panic::catch_unwind(AssertUnwindSafe(|| engine.preflight(&requests))).is_err() {
        report.record(
            RULE,
            "preflight panicked — it runs inside `build`, so this is a plane that cannot \
             be assembled rather than a run that cannot be admitted",
        );
    }
}
